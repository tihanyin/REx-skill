#    ██████╗ ███████╗██╗  ██╗    ███████╗██╗  ██╗██╗██╗     ██╗
#    ██╔══██╗██╔════╝╚██╗██╔╝    ██╔════╝██║ ██╔╝██║██║     ██║
#    ██████╔╝█████╗   ╚███╔╝     ███████╗█████╔╝ ██║██║     ██║
#    ██╔══██╗██╔══╝   ██╔██╗     ╚════██║██╔═██╗ ██║██║     ██║
#    ██║  ██║███████╗██╔╝ ██╗    ███████║██║  ██╗██║███████╗███████╗
#    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝
#
#    R E X @ S K I L L   ·   Reverse Engineering eXecution
#
#    Author :  Norbert Tihanyi
#    X      :  x.com/@TihanyiNorbert
{
  description = "RE workbench: Ghidra/PyGhidra + qemu-user + radare2/rizin + binutils";

  # Exact revision, not a channel. A channel would move Ghidra between runs, and
  # the decompiler's output IS the analyst's input -- two runs would not be
  # comparable. Reproducing an analysis means reproducing a revision.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/ffb3c9b700e759be2ef13237c9d8f953b32a1e46";

  # A SECOND pin, used for angr only. At the revision above, nixpkgs ships a
  # version-skewed angr family (angr 9.2.193 against pyvex/archinfo/cle 9.2.154)
  # and angr pins its siblings exactly, so it cannot build; aligning down to
  # 9.2.154 then breaks against that revision's pycparser. This revision has a
  # coherent family that builds. Pinned by rev, because a channel name moves.
  inputs.nixpkgs-angr.url = "github:NixOS/nixpkgs/ac62194c3917d5f474c1a844b6fd6da2db95077d";

  outputs = { self, nixpkgs, nixpkgs-angr }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
      forAll = nixpkgs.lib.genAttrs systems;
    in {
      devShells = forAll (system:
        let
          # qiling is NOT available here: its dependency python-registry does not
          # build on this python, which is why nixpkgs flags it broken. Unicorn
          # plus scripts/emulate.py covers one-function emulation (SKILL-RE §8).
          pkgs = import nixpkgs { inherit system; };

          # angr gets its own interpreter from the second pin, reached ONLY via
          # $ANGR_PYTHON. It is deliberately NOT in `packages`: two
          # python.withPackages environments on the same PATH cross-contaminate
          # PYTHONPATH, and 3.14's cffi then loads 3.12's _cffi_backend and dies.
          # Same shell and same session as Ghidra, two interpreters, no collision.
          # SKILL-RE §29/§30 call $ANGR_PYTHON; everything else calls $RE_PYTHON.
          angrPython = nixpkgs-angr.legacyPackages.${system}.python3.withPackages
            (ps: with ps; [ angr claripy cle pyvex archinfo capstone ]);

          # The main python env exports PYTHONPATH, which would make this 3.12
          # interpreter load the 3.14 env's cffi and die on a version mismatch.
          # Clear it at the door. This wrapper is what $ANGR_PYTHON points at.
          angrPythonWrapper = pkgs.writeShellScriptBin "angr-python" ''
            unset PYTHONPATH
            exec ${angrPython}/bin/python3 "$@"
          '';

          # capa ships no rules in nixpkgs, and without them it exits 10 and writes
          # nothing. Pin the matching rule set so capability detection actually
          # works, and pin it by tag for the same reason everything else is pinned.
          capaRules = pkgs.fetchzip {
            url = "https://github.com/mandiant/capa-rules/archive/refs/tags/v9.4.0.tar.gz";
            hash = "sha256-jFjhS+ZxyJr/tNyZbNkUUmcModPMRLl7bZRWHMPxWqM=";
          };

          # AFL++ QEMU mode, for EVERY architecture the shell can emulate.
          #
          # afl-qemu-trace is an ordinary ELF built for one target: nixpkgs
          # configures it `--target-list=<host>-linux-user`, so on x86-64 it
          # rejects an i386, MIPS or PowerPC binary outright ("Invalid ELF image
          # for this architecture"), and afl-fuzz reports that as a fork server
          # handshake failure. Coverage-guided fuzzing was therefore available on
          # exactly one of the ten architectures this shell can otherwise analyse.
          #
          # --target-list is comma-separated, so ONE derivation builds them all.
          # Measured: 72s and 67 MB for all nine, against ~50s for the single
          # target nixpkgs builds by default.
          # ppc64 and ppc64le are deliberately absent: qemuafl is a fork of
          # qemu 5.2, and its target/ppc/translate.c does not compile with a
          # current gcc ("passing argument 1 of tcg_gen_movi_i32 from
          # incompatible pointer type"). 32-bit ppc is unaffected. Both remain
          # fully analysable -- qemu-user runs them and they have sysroots --
          # they simply cannot be fuzzed under AFL++ here, and fuzz_target.sh
          # says so rather than pretending otherwise.
          aflQemuTargets = [
            "x86_64" "i386" "arm" "aarch64"
            "mips" "mipsel" "mips64" "mips64el"
            "ppc" "riscv64"
          ];
          aflQemuMulti = pkgs.aflplusplus.qemu.overrideAttrs (o: {
            configureFlags =
              [ ("--target-list=" + pkgs.lib.concatStringsSep ","
                   (map (t: t + "-linux-user") aflQemuTargets)) ]
              ++ builtins.filter
                   (f: !(pkgs.lib.hasPrefix "--target-list=" f))
                   o.configureFlags;
          });
          # afl-fuzz resolves afl-qemu-trace through $AFL_PATH, so give each
          # target its own directory holding a correctly-named binary.
          aflQemuTraces = pkgs.runCommand "afl-qemu-traces" { } (
            pkgs.lib.concatMapStrings (t: ''
              mkdir -p $out/${t}
              ln -s ${aflQemuMulti}/bin/qemu-${t} $out/${t}/afl-qemu-trace
            '') aflQemuTargets);

          # A cross compiler per target, for scripts/argvfuzz.c.
          #
          # The argv shim is an LD_PRELOAD object, so it must be the target's
          # architecture. Built for the host and preloaded into a MIPS process it
          # is discarded -- "wrong ELF class: ELFCLASS64: ignored" -- and the
          # program then runs with NO argv at all. It still executes, AFL still
          # counts six figures of executions, and the result is recorded clean.
          # Nothing about that is true, which is why the compiler is pinned here
          # rather than left to whatever `cc` happens to be on PATH.
          crossCcFor = {
            x86_64  = pkgs.stdenv.cc;
            i386    = pkgs.pkgsCross.gnu32.stdenv.cc;
            aarch64 = pkgs.pkgsCross.aarch64-multiplatform.stdenv.cc;
            arm     = pkgs.pkgsCross.armv7l-hf-multiplatform.stdenv.cc;
            mips    = pkgs.pkgsCross.mips-linux-gnu.stdenv.cc;
            mipsel  = pkgs.pkgsCross.mipsel-linux-gnu.stdenv.cc;
            mips64  = pkgs.pkgsCross.mips64-linux-gnuabi64.stdenv.cc;
            mips64el= pkgs.pkgsCross.mips64el-linux-gnuabi64.stdenv.cc;
            ppc     = pkgs.pkgsCross.ppc32.stdenv.cc;
            ppc64   = pkgs.pkgsCross.ppc64.stdenv.cc;
            ppc64le = pkgs.pkgsCross.powernv.stdenv.cc;
            riscv64 = pkgs.pkgsCross.riscv64.stdenv.cc;
          };
          crossCc = pkgs.writeText "cross_cc.json" (builtins.toJSON
            (pkgs.lib.mapAttrs (_: cc: "${cc}/bin/${cc.targetPrefix}cc") crossCcFor));

          # Cross sysroots, BUILT WITH THE SHELL. qemu-user can only run a
          # dynamically linked foreign binary if it can find that target's ld.so
          # and libc; without them every foreign-architecture binary falls back to
          # static-only, which is the single largest loss of analytical power
          # available (SKILL-RE section 9). Shipping them means emulation works on
          # `nix develop` instead of after a separate 40-minute step nobody runs.
          sysrootFor = {
            i386    = pkgs.pkgsCross.gnu32.glibc;
            aarch64 = pkgs.pkgsCross.aarch64-multiplatform.glibc;
            arm     = pkgs.pkgsCross.armv7l-hf-multiplatform.glibc;
            mips    = pkgs.pkgsCross.mips-linux-gnu.glibc;
            mipsel  = pkgs.pkgsCross.mipsel-linux-gnu.glibc;
            mips64  = pkgs.pkgsCross.mips64-linux-gnuabi64.glibc;
            mips64el= pkgs.pkgsCross.mips64el-linux-gnuabi64.glibc;
            ppc     = pkgs.pkgsCross.ppc32.glibc;
            # powernv is ppc64 LITTLE-endian. Using it for the big-endian key
            # hands qemu-ppc64 a sysroot of the wrong byte order, and every
            # big-endian ppc64 binary then fails to start for a reason that
            # looks like the binary's fault.
            ppc64   = pkgs.pkgsCross.ppc64.glibc;
            ppc64le = pkgs.pkgsCross.powernv.glibc;
            riscv64 = pkgs.pkgsCross.riscv64.glibc;
          };
          sysroots = pkgs.runCommand "re-sysroots" { } (''
            mkdir -p $out
          '' + builtins.concatStringsSep "\n" (pkgs.lib.mapAttrsToList
                (a: p: "ln -s ${p} $out/${a}") sysrootFor) + ''

            cat > $out/sysroots.json <<'JSON'
            {
          '' + builtins.concatStringsSep ",\n" (pkgs.lib.mapAttrsToList
                (a: p: ''  "${a}": {"qemu": "qemu-${a}", "sysroot": "${p}"}'') sysrootFor) + ''

            }
            JSON
          '');

          python = pkgs.python3.withPackages (ps: with ps; [
            pyghidra          # drives Ghidra headless from the pipeline
            capstone          # disassembly from Python
            pyelftools        # ELF parsing without shelling out
            lief              # multi-format binary parsing and patching
            pycryptodome      # checking crypto constants against known tables
            # --- reachability, emulation and solving: SKILL-RE §8, §19, §29, §30 ---
            triton            # concolic + taint over a concrete trace (§30)
            # z3-solver is NOT here: at this pin its libz3.so wants a glibc ABI
            # (GLIBC_ABI_GNU2_TLS) the pinned glibc does not provide. $ANGR_PYTHON
            # carries a working z3; use it for anything that needs the solver.
            unicorn           # run ONE function in isolation (§8 oracle)
            pwntools          # crafted inputs, cyclic offsets, ELF/ROP helpers
            # --- formats and containers: §21, §22 ---
            pefile            # PE parsing, delay-imports and ordinals
            construct         # declarative parser for a recovered grammar
            kaitaistruct      # the same, as a portable spec
            r2pipe            # script radare2 instead of shelling out
            yara-python       # rule matching from the pipeline
            # scapy is NOT here: it pulls `fs`, which does not support python3.14
            # at this pin. Use tshark to read a protocol; craft frames with a
            # plain socket or `construct`, both of which are present.
          ]);
        in {
          default = pkgs.mkShell {
            packages = [
              python
              angrPythonWrapper    # `angr-python`, also $ANGR_PYTHON (§29, §30)
              pkgs.ghidra          # the decompiler -- the single load-bearing tool
              pkgs.jdk21           # PyGhidra boots the JVM itself
              pkgs.radare2         # interactive: axt, afl, pdf, iz
              pkgs.rizin           # radare2 fork, cleaner API
              pkgs.yara            # known-pattern matching
              pkgs.upx             # detect and unpack UPX (SKILL-RE §16)
              pkgs.binwalk         # embedded blobs and firmware
              pkgs.parallel        # batch_decompile.sh driver
              pkgs.jq
              pkgs.file
              pkgs.binutils        # readelf, objdump, nm, strings, size
              pkgs.unzip
              # --- hardening and exploitability (§3.1, §24) ---
              pkgs.checksec         # NX/RELRO/canary/PIE/fortify in one call
              pkgs.ropgadget        # are there usable gadgets? -- §24's "NX leaves ROP open"
              pkgs.one_gadget       # libc one-shot gadgets, for the same question
              # --- triage force multipliers (§4, §5) ---
              pkgs.capa             # capability detection from rules: what CAN this do
              pkgs.flare-floss      # strings that `strings` cannot see: stack/encoded
              pkgs.detect-it-easy   # packer/compiler identification (§17)
              # --- second and third opinions; §7 says cross-check, so make it possible ---
              pkgs.rizinPlugins.rz-ghidra   # decompiler inside rizin: `pdg`
              pkgs.diffoscope               # structural diffing (§18)
              # --- containers other than ELF (§22) ---
              pkgs.pev              # PE toolkit
              pkgs.osslsigncode     # Authenticode signatures
              pkgs.openssl
              # --- data formats and protocols (§21) ---
              pkgs.kaitai-struct-compiler  # §21 says "write it as a Kaitai spec" -- this compiles it
              pkgs.tshark                  # §21's Wireshark dissector, headless
              pkgs.hexyl                   # xxd with colour; header-vs-hypothesis at a glance
              pkgs.dwarfdump               # §4.1b: harvest debug info before reversing by hand
              pkgs.radamsa                 # dumb mutation fuzzer -- no harness required (§26)
              # --- firmware extraction: binwalk needs these to unpack anything (§23) ---
              pkgs.squashfsTools
              pkgs.sasquatch        # vendor-patched squashfs, which is what routers ship
              pkgs.jefferson        # JFFS2
              pkgs.ubi_reader       # UBIFS
              pkgs.cramfsswap
              pkgs.p7zip
              pkgs.cabextract
              pkgs.lz4
              pkgs.zstd
              pkgs.lzop
              # --- making a silent bug loud: SKILL-RE section 26 ---
              pkgs.clang            # -fsanitize=address,undefined on a LIFTED function
              pkgs.symcc            # concolic via compile-time instrumentation. NEEDS
                                    # compilable source, so it serves §26 Tier 3 only --
                                    # it cannot touch a binary you cannot rebuild.
              pkgs.z3               # solver CLI
              pkgs.bitwuzla         # faster on bitvector-heavy queries than z3
              pkgs.cppcheck         # static analysis that tolerates non-compiling C
              pkgs.semgrep          # pattern rules over decompiled C, no build needed
              pkgs.flawfinder       # cheap lexical pass over decompiled output
              # --- misc ---
              pkgs.patchelf         # make a foreign binary runnable
              pkgs.elfutils         # eu-readelf: survives malformed ELF that binutils rejects
              pkgs.nasm
              # The agent itself, pinned like the rest. Provider-agnostic, so the
              # same toolchain can be driven by a non-Anthropic model without
              # changing anything else -- which is what makes a model comparison
              # a comparison. Claude Code is NOT vendored here: it is installed
              # per-machine and inherits this PATH when launched from the shell.
              # The AGENTS ARE DELIBERATELY NOT HERE. Pin the analysis tools --
              # Ghidra, radare2, qemu -- because their output IS the evidence and a
              # version change makes two runs incomparable. An agent is a different
              # kind of thing: a client that has to track an evolving API, so
              # freezing one does not buy reproducibility, it buys an agent that
              # cannot reach the model you are testing. Install them per machine,
              # let them self-update, and RECORD the version in the run metadata:
              #
              #   curl -fsSL https://claude.ai/install.sh | bash   -> ~/.local/bin
              #   npm i -g @openai/codex                           (or its installer)
              #   npm i -g opencode-ai                             (or its installer)
              #
              # Launched from inside this shell they inherit the whole PATH, so they
              # call r2, readelf and $RE_PYTHON exactly as a pinned copy would.
            ]
            # Linux-only. qemu-user translates *Linux* syscalls to host syscalls,
            # so it does not exist on darwin -- and ltrace/strace/gdb likewise.
            # On darwin you get every static stage but no execution (§8).
            ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
              pkgs.qemu            # qemu-arm, qemu-mips, qemu-ppc, qemu-riscv64, ...
              pkgs.gdb
              pkgs.ltrace          # §3.0 quick wins -- badly underused
              pkgs.strace
              pkgs.gef             # gdb, made usable (§25)
              pkgs.valgrind        # memory errors on a native run
              pkgs.aflplusplus     # coverage-guided fuzzing (§19)
              pkgs.frida-tools     # runtime instrumentation (§19)
              pkgs.bpftrace        # eBPF tracing: which syscall sees which bytes (§9)
              pkgs.honggfuzz       # second fuzzer; persistent mode
              pkgs.rr              # record/replay: reverse-continue to the corruption
            ];

            shellHook = ''
              export GHIDRA_INSTALL_DIR="${pkgs.ghidra}/lib/ghidra"
              # Deliberately NOT setting NIX_GHIDRAHOME: with Ghidra 12.x pyghidra
              # registers it as a second application root, the layout then finds
              # GPL/DemanglerGnu twice, and it dies with "Multiple modules collided
              # with same name". GHIDRA_INSTALL_DIR alone is what pyghidra 3.1 wants.
              unset NIX_GHIDRAHOME
              export JAVA_HOME="${pkgs.jdk21}"
              # A plugin shim can shadow python3 with an interpreter that has no
              # pyghidra. Every stage uses $RE_PYTHON, never bare python3.
              export RE_PYTHON="${python}/bin/python3"
              # scripts/run_tools.sh reads this; capa cannot run without it.
              export CAPA_RULES="${capaRules}"
              # scripts/dynamic_probe.py falls back to this when no --sysroots is
              # given, so foreign-architecture emulation works out of the box.
              export RE_SYSROOTS="${sysroots}/sysroots.json"
              # scripts/fuzz_target.sh points $AFL_PATH at the subdirectory for
              # the target's architecture, which is what makes coverage-guided
              # fuzzing work on a foreign-architecture binary.
              export RE_AFL_QEMU="${aflQemuTraces}"
              # scripts/fuzz_target.sh builds the argv shim with the compiler for
              # the TARGET architecture, not the host's.
              export RE_CROSS_CC="${crossCc}"
              # angr lives in its own interpreter, from the second pin. Same shell.
              export ANGR_PYTHON="${angrPythonWrapper}/bin/angr-python"
              # Ghidra rejects any path containing a '.'-prefixed element, which
              # rules out ~/.config/... and this repo's own dot-directories.
              export RE_SCRATCH="''${RE_SCRATCH:-/tmp/re-scratch}"
              export PRJ_ROOT="$PWD"
              # Only greet a human. Printed unconditionally, this banner lands in
              # the middle of every scripted `nix develop --command` invocation
              # and corrupts anything that parses the output.
              # Everything else in this shell is realised by Nix before the
              # prompt appears. The argv shim is the one piece that is compiled
              # rather than fetched, so build it here for every architecture
              # instead of in the middle of an analysis -- a missing compiler is
              # then a setup problem, which is where it belongs.
              for _s in "$PWD/../scripts/build_shims.sh" "$PWD/scripts/build_shims.sh"; do
                if [ -x "$_s" ]; then _SHIMOUT="$(bash "$_s" 2>&1)"; break; fi
              done
              unset _s

              if [ -t 1 ]; then
                echo "RE workbench ready  --  read SKILL-RE.md"
                echo "  GHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR"
                echo "  RE_PYTHON=$RE_PYTHON"
                echo "  ANGR_PYTHON=$ANGR_PYTHON"
                echo "  CAPA_RULES=$CAPA_RULES"
                echo "  RE_SYSROOTS=$RE_SYSROOTS"
                echo "  RE_AFL_QEMU=$RE_AFL_QEMU"
                echo "  RE_CROSS_CC=$RE_CROSS_CC"
                [ -n "''${_SHIMOUT:-}" ] && echo "''${_SHIMOUT}"
                ${pkgs.lib.optionalString (!pkgs.stdenv.hostPlatform.isLinux)
                  ''echo "  WARNING: darwin -- no qemu-user/gdb/ltrace; execution stages unavailable"''}
              fi
            '';
          };
        });
    };
}
