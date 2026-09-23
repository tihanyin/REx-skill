#!/usr/bin/env python3
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

"""Force-create a function at an address Ghidra missed and print its C.

Some ARM binaries reference main only through a GOT relocation, so the loader
never marks it executable and Ghidra never creates the function. This clears any
stale ARM-mode decode, forces the TMode context (ARMv8 code is Thumb-2), then
disassembles, creates the function and decompiles it.

    python3 scripts/decompile_addr.py <binary> <hex_va> [--arm]
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pyghidra  # noqa: E402


def main():
    args = [a for a in sys.argv[2:] if not a.startswith("--")]
    force_arm = "--arm" in sys.argv
    if len(sys.argv) < 3 or not args:
        print("usage: decompile_addr.py <binary> <hex_va> [--arm]", file=sys.stderr)
        return 2
    path = sys.argv[1]
    vas = [int(a, 16) for a in args]

    pyghidra.start()
    from java.math import BigInteger
    from ghidra.app.decompiler import DecompInterface
    from ghidra.app.cmd.disassemble import DisassembleCommand
    from ghidra.app.cmd.function import CreateFunctionCmd
    from ghidra.util.task import ConsoleTaskMonitor

    monitor = ConsoleTaskMonitor()
    monitor.setCancelEnabled(False)

    with pyghidra.open_program(path, analyze=True) as flat:
        program = flat.getCurrentProgram()
        space = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        ctx = program.getProgramContext()
        tmode = ctx.getRegister("TMode")
        listing = program.getListing()
        di = DecompInterface()
        di.openProgram(program)

        tx = program.startTransaction("force functions")
        made = []
        try:
            for va in vas:
                even = space.getAddress(va & ~1)
                block = program.getMemory().getBlock(even)
                if block is None:
                    print(f"// no memory block at {hex(va)}")
                    continue
                end = block.getEnd()
                if fm.getFunctionAt(even) is None:
                    listing.clearCodeUnits(even, end, False)
                    if tmode is not None:
                        ctx.setValue(tmode, even, end,
                                     BigInteger.valueOf(0 if force_arm else 1))
                    DisassembleCommand(even, None, True).applyTo(program, monitor)
                    if fm.getFunctionAt(even) is None:
                        CreateFunctionCmd(even).applyTo(program)
                func = fm.getFunctionAt(even)
                if func is None:
                    print(f"// could not create function at {hex(va)}")
                    continue
                made.append(func)
        finally:
            program.endTransaction(tx, True)

        for func in made:
            res = di.decompileFunction(func, 180, monitor)
            if res is None or not res.decompileCompleted():
                print(f"// decompile failed at {func.getEntryPoint()}")
                continue
            print(f"// ===== forced function @ {func.getEntryPoint()} "
                  f"thumb={not force_arm} =====")
            print(res.getDecompiledFunction().getC())


if __name__ == "__main__":
    raise SystemExit(main())
