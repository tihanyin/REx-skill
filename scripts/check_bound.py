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

"""Discharge a bounds claim with a solver instead of arguing it.

    $ANGR_PYTHON scripts/check_bound.py index --buf 28 --elem 4 --clamp "i<=8"
    $ANGR_PYTHON scripts/check_bound.py mul   --width 32 --limit 0x140
    $ANGR_PYTHON scripts/check_bound.py sub   --width 32 --unsigned
    $ANGR_PYTHON scripts/check_bound.py cast  --from 32 --to 16 --guard "x<=1000"

the skill: a claim like "the index is clamped", "at most N records fit", or
"the loop terminates after K passes" is ARITHMETIC YOU DID IN YOUR HEAD. Mental arithmetic over recovered code is the single most reliable way
to produce a confident wrong verdict -- it reads exactly like an observation and
is not one.

The operations below are decidable. Ask the solver, record the answer.

Every mode prints either:
  SAFE      - no counterexample exists within the stated constraints (a real result)
  UNSAFE    - here is the concrete input that breaks it (that IS your trigger)
"""
from __future__ import annotations
import argparse, sys

def _z3():
    try:
        import z3
        return z3
    except ImportError:
        sys.exit("check_bound.py needs z3. Run it under $ANGR_PYTHON -- the angr "
                 "environment always carries one -- or 'pip install z3-solver'.")

def _parse(z3, expr, var, signed=True):
    """Turn 'i<=8' into a z3 constraint over `var`.

    Signedness is NOT cosmetic here: z3's <= on a BitVec is the SIGNED compare,
    so an unsigned guard written with <= silently becomes a signed one and the
    tool reports a counterexample that the real program cannot reach. Which
    comparison the binary performs is in the disassembly -- read it (section 7).
    """
    import re
    e = expr.replace(" ", "")
    m = re.fullmatch(r"[A-Za-z_]\w*(<=|>=|<|>|==|!=)(-?(?:0x)?[0-9a-fA-F]+)", e)
    if not m:
        sys.exit(f"cannot parse guard {expr!r}; use forms like i<=8, i<0x20, i==3")
    op, num = m.group(1), int(m.group(2), 0)
    if signed:
        return {"<=": var <= num, ">=": var >= num, "<": var < num,
                ">": var > num, "==": var == num, "!=": var != num}[op]
    return {"<=": z3.ULE(var, num), ">=": z3.UGE(var, num), "<": z3.ULT(var, num),
            ">": z3.UGT(var, num), "==": var == num, "!=": var != num}[op]

def mode_index(a):
    """Claim: every index that reaches buf[i] is in bounds."""
    z3 = _z3()
    i = z3.BitVec("i", a.width)
    s = z3.Solver()
    for g in a.clamp:
        s.add(_parse(z3, g, i, signed=a.signed))
    n_elems = a.buf // a.elem
    # the access is out of bounds if the byte offset lands outside the object
    ext = z3.SignExt if a.signed else z3.ZeroExt
    wide = z3.BitVec("off", a.width * 2)
    s.add(wide == ext(a.width, i) * a.elem)
    s.add(z3.Or(wide < 0, wide + a.elem > a.buf))
    print(f"  buffer {a.buf} bytes / {a.elem}-byte elements = {n_elems} slots")
    print(f"  guards: {a.clamp or ['(none)']}   index treated as {'signed' if a.signed else 'unsigned'}")
    if s.check() == z3.sat:
        m = s.model()
        print(f"\n  UNSAFE  i = {m[i].as_signed_long() if a.signed else m[i].as_long()} "
              f"-> byte offset {m[wide].as_signed_long()} escapes a {a.buf}-byte object")
        print("  That value IS your trigger. Confirm it on the binary before reporting.")
        return 1
    print("\n  SAFE    no in-guard index escapes the object.")
    print("  This holds ONLY for the guards you listed. If a path reaches the sink")
    print("  without one of them, the result says nothing about that path.")
    return 0

def mode_mul(a):
    """Claim: this size multiplication cannot wrap."""
    z3 = _z3()
    x, y = z3.BitVec("x", a.width), z3.BitVec("y", a.width)
    s = z3.Solver()
    for g in a.clamp:
        s.add(_parse(z3, g, x if g.lstrip()[0] in "xX" else y, signed=False))
    wide = z3.ZeroExt(a.width, x) * z3.ZeroExt(a.width, y)
    narrow = z3.ZeroExt(a.width, x * y)
    s.add(wide != narrow)                       # it wrapped
    if a.limit is not None:
        s.add(z3.ZeroExt(a.width, x * y) <= a.limit)   # ...and still passed the check
    print(f"  {a.width}-bit multiply" + (f", result compared <= {a.limit}" if a.limit is not None else ""))
    if s.check() == z3.sat:
        m = s.model()
        xv, yv = m[x].as_long(), m[y].as_long()
        print(f"\n  UNSAFE  x={xv} (0x{xv:x})  y={yv} (0x{yv:x})")
        print(f"          true product {xv*yv} wraps to {(xv*yv) % (1 << a.width)}")
        if a.limit is not None:
            print("          ...which passes the size check, so a short buffer is allocated.")
        return 1
    print("\n  SAFE    no wrap possible under those constraints.")
    return 0

def mode_sub(a):
    """Claim: this subtraction cannot underflow."""
    z3 = _z3()
    x, y = z3.BitVec("x", a.width), z3.BitVec("y", a.width)
    s = z3.Solver()
    for g in a.clamp:
        s.add(_parse(z3, g, x if g.lstrip()[0] in "xX" else y, signed=not a.unsigned))
    if a.unsigned:
        s.add(z3.ULT(x, y))                     # x - y wraps to a huge value
    else:
        s.add(x - y > x)                        # signed overflow shape
    print(f"  {a.width}-bit {'unsigned' if a.unsigned else 'signed'} subtraction x - y")
    if s.check() == z3.sat:
        m = s.model()
        xv, yv = m[x].as_long(), m[y].as_long()
        print(f"\n  UNSAFE  x={xv} y={yv} -> x-y = {(xv-yv) % (1 << a.width)} "
              f"(a length of ~{(xv-yv) % (1 << a.width)} bytes)")
        return 1
    print("\n  SAFE    no underflow under those constraints.")
    return 0

def mode_cast(a):
    """Claim: narrowing this value loses nothing that matters."""
    z3 = _z3()
    x = z3.BitVec("x", getattr(a, "from_"))
    s = z3.Solver()
    for g in a.clamp:
        s.add(_parse(z3, g, x, signed=False))
    narrowed = z3.Extract(a.to - 1, 0, x)
    s.add(z3.ZeroExt(getattr(a, "from_") - a.to, narrowed) != x)
    print(f"  {getattr(a,'from_')}-bit -> {a.to}-bit, guards: {a.clamp or ['(none)']}")
    if s.check() == z3.sat:
        m = s.model(); xv = m[x].as_long()
        print(f"\n  UNSAFE  x={xv} (0x{xv:x}) narrows to {xv & ((1<<a.to)-1)}")
        print("          A check on the wide value does not constrain the narrow one.")
        return 1
    print("\n  SAFE    narrowing is lossless under those constraints.")
    return 0


def mode_range(a):
    """Claim: offset + length stays inside the object.

    The single most common real parser bug: a record carries an offset and a
    length, each individually checked against the buffer, and their SUM is not.
    Check them together, in a width that cannot wrap, or the check is decorative.
    """
    z3 = _z3()
    off = z3.BitVec("off", a.width); ln = z3.BitVec("len", a.width)
    s = z3.Solver()
    for g in a.clamp:
        v = off if g.lstrip()[:3].lower().startswith("off") else ln
        s.add(_parse(z3, g, v, signed=a.signed))
    ext = z3.SignExt if a.signed else z3.ZeroExt
    wide = ext(a.width, off) + ext(a.width, ln)
    s.add(z3.Or(wide > a.buf, ext(a.width, off + ln) != wide))   # escapes, or wrapped
    print(f"  object {a.buf} bytes, {a.width}-bit offset+length, "
          f"{'signed' if a.signed else 'unsigned'}")
    print(f"  guards: {a.clamp or ['(none)']}")
    if s.check() == z3.sat:
        m = s.model(); o, l = m[off].as_long(), m[ln].as_long()
        tot = o + l
        print(f"\n  UNSAFE  offset={o} len={l} -> offset+len={tot}"
              f"{' (WRAPS to %d)' % (tot % (1 << a.width)) if tot >= (1 << a.width) else ''}"
              f", object is {a.buf}")
        print("  Checking offset and length separately does not check their sum.")
        return 1
    print("\n  SAFE    offset+length stays inside the object and cannot wrap.")
    return 0


def mode_div(a):
    """Claim: this divisor cannot be zero (CWE-369)."""
    z3 = _z3()
    d = z3.BitVec("d", a.width)
    s = z3.Solver()
    for g in a.clamp:
        s.add(_parse(z3, g, d, signed=a.signed))
    s.add(d == 0)
    print(f"  {a.width}-bit divisor, guards: {a.clamp or ['(none)']}")
    if s.check() == z3.sat:
        print("\n  UNSAFE  the divisor can be 0 under those guards -> CWE-369.")
        print("  Where the ISA traps division there is no import to give this away;")
        print("  where it is a libgcc helper, the helper calls raise().")
        return 1
    if a.signed:
        s2 = z3.Solver()
        for g in a.clamp: s2.add(_parse(z3, g, d, signed=True))
        s2.add(d == -1)
        if s2.check() == z3.sat:
            print("\n  UNSAFE  divisor can be -1: INT_MIN / -1 overflows and traps too.")
            return 1
    print("\n  SAFE    divisor is non-zero under those constraints.")
    return 0


def mode_shift(a):
    """Claim: this shift amount is in range."""
    z3 = _z3()
    n = z3.BitVec("n", a.width)
    s = z3.Solver()
    for g in a.clamp:
        s.add(_parse(z3, g, n, signed=a.signed))
    s.add(z3.Or(z3.UGE(n, a.width), n < 0) if a.signed else z3.UGE(n, a.width))
    print(f"  shifting a {a.width}-bit value, guards: {a.clamp or ['(none)']}")
    if s.check() == z3.sat:
        print(f"\n  UNSAFE  shift amount = {s.model()[n].as_long()} on a {a.width}-bit "
              f"value: undefined, and in practice the CPU masks it to a value you did "
              f"not intend.")
        return 1
    print(f"\n  SAFE    shift amount stays in [0,{a.width}).")
    return 0


def mode_alloc(a):
    """Claim: header + count*element cannot wrap before the allocation."""
    z3 = _z3()
    cnt = z3.BitVec("count", a.width)
    s = z3.Solver()
    for g in a.clamp:
        s.add(_parse(z3, g, cnt, signed=False))
    wide = z3.ZeroExt(a.width, cnt) * a.elem + a.header
    narrow = z3.ZeroExt(a.width, cnt * a.elem + a.header)
    s.add(wide != narrow)
    if a.limit is not None:
        s.add(z3.ZeroExt(a.width, cnt * a.elem + a.header) <= a.limit)
    print(f"  malloc({a.header} + count * {a.elem}) at {a.width} bits"
          + (f", checked <= {a.limit}" if a.limit is not None else ""))
    if s.check() == z3.sat:
        c = s.model()[cnt].as_long()
        real = a.header + c * a.elem
        print(f"\n  UNSAFE  count={c} -> real size {real}, allocated "
              f"{real % (1 << a.width)}")
        print("  The allocation is short; the loop that fills it is not.")
        return 1
    print("\n  SAFE    no wrap in the allocation size.")
    return 0


def mode_expr(a):
    """Generic: your own variables, constraints and safety property.

    The catalogue above covers the shapes that recur. This is for everything else:
    declare the bitvectors, state what the guards establish, state the property you
    believe holds, and get a counterexample or a proof of its absence.

      check_bound.py expr --var 'len:32' --var 'idx:32' \
          --assume 'ULE(len, 64)' --assume 'ULT(idx, len)' \
          --claim 'ULT(idx, 64)'

    Names available: the z3 module as z3, and every helper z3 exports -- ULT, ULE,
    UGT, UGE, And, Or, Not, If, Extract, ZeroExt, SignExt, BitVecVal.
    """
    z3 = _z3()
    env = {n: getattr(z3, n) for n in dir(z3) if not n.startswith("_")}
    env["z3"] = z3
    for spec in a.var:
        name, _, w = spec.partition(":")
        env[name.strip()] = z3.BitVec(name.strip(), int(w or 32))
    s = z3.Solver()
    try:
        for c in a.assume:
            s.add(eval(c, env))
        claim = eval(a.claim, env)
    except Exception as e:
        sys.exit(f"could not evaluate: {e}\nRemember unsigned comparisons are "
                 f"ULT/ULE/UGT/UGE; bare < and <= are SIGNED on a bitvector.")
    s.add(z3.Not(claim))
    print(f"  vars: {', '.join(a.var)}")
    print(f"  assuming: {a.assume or ['(nothing)']}")
    print(f"  claim: {a.claim}")
    if s.check() == z3.sat:
        m = s.model()
        print("\n  UNSAFE  the claim does not hold. Counterexample:")
        for d in m.decls():
            print(f"      {d.name()} = {m[d]}  (0x{m[d].as_long():x})")
        return 1
    print("\n  SAFE    the claim holds under those assumptions.")
    print("  It says nothing about paths where the assumptions do not hold.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="mode", required=True)

    p = sub.add_parser("index", help="does any allowed index escape the buffer?")
    p.add_argument("--buf", type=lambda s: int(s, 0), required=True, help="object size in BYTES")
    p.add_argument("--elem", type=lambda s: int(s, 0), default=1, help="element size in bytes")
    p.add_argument("--width", type=int, default=32, help="index register width")
    p.add_argument("--signed", action="store_true", help="index is signed (read the .S!)")
    p.add_argument("--clamp", action="append", default=[], help="guard, e.g. i<=8 (repeatable)")
    p.set_defaults(fn=mode_index)

    p = sub.add_parser("mul", help="can this size multiplication wrap?")
    p.add_argument("--width", type=int, default=32)
    p.add_argument("--limit", type=lambda s: int(s, 0), default=None,
                   help="the size check applied AFTER the multiply")
    p.add_argument("--clamp", action="append", default=[])
    p.set_defaults(fn=mode_mul)

    p = sub.add_parser("sub", help="can this subtraction underflow?")
    p.add_argument("--width", type=int, default=32)
    p.add_argument("--unsigned", action="store_true")
    p.add_argument("--clamp", action="append", default=[])
    p.set_defaults(fn=mode_sub)

    p = sub.add_parser("cast", help="does narrowing lose a value the guard relied on?")
    p.add_argument("--from", dest="from_", type=int, required=True)
    p.add_argument("--to", type=int, required=True)
    p.add_argument("--clamp", action="append", default=[])
    p.set_defaults(fn=mode_cast)

    p = sub.add_parser("range", help="does offset+length escape the object, or wrap?")
    p.add_argument("--buf", type=lambda s: int(s, 0), required=True)
    p.add_argument("--width", type=int, default=32)
    p.add_argument("--signed", action="store_true")
    p.add_argument("--clamp", action="append", default=[],
                   help="guard on off or len, e.g. 'off<=64' / 'len<=64'")
    p.set_defaults(fn=mode_range)

    p = sub.add_parser("div", help="can this divisor be zero? (CWE-369)")
    p.add_argument("--width", type=int, default=32)
    p.add_argument("--signed", action="store_true")
    p.add_argument("--clamp", action="append", default=[])
    p.set_defaults(fn=mode_div)

    p = sub.add_parser("shift", help="can the shift amount reach the type width?")
    p.add_argument("--width", type=int, default=32)
    p.add_argument("--signed", action="store_true")
    p.add_argument("--clamp", action="append", default=[])
    p.set_defaults(fn=mode_shift)

    p = sub.add_parser("alloc", help="can header + count*elem wrap before malloc?")
    p.add_argument("--header", type=lambda s: int(s, 0), default=0)
    p.add_argument("--elem", type=lambda s: int(s, 0), required=True)
    p.add_argument("--width", type=int, default=32)
    p.add_argument("--limit", type=lambda s: int(s, 0), default=None)
    p.add_argument("--clamp", action="append", default=[])
    p.set_defaults(fn=mode_alloc)

    p = sub.add_parser("expr", help="your own constraints and claim -- anything not above")
    p.add_argument("--var", action="append", default=[], help="name:width, repeatable")
    p.add_argument("--assume", action="append", default=[], help="constraint, repeatable")
    p.add_argument("--claim", required=True, help="the property you believe holds")
    p.set_defaults(fn=mode_expr)

    a = ap.parse_args()
    return a.fn(a)

if __name__ == "__main__":
    sys.exit(main())
