#!/usr/bin/env python3
import argparse
import sys

from keystone import *
from pwn import *
from pwnlib.context import LocalContext
from pwnlib.commandline import common

parser = argparse.ArgumentParser(
    'asm',
    description = 'Assemble shellcode into bytes',
)

parser.add_argument(
    'lines',
    metavar='line',
    nargs='*',
    help='Lines to assemble. If none are supplied, use stdin'
)

parser.add_argument(
    "-f", "--format",
    help="Output format (defaults to hex for ttys, otherwise raw)",
    choices=['raw', 'hex', 'string', 'elf']
)

parser.add_argument(
    "-o","--output",
    metavar='file',
    help="Output file (defaults to stdout)",
    type=argparse.FileType('wb'),
    default=getattr(sys.stdout, 'buffer', sys.stdout)
)

parser.add_argument(
    '-c', '--context',
    metavar = 'context',
    action = 'append',
    type   = common.context_arg,
    choices = common.choices,
    help = 'The os/architecture/endianness/bits the shellcode will run in (default: linux/i386), choose from: %s' % common.choices,
)

parser.add_argument(
    '-v', '--avoid',
    action='append',
    help = 'Encode the shellcode to avoid the listed bytes (provided as hex)'
)

parser.add_argument(
    '-n', '--newline',
    dest='avoid',
    action='append_const',
    const='0a',
    help = 'Encode the shellcode to avoid newlines'
)

parser.add_argument(
    '-z', '--zero',
    dest='avoid',
    action='append_const',
    const='00',
    help = 'Encode the shellcode to avoid NULL bytes'
)


parser.add_argument(
    '-d',
    '--debug',
    help='Debug the shellcode with GDB',
    action='store_true'
)

parser.add_argument(
    '-e',
    '--encoder',
    help="Specific encoder to use"
)

parser.add_argument(
    '-i',
    '--infile',
    help="Specify input file",
    default=sys.stdin,
    type=argparse.FileType('r')
)

parser.add_argument(
    '-r',
    '--run',
    help="Run output",
    action='store_true'
)

@LocalContext
def asm(shellcode):
    try:
        assembler = _assembler()
        encoding, _count = assembler.asm(shellcode, as_bytes=True)
    except KsError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        raise e
    return encoding

def _assembler():
    E = {
        'big':    KS_MODE_BIG_ENDIAN,
        'little': KS_MODE_LITTLE_ENDIAN,
    }[context.endianness]

    B = {16: KS_MODE_16, 32: KS_MODE_32, 64: KS_MODE_64}[context.bits]

    params = {
        'i386'   : (KS_ARCH_X86, B),
        'amd64'  : (KS_ARCH_X86, B),
        'thumb'  : (KS_ARCH_ARM, KS_MODE_THUMB + E),
        'arm'    : (KS_ARCH_ARM, KS_MODE_ARM + E),
        'aarch64': (KS_ARCH_ARM64, KS_MODE_ARM + E),
        'mips'   : (KS_ARCH_MIPS, KS_MODE_MIPS32 + E),
        'mips64' : (KS_ARCH_MIPS, KS_MODE_MIPS64 + E),
        'sparc':   (KS_ARCH_SPARC, KS_MODE_SPARC32 + E),
        'sparc64': (KS_ARCH_SPARC, KS_MODE_SPARC64 + E),
        # Powerpc wants -mbig or -mlittle, and -mppc32 or -mppc64
        'powerpc':   (KS_ARCH_PPC, KS_MODE_PPC32 + E + B),
        'powerpc64': (KS_ARCH_PPC, KS_MODE_PPC64 + E + B),
        # ia64 only accepts -mbe or -mle
        # 'ia64':    None,
        # FIXME: waiting new keystone
        # riscv64-unknown-elf-as supports riscv32 as well as riscv64
        # 'riscv32': None,
        # 'riscv64': None,
    }

    arch, mode = params.get(context.arch) or exit(69)
    assembler = Ks(arch, mode)

    return assembler

def main():
    args = parser.parse_args()
    tty = args.output.isatty()

    if args.infile.isatty() and not args.lines:
        parser.print_usage()
        sys.exit(1)

    data   = '\n'.join(args.lines) or args.infile.read()
    output = asm(data.replace(';', '\n'))
    fmt    = args.format or ('hex' if tty else 'raw')
    formatters = {'r':bytes, 'h':enhex, 's':repr}

    if args.avoid:
        avoid = unhex(''.join(args.avoid))
        output = encode(output, avoid)

    if args.debug:
        proc = gdb.debug_shellcode(output, arch=context.arch)
        proc.interactive()
        sys.exit(0)

    if args.run:
        proc = run_shellcode(output)
        proc.interactive()
        sys.exit(0)

    if fmt[0] == 'e':
        args.output.write(make_elf(output))
        try: os.fchmod(args.output.fileno(), 0o700)
        except OSError: pass
    else:
        output = formatters[fmt[0]](output)
        if not hasattr(output, 'decode'):
            output = output.encode('ascii')
        args.output.write(output)

    if tty and fmt != 'raw':
        args.output.write(b'\n')

if __name__ == '__main__':
    main()
