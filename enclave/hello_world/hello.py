import sys
import os

print("Hello from inside SGX enclave")
print(f"Python version: {sys.version}")
print(f"PID: {os.getpid()}")
