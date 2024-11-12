# This script assumes msfvenom is in your PATH
import os

for i in range(1,101):
    for j in range(1, 11):
        command = f"echo -en \"\\x90\\x90\\x90\\x90\" | msfvenom -a x64 --platform Windows -p - -b \"\\x9e\" -n {i*10} > msfvenom_nop_{i*10}bytes_{j}.bin"
        print(command)
        os.system(command)