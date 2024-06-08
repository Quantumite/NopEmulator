# NopEmulator
 Identification of Arbitrary Length Shellcode for the Intel x64 Architecture as a NOP Sled through Ghidra Scripting

## Summary
The NopEmulator is a Ghidra Script developed for the purpose of emulation Intel x64 instructions to determine if a Nop Sled is present in the binary. This tool originated from prior research that only used the ability to execute or parse the code as the only heuristic for valid Nop Sleds being present. This tool takes it one step further to emulate the instructions and validate if the resulting execution context is truly a Nop Sled. The tool can be applied to reverse engineering, malware analysis, and even to detecting exploits in network traffic that use Nop Sleds to transfer execution.

While using the tool, the analyst has the option to configure how the script operates based on analysis need. This includes modifying the registers being analyzed by ignoring unimportant ones or specific ones based on their analysis needs. The script can also run from start-to-end, address-to-addresd, address for a length of bytes, or full analysis. The full analysis does a full bruteforce pass of every possible start and end value looking for Nop Sleds hidden within the bytes. In addition, when found, a comment is added to the starting and ending addresses to make analysis easier.

## Features


## Usage


## Installation
1. Simply clone the code base and include the path in Ghidra's Bundle Manager, which can be accessed in the Script Manager window.

![Installation](images/installation.jpg)

## License
NopEmulator is free, open source, and released under the MIT License.

## Changelog