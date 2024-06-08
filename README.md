# NopEmulator

 Identification of Arbitrary Length Shellcode for the Intel x64 Architecture as a NOP Sled through Ghidra Scripting

## Summary

The NopEmulator is a Ghidra Script developed for the purpose of emulation Intel x64 instructions to determine if a Nop Sled is present in the binary. This tool originated from prior research that only used the ability to execute or parse the code as the only heuristic for valid Nop Sleds being present. This tool takes it one step further to emulate the instructions and validate if the resulting execution context is truly a Nop Sled. The tool can be applied to reverse engineering, malware analysis, and even to detecting exploits in network traffic that use Nop Sleds to transfer execution.

While using the tool, the analyst has the option to configure how the script operates based on analysis need. This includes modifying the registers being analyzed by ignoring unimportant ones or specific ones based on their analysis needs. The script can also run from start-to-end, address-to-addresd, address for a length of bytes, or full analysis. The full analysis does a full bruteforce pass of every possible start and end value looking for Nop Sleds hidden within the bytes. In addition, when found, a comment is added to the starting and ending addresses to make analysis easier.

This script does not just look for a sequence of 0x90 bytes within the code, although it will find those too, it actually emulates each instruction to determine if the code is __effectively__ a Nop Sled. Check the [Usage](#usage) section for more examples of how it works.

## Features

- Four different types of analysis
  1. Start to End
  2. Start Address to End Address
  3. Start Address with Length
  4. Full analysis
- Ignoring Registers
- Setting initial values

### Start to End

The start to end analysis emulates the entire sequence of bytes as Intel x64 architecture instructions and keeps track of beginning and ending values of the execution context. The execution context, consisting mainly of registers, will be compared between the initial values and the ending values to determine if the byte sequence is a Nop Sled.

### Start Address to End Address

During your analysis, you find a large sequence of bytes you want to analyze more closely, but you don't want to emulate the entire program; picking a starting and ending address will help! You can specify the beginning and ending address for analysis and NopEmulator will only execute those instructions and determine if that sequence of bytes is a Nop Sled. This can speed up any reverse engineering task when it's obvious that a sequence of bytes effectively makes no change to the state of execution within the program.

### Start Address with Length

Similar to the beginning and ending address option, potentially you just want to analyze the next X bytes from where you are. Great! Enter the starting address and the length you want to analyze and NopEmulator will emulate those instructions and give you your result as well. It's important to have flexibility in your analysis tools.

### Full Analysis

Full analysis is the heaviest version of analysis this tool does. As an initial pass, one could certainly ask, "I wonder if there are __ANY__ Nop Sleds __ANYWHERE__ in this byte sequence?" In fact, full analysis is the answer for that. Full analysis will brute force every starting and ending offset in the byte sequence looking for NopSleds. In addition, when it finds one, it will add a comment in the Listing window at the beginning and ending addresses to make analysis easier. This can be useful for finding any length byte sequences that don't change the state of execution and could be ignored during analysis. This may be a result of poor coding practices, obfuscation, or when looking at an exploit byte sequence, an indication that a Nop Sled is present in the payload.

## Usage

### Start to End Example

Let's walk through using the script with a simple example of the default analysis. For this example, a basic Nop Sled was created that involved looping a few simple instructions 0x100 times before continuing on. Effectively, this does nothing, but most of the instructions do not look like NOPs.

First, start up the script and you'll see a dialogue box to select which analysis you'd like to perform.

![Default Analysis Dialog Box](images/default_analysis_dialog_box.png)

Click 'Ok' to move onto register selection. For register selection, there is a default selection of registers that are ignored including the EFLAGS register (and it's component flags) and the instruction pointer (RIP).

![Default Analysis Register Selection Dialog Box](images/default_analysis_register_selection_dialog_box.png)

We will accept the defaults for this example by clicking 'No'. Next, you can specify if you would like to modify the initial values of any register. This might prove useful if the Nop Sled requires certain values to be set at the beginning of execution.

![Default Analysis Register Value Selection Dialog box](images/default_analysis_register_value_dialog_box.png)

Once again, for this example, we'll leave it with the default values (0) and click 'No'. Once you click 'No', the analysis begins and returns our result.

![Default Analysis NopEmulator Result](images/default_analysis_result.png)

Here we can see that the NopEmulator script correctly determined the byte sequence is in fact a Nop Sled!

## Installation

1. Simply clone the code base and include the path in Ghidra's Bundle Manager, which can be accessed in the Script Manager window.

![Installation](images/installation.jpg)

## License

NopEmulator is free, open source, and released under the MIT License.

## Changelog

### Version 1.0

- Added start to end analysis
- Added starting address to ending address analysis
- Added starting address with length analysis
- Added Full Analysis
- Dialog boxes for easy configuration of script execution
- Support for x64 Intel architecture
- Initial algorithm implementation as a Ghidra Script
