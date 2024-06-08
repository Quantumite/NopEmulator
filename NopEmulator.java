//Emulate instructions to determine if the sequence of instructions perform an effective No-OP (NOP).
//@author Austin Norby (quantumite)
//@category Emulation
//@keybinding
//@menupath
//@toolbar

/*
 * NOTE:
 * ------------
 * When providing strings to prompts, wrap them in ""s and use ; as the separator.
 * This script makes use of the ask*() and parse*() functions provided by GhidraScript
 * and requires the formatting to be as such.
 * */

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.ProgramContext;
import ghidra.util.exception.CancelledException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.math.BigInteger;

public class NopEmulator extends GhidraScript {
	
	//Context hashmaps for storing register values
	HashMap<String,BigInteger> beginContext = new HashMap<String,BigInteger>();
	HashMap<String,BigInteger> runningContext = new HashMap<String,BigInteger>();
	
	//List of registers to ignore changes in value
	List<Register> ignoreRegisters = new ArrayList<Register>();
	
	//Selections for askChoice in run()
	String analysisTypeBeginToEnd = "Beginning to End (Default)";
	String analysisTypeHereToThere = "Start Address to End Address";
	String analysisTypeAddressOffset = "Start Address and Length";
	String analysisTypeFull = "Full Analysis";
	
	//Wrapper around askAddress for start/end addresses
	private Address myGetAddress(String question)
	{
		try {
			return askAddress(question + " Address", "Enter the "+question+" address: ");
		} catch (CancelledException e) {
			e.printStackTrace();
		}
		return Address.NO_ADDRESS;
	}
	
	//Take results from run*() methods and display user feedback
	private void printResult(int result)
	{
		if(result == 0)
		{
			popup("EFFECTIVE NOP");
			println("EFFECTIVE NOP");
		}
		else if (result == 1)
		{
			popup("NOT A NOP");
			println("NOT A NOP");
		}
		else if (result == 2)
		{
			popup("Unknown Result.");
			println("Unknown Result.");
		}
		else
		{
			popup("Invalid Result.");
			println("Invalid Result.");
		}
	}
	
	//Wrapper around pre- and post-comment functions during full analysis
	private void AddComment(Address i, Address j) {
		
		//Default comment strings
		String newPreComment = "BEGIN -- NOP Sled from "+i.toString()+" to "+j.toString()+"\n";
		String newPostComment = "END -- NOP Sled from "+i.toString()+" to "+j.toString()+"\n";
		
		//If Address i had previous pre comments, prepend them to new comment
		String previousPreComment = getPreComment(i);
		if(previousPreComment != null)
		{
			newPreComment = previousPreComment+newPreComment;
		}
		setPreComment(i, newPreComment);
		
		//If address j had previous post comments, append new post comment
		String previousPostComment = getPostComment(j);
		if(previousPostComment != null)
		{
			newPostComment = previousPostComment+newPostComment;
		}
		setPostComment(j, newPostComment);
	}
	
	//run analysis from startAddress to endAddress
	private int runHereToThere(Address startAddress, Address endAddress) throws CancelledException
	{
		
		//Get Program Context
		ProgramContext pc = currentProgram.getProgramContext();
		Instruction inst = getInstructionAt(startAddress);	
		EmulatorHelper eh = new EmulatorHelper(currentProgram);
		int result = 1;
		
		//Disassemble start to end with restricted set of addresses (AddressSet)
		DisassembleCommand cmd = new DisassembleCommand(startAddress, new AddressSet(startAddress, endAddress), false);
		cmd.applyTo(currentProgram, monitor);
				
		
		//Full copy to modifiable context hashmap
		runningContext.putAll(beginContext);
		
		//Set emulator to correct first byte
		eh.getEmulator().setExecuteAddress(startAddress.getOffset());
		
		//Emulate instructions
		while(eh.step(monitor)){
			inst = currentProgram.getListing().getInstructionAt(eh.getEmulator().getLastExecuteAddress());
			
			//Handle issues with decoding instructions and minimal obfuscation
			if(inst == null)
			{
				try
				{
					//Since the instruction wasn't defined, let's clear from here forward...
					clearListing(eh.getEmulator().getLastExecuteAddress(), endAddress);
				}
				catch(IllegalArgumentException iae)
				{
					//This exception only seems to occur when the endAddress is less than the startAddress
					// during full analysis.
					println("Cannot clear listing. Likely reached end of analysis range. Returning result.");
					break;
				}

				//Re-do disassemble command, after clearing, at first instruction to fail, this will sometimes fix the problem
				cmd = new DisassembleCommand(eh.getEmulator().getLastExecuteAddress(), new AddressSet(startAddress, endAddress), false);
				cmd.applyTo(currentProgram, monitor);

				//Attempt to get instruction again
				inst = currentProgram.getListing().getInstructionAt(eh.getEmulator().getLastExecuteAddress());
				
				//If inst is still null...
				if(inst == null)
				{
					//This is likely an invalid instruction or more obfuscated than this script
					// can currently handle.
					println("No instruction defined!");
					result = 2;
					return result;
				}
				
			}
			System.out.println(inst);
			
			//Get all register values after executing instruction
			Object[] resultObjectArray = inst.getResultObjects();
			for(Object o : resultObjectArray)
			{
								
				System.out.println(o);
				//If the register is in the ignore list, skip it
				if(ignoreRegisters.contains(o))
				{
					continue;
				}				
				
				try
				{
					//Get the value of the register and store it in the running context
					BigInteger rv = eh.readRegister((Register)o);
					runningContext.replace(o.toString(), rv);
				}
				catch(Exception e)
				{
					println(e.toString());
				}
			}
			//Stop execution if you've reached the endAddress
			if(eh.getEmulator().getLastExecuteAddress().equals(endAddress)) break;
		} 
		
		//Calculate differences between initial and running contexts
		BigInteger runningValue = BigInteger.ZERO;
		BigInteger beginValue = BigInteger.ZERO;
		BigInteger diff = BigInteger.ZERO;
		boolean foundDiff = false;
		for(String s : runningContext.keySet())	
		{
			runningValue = runningContext.get(s);
			beginValue = beginContext.get(s);
			if(runningValue != null && beginValue != null)
			{
				diff = runningValue.subtract(beginValue);
				if(!diff.equals(BigInteger.ZERO))
				{
					foundDiff = true;
					println("Register difference found!");
					println("Key: "+s);
					println("RunningContext Value: "+runningValue.toString());
					println("BeginContext Value: "+beginValue.toString());
				}
			}
			else
			{
				//Somehow the value was null...
				result = 2;
				println("Value was null");
				println("Key: "+s);
				return result;
			}
			
		}
		
		//If we found a difference, return NOT_NOP, otherwise EFFECTIVE_NOP
		if(foundDiff)
		{
			result = 1;
		}
		else
		{
			result = 0;
		}
		
		return result;
	}
	
	@Override
	protected void run() throws Exception {
		
		//Get type of analysis to run
		int result = 1;
		ProgramContext pc = currentProgram.getProgramContext();
		List<String> analysisTypes = new ArrayList<String>();
		analysisTypes.add(analysisTypeBeginToEnd);
		analysisTypes.add(analysisTypeHereToThere);
		analysisTypes.add(analysisTypeAddressOffset);
		analysisTypes.add(analysisTypeFull);
		
		//Set default (0) values for registers
		for(Register r : pc.getRegisters())
		{
			if(!beginContext.containsKey(r.getName()))
			{
				beginContext.put(r.getName(), BigInteger.ZERO);
			}
		}
				
		String stringAnalysisSelection = askChoice("NOPEmulator", 
				"Which type of analysis would you like to run?",
				analysisTypes,
				analysisTypeBeginToEnd);
		
		boolean boolIgnoreRegisters = askYesNo("Ignore Registers", "Would you like to specify which registers to ignore?");
		if(boolIgnoreRegisters)
		{
			String stringRegistersToIgnore = askString("Ignore Registers", "Which registers would you like to ignore, if any? Enter \"\" for default.");
			try
			{
				List<String> listRegistersToIgnore = parseChoices(stringRegistersToIgnore, new ArrayList<String>(beginContext.keySet()));
				for(String s : listRegistersToIgnore)
				{
					ignoreRegisters.add(currentProgram.getProgramContext().getRegister(s));
				}
			}
			catch(IllegalArgumentException iae)
			{
				//alert user to malformed data
				popup("Unable to parse registers to ignore. Continuing with defaults.");
				
				//Apply defaults for registers to ignore
				ignoreRegisters.add(currentProgram.getProgramContext().getRegister("ZF"));
				ignoreRegisters.add(currentProgram.getProgramContext().getRegister("PF"));
				ignoreRegisters.add(currentProgram.getProgramContext().getRegister("CF"));
				ignoreRegisters.add(currentProgram.getProgramContext().getRegister("AF"));
				ignoreRegisters.add(currentProgram.getProgramContext().getRegister("SF"));
				ignoreRegisters.add(currentProgram.getProgramContext().getRegister("DF"));
				ignoreRegisters.add(currentProgram.getProgramContext().getRegister("OF"));
				ignoreRegisters.add(currentProgram.getProgramContext().getRegister("RIP"));
			}
		}
		else
		{
			//Apply defaults for registers to ignore
			ignoreRegisters.add(currentProgram.getProgramContext().getRegister("ZF"));
			ignoreRegisters.add(currentProgram.getProgramContext().getRegister("PF"));
			ignoreRegisters.add(currentProgram.getProgramContext().getRegister("CF"));
			ignoreRegisters.add(currentProgram.getProgramContext().getRegister("AF"));
			ignoreRegisters.add(currentProgram.getProgramContext().getRegister("SF"));
			ignoreRegisters.add(currentProgram.getProgramContext().getRegister("DF"));
			ignoreRegisters.add(currentProgram.getProgramContext().getRegister("OF"));
			ignoreRegisters.add(currentProgram.getProgramContext().getRegister("RIP"));
		}
		
		boolean boolSetRegisterValues = askYesNo("Register Values", "Would you like to set any registers to a specific value? (Default: 0)");
		if(boolSetRegisterValues)
		{
			String stringSetRegisterValues = askString("Register Values", "Which registers would you like to set? Only specify registers, values come next.");
			try
			{
				List<String> listRegistersToSet = parseChoices(stringSetRegisterValues, new ArrayList<String>(beginContext.keySet()));
				for(String s : listRegistersToSet)
				{
					long val = askLong("Set "+s, "Set "+s+" to...");
					beginContext.put(s,BigInteger.valueOf(val));
				}
			}
			catch(IllegalArgumentException iae)
			{
				//alert user to malformed data
				popup("Unable to parse registers values. Continuing with defaults.");
			}
		}
		
		if(stringAnalysisSelection.equals(analysisTypeBeginToEnd))
		{
			try
			{
				//beginning to end == min address to max address
				result = runHereToThere(currentProgram.getMinAddress(), currentProgram.getMaxAddress());
			}
			catch(CancelledException ce)
			{
				ce.printStackTrace();
			}
			printResult(result);
		}
		else if(stringAnalysisSelection.equals(analysisTypeHereToThere))
		{
			try
			{
				//Get start and end address
				Address start = myGetAddress("Start");
				Address end = myGetAddress("End");				
				result = runHereToThere(start, end);
			}
			catch(CancelledException ce)
			{
				ce.printStackTrace();
			}
			printResult(result);
		}
		else if(stringAnalysisSelection.equals(analysisTypeAddressOffset))
		{
			try
			{
				//Compute start and end address
				Address start = myGetAddress("Start");
				long end = askLong("Length", "Enter the length: ");
				Address endAddress = start.add(end);				
				result = runHereToThere(start, endAddress);
			}
			catch(CancelledException ce)
			{
				ce.printStackTrace();
			}
			printResult(result);
		}
		else if(stringAnalysisSelection.equals(analysisTypeFull))
		{
			//Look for NOP Sleds of any length from beginning to end of the current program
			//This can take a LONG TIME
			Address start = Address.NO_ADDRESS;
			Address end = Address.NO_ADDRESS;
			for(long i = currentProgram.getMinAddress().getOffset(); i <= currentProgram.getMaxAddress().getOffset(); i++)
			{
				for(long j = i+1; j <= currentProgram.getMaxAddress().getOffset(); j++)
				{
					start = toAddr(i);
					end = toAddr(j);
					result = runHereToThere(start, end);
					println("Finished "+start.toString()+" to "+end.toString()+".");
					
					//Clear listing after each analysis to not affect future iterations
					clearListing(currentProgram.getMinAddress(), currentProgram.getMaxAddress());
					
					//If the current byte array is an effective nop, add comments to the involved addresses
					if(result == 0)
					{
						println("Effective NOP from "+i+" to "+j);
						AddComment(start, end);
					}
				}
			}
		}
		else
		{
			popup("Invalid Selection for analysis.");
			println("Invalid Selection for analysis.");
			return;
		}
	}

	
}
