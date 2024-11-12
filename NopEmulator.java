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
import ghidra.app.emulator.Emulator;
import ghidra.app.emulator.EmulatorConfiguration;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emulate.InstructionDecodeException;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.math.BigInteger;

final class NopEmulatorHelper extends EmulatorHelper {

	public String NopLastError = null;
	private final Emulator NopEmulator = getEmulator();
	private final Program NopProgram = getProgram();
	
	//Created default constructor that users the same construction
	// as the parent class because we only need to modify
	// a few functions for our use case.
	public NopEmulatorHelper(Program program) {
		super(program);
		this.enableMemoryWriteTracking(true);
	}
	
	/**
	 * Step execution one instruction which may consist of multiple
	 * pcode operations.  No adjustment will be made to the context beyond the normal 
	 * context flow behavior defined by the language.
	 * Method will block until execution stops.
	 * @return true if execution completes without error
	 * @throws CancelledException if execution cancelled via monitor
	 */
	public synchronized boolean step(TaskMonitor monitor) throws CancelledException {
		executeInstruction(true, monitor);
		NopLastError = getLastError();
		return NopLastError == null;
	}
	
	private void setProcessorContext() {
		// this assumes you have set the emulation address
		//   the emu will have cleared the context for the new address
		RegisterValue contextRegisterValue = NopEmulator.getContextRegisterValue();
		if (contextRegisterValue != null) {
			return;
		}

		Address executeAddress = NopEmulator.getExecuteAddress();
		Instruction instructionAt = NopProgram.getListing().getInstructionAt(executeAddress);
		if (instructionAt != null) {
			RegisterValue disassemblyContext =
				instructionAt.getRegisterValue(instructionAt.getBaseContextRegister());
			NopEmulator.setContextRegisterValue(disassemblyContext);
		}
	}
	
	/**
	 * Execute instruction at current address
	 * @param stopAtBreakpoint if true and breakpoint hits at current execution address
	 * execution will halt without executing instruction.
	 * @throws CancelledException if execution was cancelled
	 */
	private void executeInstruction(boolean stopAtBreakpoint, TaskMonitor monitor)
			throws CancelledException, LowlevelError, InstructionDecodeException {

		NopLastError = null;
		try {
			if (NopEmulator.getLastExecuteAddress() == null) {
				setProcessorContext();
			}
			NopEmulator.executeInstruction(stopAtBreakpoint, monitor);
		}
		catch (Throwable t) {
			NopLastError = t.getMessage();
			if (NopLastError == null) {
				NopLastError = t.toString();
			}
			NopEmulator.setHalt(true); // force execution to stop
			if (t instanceof CancelledException) {
				throw (CancelledException) t;
			}
			
			// Main changes for NopEmulator are here so the exceptions are passed up
			// and not handled internal to the EmulatorHelper
			if (t instanceof LowlevelError)
			{
				throw (LowlevelError) t;
			}
			if (t instanceof InstructionDecodeException)
			{
				throw (InstructionDecodeException) t;
			}
		}
	}
	
}

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
	String analysisTypeLongest = "Longest";
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
	private int runHereToThere(Address startAddress, Address endAddress, boolean bCheckWritable) throws CancelledException
	{
		
		//Get Program Context
		ProgramContext pc = currentProgram.getProgramContext();
		Instruction inst = getInstructionAt(startAddress);	
		NopEmulatorHelper eh = new NopEmulatorHelper(currentProgram);
		AddressSetView asv = eh.getTrackedMemoryWriteSet();
		int result = 1;
		
		//Disassemble start to end with restricted set of addresses (AddressSet)
		DisassembleCommand cmd = new DisassembleCommand(startAddress, new AddressSet(startAddress, endAddress), false);
		cmd.applyTo(currentProgram, monitor);
				
		
		//Full copy to modifiable context hashmap
		runningContext.putAll(beginContext);
		
		//Set emulator to correct first byte
		eh.getEmulator().setExecuteAddress(startAddress.getOffset());
		
		//Emulate instructions
		boolean bNopEmulatorKeepRunning = true;
		while(bNopEmulatorKeepRunning){
			try{
				bNopEmulatorKeepRunning = eh.step(monitor);
			}
			catch(InstructionDecodeException ide)
			{
				System.out.println("here");
				bNopEmulatorKeepRunning = false;
				result = 1; // NOT A NOP
				return result;
			}
			catch(LowlevelError lle)
			{
				bNopEmulatorKeepRunning = false;
				result = 1; // NOT A NOP
				return result;
			}
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
			if (inst.getMnemonicString().equalsIgnoreCase("HLT"))
			{
				result = 1;
				return result;
			}
			
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
		
		for(AddressRange as : asv)
		{
			if(as.getAddressSpace().getName().equals("ram"))
			{
				System.out.println(as);
				if(bCheckWritable)
				{
					foundDiff = true;
					break;
				}
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
	
	private Address updateEndAddressToIncludeInstruction(Address start, Address end) throws CancelledException
	{
		Instruction inst;
		Address instEnd;
		long retAddr = end.getOffset();
		
		//Disassemble start to end with restricted set of addresses (AddressSet)
		DisassembleCommand cmd = new DisassembleCommand(start, new AddressSet(start, end), false);
		cmd.applyTo(currentProgram, monitor);
		
		Address temp = start;
		do
		{
			inst = getInstructionContaining(temp);
			if(inst == null)
			{
				//Break out of while loop in order to skip to next instruction
				break;
			}
			
			instEnd = temp.add(inst.getLength()-1); //Get length but don't sent end at beginning of next instruction
			
			if(end.subtract(instEnd) < 0) //Instruction end is after end address, update j
			{
				retAddr += instEnd.subtract(end);
				end = instEnd;
				println("Instruction longer than here-to-there range. Expanding range to include full instruction.");
				break;
			}
			temp = instEnd.add(1);
		} while(end.subtract(instEnd) > 0 && temp.subtract(end) <= 0);
		// While there are more instructions between start and end, keep checking if end
		// doesn't include the full instruction based on the range given. Update end
		// if necessary.
		
		if(inst == null)
		{
			//decompilation of the instruction failed, skip to next end address
			retAddr = end.getOffset();
		}
		
		//Clear listing after each analysis to not affect future iterations
		try
		{
			clearListing(start, end);
		}
		catch(CancelledException ce)
		{
			throw (CancelledException) ce;
		}
		
		return toAddr(retAddr);
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
		analysisTypes.add(analysisTypeLongest);
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
		
		boolean bCheckWriteLocations = askYesNo("Check Writable Locations", "Should writing to memory be considered a NOP?");
				
		if(stringAnalysisSelection.equals(analysisTypeBeginToEnd))
		{
			try
			{
				//beginning to end == min address to max address
				result = runHereToThere(currentProgram.getMinAddress(), currentProgram.getMaxAddress(), !bCheckWriteLocations);
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
				end = updateEndAddressToIncludeInstruction(start, end);
				result = runHereToThere(start, end, !bCheckWriteLocations);
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
				long endOffset = askLong("Length", "Enter the length: ");
				Address end = start.add(endOffset);
				end = updateEndAddressToIncludeInstruction(start, end);
				result = runHereToThere(start, end, !bCheckWriteLocations);
			}
			catch(CancelledException ce)
			{
				ce.printStackTrace();
			}
			printResult(result);
		}
		else if(stringAnalysisSelection.equals(analysisTypeLongest))
		{
			Address start = Address.NO_ADDRESS;
			Address end = Address.NO_ADDRESS;
			Address startLongest = start;
			Address endLongest = start;
			for(long i = currentProgram.getMinAddress().getOffset(); i <= currentProgram.getMaxAddress().getOffset(); i++)
			{
				for(long j = i; j <= currentProgram.getMaxAddress().getOffset(); j++)
				{
					start = toAddr(i);
					end = toAddr(j);
					end = updateEndAddressToIncludeInstruction(start, end);
					j = end.getOffset();
					
					result = runHereToThere(start, end, !bCheckWriteLocations);
					
					//If a NOP Sled is found, see if it's the longest
					if(result == 0)
					{
						if(end.subtract(start) > endLongest.subtract(startLongest))
						{
							println("New Longest Effective NOP found: "+Long.toHexString(i)+", "+Long.toHexString(j));
							startLongest = start;
							endLongest = end;
						}
						
					}
					
					//Clear listing after each analysis to not affect future iterations
					clearListing(currentProgram.getMinAddress(), currentProgram.getMaxAddress());
				}
			}
			
			//Comment longest NOP Sled
			println("Longest Effective NOP from "+startLongest.toString()+" to "+endLongest.toString());
			AddComment(startLongest, endLongest);
		}
		else if(stringAnalysisSelection.equals(analysisTypeFull))
		{
			//Look for NOP Sleds of any length from beginning to end of the current program
			//This can take a LONG TIME
			Address start = Address.NO_ADDRESS;
			Address end = Address.NO_ADDRESS;
			for(long i = currentProgram.getMinAddress().getOffset(); i <= currentProgram.getMaxAddress().getOffset(); i++)
			{
				for(long j = i; j <= currentProgram.getMaxAddress().getOffset(); j++)
				{
					start = toAddr(i);
					end = toAddr(j);
					end = updateEndAddressToIncludeInstruction(start, end);
					j = end.getOffset();
					
					result = runHereToThere(start, end, !bCheckWriteLocations);
					println("Finished "+start.toString()+" to "+end.toString()+".");
					
					//Clear listing after each analysis to not affect future iterations
					clearListing(currentProgram.getMinAddress(), currentProgram.getMaxAddress());
					
					//If the current byte array is an effective nop, add comments to the involved addresses
					if(result == 0)
					{
						println("Effective NOP from "+Long.toHexString(i)+" to "+Long.toHexString(j));
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
