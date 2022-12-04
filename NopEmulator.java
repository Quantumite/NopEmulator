//Emulate instructions to determine if the sequence of instructions perform an effective No-OP (NOP).
//@author Austin Norby
//@category Emulation
//@keybinding
//@menupath
//@toolbar

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.ProgramContext;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.math.BigInteger;

public class NopEmulator extends GhidraScript {
	
	HashMap<String,BigInteger> beginContext = new HashMap<String,BigInteger>();
	HashMap<String,BigInteger> runningContext = new HashMap<String,BigInteger>();
	List<Register> ignoreRegisters = new ArrayList<Register>();
	
	enum ReturnResult {DEFINITELY_NOP, NOT_NOP, UNKNOWN};
	
	@Override
	protected void run() throws Exception {
		//Get Program Context
		ProgramContext pc = currentProgram.getProgramContext();
		Instruction inst = getFirstInstruction();	
		EmulatorHelper eh = new EmulatorHelper(currentProgram);
		ReturnResult result = ReturnResult.NOT_NOP;
		
		//Populate IgnoreList
		ignoreRegisters.add(currentProgram.getProgramContext().getRegister("ZF"));
		ignoreRegisters.add(currentProgram.getProgramContext().getRegister("PF"));
		ignoreRegisters.add(currentProgram.getProgramContext().getRegister("CF"));
		ignoreRegisters.add(currentProgram.getProgramContext().getRegister("AF"));
		ignoreRegisters.add(currentProgram.getProgramContext().getRegister("SF"));
		ignoreRegisters.add(currentProgram.getProgramContext().getRegister("DF"));
		ignoreRegisters.add(currentProgram.getProgramContext().getRegister("OF"));
		ignoreRegisters.add(currentProgram.getProgramContext().getRegister("RIP"));
		
		//Set default (0) values for registers
		for(Register r : pc.getRegisters())
		{
			if(!beginContext.containsKey(r.getName()))
			{
				beginContext.put(r.getName(), BigInteger.ZERO);
			}
		}
		
		//Full copy to modifiable context hashmap
		runningContext.putAll(beginContext);		
		
		//Emulate instructions
		while(eh.step(monitor)){
			inst = currentProgram.getListing().getInstructionAt(eh.getEmulator().getLastExecuteAddress());
			if(inst == null) break;
			System.out.println(inst);
			
			Object[] resultObjectArray = inst.getResultObjects();
			for(Object o : resultObjectArray)
			{
								
				System.out.println(o);
				if(ignoreRegisters.contains(o))
				{
					continue;
				}				
				
				try
				{
					BigInteger rv = eh.readRegister((Register)o);
					runningContext.replace(o.toString(), rv);
				}
				catch(Exception e)
				{
					println(e.toString());
				}
			}
		}
		
		//Calculate differences
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
				result = ReturnResult.UNKNOWN;
				println("Value was null");
				println("Key: "+s);
			}
			
		}
		
		if(result != ReturnResult.UNKNOWN)
		{
			if(foundDiff)
			{
				result = ReturnResult.NOT_NOP;
			}
			else
			{
				result = ReturnResult.DEFINITELY_NOP;
			}
		}
		
		if(result == ReturnResult.DEFINITELY_NOP)
		{
			popup("EFFECTIVE NOP");
			println("EFFECTIVE NOP");
		}
		else if(result == ReturnResult.NOT_NOP)
		{
			popup("NOT A NOP");
			println("NOT A NOP");
		}
		else
		{
			popup("Current unable to determine if this is a NOP");
			println("Current unable to determine if this is a NOP");
		}
		
	}
}
