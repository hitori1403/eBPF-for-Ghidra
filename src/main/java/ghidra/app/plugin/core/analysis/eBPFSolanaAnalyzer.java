package ghidra.app.plugin.core.analysis;

import ghidra.app.cmd.function.SetFunctionNameCmd;
import ghidra.app.cmd.function.SetFunctionVarArgsCommand;
import ghidra.app.cmd.function.SetReturnDataTypeCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.address.*;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.*;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.SignedQWordDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Function;
import ghidra.app.cmd.function.AddRegisterParameterCommand;

public class eBPFSolanaAnalyzer extends AbstractAnalyzer {

	private final static String PROCESSOR_NAME = "eBPF";
	private final static String NAME = "Solana syscall ID";
	private final static String DESCRIPTION =
			"Searches external symbols for solana syscalls and applies function signatures";
	
	private long lastTransactionId = -1;

	public eBPFSolanaAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.CODE_ANALYSIS.before());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		// only perform this analysis once per transaction
		long txId = program.getCurrentTransaction().getID();
		if (txId == lastTransactionId) {
			return true;
		}
		lastTransactionId = txId;

		BookmarkManager bmmanager = program.getBookmarkManager();
		bmmanager.removeBookmarks("Error", "Bad Instruction", monitor);
		
		SymbolTable table = program.getSymbolTable();
		boolean includeDynamicSymbols = true;
		SymbolIterator symbols = table.getAllSymbols(includeDynamicSymbols);
		
		CategoryPath solanaCategory = new CategoryPath("/SOLANA");
		
		Structure pubkeyStruct = new StructureDataType("Pubkey", 0);
		pubkeyStruct.add(
				new ArrayDataType(new ByteDataType(), 32, 1),
				"data",
				"");
		try {
			pubkeyStruct.setCategoryPath(solanaCategory);
		} catch (DuplicateNameException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		program.getDataTypeManager().addDataType(pubkeyStruct, null);
		
		for (ghidra.program.model.symbol.Symbol s : symbols) {
			if (monitor.isCancelled())
				return false;
			
			if (!s.isExternal())
				continue;
				
			if (s.getName().startsWith("sol_")){			
				Function func = program.getFunctionManager().getFunctionAt(s.getAddress());
				
				//Definitions for datatypes
				DataType dstruct = null;
				DataType dvoid = new VoidDataType();
				DataType dint = new IntegerDataType();
				DataType dchar = new CharDataType();
				DataType duint = new UnsignedIntegerDataType();	
				DataType dulong = new UnsignedLongDataType();
				DataType dushort = new UnsignedShortDataType();				
				DataType dslong = new SignedQWordDataType();
				DataType duchar = new UnsignedCharDataType(); 
				DataType dvp = new PointerDataType(dvoid, 0);	
				DataType dcp = new PointerDataType(dchar, 0);	
				DataType dsp; //DataType for struct-pointer					
				
				//Command-vars
				SetFunctionNameCmd cmdName;
				SetReturnDataTypeCmd cmdRet;
				AddRegisterParameterCommand cmdArg1;
				AddRegisterParameterCommand cmdArg2;
				AddRegisterParameterCommand cmdArg3;
				AddRegisterParameterCommand cmdArg4;
				AddRegisterParameterCommand cmdArg5;
				SetFunctionVarArgsCommand cmdVar = new SetFunctionVarArgsCommand(func,true);
				
				try {
					func.setCallingConvention("ebpf_call");
				} catch (InvalidInputException e) {
					e.printStackTrace();
				}
				
				switch(s.getName()) {
					case("sol_log_"):
						// TODO: write code that parses an annotated syscalls.txt and generates switch-cases like this
						cmdName = new SetFunctionNameCmd(s.getAddress(), "sol_log_", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dint , SourceType.ANALYSIS);
						
						cmdArg1 = new AddRegisterParameterCommand(func, program.getProgramContext().getRegister("R1"), "addr", dcp, 0, SourceType.ANALYSIS);	
						cmdArg2 = new AddRegisterParameterCommand(func, program.getProgramContext().getRegister("R2"), "len", duint, 1, SourceType.ANALYSIS);							
												
						cmdName.applyTo(program);
						cmdRet.applyTo(program);
						cmdArg1.applyTo(program);
						cmdArg2.applyTo(program);						
						program.flushEvents();							
						break;
						
					 default:
						 //void bpf_undef()
						cmdName = new SetFunctionNameCmd(s.getAddress(), "bpf_undef", SourceType.ANALYSIS);					
						cmdRet = new SetReturnDataTypeCmd(s.getAddress(), dvoid , SourceType.ANALYSIS);		
							
						cmdName.applyTo(program);
						cmdRet.applyTo(program);						
						program.flushEvents();	 
						break;
				}
				bmmanager.setBookmark(s.getAddress(), "Analysis", "eBPF-helpers", "eBPF-helper Identified");
			}			
		}
		
		return true;
	}
}
