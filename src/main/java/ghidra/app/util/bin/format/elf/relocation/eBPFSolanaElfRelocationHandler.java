package ghidra.app.util.bin.format.elf.relocation;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.NotFoundException;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class eBPFSolanaElfRelocationHandler extends ElfRelocationHandler {
	/// Start of the program bits (text and ro segments) in the memory map
	public static final long MM_PROGRAM_START = 0x100000000L;
	/// Start of the stack in the memory map
	public static final long MM_STACK_START = 0x200000000L;
	/// Start of the heap in the memory map
	public static final long MM_HEAP_START = 0x300000000L;
	/// Start of the input buffers in the memory map
	public static final long MM_INPUT_START = 0x400000000L;

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_BPF;
	}

	@Override
	public void relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation,
			Address relocationAddress) throws MemoryAccessException, NotFoundException {
		
		ElfHeader elf = elfRelocationContext.getElfHeader();
		if (elf.e_machine() != ElfConstants.EM_BPF) {
			return;
		}

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		int type = relocation.getType();	
		int symbolIndex = relocation.getSymbolIndex();				

		// addend is either pulled from the relocation or the bytes in memory
		long addend =
			relocation.hasAddend() ? relocation.getAddend() : memory.getLong(relocationAddress);
		ElfSymbol sym = null;

		long symbolValue = 0;
		Address symbolAddr = null;
		String symbolName = null;
		long symbolSize = 0;

		if (symbolIndex != 0) {
			sym = elfRelocationContext.getSymbol(symbolIndex);
		}

		if (sym != null) {
			symbolAddr = elfRelocationContext.getSymbolAddress(sym);
			symbolValue = elfRelocationContext.getSymbolValue(sym);
			symbolName = sym.getNameAsString();
			symbolSize = sym.getSize();
		}

		long offset = relocationAddress.getOffset();

		long value;
		boolean appliedSymbol = true;

		long baseOffset = elfRelocationContext.getImageBaseWordAdjustmentOffset();
		Address imm_offset = relocationAddress.add(4);
		// the types are (hopefully) implemented according to how the solana rBPF implementation does it
		// R_BPF_64_64
		if (type == 1) {
			
			value = symbolValue;
			Address refd_va = program.getAddressFactory().getDefaultAddressSpace().getAddress(memory.getInt(imm_offset));
			value += refd_va.getOffset(); 
				
			// do the actual relocation work
			memory.setInt(imm_offset, (int)(value & 0xffffffff));			
			memory.setInt(imm_offset.add(8), (int)(value >> 32));					
		}
		// R_BPF_64_Relative
		else if (type == 8) {
			value = symbolValue;

			Address refd_va = program.getAddressFactory().getDefaultAddressSpace().getAddress(memory.getInt(imm_offset));
			Address refd_pa = refd_va.add(baseOffset);
			value += refd_pa.getOffset();
			ElfSectionHeader text_section = elf.getSection(".text");
			// check if split relocation across 2 instruction slots or single 64 bit value
			long relativeOffset = offset - baseOffset;
			if (text_section.getOffset() <= relativeOffset && relativeOffset <= text_section.getOffset() + text_section.getSize()) {
				// write value split in two slots, high and slow
				// elfRelocationContext.getLog().appendMsg(String.format("split set: %x = %x", imm_offset.getOffset(), value));
				memory.setInt(imm_offset, (int)(value & 0xffffffff));
				memory.setInt(imm_offset.add(8), (int)(value >> 32));
			} else {
				// elfRelocationContext.getLog().appendMsg(String.format("64 bit set: %x = %x", relocationAddress.getOffset(), refd_pa.getOffset()));
				// 64 bit memory location, write entire 64 bit physical address directly
				memory.setLong(relocationAddress, refd_pa.getOffset());
			}
		}
		// R_Bpf_64_32 = 10,
		else if (type == 10) {
			int targetAddr;
			String call_type;
			// normally we would put the hash into the immediate field of
			// the call but then we would have to resolve the call again
			// in sleigh and I don't know how to do that
			// therefore we just resolve the address relative to the current
			// instruction and resolve it immediately :)
			if (sym.isFunction() && symbolValue != 0) {
				// bpf call
				long target_pc = symbolValue;// - text_section.getAddress();
				
				// next instruction address that the call will be relative to
				// minus modulo 8 to get to the address of the current instruction
				// then add 8 to get to the next one
				long this_pc = relocation.getOffset() - (relocation.getOffset() % 8) + 8 + baseOffset;
				targetAddr = (int)((target_pc - this_pc)/8);
				call_type = "function";
			} else {
				// syscall
				call_type = "syscall";
				// address of the symbol in the EXTERNAL section
				long target_pc = symbolAddr.getOffset();
				// next instruction address that the call will be relative to
				// minus modulo 8 to get to the address of the current instruction
				// then add 8 to get to the next one
				long this_pc = relocation.getOffset() - (relocation.getOffset() % 8) + 8 + baseOffset;
				targetAddr = (int)((target_pc - this_pc)/8);
			}
			
			memory.setInt(imm_offset, targetAddr);
			// Listing listing = program.getListing();
			// listing.setComment(relocationAddress, CodeUnit.EOL_COMMENT,
			//	String.format("%s_%s", call_type, symbolName));
		} else {
			appliedSymbol = false;
		}

		// if (appliedSymbol && symbolIndex == 0) {
		// 	markAsWarning(program, relocationAddress, Long.toString(type),
		// 		"applied relocation with symbol-index of 0", elfRelocationContext.getLog());
		// }

	}
}
