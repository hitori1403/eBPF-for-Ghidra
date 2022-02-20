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

	private int hashSymbolName(CharBuffer name) {
		int hash = 0;//MurmurHash3.murmurhash3_x86_32(name, 0, name.length(), 0);
		return hash;
	}

	private int hashBpfFunction(long pc, String name) {
		ByteBuffer buffer;
		if (name == "entrypoint") {
			buffer = ByteBuffer.allocate("entrypoint".length());
			for (char c : "entrypoint".toCharArray()) {
				buffer.putChar(c);
			}
		} else {
			buffer = ByteBuffer.allocate(Long.BYTES);
			buffer.putLong(pc);
		}
		buffer.rewind();
		return hashSymbolName(buffer.asCharBuffer());
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
		// markAsWarning(program, imm_offset, symbolName, "checkIt", elfRelocationContext.getLog());
		// R_BPF_64_64
		if (type == 1) {			
			elfRelocationContext.getLog().appendMsg(String.format("type 1 reloc"));
			try {
				//String sec_name = elfRelocationContext.relocationTable.getSectionToBeRelocated().getNameAsString();
				//if (sec_name.toString().contains("debug")) {
				//	return;
				//}

				// skip relocations in the debug section ???
				// String map = Symbol.getNameAsString();				
				// long val = Symbol.getValue();
					
				// SymbolTable table = program.getSymbolTable();
				// Address mapAddr = table.getSymbol(val).getAddress();
				value = symbolValue + addend;

				Address refd_va = program.getAddressFactory().getDefaultAddressSpace().getAddress(memory.getInt(imm_offset));
				Address refd_pa = refd_va.add(baseOffset);
				value += refd_pa.getOffset();
					
				// do the actual relocation work
				// docs that explains how it works
				// https://www.kernel.org/doc/Documentation/bpf/llvm_reloc.rst
				// value = mapAddr.getAddressableWordOffset();		
				// Byte dst = memory.getByte(relocationAddress.add(0x1));
				memory.setInt(imm_offset, (int)(value & 0xffffffff));			
				memory.setInt(imm_offset.add(8), (int)(value >> 32));			
				// memory.setByte(relocationAddress.add(0x1), (byte) (dst + 0x10));				
				}
				catch(NullPointerException e) {}
		}
		// R_BPF_64_Relative
		else if (type == 8) {
			value = symbolValue;

			Address refd_va = program.getAddressFactory().getDefaultAddressSpace().getAddress(memory.getInt(imm_offset));
			Address refd_pa = refd_va.add(baseOffset);
			value += refd_pa.getOffset();
			ElfSectionHeader text_section = elf.getSection(".text");
			// check if
			if (text_section.getOffset() <= offset && offset <= text_section.getOffset() + text_section.getSize()) {
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
			int hash;
			String call_type;
			// elfRelocationContext.getLog().appendMsg(String.format("type 10 reloc"));
			if (sym.isFunction() && symbolValue != 0) {
				// bpf call
				// ElfSectionHeader text_section = elf.getSection(".text");
				long target_pc = symbolValue;// - text_section.getAddress();
				// normally we would put the hash into the immediate field of
				// the call but then we would have to resolve the call again
				// in sleigh and I don't know how to do that
				// therefore we just resolve the address relative to the current
				// instruction and resolve it immediately :)
				// // hash = hashBpfFunction(target_pc, symbolName);
				// // current instruction address that the call will be relative to
				long this_pc = relocation.getOffset() + 3 + 8 + baseOffset;
				hash = (int)((target_pc - this_pc)/8);
				// elfRelocationContext.getLog().appendMsg(String.format("this_pc: %x\ntarget_pc: %x\nhash: %x", this_pc, target_pc, hash));
				call_type = "function";
			} else {
				// syscall
				CharBuffer buffer = CharBuffer.allocate(symbolName.length());
				buffer.put(symbolName);
				buffer.rewind();
				hash = hashSymbolName(buffer);
				// elfRelocationContext.getLog().appendMsg(String.format("type 10 (syscall) %s %x = %x, buf_pos: %d, len: %d, buffer: %s", symbolName, imm_offset.getOffset(), hash, buffer.position(), symbolName.length(),
					// Arrays.toString(buffer.array())));
				// buffer.charAt(buffer.position() -1)));
				call_type = "syscall";
			}
			// elfRelocationContext.getLog().appendMsg(String.format("type 10 (isFunction %b) %s %x = %x", sym.isFunction() && symbolValue != 0, symbolName, imm_offset.getOffset(), hash));

			memory.setInt(imm_offset, hash);
			Listing listing = program.getListing();
			listing.setComment(relocationAddress, CodeUnit.EOL_COMMENT,
				String.format("%s_%s", call_type, symbolName));
		} else {
			appliedSymbol = false;
		}

		// if (appliedSymbol && symbolIndex == 0) {
		// 	markAsWarning(program, relocationAddress, Long.toString(type),
		// 		"applied relocation with symbol-index of 0", elfRelocationContext.getLog());
		// }

	}
}
