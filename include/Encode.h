#pragma once

// Encode.h:
// EncodeASM functions for core instruction encoding.
//
// See LICENSE file for license details.

#include "Instruction.h"
#include "Memory.h"
#include "GeneralRegisters.h"
#include "Types.h"

namespace encodeasm {
namespace mode64bit {

namespace encoders {
	template<typename RegType>
	constexpr uint8 REXR(RegType r) noexcept {
		// REX: 0100WRXB (01000R00)
		return 0x40 | ((uint8(r)&0b1000)>>1);
	}
	template<typename RegType>
	constexpr uint8 REXB(RegType r) noexcept {
		// REX: 0100WRXB (0100000B)
		return 0x40 | ((uint8(r)&0b1000)>>3);
	}
	constexpr uint8 REXW() noexcept {
		// REX: 0100WRXB (0100W000)
		return 0x48;
	}
	template<typename RegType>
	constexpr uint8 REXWB(RegType r) noexcept {
		// REX: 0100WRXB (0100W00B)
		return 0x48 | ((uint8(r)&0b1000)>>3);
	}
	template<typename RegType0,typename RegType1>
	constexpr uint8 REXRB(RegType0 r, RegType1 b) noexcept {
		// REX: 0100WRXB (01000R0B)
		return 0x40 | ((uint8(r)&0b1000)>>1) | (uint8(b)>>3);
	}
	template<typename RegType0,typename RegType1>
	constexpr uint8 REXWRB(RegType0 r, RegType1 b) noexcept {
		// REX: 0100WRXB (0100WR0B)
		return 0x48 | ((uint8(r)&0b1000)>>1) | (uint8(b)>>3);
	}
	template<typename RegType0,typename RegType1>
	constexpr uint8 ModRegRm(RegType0 reg, RegType1 rm) noexcept {
		// Mod = 11 when two registers
		return 0xC0 | ((uint8(reg)&0b111)<<3) | (uint8(rm)&0b111);
	}
} //namespace encoders

#define ENCODEASM_CONDITIONAL_ENUM_WRAPPER(MNEMONIC_PREFIX) \
	MNEMONIC_PREFIX ## O, \
	MNEMONIC_PREFIX ## NO, \
	MNEMONIC_PREFIX ## C, \
	MNEMONIC_PREFIX ## B = MNEMONIC_PREFIX ## C, \
	MNEMONIC_PREFIX ## NAE = MNEMONIC_PREFIX ## C, \
	MNEMONIC_PREFIX ## NC, \
	MNEMONIC_PREFIX ## AE = MNEMONIC_PREFIX ## NC, \
	MNEMONIC_PREFIX ## NB = MNEMONIC_PREFIX ## NC, \
	MNEMONIC_PREFIX ## Z, \
	MNEMONIC_PREFIX ## E = MNEMONIC_PREFIX ## Z, \
	MNEMONIC_PREFIX ## NZ, \
	MNEMONIC_PREFIX ## NE = MNEMONIC_PREFIX ## NZ, \
	MNEMONIC_PREFIX ## BE, \
	MNEMONIC_PREFIX ## NA = MNEMONIC_PREFIX ## BE, \
	MNEMONIC_PREFIX ## A, \
	MNEMONIC_PREFIX ## NBE = MNEMONIC_PREFIX ## A, \
	MNEMONIC_PREFIX ## S, \
	MNEMONIC_PREFIX ## NS, \
	MNEMONIC_PREFIX ## P, \
	MNEMONIC_PREFIX ## PE = MNEMONIC_PREFIX ## P, \
	MNEMONIC_PREFIX ## NP, \
	MNEMONIC_PREFIX ## PO = MNEMONIC_PREFIX ## NP, \
	MNEMONIC_PREFIX ## L, \
	MNEMONIC_PREFIX ## NGE = MNEMONIC_PREFIX ## L, \
	MNEMONIC_PREFIX ## GE, \
	MNEMONIC_PREFIX ## NL = MNEMONIC_PREFIX ## GE, \
	MNEMONIC_PREFIX ## LE, \
	MNEMONIC_PREFIX ## NG = MNEMONIC_PREFIX ## LE, \
	MNEMONIC_PREFIX ## G, \
	MNEMONIC_PREFIX ## NLE = MNEMONIC_PREFIX ## G, \
	// End of ENCODEASM_CONDITIONAL_ENUM_WRAPPER macro

enum class mnemonic : uint32 {
	ADD,
	OR,  // NOTE: Can't be lowercase, because "or" is a C++ keyword.
	ADC,
	SBB,
	AND, // NOTE: Can't be lowercase, because "and" is a C++ keyword.
	SUB,
	XOR, // NOTE: Can't be lowercase, because "xor" is a C++ keyword.
	CMP,

	MOV, // NOTE: There are separate enum entries for moving segment, control, and debug registers.
	LEA,
	TEST,
	XCHG,
	NOT,
	NEG,
	MUL,
	IMUL,
	DIV,
	IDIV,
	INC,
	DEC,

	BSF,
	BSR,
	BSWAP,
	BT,
	BTS,
	BTR,
	BTC,
	CBW,
	CWDE,
	CDQE,
	CWD,
	CDQ,
	CQO,
	CLC,
	CMC,
	STC,
	CMPXCHG,
	CMPXCHG8B,
	CMPXCHG16B,
	CPUID,
	JRCXZ,
	MOVSB,
	MOVSW,
	MOVSD,
	MOVSQ,
	REP_MOVSB,
	REP_MOVSW,
	REP_MOVSD,
	REP_MOVSQ,
	PAUSE,
	POPF,
	POPFQ,
	PUSHF,
	PUSHFQ,
	RCL,
	RCR,
	ROL,
	ROR,
	RDPMC,
	RDTSC,
	SAR,
	SHL,
	SHR,
	SHLD,
	SHRD,
	STOSB,
	STOSW,
	STOSD,
	STOSQ,
	REP_STOSB,
	REP_STOSW,
	REP_STOSD,
	REP_STOSQ,
	UD2,
	XADD,

	JMP,

	ENCODEASM_CONDITIONAL_ENUM_WRAPPER(J)
	ENCODEASM_CONDITIONAL_ENUM_WRAPPER(SET)
	ENCODEASM_CONDITIONAL_ENUM_WRAPPER(CMOV)

	CALL,
	RET,

	// OS-related
	RET_FAR
};

#undef ENCODEASM_CONDITIONAL_ENUM_WRAPPER

namespace encoders {
	template<int membytes,typename RegType>
	static constexpr int OpcodeAndMemStart(Instruction &i, MemT<membytes> m, RegType r, int index) noexcept {
		if (m.hasSegmentPrefix()) {
			i.bytes[index] = memory::os::getSegmentPrefix(m.segment_prefix);
			++index;
		}
		uint8 rbit3 = uint8(r)&0b1000;
		if (m.hasrex || rbit3) {
			// NOTE: If !m.hasrex, m.rex is 0x40, so this should work for either m.hasrex or !m.hasrex.
			i.bytes[index] = m.rex | (rbit3>>1);
			++index;
		}
		return index;
	}
	template<int membytes,typename RegType>
	static constexpr int OpcodeAndMemEnd(Instruction &i, MemT<membytes> m, RegType r, int index) noexcept {
		i.bytes[index] = m.modregrm | ((uint8(r)&0b111)<<3);
		++index;
		if (m.hassib) {
			i.bytes[index] = m.sib;
			++index;
		}
		if (m.dispbytes) {
			i.bytes[index] = uint8(m.displacement);
			if (m.dispbytes==4) {
				// 4-byte displacement
				i.bytes[index+1] = uint8(m.displacement>>8);
				i.bytes[index+2] = uint8(m.displacement>>16);
				i.bytes[index+3] = uint8(m.displacement>>24);
			}
			index += m.dispbytes;
		}
		return index;
	}
	template<int membytes,typename RegType>
	static constexpr int OpcodeAndMem(Instruction &i, uint8 opcode, MemT<membytes> m, RegType r, int start=0) noexcept {
		int index = OpcodeAndMemStart(i, m, r, start);
		i.bytes[index] = opcode;
		return OpcodeAndMemEnd(i, m, r, index+1);
	}
	template<int membytes,typename RegType>
	static constexpr int OpcodeAndMem(Instruction &i, uint8 opcode0, uint8 opcode1, MemT<membytes> m, RegType r, int start=0) noexcept {
		int index = OpcodeAndMemStart(i, m, r, start);
		i.bytes[index] = opcode0;
		i.bytes[index+1] = opcode1;
		return OpcodeAndMemEnd(i, m, r, index+2);
	}
	static constexpr Instruction commonEncode(const uint8 opcode_base, const core::reg8 r, const core::reg8 rm, bool alternate_encoding=false) noexcept {
		if (uint8(r) < 4 && uint8(rm)<4) {
			// No REX needed if al, cl, dl, or bl.
			if (!alternate_encoding) {
				return Instruction(opcode_base | 2, ModRegRm(r,rm));
			}
			return Instruction(opcode_base, ModRegRm(rm,r));
		}
		// REX is needed for spl, bpl, sil, dil,
		// r8b, r9b, r10b, r11b, ...
		if (!alternate_encoding) {
			return Instruction(REXRB(r,rm), opcode_base | 2, ModRegRm(r,rm));
		}
		return Instruction(REXRB(rm,r), opcode_base, ModRegRm(rm,r));
	}
	static constexpr Instruction commonEncode(const uint8 opcode_base, const core::reg8_32 r, const core::reg8_32 rm, bool alternate_encoding=false) noexcept {
		// No REX in this case (al, cl, dl, or bl, ah, ch, dh, or bh).
		if (!alternate_encoding) {
			return Instruction(opcode_base | 2, ModRegRm(r,rm));
		}
		return Instruction(opcode_base, ModRegRm(rm,r));
	}
	/// NOTE: Unordered; opcode determines the operand order.
	static constexpr Instruction commonEncode(const uint8 opcode, const core::reg8 r, const MemT<1> rm) noexcept {
		if (rm.hasError()) {
			return Instruction::createError("Invalid memory operand");
		}
		Instruction i = EMPTY_INSTRUCTION;
		if (uint8(r) < 4 || uint8(r) >= 8 || rm.hasrex) {
			// No REX needed if al, cl, dl, or bl and !rm.hasrex,
			// and if rm.hasrex or r8b+, it handles the REX byte automatically.
			i.length = OpcodeAndMem(i, opcode, rm, r);
			return i;
		}
		// REX is needed for spl, bpl, sil, or dil, which wouldn't
		// be added automatically.
		i.bytes[0] = REXR(r);
		i.length = OpcodeAndMem(i, opcode, rm, r, 1);
		return i;
	}
	/// NOTE: This is intentionally *not* constexpr, to produce a compile
	///       error if hit at compile time.
	static inline Instruction error_reg8_32_registers_cant_be_used_with_memory_operand_with_rex() noexcept {
		return Instruction::createError("Legacy 8-bit registers, like ah, ch, dh, or bh, can't be used with a memory operand using r8, r9, r10, ..., r15");
	}
	/// NOTE: Unordered; opcode determines the operand order.
	static constexpr Instruction commonEncode(const uint8 opcode, const core::reg8_32 r, const MemT<1> rm) noexcept {
		if (rm.hasError()) {
			return Instruction::createError("Invalid memory operand");
		}
		if (uint8(r) >= 4 && rm.hasrex) {
			return error_reg8_32_registers_cant_be_used_with_memory_operand_with_rex();
		}
		Instruction i = EMPTY_INSTRUCTION;
		// No REX in this case (al, cl, dl, or bl, ah, ch, dh, or bh).
		// REX from memory operand allowed if al, cl, dl, or bl.
		i.length = OpcodeAndMem(i, opcode, rm, r);
		return i;
	}
	static constexpr Instruction commonEncode(const uint8 opcode_base, const core::reg16 r, const core::reg16 rm, bool alternate_encoding=false) noexcept {
		if (uint8(r) < 8 && uint8(rm) < 8) {
			// No REX needed if both ax, cx, dx, bx, sp, bp, si, or di.
			if (!alternate_encoding) {
				return Instruction(memory::SIZE_PREFIX, opcode_base | 3, ModRegRm(r,rm));
			}
			return Instruction(memory::SIZE_PREFIX, opcode_base | 1, ModRegRm(rm,r));
		}
		// REX is needed for r8w, r9w, r10w, r11w, ...
		if (!alternate_encoding) {
			return Instruction(memory::SIZE_PREFIX, REXRB(r,rm), opcode_base | 3, ModRegRm(r,rm));
		}
		return Instruction(memory::SIZE_PREFIX, REXRB(rm,r), opcode_base | 1, ModRegRm(rm,r));
	}
	/// NOTE: Unordered; opcode determines the operand order.
	static constexpr Instruction commonEncode(const uint8 opcode, const core::reg16 r, const MemT<2> rm) noexcept {
		if (rm.hasError()) {
			return Instruction::createError("Invalid memory operand");
		}
		Instruction i = EMPTY_INSTRUCTION;
		i.bytes[0] = memory::SIZE_PREFIX;
		// REX is handled automatically, if needed.
		i.length = OpcodeAndMem(i, opcode, rm, r, 1);
		return i;
	}
	static constexpr Instruction commonEncode(const uint8 opcode_base, const core::reg32 r, const core::reg32 rm, bool alternate_encoding=false) noexcept {
		if (uint8(r) < 8 && uint8(rm) < 8) {
			// No REX needed if both eax, ecx, edx, ebx, esp, ebp, esi, or edi.
			if (!alternate_encoding) {
				return Instruction(opcode_base | 3, ModRegRm(r,rm));
			}
			return Instruction(opcode_base | 1, ModRegRm(rm,r));
		}
		// REX is needed for r8d, r9d, r10d, r11d, ...
		if (!alternate_encoding) {
			return Instruction(REXRB(r,rm), opcode_base | 3, ModRegRm(r,rm));
		}
		return Instruction(REXRB(rm,r), opcode_base | 1, ModRegRm(rm,r));
	}
	/// NOTE: Unordered; opcode determines the operand order.
	static constexpr Instruction commonEncode(const uint8 opcode, const core::reg32 r, const MemT<4> rm) noexcept {
		if (rm.hasError()) {
			return Instruction::createError("Invalid memory operand");
		}
		Instruction i = EMPTY_INSTRUCTION;
		// REX is handled automatically, if needed.
		i.length = OpcodeAndMem(i, opcode, rm, r);
		return i;
	}
	static constexpr Instruction commonEncode(const uint8 opcode_base, const core::reg r, const core::reg rm, bool alternate_encoding=false) noexcept {
		if (!alternate_encoding) {
			return Instruction(REXWRB(r,rm), opcode_base | 3, ModRegRm(r,rm));
		}
		return Instruction(REXWRB(rm,r), opcode_base | 1, ModRegRm(rm,r));
	}
	/// NOTE: Unordered; opcode determines the operand order.
	static constexpr Instruction commonEncode(const uint8 opcode, const core::reg r, const MemT<8> rm) noexcept {
		if (rm.hasError()) {
			return Instruction::createError("Invalid memory operand");
		}
		Instruction i = EMPTY_INSTRUCTION;
		// REX is handled automatically, including W from rm.
		i.length = OpcodeAndMem(i, opcode, rm, r);
		return i;
	}
	static constexpr Instruction commonEncode(const uint8 opcode, const uint8 num, const core::reg8 r, const int8 imm) noexcept {
		if (uint8(r) < 4) {
			// No REX needed if al, cl, dl, or bl.
			return Instruction(opcode, ModRegRm(num,r), imm);
		}
		// REX is needed for spl, bpl, sil, dil,
		// r8b, r9b, r10b, r11b, ...
		return Instruction(REXB(r), opcode, ModRegRm(num,r), imm);
	}
	static constexpr Instruction commonEncode(const uint8 opcode, const uint8 num, const core::reg16 r, const int16 imm) noexcept {
		if (uint8(r) < 8) {
			// No REX needed if ax, cx, dx, bx, sp, bp, si, or di.
			return Instruction(memory::SIZE_PREFIX, opcode, ModRegRm(num,r), uint8(imm), uint8(imm>>8));
		}
		// REX is needed for r8w, r9w, r10w, r11w, ...
		return Instruction(memory::SIZE_PREFIX, REXB(r), opcode, ModRegRm(num,r), uint8(imm), uint8(imm>>8));
	}
	static constexpr Instruction commonEncode(const uint8 opcode, const uint8 num, const core::reg32 r, const int32 imm) noexcept {
		if (uint8(r) < 8) {
			// No REX needed if eax, ecx, edx, ebx, esp, ebp, esi, or edi.
			return Instruction(opcode, ModRegRm(num,r), uint8(imm), uint8(imm>>8), uint8(imm>>16), uint8(imm>>24));
		}
		// REX is needed for r8d, r9d, r10d, r11d, ...
		return Instruction(REXB(r), opcode, ModRegRm(num,r), uint8(imm), uint8(imm>>8), uint8(imm>>16), uint8(imm>>24));
	}
	static constexpr Instruction commonEncode(const uint8 opcode, const uint8 num, const core::reg r, const int32 imm) noexcept {
		return Instruction(REXWB(r), opcode, ModRegRm(num,r), uint8(imm), uint8(imm>>8), uint8(imm>>16), uint8(imm>>24));
	}
	static constexpr Instruction commonEncode(const uint8 opcode, const uint8 num, const MemT<1> m,const int8 imm) noexcept {
		if (m.hasError()) {
			return Instruction::createError("Invalid memory operand");
		}
		Instruction i = EMPTY_INSTRUCTION;
		int index = OpcodeAndMem(i, opcode, m, num);
		i.bytes[index] = imm;
		i.length = index+1;
		return i;
	}
	static constexpr Instruction commonEncode(const uint8 opcode, const uint8 num, const MemT<2> m, const int16 imm) noexcept {
		if (m.hasError()) {
			return Instruction::createError("Invalid memory operand");
		}
		Instruction i = EMPTY_INSTRUCTION;
		i.bytes[0] = memory::SIZE_PREFIX;
		int index = OpcodeAndMem(i, opcode, m, num, 1);
		i.bytes[index] = uint8(imm);
		i.bytes[index+1] = uint8(imm>>8);
		i.length = index+2;
		return i;
	}
	static constexpr Instruction commonEncode(const uint8 opcode, const uint8 num, const MemT<4> m, const int32 imm) noexcept {
		if (m.hasError()) {
			return Instruction::createError("Invalid memory operand");
		}
		Instruction i = EMPTY_INSTRUCTION;
		int index = OpcodeAndMem(i, opcode, m, num);
		i.bytes[index] = uint8(imm);
		i.bytes[index+1] = uint8(imm>>8);
		i.bytes[index+2] = uint8(imm>>16);
		i.bytes[index+3] = uint8(imm>>24);
		i.length = index+4;
		return i;
	}
	static constexpr Instruction commonEncode(const uint8 opcode, const uint8 num, const MemT<8> m, const int32 imm) noexcept {
		if (m.hasError()) {
			return Instruction::createError("Invalid memory operand");
		}
		Instruction i = EMPTY_INSTRUCTION;
		// NOTE: REX.W is already set in m.
		int index = OpcodeAndMem(i, opcode, m, num);
		i.bytes[index] = uint8(imm);
		i.bytes[index+1] = uint8(imm>>8);
		i.bytes[index+2] = uint8(imm>>16);
		i.bytes[index+3] = uint8(imm>>24);
		i.length = index+4;
		return i;
	}

	template<uint8 num> struct standard_encoder {
		static constexpr Instruction encode(const core::reg8 r, const int8 imm) noexcept {
			if (r == core::reg8::al) {
				// Short encoding for al
				return Instruction((num<<3) | 4, imm);
			}
			return commonEncode(0x80, num, r, imm);
		}
		static constexpr Instruction encode(const core::reg8_32 r, const int8 imm) noexcept {
			if (r == core::reg8_32::al) {
				// Short encoding for al
				return Instruction((num<<3) | 4, imm);
			}
			// No REX needed for al, cl, dl, bl, ah, ch, dh, or bh.
			return Instruction(0x80, ModRegRm(num,r), imm);
		}
		static constexpr Instruction encode(const MemT<1> m,const int8 imm) noexcept {
			return commonEncode(0x80, num, m, imm);
		}
		static constexpr Instruction encode(const core::reg16 r, const int8 imm) noexcept {
			if (uint8(r) < 8) {
				// No REX needed if ax, cx, dx, bx, sp, bp, si, or di.
				return Instruction(memory::SIZE_PREFIX, 0x83, ModRegRm(num,r), imm);
			}
			// REX is needed for r8w, r9w, r10w, r11w, ...
			return Instruction(memory::SIZE_PREFIX, REXB(r), 0x83, ModRegRm(num,r), imm);
		}
		static constexpr Instruction encode(const MemT<2> m,const int8 imm) noexcept {
			if (m.hasError()) {
				return Instruction::createError("Invalid memory operand");;
			}
			Instruction i = EMPTY_INSTRUCTION;
			i.bytes[0] = memory::SIZE_PREFIX;
			int index = OpcodeAndMem(i, 0x83, m, num, 1);
			i.bytes[index] = imm;
			i.length = index+1;
			return i;
		}
		static constexpr Instruction encode(const core::reg32 r, const int8 imm) noexcept {
			if (uint8(r) < 8) {
				// No REX needed if eax, ecx, edx, ebx, esp, ebp, esi, or edi.
				return Instruction(0x83, ModRegRm(num,r), imm);
			}
			// REX is needed for r8d, r9d, r10d, r11d, ...
			return Instruction(REXB(r), 0x83, ModRegRm(num,r), imm);
		}
		static constexpr Instruction encode(const MemT<4> m,const int8 imm) noexcept {
			if (m.hasError()) {
				return Instruction::createError("Invalid memory operand");;
			}
			Instruction i = EMPTY_INSTRUCTION;
			int index = OpcodeAndMem(i, 0x83, m, num);
			i.bytes[index] = imm;
			i.length = index+1;
			return i;
		}
		static constexpr Instruction encode(const core::reg r, const int8 imm) noexcept {
			return Instruction(REXWB(r), 0x83, ModRegRm(num,r), uint8(imm));
		}
		static constexpr Instruction encode(const MemT<8> m,const int8 imm) noexcept {
			if (m.hasError()) {
				return Instruction::createError("Invalid memory operand");;
			}
			Instruction i = EMPTY_INSTRUCTION;
			// NOTE: REX.W is already set in m.
			int index = OpcodeAndMem(i, 0x83, m, num);
			i.bytes[index] = imm;
			i.length = index+1;
			return i;
		}

		static constexpr Instruction encode(const core::reg16 r, const int16 imm) noexcept {
			if (r == core::reg16::ax) {
				// Short encoding for ax
				return Instruction(memory::SIZE_PREFIX, (num<<3) | 5, uint8(imm), uint8(imm>>8));
			}
			return commonEncode(0x81, num, r, imm);
		}
		static constexpr Instruction encode(const MemT<2> m, const int16 imm) noexcept {
			return commonEncode(0x81, num, m, imm);
		}
		static constexpr Instruction encode(const core::reg32 r, const int32 imm) noexcept {
			if (r == core::reg32::eax) {
				// Short encoding for eax
				return Instruction((num<<3) | 5, uint8(imm), uint8(imm>>8), uint8(imm>>16), uint8(imm>>24));
			}
			return commonEncode(0x81, num, r, imm);
		}
		static constexpr Instruction encode(const MemT<4> m, const int32 imm) noexcept {
			return commonEncode(0x81, num, m, imm);
		}
		static constexpr Instruction encode(const core::reg r, const int32 imm) noexcept {
			if (r == core::reg::rax) {
				// Short encoding for rax
				return Instruction(REXW(), (num<<3) | 5, uint8(imm), uint8(imm>>8), uint8(imm>>16), uint8(imm>>24));
			}
			return commonEncode(0x81, num, r, imm);
		}
		static constexpr Instruction encode(const MemT<8> m, const int32 imm) noexcept {
			return commonEncode(0x81, num, m, imm);
		}
		static constexpr Instruction encode(const core::reg8 r, const core::reg8 rm, bool alternate_encoding=false) noexcept {
			return commonEncode(num<<3, r, rm, alternate_encoding);
		}
		static constexpr Instruction encode(const core::reg8_32 r, const core::reg8_32 rm, bool alternate_encoding=false) noexcept {
			return commonEncode(num<<3, r, rm, alternate_encoding);
		}
		static constexpr Instruction encode(const core::reg8 r, const MemT<1> rm) noexcept {
			return commonEncode((num<<3) | 2, r, rm);
		}
		static constexpr Instruction encode(const MemT<1> rm, const core::reg8 r) noexcept {
			return commonEncode((num<<3), r, rm);
		}
		static constexpr Instruction encode(const core::reg8_32 r, const MemT<1> rm) noexcept {
			return commonEncode((num<<3) | 2, r, rm);
		}
		static constexpr Instruction encode(const MemT<1> rm, const core::reg8_32 r) noexcept {
			return commonEncode((num<<3), r, rm);
		}
		static constexpr Instruction encode(const core::reg16 r, const core::reg16 rm, bool alternate_encoding=false) noexcept {
			return commonEncode(num<<3, r, rm, alternate_encoding);
		}
		static constexpr Instruction encode(const core::reg16 r, const MemT<2> rm) noexcept {
			return commonEncode((num<<3) | 3, r, rm);
		}
		static constexpr Instruction encode(const MemT<2> rm, const core::reg16 r) noexcept {
			return commonEncode((num<<3) | 1, r, rm);
		}
		static constexpr Instruction encode(const core::reg32 r, const core::reg32 rm, bool alternate_encoding=false) noexcept {
			return commonEncode(num<<3, r, rm, alternate_encoding);
		}
		static constexpr Instruction encode(const core::reg32 r, const MemT<4> rm) noexcept {
			return commonEncode((num<<3) | 3, r, rm);
		}
		static constexpr Instruction encode(const MemT<4> rm, const core::reg32 r) noexcept {
			return commonEncode((num<<3) | 1, r, rm);
		}
		static constexpr Instruction encode(const core::reg r, const core::reg rm, bool alternate_encoding=false) noexcept {
			return commonEncode(num<<3, r, rm, alternate_encoding);
		}
		static constexpr Instruction encode(const core::reg r, const MemT<8> rm) noexcept {
			return commonEncode((num<<3) | 3, r, rm);
		}
		static constexpr Instruction encode(const MemT<8> rm, const core::reg r) noexcept {
			return commonEncode((num<<3) | 1, r, rm);
		}
	};

	struct mov_encoder {
		static constexpr uint8 opcode_base0 = 0x88;

		static constexpr Instruction encode(const core::reg8 r, const core::reg8 rm, const bool alternate_encoding=false) noexcept {
			return commonEncode(opcode_base0, r, rm, alternate_encoding);
		}
		static constexpr Instruction encode(const core::reg8_32 r, const core::reg8_32 rm, const bool alternate_encoding=false) noexcept {
			return commonEncode(opcode_base0, r, rm, alternate_encoding);
		}
		static constexpr Instruction encode(const core::reg8 r, const MemT<1> rm) noexcept {
			return commonEncode(opcode_base0 | 2, r, rm);
		}
		static constexpr Instruction encode(const MemT<1> rm, const core::reg8 r) noexcept {
			return commonEncode(opcode_base0, r, rm);
		}
		static constexpr Instruction encode(const core::reg8_32 r, const MemT<1> rm) noexcept {
			return commonEncode(opcode_base0 | 2, r, rm);
		}
		static constexpr Instruction encode(const MemT<1> rm, const core::reg8_32 r) noexcept {
			return commonEncode(opcode_base0, r, rm);
		}
		static constexpr Instruction encode(const core::reg16 r, const core::reg16 rm, const bool alternate_encoding=false) noexcept {
			return commonEncode(opcode_base0, r, rm, alternate_encoding);
		}
		static constexpr Instruction encode(const core::reg16 r, const MemT<2> rm) noexcept {
			return commonEncode(opcode_base0 | 3, r, rm);
		}
		static constexpr Instruction encode(const MemT<2> rm, const core::reg16 r) noexcept {
			return commonEncode(opcode_base0 | 1, r, rm);
		}
		static constexpr Instruction encode(const core::reg32 r, const core::reg32 rm, const bool alternate_encoding=false) noexcept {
			return commonEncode(opcode_base0, r, rm, alternate_encoding);
		}
		static constexpr Instruction encode(const core::reg32 r, const MemT<4> rm) noexcept {
			return commonEncode(opcode_base0 | 3, r, rm);
		}
		static constexpr Instruction encode(const MemT<4> rm, const core::reg32 r) noexcept {
			return commonEncode(opcode_base0 | 1, r, rm);
		}
		static constexpr Instruction encode(const core::reg r, const core::reg rm, const bool alternate_encoding=false) noexcept {
			return commonEncode(opcode_base0, r, rm, alternate_encoding);
		}
		static constexpr Instruction encode(const core::reg r, const MemT<8> rm) noexcept {
			return commonEncode(opcode_base0 | 3, r, rm);
		}
		static constexpr Instruction encode(const MemT<8> rm, const core::reg r) noexcept {
			return commonEncode(opcode_base0 | 1, r, rm);
		}
		static constexpr Instruction encode(const core::reg8 r, const int8 imm, const bool alternate_encoding=false) noexcept {
			if (!alternate_encoding) {
				if (uint8(r) < 4) {
					// No REX needed if al, cl, dl, or bl.
					return Instruction(0xB0 | uint8(r), imm);
				}
				// REX is needed for spl, bpl, sil, dil,
				// r8b, r9b, r10b, r11b, ...
				return Instruction(REXB(r), 0xB0 | (uint8(r)&0b111), imm);
			}
			return commonEncode(0xC6, 0, r, imm);
		}
		static constexpr Instruction encode(const core::reg8_32 r, const int8 imm, const bool alternate_encoding=false) noexcept {
			if (!alternate_encoding) {
				// No REX needed for al, cl, dl, bl, ah, ch, dh, or bh.
				return Instruction(0xB0 | uint8(r), imm);
			}
			return Instruction(0xC6, ModRegRm(0,r), imm);
		}
		static constexpr Instruction encode(const core::reg16 r, const int16 imm, const bool alternate_encoding=false) noexcept {
			if (!alternate_encoding) {
				if (uint8(r) < 8) {
					// No REX needed if ax, cx, dx, bx, sp, bp, si, or di.
					return Instruction(memory::SIZE_PREFIX, 0xB8 | uint8(r), uint8(imm), uint8(imm>>8));
				}
				// REX is needed for r8w, r9w, r10w, r11w, ...
				return Instruction(memory::SIZE_PREFIX, REXB(r), 0xB8 | uint8(r), uint8(imm), uint8(imm>>8));
			}
			return commonEncode(0xC7, 0, r, imm);
		}
		static constexpr Instruction encode(const core::reg32 r, const int32 imm, const bool alternate_encoding=false) noexcept {
			if (!alternate_encoding) {
				if (uint8(r) < 8) {
					// No REX needed if eax, ecx, edx, ebx, esp, ebp, esi, or edi.
					return Instruction(0xB8 | uint8(r), uint8(imm), uint8(imm>>8), uint8(imm>>16), uint8(imm>>24));
				}
				// REX is needed for r8d, r9d, r10d, r11d, ...
				return Instruction(REXB(r), 0xB8 | uint8(r), uint8(imm), uint8(imm>>8), uint8(imm>>16), uint8(imm>>24));
			}
			return commonEncode(0xC7, 0, r, imm);
		}
		static constexpr Instruction encode(const core::reg r, const int32 imm, const bool alternate_encoding=false) noexcept {
			return commonEncode(0xC7, 0, r, imm);
		}
		static constexpr Instruction encode(const core::reg r, const int64 imm) noexcept {
			return Instruction(REXWB(r), 0xB8 | uint8(r), uint8(imm), uint8(imm>>8), uint8(imm>>16), uint8(imm>>24), uint8(imm>>32), uint8(imm>>40), uint8(imm>>48), uint8(imm>>56));
		}
		static constexpr Instruction encode(const MemT<1> m, const int8 imm) noexcept {
			return commonEncode(0xC6, 0, m, imm);
		}
		static constexpr Instruction encode(const MemT<2> m, const int16 imm) noexcept {
			return commonEncode(0xC7, 0, m, imm);
		}
		static constexpr Instruction encode(const MemT<4> m, const int32 imm) noexcept {
			return commonEncode(0xC7, 0, m, imm);
		}
		static constexpr Instruction encode(const MemT<8> m, const int32 imm) noexcept {
			return commonEncode(0xC7, 0, m, imm);
		}
	};
	struct lea_encoder {
		static constexpr uint8 opcode = 0x8D;

		template<int membytes>
		static constexpr Instruction encode(const core::reg r, MemT<membytes> m) noexcept {
			if (m.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}

			m.hasrex = true;
			// Add W bit, since membytes doesn't matter; the register size is what counts in this case.
			m.rex |= 0x48;

			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, including W from rm.
			i.length = OpcodeAndMem(i, opcode, m, r);
			return i;
		}
		template<int membytes>
		static constexpr Instruction encode(const core::reg32 r, MemT<membytes> m) noexcept {
			if (m.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}

			if (m.hasrex) {
				// Remove W bit, since membytes doesn't matter; the register size is what counts in this case.
				m.rex &= ~0b1000;
				if (!(m.rex & 0b0111)) {
					m.hasrex = false;
				}
			}

			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, including W from rm.
			i.length = OpcodeAndMem(i, opcode, m, r);
			return i;
		}
		template<int membytes>
		static constexpr Instruction encode(const core::reg16 r, MemT<membytes> m) noexcept {
			if (m.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}

			if (m.hasrex) {
				// Remove W bit, since membytes doesn't matter; the register size is what counts in this case.
				m.rex &= ~0b1000;
				if (!(m.rex & 0b0111)) {
					m.hasrex = false;
				}
			}

			Instruction i = EMPTY_INSTRUCTION;
			i.bytes[0] = memory::SIZE_PREFIX;
			// REX is handled automatically, including W from rm.
			i.length = OpcodeAndMem(i, opcode, m, r, 1);
			return i;
		}
	};

	struct test_encoder {
		static constexpr uint8 opcode_al = 0xA8;
		static constexpr uint8 opcode_imm = 0xF6;
		static constexpr uint8 opcode_imm_reg = 0;
		static constexpr uint8 opcode_reg = 0x84;

		static constexpr Instruction encode(const core::reg8 rm, int8 imm) noexcept {
			if (rm == core::reg8::al) {
				// Special encoding for al
				return Instruction(opcode_al, imm);
			}
			return commonEncode(opcode_imm, opcode_imm_reg, rm, imm);
		}
		static constexpr Instruction encode(const core::reg8_32 rm, int8 imm) noexcept {
			if (rm == core::reg8_32::al) {
				// Special encoding for al
				return Instruction(opcode_al, imm);
			}
			// No REX needed for al, cl, dl, bl, ah, ch, dh, or bh.
			return Instruction(opcode_imm, ModRegRm(opcode_imm_reg,rm), imm);
		}
		static constexpr Instruction encode(const MemT<1> rm, int8 imm) noexcept {
			return commonEncode(opcode_imm, opcode_imm_reg, rm, imm);
		}
		static constexpr Instruction encode(const core::reg16 rm, int16 imm) noexcept {
			if (rm == core::reg16::ax) {
				// Special encoding for ax
				return Instruction(memory::SIZE_PREFIX, opcode_al | 1, uint8(imm), uint8(imm>>8));
			}
			return commonEncode(opcode_imm, opcode_imm_reg, rm, imm);
		}
		static constexpr Instruction encode(const MemT<2> rm, int16 imm) noexcept {
			return commonEncode(opcode_imm, opcode_imm_reg, rm, imm);
		}
		static constexpr Instruction encode(const core::reg32 rm, int32 imm) noexcept {
			if (rm == core::reg32::eax) {
				// Special encoding for eax
				return Instruction(opcode_al | 1, uint8(imm), uint8(imm>>8), uint8(imm>>16), uint8(imm>>24));
			}
			return commonEncode(opcode_imm, opcode_imm_reg, rm, imm);
		}
		static constexpr Instruction encode(const MemT<4> rm, int32 imm) noexcept {
			return commonEncode(opcode_imm, opcode_imm_reg, rm, imm);
		}
		static constexpr Instruction encode(const core::reg rm, int32 imm) noexcept {
			if (rm == core::reg::rax) {
				// Special encoding for rax
				return Instruction(REXW(), opcode_al | 1, uint8(imm), uint8(imm>>8), uint8(imm>>16), uint8(imm>>24));
			}
			return commonEncode(opcode_imm, opcode_imm_reg, rm, imm);
		}
		static constexpr Instruction encode(const MemT<8> rm, int32 imm) noexcept {
			return commonEncode(opcode_imm, opcode_imm_reg, rm, imm);
		}
		static constexpr Instruction encode(const core::reg8 r, const core::reg8 rm) noexcept {
			if (uint8(r) < 4 && uint8(rm) < 4) {
				// No REX needed if al, cl, dl, or bl.
				return Instruction(opcode_reg, ModRegRm(r,rm));
			}
			// REX is needed for spl, bpl, sil, dil,
			// r8b, r9b, r10b, r11b, ...
			return Instruction(REXRB(r,rm), opcode_reg, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const core::reg8_32 r, const core::reg8_32 rm) noexcept {
			// No REX in this case (al, cl, dl, or bl, ah, ch, dh, or bh).
			return Instruction(opcode_reg, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const core::reg8 r, const MemT<1> rm) noexcept {
			return commonEncode(opcode_reg, r, rm);
		}
		static constexpr Instruction encode(const core::reg8_32 r, const MemT<1> rm) noexcept {
			return commonEncode(opcode_reg, r, rm);
		}
		static constexpr Instruction encode(const MemT<1> rm, const core::reg8 r) noexcept {
			// TEST is commutative, so rm,r encoding is same as r,rm encoding.
			return commonEncode(opcode_reg, r, rm);
		}
		static constexpr Instruction encode(const MemT<1> rm, const core::reg8_32 r) noexcept {
			// TEST is commutative, so rm,r encoding is same as r,rm encoding.
			return commonEncode(opcode_reg, r, rm);
		}
		static constexpr Instruction encode(const core::reg16 r, const core::reg16 rm) noexcept {
			if (uint8(r) < 8 && uint8(rm) < 8) {
				// No REX needed if both ax, cx, dx, bx, sp, bp, si, or di.
				return Instruction(memory::SIZE_PREFIX, opcode_reg|1, ModRegRm(r,rm));
			}
			// REX is needed for r8w, r9w, r10w, r11w, ...
			return Instruction(memory::SIZE_PREFIX, REXRB(r,rm), opcode_reg|1, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const core::reg16 r, const MemT<2> rm) noexcept {
			return commonEncode(opcode_reg|1, r, rm);
		}
		static constexpr Instruction encode(const MemT<2> rm, const core::reg16 r) noexcept {
			return commonEncode(opcode_reg|1, r, rm);
		}
		static constexpr Instruction encode(const core::reg32 r, const core::reg32 rm) noexcept {
			if (uint8(r) < 8 && uint8(rm) < 8) {
				// No REX needed if both eax, ecx, edx, ebx, esp, ebp, esi, or edi.
				return Instruction(opcode_reg|1, ModRegRm(r,rm));
			}
			// REX is needed for r8d, r9d, r10d, r11d, ...
			return Instruction(REXRB(r,rm), opcode_reg|1, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const core::reg32 r, const MemT<4> rm) noexcept {
			return commonEncode(opcode_reg|1, r, rm);
		}
		static constexpr Instruction encode(const MemT<4> rm, const core::reg32 r) noexcept {
			return commonEncode(opcode_reg|1, r, rm);
		}
		static constexpr Instruction encode(const core::reg r, const core::reg rm) noexcept {
			return Instruction(REXWRB(r,rm), opcode_reg|1, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const core::reg r, const MemT<8> rm) noexcept {
			return commonEncode(opcode_reg|1, r, rm);
		}
		static constexpr Instruction encode(const MemT<8> rm, const core::reg r) noexcept {
			return commonEncode(opcode_reg|1, r, rm);
		}
	};

	struct xchg_encoder {
		static constexpr uint8 opcode_ax_base = 0x90;
		static constexpr uint8 opcode = 0x86;

		static constexpr Instruction encode(const core::reg8 r, const core::reg8 rm) noexcept {
			if (uint8(r) < 4 && uint8(rm) < 4) {
				// No REX needed if al, cl, dl, or bl.
				return Instruction(opcode, ModRegRm(r,rm));
			}
			// REX is needed for spl, bpl, sil, dil,
			// r8b, r9b, r10b, r11b, ...
			return Instruction(REXRB(r,rm), opcode, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const core::reg8_32 r, const core::reg8_32 rm) noexcept {
			// No REX in this case (al, cl, dl, or bl, ah, ch, dh, or bh).
			return Instruction(opcode, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const core::reg8 r, const MemT<1> rm) noexcept {
			return commonEncode(opcode, r, rm);
		}
		static constexpr Instruction encode(const core::reg8_32 r, const MemT<1> rm) noexcept {
			return commonEncode(opcode, r, rm);
		}
		static constexpr Instruction encode(const MemT<1> rm, const core::reg8 r) noexcept {
			// XCHG is commutative, so rm,r encoding is same as r,rm encoding.
			return commonEncode(opcode, r, rm);
		}
		static constexpr Instruction encode(const MemT<1> rm, const core::reg8_32 r) noexcept {
			// XCHG is commutative, so rm,r encoding is same as r,rm encoding.
			return commonEncode(opcode, r, rm);
		}
		static constexpr Instruction encode(const core::reg16 r, const core::reg16 rm) noexcept {
			if (r == core::reg16::ax) {
				if (uint8(rm) < 8) {
					return Instruction(memory::SIZE_PREFIX, opcode_ax_base+uint8(rm));
				}
				return Instruction(memory::SIZE_PREFIX, REXB(rm), opcode_ax_base+uint8(rm));
			}
			if (rm == core::reg16::ax) {
				if (uint8(r) < 8) {
					return Instruction(memory::SIZE_PREFIX, opcode_ax_base+uint8(r));
				}
				return Instruction(memory::SIZE_PREFIX, REXB(r), opcode_ax_base+uint8(r));
			}
			if (uint8(r) < 8 && uint8(rm) < 8) {
				// No REX needed if both ax, cx, dx, bx, sp, bp, si, or di.
				return Instruction(memory::SIZE_PREFIX, opcode|1, ModRegRm(r,rm));
			}
			// REX is needed for r8w, r9w, r10w, r11w, ...
			return Instruction(memory::SIZE_PREFIX, REXRB(r,rm), opcode|1, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const core::reg16 r, const MemT<2> rm) noexcept {
			return commonEncode(opcode|1, r, rm);
		}
		static constexpr Instruction encode(const MemT<2> rm, const core::reg16 r) noexcept {
			// XCHG is commutative, so rm,r encoding is same as r,rm encoding.
			return commonEncode(opcode|1, r, rm);
		}
		static constexpr Instruction encode(const core::reg32 r, const core::reg32 rm) noexcept {
			if (r == core::reg32::eax) {
				if (uint8(rm) < 8) {
					return Instruction(opcode_ax_base+uint8(rm));
				}
				return Instruction(REXB(rm), opcode_ax_base+uint8(rm));
			}
			if (rm == core::reg32::eax) {
				if (uint8(r) < 8) {
					return Instruction(opcode_ax_base+uint8(r));
				}
				return Instruction(REXB(r), opcode_ax_base+uint8(r));
			}
			if (uint8(r) < 8 && uint8(rm) < 8) {
				// No REX needed if both eax, ecx, edx, ebx, esp, ebp, esi, or edi.
				return Instruction(opcode|1, ModRegRm(r,rm));
			}
			// REX is needed for r8d, r9d, r10d, r11d, ...
			return Instruction(REXRB(r,rm), opcode|1, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const core::reg32 r, const MemT<4> rm) noexcept {
			return commonEncode(opcode|1, r, rm);
		}
		static constexpr Instruction encode(const MemT<4> rm, const core::reg32 r) noexcept {
			// XCHG is commutative, so rm,r encoding is same as r,rm encoding.
			return commonEncode(opcode|1, r, rm);
		}
		static constexpr Instruction encode(const core::reg r, const core::reg rm) noexcept {
			if (r == core::reg::rax) {
				return Instruction(REXWB(rm), opcode_ax_base+uint8(rm));
			}
			if (rm == core::reg::rax) {
				return Instruction(REXWB(r), opcode_ax_base+uint8(r));
			}
			return Instruction(REXWRB(r,rm), opcode|1, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const core::reg r, const MemT<8> rm) noexcept {
			return commonEncode(opcode|1, r, rm);
		}
		static constexpr Instruction encode(const MemT<8> rm, const core::reg r) noexcept {
			// XCHG is commutative, so rm,r encoding is same as r,rm encoding.
			return commonEncode(opcode|1, r, rm);
		}
	};

	template<uint8 opcode, uint8 num>
	struct standard_unary_encoder {
		static constexpr Instruction encode(const core::reg8 rm) noexcept {
			if (uint8(rm) < 4) {
				// No REX needed if al, cl, dl, or bl.
				return Instruction(opcode, ModRegRm(num,rm));
			}
			// REX is needed for spl, bpl, sil, dil,
			// r8b, r9b, r10b, r11b, ...
			return Instruction(REXB(rm), opcode, ModRegRm(num,rm));
		}
		static constexpr Instruction encode(const core::reg8_32 rm) noexcept {
			// No REX in this case (al, cl, dl, or bl, ah, ch, dh, or bh).
			return Instruction(opcode, ModRegRm(num,rm));
		}
		static constexpr Instruction encode(const MemT<1> rm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			i.length = OpcodeAndMem(i, opcode, rm, num);
			return i;
		}
		static constexpr Instruction encode(const core::reg16 rm) noexcept {
			if (uint8(rm) < 8) {
				// No REX needed if both ax, cx, dx, bx, sp, bp, si, or di.
				return Instruction(memory::SIZE_PREFIX, opcode|1, ModRegRm(num,rm));
			}
			// REX is needed for r8w, r9w, r10w, r11w, ...
			return Instruction(memory::SIZE_PREFIX, REXB(rm), opcode|1, ModRegRm(num,rm));
		}
		static constexpr Instruction encode(const MemT<2> rm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			i.bytes[0] = memory::SIZE_PREFIX;
			i.length = OpcodeAndMem(i, opcode|1, rm, num, 1);
			return i;
		}
		static constexpr Instruction encode(const core::reg32 rm) noexcept {
			if (uint8(rm) < 8) {
				// No REX needed if both eax, ecx, edx, ebx, esp, ebp, esi, or edi.
				return Instruction(opcode|1, ModRegRm(num,rm));
			}
			// REX is needed for r8d, r9d, r10d, r11d, ...
			return Instruction(REXB(rm), opcode|1, ModRegRm(num,rm));
		}
		static constexpr Instruction encode(const MemT<4> rm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			i.length = OpcodeAndMem(i, opcode|1, rm, num);
			return i;
		}
		static constexpr Instruction encode(const core::reg rm) noexcept {
			return Instruction(REXWB(rm), opcode|1, ModRegRm(num,rm));
		}
		static constexpr Instruction encode(const MemT<8> rm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			// NOTE: REX.W is already set in m.
			i.length = OpcodeAndMem(i, opcode|1, rm, num);
			return i;
		}
	};

	struct imul_encoder : public standard_unary_encoder<0xF6,5> {
		using standard_unary_encoder<0xF6,5>::encode;

		static constexpr uint8 opcode_regrm0 = 0x0F;
		static constexpr uint8 opcode_regrm1 = 0xAF;
		static constexpr uint8 opcode_regimm8 = 0x6B;
		static constexpr uint8 opcode_regimm = 0x69;

		static constexpr Instruction encode(const core::reg16 r, const core::reg16 rm) noexcept {
			if (uint8(r) < 8 && uint8(rm) < 8) {
				// No REX needed if both ax, cx, dx, bx, sp, bp, si, or di.
				return Instruction(memory::SIZE_PREFIX, opcode_regrm0, opcode_regrm1, ModRegRm(r,rm));
			}
			// REX is needed for r8w, r9w, r10w, r11w, ...
			return Instruction(memory::SIZE_PREFIX, REXRB(r,rm), opcode_regrm0, opcode_regrm1, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const core::reg16 r, const MemT<2> rm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			i.bytes[0] = memory::SIZE_PREFIX;
			// REX is handled automatically, if needed.
			i.length = OpcodeAndMem(i, opcode_regrm0, opcode_regrm1, rm, r, 1);
			return i;
		}
		static constexpr Instruction encode(const core::reg32 r, const core::reg32 rm) noexcept {
			if (uint8(r) < 8 && uint8(rm) < 8) {
				// No REX needed if both eax, ecx, edx, ebx, esp, ebp, esi, or edi.
				return Instruction(opcode_regrm0, opcode_regrm1, ModRegRm(r,rm));
			}
			// REX is needed for r8d, r9d, r10d, r11d, ...
			return Instruction(REXRB(r,rm), opcode_regrm0, opcode_regrm1, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const core::reg32 r, const MemT<4> rm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, if needed.
			i.length = OpcodeAndMem(i, opcode_regrm0, opcode_regrm1, rm, r);
			return i;
		}
		static constexpr Instruction encode(const core::reg r, const core::reg rm) noexcept {
			return Instruction(REXWRB(r,rm), opcode_regrm0, opcode_regrm1, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const core::reg r, const MemT<8> rm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			// NOTE: REX.W is already set in m.
			i.length = OpcodeAndMem(i, opcode_regrm0, opcode_regrm1, rm, r);
			return i;
		}

		static constexpr Instruction encode(const core::reg16 r, const core::reg16 rm, const int8 imm) noexcept {
			if (uint8(r) < 8 && uint8(rm) < 8) {
				// No REX needed if both ax, cx, dx, bx, sp, bp, si, or di.
				return Instruction(memory::SIZE_PREFIX, opcode_regimm8, ModRegRm(r,rm), imm);
			}
			// REX is needed for r8w, r9w, r10w, r11w, ...
			return Instruction(memory::SIZE_PREFIX, REXRB(r,rm), opcode_regimm8, ModRegRm(r,rm), imm);
		}
		static constexpr Instruction encode(const core::reg16 r, const int8 imm) noexcept {
			return encode(r,r,imm);
		}
		static constexpr Instruction encode(const core::reg16 r, const MemT<2> rm, const int8 imm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			i.bytes[0] = memory::SIZE_PREFIX;
			// REX is handled automatically, if needed.
			int index = OpcodeAndMem(i, opcode_regimm8, rm, r, 1);
			i.bytes[index] = imm;
			i.length = index+1;
			return i;
		}
		static constexpr Instruction encode(const core::reg32 r, const core::reg32 rm, const int8 imm) noexcept {
			if (uint8(r) < 8 && uint8(rm) < 8) {
				// No REX needed if both eax, ecx, edx, ebx, esp, ebp, esi, or edi.
				return Instruction(opcode_regimm8, ModRegRm(r,rm), imm);
			}
			// REX is needed for r8d, r9d, r10d, r11d, ...
			return Instruction(REXRB(r,rm), opcode_regimm8, ModRegRm(r,rm), imm);
		}
		static constexpr Instruction encode(const core::reg32 r, const int8 imm) noexcept {
			return encode(r,r,imm);
		}
		static constexpr Instruction encode(const core::reg32 r, const MemT<4> rm, const int8 imm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, if needed.
			int index = OpcodeAndMem(i, opcode_regimm8, rm, r);
			i.bytes[index] = imm;
			i.length = index+1;
			return i;
		}
		static constexpr Instruction encode(const core::reg r, const core::reg rm, const int8 imm) noexcept {
			return Instruction(REXWRB(r,rm), opcode_regimm8, ModRegRm(r,rm), imm);
		}
		static constexpr Instruction encode(const core::reg r, const int8 imm) noexcept {
			return encode(r,r,imm);
		}
		static constexpr Instruction encode(const core::reg r, const MemT<8> rm, const int8 imm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, if needed.
			int index = OpcodeAndMem(i, opcode_regimm8, rm, r);
			i.bytes[index] = imm;
			i.length = index+1;
			return i;
		}

		static constexpr Instruction encode(const core::reg16 r, const core::reg16 rm, const int16 imm) noexcept {
			if (uint8(r) < 8 && uint8(rm) < 8) {
				// No REX needed if both ax, cx, dx, bx, sp, bp, si, or di.
				return Instruction(memory::SIZE_PREFIX, opcode_regimm, ModRegRm(r,rm), uint8(imm), uint8(imm>>8));
			}
			// REX is needed for r8w, r9w, r10w, r11w, ...
			return Instruction(memory::SIZE_PREFIX, REXRB(r,rm), opcode_regimm, ModRegRm(r,rm), uint8(imm), uint8(imm>>8));
		}
		static constexpr Instruction encode(const core::reg16 r, const int16 imm) noexcept {
			return encode(r,r,imm);
		}
		static constexpr Instruction encode(const core::reg16 r, const MemT<2> rm, const int16 imm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			i.bytes[0] = memory::SIZE_PREFIX;
			// REX is handled automatically, if needed.
			int index = OpcodeAndMem(i, opcode_regimm, rm, r, 1);
			i.bytes[index] = uint8(imm);
			i.bytes[index+1] = uint8(imm>>8);
			i.length = index+2;
			return i;
		}
		static constexpr Instruction encode(const core::reg32 r, const core::reg32 rm, const int32 imm) noexcept {
			if (uint8(r) < 8 && uint8(rm) < 8) {
				// No REX needed if both eax, ecx, edx, ebx, esp, ebp, esi, or edi.
				return Instruction(opcode_regimm, ModRegRm(r,rm), uint8(imm), uint8(imm>>8), uint8(imm>>16), uint8(imm>>24));
			}
			// REX is needed for r8d, r9d, r10d, r11d, ...
			return Instruction(REXRB(r,rm), opcode_regimm, ModRegRm(r,rm), uint8(imm), uint8(imm>>8), uint8(imm>>16), uint8(imm>>24));
		}
		static constexpr Instruction encode(const core::reg32 r, const int32 imm) noexcept {
			return encode(r,r,imm);
		}
		static constexpr Instruction encode(const core::reg32 r, const MemT<4> rm, const int32 imm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, if needed.
			int index = OpcodeAndMem(i, opcode_regimm, rm, r);
			i.bytes[index] = uint8(imm);
			i.bytes[index+1] = uint8(imm>>8);
			i.bytes[index+2] = uint8(imm>>16);
			i.bytes[index+3] = uint8(imm>>24);
			i.length = index+4;
			return i;
		}
		static constexpr Instruction encode(const core::reg r, const core::reg rm, const int32 imm) noexcept {
			return Instruction(REXWRB(r,rm), opcode_regimm, ModRegRm(r,rm), uint8(imm>>8), uint8(imm>>16), uint8(imm>>24));
		}
		static constexpr Instruction encode(const core::reg r, const int32 imm) noexcept {
			return encode(r,r,imm);
		}
		static constexpr Instruction encode(const core::reg r, const MemT<8> rm, const int32 imm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, if needed.
			int index = OpcodeAndMem(i, opcode_regimm, rm, r);
			i.bytes[index] = uint8(imm);
			i.bytes[index+1] = uint8(imm>>8);
			i.bytes[index+2] = uint8(imm>>16);
			i.bytes[index+3] = uint8(imm>>24);
			i.length = index+4;
			return i;
		}
	};

	template<uint8 opcode_base>
	struct memreg_encoder {
		static constexpr Instruction encode(const core::reg8 rm, const core::reg8 r) noexcept {
			if (uint8(r) < 4 && uint8(rm)<4) {
				// No REX needed if al, cl, dl, or bl.
				return Instruction(0x0F, opcode_base, ModRegRm(r,rm));
			}
			// REX is needed for spl, bpl, sil, dil,
			// r8b, r9b, r10b, r11b, ...
			return Instruction(REXRB(r,rm), 0x0F, opcode_base, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const core::reg8_32 rm, const core::reg8_32 r) noexcept {
			// No REX in this case (al, cl, dl, or bl, ah, ch, dh, or bh).
			return Instruction(0x0F, opcode_base, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const MemT<1> rm, const core::reg8 r) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			if (uint8(r) < 4 || uint8(r) >= 8 || rm.hasrex) {
				// No REX needed if al, cl, dl, or bl and !rm.hasrex,
				// and if rm.hasrex or r8b+, it handles the REX byte automatically.
				i.length = OpcodeAndMem(i, 0x0F, opcode_base, rm, r);
				return i;
			}
			// REX is needed for spl, bpl, sil, or dil, which wouldn't
			// be added automatically.
			i.bytes[0] = REXR(r);
			i.length = OpcodeAndMem(i, 0x0F, opcode_base, rm, r, 1);
			return i;
		}
		static constexpr Instruction encode(const MemT<1> rm, const core::reg8_32 r) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			if (uint8(r) >= 4 && rm.hasrex) {
				return error_reg8_32_registers_cant_be_used_with_memory_operand_with_rex();
			}
			Instruction i = EMPTY_INSTRUCTION;
			// No REX in this case (al, cl, dl, or bl, ah, ch, dh, or bh).
			// REX from memory operand allowed if al, cl, dl, or bl.
			i.length = OpcodeAndMem(i, 0x0F, opcode_base, rm, r);
			return i;
		}
		static constexpr Instruction encode(const core::reg16 rm, const core::reg16 r) noexcept {
			if (uint8(r) < 8 && uint8(rm) < 8) {
				// No REX needed if both ax, cx, dx, bx, sp, bp, si, or di.
				return Instruction(memory::SIZE_PREFIX, 0x0F, opcode_base | 1, ModRegRm(r,rm));
			}
			// REX is needed for r8w, r9w, r10w, r11w, ...
			return Instruction(memory::SIZE_PREFIX, REXRB(r,rm), 0x0F, opcode_base | 1, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const MemT<2> rm, const core::reg16 r) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			i.bytes[0] = memory::SIZE_PREFIX;
			// REX is handled automatically, if needed.
			i.length = OpcodeAndMem(i, 0x0F, opcode_base | 1, rm, r, 1);
			return i;
		}
		static constexpr Instruction encode(const core::reg32 rm, const core::reg32 r) noexcept {
			if (uint8(r) < 8 && uint8(rm) < 8) {
				// No REX needed if both eax, ecx, edx, ebx, esp, ebp, esi, or edi.
				return Instruction(0x0F, opcode_base | 1, ModRegRm(r,rm));
			}
			// REX is needed for r8d, r9d, r10d, r11d, ...
			return Instruction(REXRB(r,rm), 0x0F, opcode_base | 1, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const MemT<4> rm, const core::reg32 r) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, if needed.
			i.length = OpcodeAndMem(i, 0x0F, opcode_base | 1, rm, r);
			return i;
		}
		static constexpr Instruction encode(const core::reg rm, const core::reg r) noexcept {
			return Instruction(REXWRB(r,rm), 0x0F, opcode_base | 1, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const MemT<8> rm, const core::reg r) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, including W from rm.
			i.length = OpcodeAndMem(i, 0x0F, opcode_base | 1, rm, r);
			return i;
		}
	};

	template<bool reverse>
	struct bscan_encoder {
		static constexpr uint8 opcode0 = 0x0F;
		static constexpr uint8 opcode1 = 0xBC + uint8(reverse);

		static constexpr Instruction encode(const core::reg16 r, const core::reg16 rm) noexcept {
			if (uint8(r) < 8 && uint8(rm) < 8) {
				// No REX needed if both ax, cx, dx, bx, sp, bp, si, or di.
				return Instruction(memory::SIZE_PREFIX, opcode0, opcode1, ModRegRm(r,rm));
			}
			// REX is needed for r8w, r9w, r10w, r11w, ...
			return Instruction(memory::SIZE_PREFIX, REXRB(r,rm), opcode0, opcode1, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const core::reg16 r, const MemT<2> rm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			i.bytes[0] = memory::SIZE_PREFIX;
			// REX is handled automatically, if needed.
			i.length = OpcodeAndMem(i, opcode0, opcode1, rm, r, 1);
			return i;
		}
		static constexpr Instruction encode(const core::reg32 r, const core::reg32 rm) noexcept {
			if (uint8(r) < 8 && uint8(rm) < 8) {
				// No REX needed if both eax, ecx, edx, ebx, esp, ebp, esi, or edi.
				return Instruction(opcode0, opcode1, ModRegRm(r,rm));
			}
			// REX is needed for r8d, r9d, r10d, r11d, ...
			return Instruction(REXRB(r,rm), opcode0, opcode1, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const core::reg32 r, const MemT<4> rm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, if needed.
			i.length = OpcodeAndMem(i, opcode0, opcode1, rm, r);
			return i;
		}
		static constexpr Instruction encode(const core::reg r, const core::reg rm) noexcept {
			return Instruction(REXWRB(r,rm), opcode0, opcode1, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const core::reg r, const MemT<8> rm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, including W from rm.
			i.length = OpcodeAndMem(i, opcode0, opcode1, rm, r);
			return i;
		}
	};

	struct bswap_encoder {
		static constexpr uint8 opcode0 = 0x0F;
		static constexpr uint8 opcode1_base = 0xC8;

		static constexpr Instruction encode(const core::reg32 r) noexcept {
			if (uint8(r) < 8) {
				// No REX needed if both eax, ecx, edx, ebx, esp, ebp, esi, or edi.
				return Instruction(opcode0, opcode1_base | uint8(r));
			}
			return Instruction(REXB(r), opcode0, opcode1_base | (uint8(r)&0b111));
		}
		static constexpr Instruction encode(const core::reg r) noexcept {
			return Instruction(REXWB(r), opcode0, opcode1_base | (uint8(r)&0b111));
		}
	};

	template<uint8 num>
	struct btest_encoder {
		static constexpr uint8 opcode0 = 0x0F;
		static constexpr uint8 opcode1_reg = 0xA3 | (num<<3);
		static constexpr uint8 opcode1_imm = 0xBA;
		static constexpr uint8 opcode1_imm_reg = 4 | num;

		static constexpr Instruction encode(const core::reg16 rm, const core::reg16 r) noexcept {
			if (uint8(r) < 8 && uint8(rm) < 8) {
				// No REX needed if both ax, cx, dx, bx, sp, bp, si, or di.
				return Instruction(memory::SIZE_PREFIX, opcode0, opcode1_reg, ModRegRm(r,rm));
			}
			// REX is needed for r8w, r9w, r10w, r11w, ...
			return Instruction(memory::SIZE_PREFIX, REXRB(r,rm), opcode0, opcode1_reg, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const MemT<2> rm, const core::reg16 r) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			i.bytes[0] = memory::SIZE_PREFIX;
			// REX is handled automatically, if needed.
			i.length = OpcodeAndMem(i, opcode0, opcode1_reg, rm, r, 1);
			return i;
		}
		static constexpr Instruction encode(const core::reg32 rm, const core::reg32 r) noexcept {
			if (uint8(r) < 8 && uint8(rm) < 8) {
				// No REX needed if both eax, ecx, edx, ebx, esp, ebp, esi, or edi.
				return Instruction(opcode0, opcode1_reg, ModRegRm(r,rm));
			}
			// REX is needed for r8d, r9d, r10d, r11d, ...
			return Instruction(REXRB(r,rm), opcode0, opcode1_reg, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const MemT<4> rm, const core::reg32 r) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, if needed.
			i.length = OpcodeAndMem(i, opcode0, opcode1_reg, rm, r);
			return i;
		}
		static constexpr Instruction encode(const core::reg rm, const core::reg r) noexcept {
			return Instruction(REXWRB(r,rm), opcode0, opcode1_reg, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const MemT<8> rm, const core::reg r) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, including W from rm.
			i.length = OpcodeAndMem(i, opcode0, opcode1_reg, rm, r);
			return i;
		}
		static constexpr Instruction encode(const core::reg16 rm, const uint8 imm) noexcept {
			if (uint8(rm) < 8) {
				// No REX needed if ax, cx, dx, bx, sp, bp, si, or di.
				return Instruction(memory::SIZE_PREFIX, opcode0, opcode1_imm, ModRegRm(opcode1_imm_reg,rm), imm);
			}
			// REX is needed for r8w, r9w, r10w, r11w, ...
			return Instruction(memory::SIZE_PREFIX, REXB(rm), opcode0, opcode1_imm, ModRegRm(opcode1_imm_reg,rm), imm);
		}
		static constexpr Instruction encode(const MemT<2> rm, const uint8 imm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			i.bytes[0] = memory::SIZE_PREFIX;
			// REX is handled automatically, if needed.
			int index = OpcodeAndMem(i, opcode0, opcode1_imm, rm, opcode1_imm_reg, 1);
			i.bytes[index] = imm;
			i.length = index+1;
			return i;
		}
		static constexpr Instruction encode(const core::reg32 rm, const uint8 imm) noexcept {
			if (uint8(rm) < 8) {
				// No REX needed if both eax, ecx, edx, ebx, esp, ebp, esi, or edi.
				return Instruction(opcode0, opcode1_imm, ModRegRm(opcode1_imm_reg,rm), imm);
			}
			// REX is needed for r8d, r9d, r10d, r11d, ...
			return Instruction(REXB(rm), opcode0, opcode1_imm, ModRegRm(opcode1_imm_reg,rm), imm);
		}
		static constexpr Instruction encode(const MemT<4> rm, const uint8 imm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, if needed.
			int index = OpcodeAndMem(i, opcode0, opcode1_imm, rm, opcode1_imm_reg);
			i.bytes[index] = imm;
			i.length = index+1;
			return i;
		}
		static constexpr Instruction encode(const core::reg rm, const uint8 imm) noexcept {
			return Instruction(REXWB(rm), opcode0, opcode1_imm, ModRegRm(opcode1_imm_reg,rm), imm);
		}
		static constexpr Instruction encode(const MemT<8> rm, const uint8 imm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, including W from rm.
			int index = OpcodeAndMem(i, opcode0, opcode1_imm, rm, opcode1_imm_reg);
			i.bytes[index] = imm;
			i.length = index+1;
			return i;
		}
	};

	struct cmpxchg8b_encoder {
		static constexpr Instruction encode(MemT<8> m) noexcept {
			if (m.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}

			if (m.hasrex) {
				// Remove W bit, since W being 1 indicates cmpxchg16b.
				m.rex &= ~0b1000;
				if (!(m.rex & 0b0111)) {
					m.hasrex = false;
				}
			}

			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, if needed.
			i.length = OpcodeAndMem(i, 0x0F, 0xC7, m, 1);
			return i;
		}
	};
	struct cmpxchg16b_encoder {
		static constexpr Instruction encode(MemT<16> m) noexcept {
			if (m.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}

			// Must have REX with W bit set to 1.
			m.hasrex = true;
			m.rex |= 0x48;

			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, including W from m.
			i.length = OpcodeAndMem(i, 0x0F, 0xC7, m, 1);
			return i;
		}
	};

	template<uint8 num>
	struct shift_encoder {
		static constexpr uint8 opcode_1 = 0xD0;
		static constexpr uint8 opcode_cl = 0xD2;
		static constexpr uint8 opcode_imm = 0xC0;

		private:
		/// NOTE: This is intentionally *not* constexpr, to produce a compile
		///       error if hit at compile time.
		static Instruction error_shift_bit_count_must_be_less_than_register_size() noexcept {
			return Instruction::createError("The shift count for bit shift instructions must be strictly less than the number of bits in the register.");
		}
		/// NOTE: This is intentionally *not* constexpr, to produce a compile
		///       error if hit at compile time.
		static Instruction error_shift_bit_count_register_must_be_cl() noexcept {
			return Instruction::createError("The only register that can be used for a bit shift count is cl.");
		}
		public:

		static constexpr Instruction encode(const core::reg8 rm, const uint8 imm) noexcept {
			if (uint8(rm) < 4) {
				// No REX needed if al, cl, dl, or bl.
				if (imm == 1) {
					return Instruction(opcode_1, ModRegRm(num,rm));
				}
				if (imm < 8) {
					return Instruction(opcode_imm, ModRegRm(num,rm), imm);
				}
				return error_shift_bit_count_must_be_less_than_register_size();
			}
			// REX is needed for spl, bpl, sil, dil,
			// r8b, r9b, r10b, r11b, ...
			if (imm == 1) {
				return Instruction(REXB(rm), opcode_1, ModRegRm(num,rm));
			}
			if (imm < 8) {
				return Instruction(REXB(rm), opcode_imm, ModRegRm(num,rm), imm);
			}
			return error_shift_bit_count_must_be_less_than_register_size();
		}
		static constexpr Instruction encode(const core::reg8 rm, const core::reg8 r) noexcept {
			if (r != core::reg8::cl) {
				return error_shift_bit_count_register_must_be_cl();
			}
			if (uint8(rm) < 4) {
				// No REX needed if al, cl, dl, or bl.
				return Instruction(opcode_cl, ModRegRm(num,rm));
			}
			// REX is needed for spl, bpl, sil, dil,
			// r8b, r9b, r10b, r11b, ...
			return Instruction(REXB(rm), opcode_cl, ModRegRm(num,rm));
		}
		static constexpr Instruction encode(const core::reg8_32 rm, const uint8 imm) noexcept {
			// No REX in this case (al, cl, dl, or bl, ah, ch, dh, or bh).
			if (imm == 1) {
				return Instruction(opcode_1, ModRegRm(num,rm));
			}
			if (imm < 8) {
				return Instruction(opcode_imm, ModRegRm(num,rm), imm);
			}
			return error_shift_bit_count_must_be_less_than_register_size();
		}
		static constexpr Instruction encode(const core::reg8_32 rm, const core::reg8_32 r) noexcept {
			if (r != core::reg8_32::cl) {
				return error_shift_bit_count_register_must_be_cl();
			}
			// No REX in this case (al, cl, dl, or bl, ah, ch, dh, or bh).
			return Instruction(opcode_cl, ModRegRm(num,rm));
		}
		static constexpr Instruction encode(const MemT<1> rm, const uint8 imm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, if needed.
			int index;
			if (imm == 1) {
				index = OpcodeAndMem(i, opcode_1, rm, num);
			}
			else if (imm < 8) {
				index = OpcodeAndMem(i, opcode_imm, rm, num);
			}
			else {
				return error_shift_bit_count_must_be_less_than_register_size();
			}
			i.bytes[index] = imm;
			i.length = index+1;
			return i;
		}
		static constexpr Instruction encode(const MemT<1> rm, const core::reg8 r) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			if (r != core::reg8::cl) {
				return error_shift_bit_count_register_must_be_cl();
			}
			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, if needed.
			i.length = OpcodeAndMem(i, opcode_cl, rm, num);
			return i;
		}
		static constexpr Instruction encode(const MemT<1> rm, const core::reg8_32 r) noexcept {
			if (r != core::reg8_32::cl) {
				return error_shift_bit_count_register_must_be_cl();
			}
			// Just delegate to the other one.
			return encode(rm, core::reg8::cl);
		}
		static constexpr Instruction encode(const core::reg16 rm, const uint8 imm) noexcept {
			if (uint8(rm) < 8) {
				// No REX needed if ax, cx, dx, bx, sp, bp, si, or di.
				if (imm == 1) {
					return Instruction(memory::SIZE_PREFIX, opcode_1|1, ModRegRm(num,rm));
				}
				if (imm < 16) {
					return Instruction(memory::SIZE_PREFIX, opcode_imm|1, ModRegRm(num,rm), imm);
				}
				return error_shift_bit_count_must_be_less_than_register_size();
			}
			// REX is needed for r8w, r9w, r10w, r11w, ...
			if (imm == 1) {
				return Instruction(memory::SIZE_PREFIX, REXB(rm), opcode_1|1, ModRegRm(num,rm));
			}
			if (imm < 16) {
				return Instruction(memory::SIZE_PREFIX, REXB(rm), opcode_imm|1, ModRegRm(num,rm), imm);
			}
			return error_shift_bit_count_must_be_less_than_register_size();
		}
		static constexpr Instruction encode(const core::reg16 rm, const core::reg8 r) noexcept {
			if (r != core::reg8::cl) {
				return error_shift_bit_count_register_must_be_cl();
			}
			if (uint8(rm) < 8) {
				// No REX needed if ax, cx, dx, bx, sp, bp, si, or di.
				return Instruction(memory::SIZE_PREFIX, opcode_cl|1, ModRegRm(num,rm));
			}
			// REX is needed for r8w, r9w, r10w, r11w, ...
			return Instruction(memory::SIZE_PREFIX, REXB(rm), opcode_cl|1, ModRegRm(num,rm));
		}
		static constexpr Instruction encode(const core::reg16 rm, const core::reg8_32 r) noexcept {
			if (r != core::reg8_32::cl) {
				return error_shift_bit_count_register_must_be_cl();
			}
			// Just delegate to the other one.
			return encode(rm, core::reg8::cl);
		}
		static constexpr Instruction encode(const MemT<2> rm, const uint8 imm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			i.bytes[0] = memory::SIZE_PREFIX;
			// REX is handled automatically, if needed.
			int index;
			if (imm == 1) {
				index = OpcodeAndMem(i, opcode_1|1, rm, num, 1);
			}
			else if (imm < 16) {
				index = OpcodeAndMem(i, opcode_imm|1, rm, num, 1);
			}
			else {
				return error_shift_bit_count_must_be_less_than_register_size();
			}
			i.bytes[index] = imm;
			i.length = index+1;
			return i;
		}
		static constexpr Instruction encode(const MemT<2> rm, const core::reg8 r) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			if (r != core::reg8::cl) {
				return error_shift_bit_count_register_must_be_cl();
			}
			Instruction i = EMPTY_INSTRUCTION;
			i.bytes[0] = memory::SIZE_PREFIX;
			// REX is handled automatically, if needed.
			i.length = OpcodeAndMem(i, opcode_cl|1, rm, num, 1);
			return i;
		}
		static constexpr Instruction encode(const MemT<2> rm, const core::reg8_32 r) noexcept {
			if (r != core::reg8_32::cl) {
				return error_shift_bit_count_register_must_be_cl();
			}
			// Just delegate to the other one.
			return encode(rm, core::reg8::cl);
		}
		static constexpr Instruction encode(const core::reg32 rm, const uint8 imm) noexcept {
			if (uint8(rm) < 8) {
				// No REX needed if eax, ecx, edx, ebx, esp, ebp, esi, or edi.
				if (imm == 1) {
					return Instruction(opcode_1|1, ModRegRm(num,rm));
				}
				if (imm < 32) {
					return Instruction(opcode_imm|1, ModRegRm(num,rm), imm);
				}
				return error_shift_bit_count_must_be_less_than_register_size();
			}
			// REX is needed for r8d, r9d, r10d, r11d, ...
			if (imm == 1) {
				return Instruction(REXB(rm), opcode_1|1, ModRegRm(num,rm));
			}
			if (imm < 32) {
				return Instruction(REXB(rm), opcode_imm|1, ModRegRm(num,rm), imm);
			}
			return error_shift_bit_count_must_be_less_than_register_size();
		}
		static constexpr Instruction encode(const core::reg32 rm, const core::reg8 r) noexcept {
			if (r != core::reg8::cl) {
				return error_shift_bit_count_register_must_be_cl();
			}
			if (uint8(rm) < 8) {
				// No REX needed if eax, ecx, edx, ebx, esp, ebp, esi, or edi.
				return Instruction(opcode_cl|1, ModRegRm(num,rm));
			}
			// REX is needed for r8d, r9d, r10d, r11d, ...
			return Instruction(REXB(rm), opcode_cl|1, ModRegRm(num,rm));
		}
		static constexpr Instruction encode(const core::reg32 rm, const core::reg8_32 r) noexcept {
			if (r != core::reg8_32::cl) {
				return error_shift_bit_count_register_must_be_cl();
			}
			// Just delegate to the other one.
			return encode(rm, core::reg8::cl);
		}
		static constexpr Instruction encode(const MemT<4> rm, const uint8 imm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, if needed.
			int index;
			if (imm == 1) {
				index = OpcodeAndMem(i, opcode_1|1, rm, num);
			}
			else if (imm < 32) {
				index = OpcodeAndMem(i, opcode_imm|1, rm, num);
			}
			else {
				return error_shift_bit_count_must_be_less_than_register_size();
			}
			i.bytes[index] = imm;
			i.length = index+1;
			return i;
		}
		static constexpr Instruction encode(const MemT<4> rm, const core::reg8 r) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			if (r != core::reg8::cl) {
				return error_shift_bit_count_register_must_be_cl();
			}
			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, if needed.
			i.length = OpcodeAndMem(i, opcode_cl|1, rm, num);
			return i;
		}
		static constexpr Instruction encode(const MemT<4> rm, const core::reg8_32 r) noexcept {
			if (r != core::reg8_32::cl) {
				return error_shift_bit_count_register_must_be_cl();
			}
			// Just delegate to the other one.
			return encode(rm, core::reg8::cl);
		}
		static constexpr Instruction encode(const core::reg rm, const uint8 imm) noexcept {
			if (imm == 1) {
				return Instruction(REXWB(rm), opcode_1|1, ModRegRm(num,rm));
			}
			if (imm < 64) {
				return Instruction(REXWB(rm), opcode_imm|1, ModRegRm(num,rm), imm);
			}
			return error_shift_bit_count_must_be_less_than_register_size();
		}
		static constexpr Instruction encode(const core::reg rm, const core::reg8 r) noexcept {
			if (r != core::reg8::cl) {
				return error_shift_bit_count_register_must_be_cl();
			}
			return Instruction(REXWB(rm), opcode_cl|1, ModRegRm(num,rm));
		}
		static constexpr Instruction encode(const MemT<8> rm, const uint8 imm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, including W from rm.
			int index;
			if (imm == 1) {
				index = OpcodeAndMem(i, opcode_1|1, rm, num);
			}
			else if (imm < 64) {
				index = OpcodeAndMem(i, opcode_imm|1, rm, num);
			}
			else {
				return error_shift_bit_count_must_be_less_than_register_size();
			}
			i.bytes[index] = imm;
			i.length = index+1;
			return i;
		}
		static constexpr Instruction encode(const MemT<8> rm, const core::reg8 r) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			if (r != core::reg8::cl) {
				return error_shift_bit_count_register_must_be_cl();
			}
			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, including W from rm.
			i.length = OpcodeAndMem(i, opcode_cl|1, rm, num);
			return i;
		}
	};

	template<uint8 opcode1_imm>
	struct shiftd_encoder {
		static constexpr uint8 opcode0 = 0x0F;
		static constexpr uint8 opcode1_cl = opcode1_imm+1;

		private:
		/// NOTE: This is intentionally *not* constexpr, to produce a compile
		///       error if hit at compile time.
		static Instruction error_shift_bit_count_must_be_less_than_register_size() noexcept {
			return Instruction::createError("The shift count for double register bit shift instructions must be strictly less than the number of bits in a single register.");
		}
		/// NOTE: This is intentionally *not* constexpr, to produce a compile
		///       error if hit at compile time.
		static Instruction error_shift_bit_count_register_must_be_cl() noexcept {
			return Instruction::createError("The only register that can be used for a bit shift count is cl.");
		}
		public:

		static constexpr Instruction encode(const core::reg16 rm, const core::reg16 r, const uint8 imm) noexcept {
			if (imm >= 16) {
				return error_shift_bit_count_must_be_less_than_register_size();
			}
			if (uint8(rm) < 8 && uint8(r) < 8) {
				return Instruction(memory::SIZE_PREFIX, opcode0, opcode1_imm, ModRegRm(r,rm), imm);
			}
			return Instruction(memory::SIZE_PREFIX, REXRB(r,rm), opcode0, opcode1_imm, ModRegRm(r,rm), imm);
		}
		static constexpr Instruction encode(const MemT<2> rm, const core::reg16 r, const uint8 imm) noexcept {
			if (imm >= 16) {
				return error_shift_bit_count_must_be_less_than_register_size();
			}
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			i.bytes[0] = memory::SIZE_PREFIX;
			// REX is handled automatically, if needed.
			int index = OpcodeAndMem(i, opcode0, opcode1_imm, rm, r, 1);
			i.bytes[index] = imm;
			i.length = index+1;
			return i;
		}
		static constexpr Instruction encode(const core::reg16 rm, const core::reg16 r, const core::reg8 s) noexcept {
			if (s != core::reg8::cl) {
				return error_shift_bit_count_register_must_be_cl();
			}
			if (uint8(rm) < 8 && uint8(r) < 8) {
				return Instruction(memory::SIZE_PREFIX, opcode0, opcode1_cl, ModRegRm(r,rm));
			}
			return Instruction(memory::SIZE_PREFIX, REXRB(r,rm), opcode0, opcode1_cl, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const MemT<2> rm, const core::reg16 r, const core::reg8 s) noexcept {
			if (s != core::reg8::cl) {
				return error_shift_bit_count_register_must_be_cl();
			}
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			i.bytes[0] = memory::SIZE_PREFIX;
			// REX is handled automatically, if needed.
			i.length = OpcodeAndMem(i, opcode0, opcode1_cl, rm, r, 1);
			return i;
		}
		static constexpr Instruction encode(const core::reg32 rm, const core::reg32 r, const uint8 imm) noexcept {
			if (imm >= 32) {
				return error_shift_bit_count_must_be_less_than_register_size();
			}
			if (uint8(rm) < 8 && uint8(r) < 8) {
				return Instruction(opcode0, opcode1_imm, ModRegRm(r,rm), imm);
			}
			return Instruction(REXRB(r,rm), opcode0, opcode1_imm, ModRegRm(r,rm), imm);
		}
		static constexpr Instruction encode(const MemT<4> rm, const core::reg32 r, const uint8 imm) noexcept {
			if (imm >= 32) {
				return error_shift_bit_count_must_be_less_than_register_size();
			}
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, if needed.
			int index = OpcodeAndMem(i, opcode0, opcode1_imm, rm, r);
			i.bytes[index] = imm;
			i.length = index+1;
			return i;
		}
		static constexpr Instruction encode(const core::reg32 rm, const core::reg32 r, const core::reg8 s) noexcept {
			if (s != core::reg8::cl) {
				return error_shift_bit_count_register_must_be_cl();
			}
			if (uint8(rm) < 8 && uint8(r) < 8) {
				return Instruction(opcode0, opcode1_cl, ModRegRm(r,rm));
			}
			return Instruction(REXRB(r,rm), opcode0, opcode1_cl, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const MemT<4> rm, const core::reg32 r, const core::reg8 s) noexcept {
			if (s != core::reg8::cl) {
				return error_shift_bit_count_register_must_be_cl();
			}
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, if needed.
			i.length = OpcodeAndMem(i, opcode0, opcode1_cl, rm, r);
			return i;
		}
		static constexpr Instruction encode(const core::reg rm, const core::reg r, const uint8 imm) noexcept {
			if (imm >= 64) {
				return error_shift_bit_count_must_be_less_than_register_size();
			}
			return Instruction(REXWRB(r,rm), opcode0, opcode1_imm, ModRegRm(r,rm), imm);
		}
		static constexpr Instruction encode(const MemT<8> rm, const core::reg r, const uint8 imm) noexcept {
			if (imm >= 64) {
				return error_shift_bit_count_must_be_less_than_register_size();
			}
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, including W from rm.
			int index = OpcodeAndMem(i, opcode0, opcode1_imm, rm, r);
			i.bytes[index] = imm;
			i.length = index+1;
			return i;
		}
		static constexpr Instruction encode(const core::reg rm, const core::reg r, const core::reg8 s) noexcept {
			if (s != core::reg8::cl) {
				return error_shift_bit_count_register_must_be_cl();
			}
			return Instruction(REXWRB(r,rm), opcode0, opcode1_cl, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const MemT<8> rm, const core::reg r, const core::reg8 s) noexcept {
			if (s != core::reg8::cl) {
				return error_shift_bit_count_register_must_be_cl();
			}
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, including W from rm.
			i.length = OpcodeAndMem(i, opcode0, opcode1_cl, rm, r);
			return i;
		}
	};

	template<uint8 opcode>
	struct none_encoder {
		static constexpr Instruction encode() noexcept {
			return Instruction(opcode);
		}
	};
	template<uint8 opcode0,uint8 opcode1>
	struct none_encoder2 {
		static constexpr Instruction encode() noexcept {
			return Instruction(opcode0, opcode1);
		}
	};
	template<uint8 opcode0,uint8 opcode1,uint8 opcode2>
	struct none_encoder3 {
		static constexpr Instruction encode() noexcept {
			return Instruction(opcode0, opcode1, opcode2);
		}
	};

	struct call_encoder {
		static constexpr uint8 opcode_direct = 0xE8;
		static constexpr uint8 opcode_indirect = 0xFF;
		static constexpr uint8 opcode_indirect_reg = 2;

		static constexpr Instruction encode(const void *const function_address) noexcept {
			return Instruction::createCallToAddress(function_address, opcode_direct);
		}
		static constexpr Instruction encode(const char *const target_label) noexcept {
			return Instruction::createCallToLabel(target_label, opcode_direct);
		}
		static constexpr Instruction encode(const core::reg rm) noexcept {
			// No REX W bit, since always 64-bit.
			if (uint8(rm) < 8) {
				return Instruction(opcode_indirect, ModRegRm(opcode_indirect_reg,rm));
			}
			return Instruction(REXB(rm), opcode_indirect, ModRegRm(opcode_indirect_reg,rm));
		}
		static constexpr Instruction encode(MemT<8> rm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}

			if (rm.hasrex) {
				// Remove W bit, since always 64-bit.
				rm.rex &= ~0b1000;
				if (!(rm.rex & 0b0111)) {
					rm.hasrex = false;
				}
			}

			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, if needed.
			i.length = OpcodeAndMem(i, opcode_indirect, rm, opcode_indirect_reg);
			return i;
		}
	};

	template<uint8 main_opcode>
	struct ret_encoder {
		static constexpr Instruction encode() noexcept {
			return Instruction(main_opcode);
		}
		static constexpr Instruction encode(uint16 bytes_to_pop) noexcept {
			return Instruction(main_opcode-1, uint8(bytes_to_pop), uint8(bytes_to_pop>>8));
		}
	};

	struct jmp_encoder {
		static constexpr uint8 opcode_indirect = 0xFF;
		static constexpr uint8 opcode_indirect_reg = 4;

		static constexpr Instruction encode(const char*const target_label) noexcept {
			return Instruction::createJump(target_label, 0xEB, 0xE9);
		}
		static constexpr Instruction encode(const core::reg rm) noexcept {
			if (uint8(rm) & 0b1000) {
				return Instruction(opcode_indirect, ModRegRm(opcode_indirect_reg,rm));
			}
			return Instruction(REXB(rm), opcode_indirect, ModRegRm(opcode_indirect_reg,rm));
		}
		static constexpr Instruction encode(MemT<8> rm) noexcept {
			// REX byte is optional in this case, and doesn't need W set.
			if (rm.rex == 0x48) {
				rm.hasrex = false;
			}
			// Clear W bit
			rm.rex &= ~0b1000;

			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, from rm.
			i.length = OpcodeAndMem(i, opcode_indirect, rm, opcode_indirect_reg);
			return i;
		}
	};

	enum class flags_condition : uint8 {
		overflow = 0,   // NOTE: This has to be lowercase because of a define in the Visual C++ headers.
		no_overflow = 1,
		carry = 2,
		below = 2,
		not_above_or_equal = 2,
		no_carry = 3,
		above_or_equal = 3,
		not_below = 3,
		zero = 4,
		equal = 4,
		not_zero = 5,
		not_equal = 5,
		below_or_equal = 6,
		not_above = 6,
		above = 7,
		not_below_or_equal = 7,
		sign = 8,
		no_sign = 9,
		parity = 10,
		parity_even = 10,
		no_parity = 11,
		parity_odd = 11,
		less = 12,
		not_greater_or_equal = 12,
		greater_or_equal = 13,
		not_less = 13,
		less_or_equal = 14,
		not_greater = 14,
		greater = 15,
		not_less_or_equal = 15
	};

	template<flags_condition num>
	struct jcc_encoder {
		static constexpr uint8 short_opcode = 0x70+uint8(num);
		static constexpr uint8 near_opcode = 0x80+uint8(num);

		static constexpr Instruction encode(const char*const target_label) noexcept {
			return Instruction::createJump(target_label, short_opcode, 0x0F, near_opcode);
		}
		static constexpr Instruction encodeLikely(const char*const target_label) noexcept {
			return Instruction::createJump(target_label, short_opcode, 0x0F, near_opcode, 0x3E);
		}
		static constexpr Instruction encodeUnlikely(const char*const target_label) noexcept {
			return Instruction::createJump(target_label, short_opcode, 0x0F, near_opcode, 0x2E);
		}
	};

	struct jrcxz_encoder {
		static constexpr uint8 opcode = 0xE3;

		static constexpr Instruction encode(const char*const target_label) noexcept {
			// NOTE: JRCXZ only support short jumps.
			return Instruction(Instruction::jump_short_init_tag(),target_label, opcode);
		}
		static constexpr Instruction encodeLikely(const char*const target_label) noexcept {
			// NOTE: JRCXZ only support short jumps.
			return Instruction(Instruction::jump_short_init_tag(),target_label, opcode, 0x3E);
		}
		static constexpr Instruction encodeUnlikely(const char*const target_label) noexcept {
			// NOTE: JRCXZ only support short jumps.
			return Instruction(Instruction::jump_short_init_tag(),target_label, opcode, 0x2E);
		}
	};

	template<flags_condition num>
	struct setcc_encoder {
		static constexpr uint8 opcode0 = 0x0F;
		static constexpr uint8 opcode1 = 0x90+uint8(num);

		static constexpr Instruction encode(const core::reg8 r) noexcept {
			if (uint8(r) < 4) {
				// No REX needed if al, cl, dl, or bl.
				return Instruction(opcode0, opcode1, ModRegRm(0,r));
			}
			// REX is needed for spl, bpl, sil, dil,
			// r8b, r9b, r10b, r11b, ...
			return Instruction(REXB(r), opcode0, opcode1, ModRegRm(0,r));
		}
		static constexpr Instruction encode(const core::reg8_32 r) noexcept {
			return Instruction(opcode0, opcode1, ModRegRm(0,r));
		}
		static constexpr Instruction encode(const MemT<1> m) noexcept {
			if (m.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}
			Instruction i = EMPTY_INSTRUCTION;
			i.length = OpcodeAndMem(i, opcode0, opcode1, m, 0);
			return i;
		}
	};

	template<flags_condition num>
	struct cmovcc_encoder {
		static constexpr uint8 opcode0 = 0x0F;
		static constexpr uint8 opcode1 = 0x40+uint8(num);

		static constexpr Instruction encode(const core::reg16 r, const core::reg16 rm) noexcept {
			if (uint8(r) < 8 && uint8(rm) < 8) {
				// No REX needed if both ax, cx, dx, bx, sp, bp, si, or di.
				return Instruction(memory::SIZE_PREFIX, opcode0, opcode1, ModRegRm(r,rm));
			}
			// REX is needed for r8w, r9w, r10w, r11w, ...
			return Instruction(memory::SIZE_PREFIX, REXRB(r,rm), opcode0, opcode1, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const core::reg16 r, const MemT<2> rm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}

			Instruction i = EMPTY_INSTRUCTION;
			i.bytes[0] = memory::SIZE_PREFIX;
			// REX is handled automatically, if needed.
			i.length = OpcodeAndMem(i, opcode0, opcode1, rm, r, 1);
			return i;
		}
		static constexpr Instruction encode(const core::reg32 r, const core::reg32 rm) noexcept {
			if (uint8(r) < 8 && uint8(rm) < 8) {
				// No REX needed if both eax, ecx, edx, ebx, esp, ebp, esi, or edi.
				return Instruction(opcode0, opcode1, ModRegRm(r,rm));
			}
			// REX is needed for r8d, r9d, r10d, r11d, ...
			return Instruction(REXRB(r,rm), opcode0, opcode1, ModRegRm(r,rm));
		}
		static constexpr Instruction encode(const core::reg32 r, const MemT<4> rm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}

			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, if needed.
			i.length = OpcodeAndMem(i, opcode0, opcode1, rm, r);
			return i;
		}
		static constexpr Instruction encode(const core::reg r, const core::reg rm) noexcept {
			return Instruction(REXWRB(rm,r), opcode0, opcode1, ModRegRm(rm,r));
		}
		static constexpr Instruction encode(const core::reg r, const MemT<8> rm) noexcept {
			if (rm.hasError()) {
				return Instruction::createError("Invalid memory operand");
			}

			Instruction i = EMPTY_INSTRUCTION;
			// REX is handled automatically, including W from rm.
			i.length = OpcodeAndMem(i, opcode0, opcode1, rm, r);
			return i;
		}
	};
} // namespace encoders

template<mnemonic> struct encoder {};
template<> struct encoder<mnemonic::ADD> : public encoders::standard_encoder<0> {};
template<> struct encoder<mnemonic::OR > : public encoders::standard_encoder<1> {};
template<> struct encoder<mnemonic::ADC> : public encoders::standard_encoder<2> {};
template<> struct encoder<mnemonic::SBB> : public encoders::standard_encoder<3> {};
template<> struct encoder<mnemonic::AND> : public encoders::standard_encoder<4> {};
template<> struct encoder<mnemonic::SUB> : public encoders::standard_encoder<5> {};
template<> struct encoder<mnemonic::XOR> : public encoders::standard_encoder<6> {};
template<> struct encoder<mnemonic::CMP> : public encoders::standard_encoder<7> {};
template<> struct encoder<mnemonic::MOV> : public encoders::mov_encoder {};
template<> struct encoder<mnemonic::LEA> : public encoders::lea_encoder {};
template<> struct encoder<mnemonic::TEST> : public encoders::test_encoder {};
template<> struct encoder<mnemonic::XCHG> : public encoders::xchg_encoder {};
template<> struct encoder<mnemonic::NOT> : public encoders::standard_unary_encoder<0xF6,2> {};
template<> struct encoder<mnemonic::NEG> : public encoders::standard_unary_encoder<0xF6,3> {};
template<> struct encoder<mnemonic::MUL> : public encoders::standard_unary_encoder<0xF6,4> {};
template<> struct encoder<mnemonic::IMUL> : public encoders::imul_encoder {};
template<> struct encoder<mnemonic::DIV> : public encoders::standard_unary_encoder<0xF6,6> {};
template<> struct encoder<mnemonic::IDIV> : public encoders::standard_unary_encoder<0xF6,7> {};
template<> struct encoder<mnemonic::INC> : public encoders::standard_unary_encoder<0xFE,0> {};
template<> struct encoder<mnemonic::DEC> : public encoders::standard_unary_encoder<0xFE,1> {};
template<> struct encoder<mnemonic::BSF> : public encoders::bscan_encoder<false> {};
template<> struct encoder<mnemonic::BSR> : public encoders::bscan_encoder<true> {};
template<> struct encoder<mnemonic::BSWAP> : public encoders::bswap_encoder {};
template<> struct encoder<mnemonic::BT> : public encoders::btest_encoder<0> {};
template<> struct encoder<mnemonic::BTS> : public encoders::btest_encoder<1> {};
template<> struct encoder<mnemonic::BTR> : public encoders::btest_encoder<2> {};
template<> struct encoder<mnemonic::BTC> : public encoders::btest_encoder<3> {};
template<> struct encoder<mnemonic::CBW> : public encoders::none_encoder2<memory::SIZE_PREFIX,0x98> {};
template<> struct encoder<mnemonic::CWDE> : public encoders::none_encoder<0x98> {};
template<> struct encoder<mnemonic::CDQE> : public encoders::none_encoder2<encoders::REXW(),0x98> {};
template<> struct encoder<mnemonic::CWD> : public encoders::none_encoder2<memory::SIZE_PREFIX,0x99> {};
template<> struct encoder<mnemonic::CDQ> : public encoders::none_encoder<0x99> {};
template<> struct encoder<mnemonic::CQO> : public encoders::none_encoder2<encoders::REXW(),0x99> {};
template<> struct encoder<mnemonic::CLC> : public encoders::none_encoder<0xF8> {};
template<> struct encoder<mnemonic::CMC> : public encoders::none_encoder<0xF5> {};
template<> struct encoder<mnemonic::STC> : public encoders::none_encoder<0xF9> {};
template<> struct encoder<mnemonic::CMPXCHG> : public encoders::memreg_encoder<0xB0> {};
template<> struct encoder<mnemonic::CMPXCHG8B> : public encoders::cmpxchg8b_encoder {};
template<> struct encoder<mnemonic::CMPXCHG16B> : public encoders::cmpxchg16b_encoder {};
template<> struct encoder<mnemonic::CPUID> : public encoders::none_encoder2<0x0F,0xA2> {};
template<> struct encoder<mnemonic::JRCXZ> : public encoders::jrcxz_encoder {};
template<> struct encoder<mnemonic::MOVSB> : public encoders::none_encoder<0xA4> {};
template<> struct encoder<mnemonic::MOVSW> : public encoders::none_encoder2<memory::SIZE_PREFIX,0xA5> {};
template<> struct encoder<mnemonic::MOVSD> : public encoders::none_encoder<0xA5> {};
template<> struct encoder<mnemonic::MOVSQ> : public encoders::none_encoder2<encoders::REXW(),0xA5> {};
template<> struct encoder<mnemonic::REP_MOVSB> : public encoders::none_encoder2<0xF3,0xA4> {};
template<> struct encoder<mnemonic::REP_MOVSW> : public encoders::none_encoder3<0xF3,memory::SIZE_PREFIX,0xA5> {};
template<> struct encoder<mnemonic::REP_MOVSD> : public encoders::none_encoder2<0xF3,0xA5> {};
template<> struct encoder<mnemonic::REP_MOVSQ> : public encoders::none_encoder3<0xF3,encoders::REXW(),0xA5> {};
template<> struct encoder<mnemonic::PAUSE> : public encoders::none_encoder2<0xF3,0x90> {};
template<> struct encoder<mnemonic::POPF> : public encoders::none_encoder2<memory::SIZE_PREFIX,0x9D> {};
template<> struct encoder<mnemonic::POPFQ> : public encoders::none_encoder<0x9D> {};
template<> struct encoder<mnemonic::PUSHF> : public encoders::none_encoder2<memory::SIZE_PREFIX,0x9C> {};
template<> struct encoder<mnemonic::PUSHFQ> : public encoders::none_encoder<0x9C> {};
template<> struct encoder<mnemonic::ROL> : public encoders::shift_encoder<0> {};
template<> struct encoder<mnemonic::ROR> : public encoders::shift_encoder<1> {};
template<> struct encoder<mnemonic::RCL> : public encoders::shift_encoder<2> {};
template<> struct encoder<mnemonic::RCR> : public encoders::shift_encoder<3> {};
template<> struct encoder<mnemonic::SHL> : public encoders::shift_encoder<4> {};
template<> struct encoder<mnemonic::SHR> : public encoders::shift_encoder<5> {};
template<> struct encoder<mnemonic::SAR> : public encoders::shift_encoder<7> {};
template<> struct encoder<mnemonic::SHLD> : public encoders::shiftd_encoder<0xA4> {};
template<> struct encoder<mnemonic::SHRD> : public encoders::shiftd_encoder<0xAC> {};
template<> struct encoder<mnemonic::RDPMC> : public encoders::none_encoder2<0x0F,0x33> {};
template<> struct encoder<mnemonic::RDTSC> : public encoders::none_encoder2<0x0F,0x31> {};
template<> struct encoder<mnemonic::STOSB> : public encoders::none_encoder<0xAA> {};
template<> struct encoder<mnemonic::STOSW> : public encoders::none_encoder2<memory::SIZE_PREFIX,0xAB> {};
template<> struct encoder<mnemonic::STOSD> : public encoders::none_encoder<0xAB> {};
template<> struct encoder<mnemonic::STOSQ> : public encoders::none_encoder2<encoders::REXW(),0xAB> {};
template<> struct encoder<mnemonic::REP_STOSB> : public encoders::none_encoder2<0xF3,0xAA> {};
template<> struct encoder<mnemonic::REP_STOSW> : public encoders::none_encoder3<0xF3,memory::SIZE_PREFIX,0xAB> {};
template<> struct encoder<mnemonic::REP_STOSD> : public encoders::none_encoder2<0xF3,0xAB> {};
template<> struct encoder<mnemonic::REP_STOSQ> : public encoders::none_encoder3<0xF3,encoders::REXW(),0xAB> {};
template<> struct encoder<mnemonic::UD2> : public encoders::none_encoder2<0x0F,0x0B> {};
template<> struct encoder<mnemonic::XADD> : public encoders::memreg_encoder<0xC0> {};
template<> struct encoder<mnemonic::JMP> : public encoders::jmp_encoder {};
template<> struct encoder<mnemonic::CALL> : public encoders::call_encoder {};
template<> struct encoder<mnemonic::RET> : public encoders::ret_encoder<0xC3> {};

#define ENCODEASM_CONDITIONAL_ENCODER_SPECIALIZATION(MNEMONIC_PREFIX, MNEMONIC_PREFIX_LOWER) \
	template<> struct encoder<mnemonic::MNEMONIC_PREFIX ## O> : public encoders::MNEMONIC_PREFIX_LOWER ## cc_encoder<encoders::flags_condition::overflow> {}; \
	template<> struct encoder<mnemonic::MNEMONIC_PREFIX ## NO> : public encoders::MNEMONIC_PREFIX_LOWER ## cc_encoder<encoders::flags_condition::no_overflow> {}; \
	template<> struct encoder<mnemonic::MNEMONIC_PREFIX ## B> : public encoders::MNEMONIC_PREFIX_LOWER ## cc_encoder<encoders::flags_condition::below> {}; \
	template<> struct encoder<mnemonic::MNEMONIC_PREFIX ## AE> : public encoders::MNEMONIC_PREFIX_LOWER ## cc_encoder<encoders::flags_condition::above_or_equal> {}; \
	template<> struct encoder<mnemonic::MNEMONIC_PREFIX ## Z> : public encoders::MNEMONIC_PREFIX_LOWER ## cc_encoder<encoders::flags_condition::zero> {}; \
	template<> struct encoder<mnemonic::MNEMONIC_PREFIX ## NZ> : public encoders::MNEMONIC_PREFIX_LOWER ## cc_encoder<encoders::flags_condition::not_zero> {}; \
	template<> struct encoder<mnemonic::MNEMONIC_PREFIX ## BE> : public encoders::MNEMONIC_PREFIX_LOWER ## cc_encoder<encoders::flags_condition::below_or_equal> {}; \
	template<> struct encoder<mnemonic::MNEMONIC_PREFIX ## A> : public encoders::MNEMONIC_PREFIX_LOWER ## cc_encoder<encoders::flags_condition::above> {}; \
	template<> struct encoder<mnemonic::MNEMONIC_PREFIX ## S> : public encoders::MNEMONIC_PREFIX_LOWER ## cc_encoder<encoders::flags_condition::sign> {}; \
	template<> struct encoder<mnemonic::MNEMONIC_PREFIX ## NS> : public encoders::MNEMONIC_PREFIX_LOWER ## cc_encoder<encoders::flags_condition::no_sign> {}; \
	template<> struct encoder<mnemonic::MNEMONIC_PREFIX ## P> : public encoders::MNEMONIC_PREFIX_LOWER ## cc_encoder<encoders::flags_condition::parity> {}; \
	template<> struct encoder<mnemonic::MNEMONIC_PREFIX ## NP> : public encoders::MNEMONIC_PREFIX_LOWER ## cc_encoder<encoders::flags_condition::no_parity> {}; \
	template<> struct encoder<mnemonic::MNEMONIC_PREFIX ## L> : public encoders::MNEMONIC_PREFIX_LOWER ## cc_encoder<encoders::flags_condition::less> {}; \
	template<> struct encoder<mnemonic::MNEMONIC_PREFIX ## GE> : public encoders::MNEMONIC_PREFIX_LOWER ## cc_encoder<encoders::flags_condition::greater_or_equal> {}; \
	template<> struct encoder<mnemonic::MNEMONIC_PREFIX ## LE> : public encoders::MNEMONIC_PREFIX_LOWER ## cc_encoder<encoders::flags_condition::less_or_equal> {}; \
	template<> struct encoder<mnemonic::MNEMONIC_PREFIX ## G> : public encoders::MNEMONIC_PREFIX_LOWER ## cc_encoder<encoders::flags_condition::greater> {}; \
	// End of ENCODEASM_CONDITIONAL_ENCODER_SPECIALIZATION macro

ENCODEASM_CONDITIONAL_ENCODER_SPECIALIZATION(J, j)
ENCODEASM_CONDITIONAL_ENCODER_SPECIALIZATION(SET, set)
ENCODEASM_CONDITIONAL_ENCODER_SPECIALIZATION(CMOV, cmov)

#undef ENCODEASM_CONDITIONAL_ENCODER_SPECIALIZATION

namespace core {
#define ENCODEASM_FUNCTION_WRAPPER_NONE(FNAME,MNEMONIC) \
	constexpr Instruction FNAME() noexcept { \
		return encoder<mnemonic::MNEMONIC>::encode(); \
	} \
	// End of ENCODEASM_FUNCTION_WRAPPER_NONE macro
#define ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,DST_TYPE,SRC_TYPE) \
	constexpr Instruction FNAME(const DST_TYPE destination, const SRC_TYPE source) noexcept { \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source); \
	} \
	// End of ENCODEASM_FUNCTION_WRAPPER_DEST_SRC macro
#define ENCODEASM_FUNCTION_WRAPPER_SRC(FNAME,MNEMONIC,SRC_TYPE) \
	constexpr Instruction FNAME(const SRC_TYPE source) noexcept { \
		return encoder<mnemonic::MNEMONIC>::encode(source); \
	} \
	// End of ENCODEASM_FUNCTION_WRAPPER_SRC macro
#define ENCODEASM_FUNCTION_WRAPPER_DST(FNAME,MNEMONIC,DST_TYPE) \
	constexpr Instruction FNAME(const DST_TYPE destination) noexcept { \
		return encoder<mnemonic::MNEMONIC>::encode(destination); \
	} \
	// End of ENCODEASM_FUNCTION_WRAPPER_DST macro
#define ENCODEASM_FUNCTION_WRAPPER_DST_SRC_SRC(FNAME,MNEMONIC,DST_TYPE,SRC0_TYPE,SRC1_TYPE) \
	constexpr Instruction FNAME(const DST_TYPE destination, const SRC0_TYPE source0, const SRC1_TYPE source1) noexcept { \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source0, source1); \
	} \
	// End of ENCODEASM_FUNCTION_WRAPPER_DST_SRC_SRC macro

#define ENCODEASM_REGRM_ENCODING_WRAPPERS(FNAME,MNEMONIC) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg8,reg8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg8_32,reg8_32) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg8,MemT<1>) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg8_32,MemT<1>) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<1>,reg8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<1>,reg8_32) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg16,reg16) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg16,MemT<2>) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<2>,reg16) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg32,reg32) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg32,MemT<4>) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<4>,reg32) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg,reg) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg,MemT<8>) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<8>,reg) \
	// End of ENCODEASM_REGRM_ENCODING_WRAPPERS macro

#define ENCODEASM_FUNCTION_WRAPPER_DST_IMM_CHECK(FNAME,MNEMONIC,DST_TYPE,IMM_TYPE) \
	constexpr Instruction FNAME(const DST_TYPE destination, const IMM_TYPE source) noexcept { \
		if (source >= -0x80 && source <= 0x7F) { \
			return encoder<mnemonic::MNEMONIC>::encode(destination, int8(source)); \
		} \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source); \
	} \
	// End of ENCODEASM_FUNCTION_WRAPPER_DST_IMM_CHECK macro

#define ENCODEASM_STANDARD_ENCODING_WRAPPERS(FNAME,MNEMONIC) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg8,int8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg8_32,int8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<1>,int8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_IMM_CHECK(FNAME,MNEMONIC,reg16,int16) \
	ENCODEASM_FUNCTION_WRAPPER_DST_IMM_CHECK(FNAME,MNEMONIC,MemT<2>,int16) \
	ENCODEASM_FUNCTION_WRAPPER_DST_IMM_CHECK(FNAME,MNEMONIC,reg32,int32) \
	ENCODEASM_FUNCTION_WRAPPER_DST_IMM_CHECK(FNAME,MNEMONIC,MemT<4>,int32) \
	ENCODEASM_FUNCTION_WRAPPER_DST_IMM_CHECK(FNAME,MNEMONIC,reg,int32) \
	ENCODEASM_FUNCTION_WRAPPER_DST_IMM_CHECK(FNAME,MNEMONIC,MemT<8>,int32) \
	ENCODEASM_REGRM_ENCODING_WRAPPERS(FNAME,MNEMONIC) \
	// End of ENCODEASM_STANDARD_ENCODING_WRAPPERS macro

	ENCODEASM_STANDARD_ENCODING_WRAPPERS(ADD, ADD)
	ENCODEASM_STANDARD_ENCODING_WRAPPERS(operator+=, ADD)
	ENCODEASM_STANDARD_ENCODING_WRAPPERS(SUB, SUB)
	ENCODEASM_STANDARD_ENCODING_WRAPPERS(operator-=, SUB)
	ENCODEASM_STANDARD_ENCODING_WRAPPERS(AND, AND)
	ENCODEASM_STANDARD_ENCODING_WRAPPERS(operator&=, AND)
	ENCODEASM_STANDARD_ENCODING_WRAPPERS(OR, OR)
	ENCODEASM_STANDARD_ENCODING_WRAPPERS(operator|=, OR)
	ENCODEASM_STANDARD_ENCODING_WRAPPERS(XOR, XOR)
	ENCODEASM_STANDARD_ENCODING_WRAPPERS(operator^=, XOR)
	ENCODEASM_STANDARD_ENCODING_WRAPPERS(CMP, CMP)
	ENCODEASM_STANDARD_ENCODING_WRAPPERS(ADC, ADC)
	ENCODEASM_STANDARD_ENCODING_WRAPPERS(SBB, SBB)
#undef ENCODEASM_STANDARD_ENCODING_WRAPPERS
#undef ENCODEASM_FUNCTION_WRAPPER_DST_IMM_CHECK

#define ENCODEASM_MOV_ENCODING_WRAPPERS(FNAME) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MOV,reg8,int8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MOV,reg8_32,int8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MOV,MemT<1>,int8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MOV,reg16,int16) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MOV,MemT<2>,int16) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MOV,reg32,int32) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MOV,MemT<4>,int32) \
	constexpr Instruction FNAME(const reg destination, const int64 source) noexcept { \
		if (source >= -0x80000000LL && source <= 0x7FFFFFFFLL) { \
			return encoder<mnemonic::MOV>::encode(destination, int32(source)); \
		} \
		return encoder<mnemonic::MOV>::encode(destination, source); \
	} \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MOV,MemT<8>,int32) \
	ENCODEASM_REGRM_ENCODING_WRAPPERS(FNAME,MOV) \
	// End of ENCODEASM_MOV_ENCODING_WRAPPERS macro

	ENCODEASM_MOV_ENCODING_WRAPPERS(MOV)

	// Yes, it's weird to use %= for assignment, but = can't be used here,
	// else we could never actually assign a new value to a variable of type reg,
	// since that would instead just generate an Instruction.  That would be bad.
	ENCODEASM_MOV_ENCODING_WRAPPERS(operator%=)
#undef ENCODEASM_MOV_ENCODING_WRAPPERS

	template<int membytes>
	constexpr Instruction LEA(const core::reg destination, const MemT<membytes> source) noexcept {
		return encoder<mnemonic::LEA>::encode(destination, source);
	}
	constexpr Instruction operator%=(const core::reg destination, const memory::register_plus source) noexcept {
		return encoder<mnemonic::LEA>::encode(destination, Mem(source));
	}
	constexpr Instruction operator%=(const core::reg destination, const memory::scaled_register source) noexcept {
		return encoder<mnemonic::LEA>::encode(destination, Mem(source));
	}
	constexpr Instruction operator%=(const core::reg destination, const memory::scaled_register_plus source) noexcept {
		return encoder<mnemonic::LEA>::encode(destination, Mem(source));
	}
	constexpr Instruction operator%=(const core::reg destination, const memory::register_scaled_register_plus source) noexcept {
		return encoder<mnemonic::LEA>::encode(destination, Mem(source));
	}

	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(TEST,TEST,reg8,int8)
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(TEST,TEST,reg8_32,int8)
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(TEST,TEST,reg16,int16)
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(TEST,TEST,reg32,int32)
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(TEST,TEST,reg,int32)
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(TEST,TEST,MemT<1>,int8)
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(TEST,TEST,MemT<2>,int16)
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(TEST,TEST,MemT<4>,int32)
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(TEST,TEST,MemT<8>,int32)
	ENCODEASM_REGRM_ENCODING_WRAPPERS(TEST,TEST)

	ENCODEASM_REGRM_ENCODING_WRAPPERS(XCHG,XCHG)

#undef ENCODEASM_REGRM_ENCODING_WRAPPERS

	constexpr Instruction JMP(const char*const target_label) noexcept {
		return encoder<mnemonic::JMP>::encode(target_label);
	}
	ENCODEASM_FUNCTION_WRAPPER_SRC(JMP,JMP,reg)
	ENCODEASM_FUNCTION_WRAPPER_SRC(JMP,JMP,MemT<8>)

#define ENCODEASM_CONDITIONAL_ENCODING_WRAPPERS(INSTRUCTION_MACRO) \
	INSTRUCTION_MACRO(O) \
	INSTRUCTION_MACRO(NO) \
	INSTRUCTION_MACRO(C) \
	INSTRUCTION_MACRO(B) \
	INSTRUCTION_MACRO(NAE) \
	INSTRUCTION_MACRO(NC) \
	INSTRUCTION_MACRO(AE) \
	INSTRUCTION_MACRO(NB) \
	INSTRUCTION_MACRO(Z) \
	INSTRUCTION_MACRO(E) \
	INSTRUCTION_MACRO(NZ) \
	INSTRUCTION_MACRO(NE) \
	INSTRUCTION_MACRO(BE) \
	INSTRUCTION_MACRO(NA) \
	INSTRUCTION_MACRO(A) \
	INSTRUCTION_MACRO(NBE) \
	INSTRUCTION_MACRO(S) \
	INSTRUCTION_MACRO(NS) \
	INSTRUCTION_MACRO(P) \
	INSTRUCTION_MACRO(PE) \
	INSTRUCTION_MACRO(NP) \
	INSTRUCTION_MACRO(PO) \
	INSTRUCTION_MACRO(L) \
	INSTRUCTION_MACRO(NGE) \
	INSTRUCTION_MACRO(GE) \
	INSTRUCTION_MACRO(NL) \
	INSTRUCTION_MACRO(LE) \
	INSTRUCTION_MACRO(NG) \
	INSTRUCTION_MACRO(G) \
	INSTRUCTION_MACRO(NLE) \
	// End of ENCODEASM_CONDITIONAL_ENCODING_WRAPPER macro

#define ENCODEASM_JCC_ENCODING_WRAPPERS(CONDITION) \
	constexpr Instruction J##CONDITION(const char*const target_label) noexcept { \
		return encoder<mnemonic::J##CONDITION>::encode(target_label); \
	} \
	constexpr Instruction J##CONDITION##_LIKELY(const char*const target_label) noexcept { \
		return encoder<mnemonic::J##CONDITION>::encodeLikely(target_label); \
	} \
	constexpr Instruction J##CONDITION##_UNLIKELY(const char*const target_label) noexcept { \
		return encoder<mnemonic::J##CONDITION>::encodeUnlikely(target_label); \
	} \
	// End of ENCODEASM_JCC_ENCODING_WRAPPER macro

	ENCODEASM_CONDITIONAL_ENCODING_WRAPPERS(ENCODEASM_JCC_ENCODING_WRAPPERS)
	ENCODEASM_JCC_ENCODING_WRAPPERS(RCXZ)
#undef ENCODEASM_JCC_ENCODING_WRAPPERS

#define ENCODEASM_SETCC_ENCODING_WRAPPERS(CONDITION) \
	ENCODEASM_FUNCTION_WRAPPER_DST(SET##CONDITION,SET##CONDITION,reg8) \
	ENCODEASM_FUNCTION_WRAPPER_DST(SET##CONDITION,SET##CONDITION,reg8_32) \
	ENCODEASM_FUNCTION_WRAPPER_DST(SET##CONDITION,SET##CONDITION,MemT<1>) \
	// End of ENCODEASM_SETCC_ENCODING_WRAPPER macro

	ENCODEASM_CONDITIONAL_ENCODING_WRAPPERS(ENCODEASM_SETCC_ENCODING_WRAPPERS)
#undef ENCODEASM_SETCC_ENCODING_WRAPPERS

#define ENCODEASM_CMOVCC_ENCODING_WRAPPERS(CONDITION) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(CMOV##CONDITION,CMOV##CONDITION,reg16,reg16) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(CMOV##CONDITION,CMOV##CONDITION,reg16,MemT<2>) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(CMOV##CONDITION,CMOV##CONDITION,reg32,reg32) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(CMOV##CONDITION,CMOV##CONDITION,reg32,MemT<4>) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(CMOV##CONDITION,CMOV##CONDITION,reg,reg) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(CMOV##CONDITION,CMOV##CONDITION,reg,MemT<8>) \
	// End of ENCODEASM_CMOVCC_ENCODING_WRAPPER macro

	ENCODEASM_CONDITIONAL_ENCODING_WRAPPERS(ENCODEASM_CMOVCC_ENCODING_WRAPPERS)
#undef ENCODEASM_CMOVCC_ENCODING_WRAPPERS
#undef ENCODEASM_CONDITIONAL_ENCODING_WRAPPERS

#define ENCODEASM_STANDARD_UNARY_ENCODING_WRAPPERS(FNAME,MNEMONIC) \
	ENCODEASM_FUNCTION_WRAPPER_SRC(FNAME,MNEMONIC,reg8) \
	ENCODEASM_FUNCTION_WRAPPER_SRC(FNAME,MNEMONIC,reg8_32) \
	ENCODEASM_FUNCTION_WRAPPER_SRC(FNAME,MNEMONIC,MemT<1>) \
	ENCODEASM_FUNCTION_WRAPPER_SRC(FNAME,MNEMONIC,reg16) \
	ENCODEASM_FUNCTION_WRAPPER_SRC(FNAME,MNEMONIC,MemT<2>) \
	ENCODEASM_FUNCTION_WRAPPER_SRC(FNAME,MNEMONIC,reg32) \
	ENCODEASM_FUNCTION_WRAPPER_SRC(FNAME,MNEMONIC,MemT<4>) \
	ENCODEASM_FUNCTION_WRAPPER_SRC(FNAME,MNEMONIC,reg) \
	ENCODEASM_FUNCTION_WRAPPER_SRC(FNAME,MNEMONIC,MemT<8>) \
	// End of ENCODEASM_STANDARD_UNARY_ENCODING_WRAPPERS macro

	ENCODEASM_STANDARD_UNARY_ENCODING_WRAPPERS(NOT,NOT)
	ENCODEASM_STANDARD_UNARY_ENCODING_WRAPPERS(NEG,NEG)
	ENCODEASM_STANDARD_UNARY_ENCODING_WRAPPERS(MUL,MUL)
	ENCODEASM_STANDARD_UNARY_ENCODING_WRAPPERS(IMUL,IMUL)
	ENCODEASM_STANDARD_UNARY_ENCODING_WRAPPERS(DIV,DIV)
	ENCODEASM_STANDARD_UNARY_ENCODING_WRAPPERS(IDIV,IDIV)
	ENCODEASM_STANDARD_UNARY_ENCODING_WRAPPERS(INC,INC)
	ENCODEASM_STANDARD_UNARY_ENCODING_WRAPPERS(DEC,DEC)
#undef ENCODEASM_STANDARD_UNARY_ENCODING_WRAPPERS

	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(IMUL,IMUL,reg16,reg16)
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(IMUL,IMUL,reg16,MemT<2>)
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(IMUL,IMUL,reg32,reg32)
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(IMUL,IMUL,reg32,MemT<4>)
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(IMUL,IMUL,reg,reg)
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(IMUL,IMUL,reg,MemT<8>)
#define ENCODEASM_IMUL_ENCODING_WRAPPER(REG_TYPE,MEM_TYPE,IMM_TYPE) \
	constexpr Instruction IMUL(const REG_TYPE destination, const REG_TYPE source, const IMM_TYPE immediate) noexcept { \
		if (immediate >= -0x80 && immediate <= 0x7F) { \
			return encoder<mnemonic::IMUL>::encode(destination, source, int8(immediate)); \
		} \
		return encoder<mnemonic::IMUL>::encode(destination, source, immediate); \
	} \
	constexpr Instruction IMUL(const REG_TYPE destination, const IMM_TYPE immediate) noexcept { \
		return IMUL(destination,destination,immediate); \
	} \
	constexpr Instruction IMUL(const REG_TYPE destination, const MEM_TYPE source, const IMM_TYPE immediate) noexcept { \
		if (immediate >= -0x80 && immediate <= 0x7F) { \
			return encoder<mnemonic::IMUL>::encode(destination, source, int8(immediate)); \
		} \
		return encoder<mnemonic::IMUL>::encode(destination, source, immediate); \
	} \
	// End of ENCODEASM_IMUL_ENCODING_WRAPPER macro

	ENCODEASM_IMUL_ENCODING_WRAPPER(reg16,MemT<2>,int16)
	ENCODEASM_IMUL_ENCODING_WRAPPER(reg32,MemT<4>,int32)
	ENCODEASM_IMUL_ENCODING_WRAPPER(reg,MemT<8>,int32)
#undef ENCODEASM_IMUL_ENCODING_WRAPPER

	ENCODEASM_FUNCTION_WRAPPER_NONE(CBW,CBW)
	ENCODEASM_FUNCTION_WRAPPER_NONE(CWDE,CWDE)
	ENCODEASM_FUNCTION_WRAPPER_NONE(CDQE,CDQE)
	ENCODEASM_FUNCTION_WRAPPER_NONE(CWD,CWD)
	ENCODEASM_FUNCTION_WRAPPER_NONE(CDQ,CDQ)
	ENCODEASM_FUNCTION_WRAPPER_NONE(CQO,CQO)
	ENCODEASM_FUNCTION_WRAPPER_NONE(CLC,CLC)
	ENCODEASM_FUNCTION_WRAPPER_NONE(CMC,CMC)
	ENCODEASM_FUNCTION_WRAPPER_NONE(STC,STC)
	ENCODEASM_FUNCTION_WRAPPER_NONE(CPUID,CPUID)
	ENCODEASM_FUNCTION_WRAPPER_NONE(MOVSB,MOVSB)
	ENCODEASM_FUNCTION_WRAPPER_NONE(MOVSW,MOVSW)
	ENCODEASM_FUNCTION_WRAPPER_NONE(MOVSD,MOVSD)
	ENCODEASM_FUNCTION_WRAPPER_NONE(MOVSQ,MOVSQ)
	ENCODEASM_FUNCTION_WRAPPER_NONE(REP_MOVSB,REP_MOVSB)
	ENCODEASM_FUNCTION_WRAPPER_NONE(REP_MOVSW,REP_MOVSW)
	ENCODEASM_FUNCTION_WRAPPER_NONE(REP_MOVSD,REP_MOVSD)
	ENCODEASM_FUNCTION_WRAPPER_NONE(REP_MOVSQ,REP_MOVSQ)
	ENCODEASM_FUNCTION_WRAPPER_NONE(PAUSE,PAUSE)
	ENCODEASM_FUNCTION_WRAPPER_NONE(POPF,POPF)
	ENCODEASM_FUNCTION_WRAPPER_NONE(POPFQ,POPFQ)
	ENCODEASM_FUNCTION_WRAPPER_NONE(PUSHF,PUSHF)
	ENCODEASM_FUNCTION_WRAPPER_NONE(PUSHFQ,PUSHFQ)
	ENCODEASM_FUNCTION_WRAPPER_NONE(RDPMC,RDPMC)
	ENCODEASM_FUNCTION_WRAPPER_NONE(RDTSC,RDTSC)
	ENCODEASM_FUNCTION_WRAPPER_NONE(STOSB,STOSB)
	ENCODEASM_FUNCTION_WRAPPER_NONE(STOSW,STOSW)
	ENCODEASM_FUNCTION_WRAPPER_NONE(STOSD,STOSD)
	ENCODEASM_FUNCTION_WRAPPER_NONE(STOSQ,STOSQ)
	ENCODEASM_FUNCTION_WRAPPER_NONE(REP_STOSB,REP_STOSB)
	ENCODEASM_FUNCTION_WRAPPER_NONE(REP_STOSW,REP_STOSW)
	ENCODEASM_FUNCTION_WRAPPER_NONE(REP_STOSD,REP_STOSD)
	ENCODEASM_FUNCTION_WRAPPER_NONE(REP_STOSQ,REP_STOSQ)
	ENCODEASM_FUNCTION_WRAPPER_NONE(UD2,UD2)

	constexpr Instruction CALL(const void *const function_address) noexcept {
		return encoder<mnemonic::CALL>::encode(function_address);
	}
	constexpr Instruction CALL(const char *const target_label) noexcept {
		return encoder<mnemonic::CALL>::encode(target_label);
	}
	ENCODEASM_FUNCTION_WRAPPER_SRC(CALL,CALL,reg)
	ENCODEASM_FUNCTION_WRAPPER_SRC(CALL,CALL,MemT<8>)

	ENCODEASM_FUNCTION_WRAPPER_NONE(RET,RET)

	/// NOTE: You probably don't want to call this version.
	///       It just returns and then adds bytes_to_pop to rsp.
	constexpr Instruction RET(uint16 bytes_to_pop) noexcept {
		return encoder<mnemonic::RET>::encode(bytes_to_pop);
	}

#define ENCODEASM_RMREG_ENCODING_WRAPPERS(FNAME,MNEMONIC) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg8,reg8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg8_32,reg8_32) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<1>,reg8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<1>,reg8_32) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg16,reg16) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<2>,reg16) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg32,reg32) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<4>,reg32) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg,reg) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<8>,reg) \
	// End of ENCODEASM_RMREG_ENCODING_WRAPPERS macro

	ENCODEASM_RMREG_ENCODING_WRAPPERS(XADD,XADD)
	ENCODEASM_RMREG_ENCODING_WRAPPERS(CMPXCHG,CMPXCHG)
#undef ENCODEASM_RMREG_ENCODING_WRAPPERS

#define ENCODEASM_BSCAN_ENCODING_WRAPPERS(FNAME,MNEMONIC) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg16,reg16) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg16,MemT<2>) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg32,reg32) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg32,MemT<4>) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg,reg) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg,MemT<8>) \
	// End of ENCODEASM_BSCAN_ENCODING_WRAPPERS macro

	ENCODEASM_BSCAN_ENCODING_WRAPPERS(BSF,BSF)
	ENCODEASM_BSCAN_ENCODING_WRAPPERS(BSR,BSR)
#undef ENCODEASM_BSCAN_ENCODING_WRAPPERS

	ENCODEASM_FUNCTION_WRAPPER_DST(BSWAP,BSWAP,reg32)
	ENCODEASM_FUNCTION_WRAPPER_DST(BSWAP,BSWAP,reg)

#define ENCODEASM_BTEST_ENCODING_WRAPPERS(FNAME,MNEMONIC) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg16,reg16) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<2>,reg16) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg32,reg32) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<4>,reg32) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg,reg) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<8>,reg) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg16,uint8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<2>,uint8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg32,uint8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<4>,uint8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg,uint8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<8>,uint8) \
	// End of ENCODEASM_BTEST_ENCODING_WRAPPERS macro

	ENCODEASM_BTEST_ENCODING_WRAPPERS(BT,BT)
	ENCODEASM_BTEST_ENCODING_WRAPPERS(BTS,BTS)
	ENCODEASM_BTEST_ENCODING_WRAPPERS(BTR,BTR)
	ENCODEASM_BTEST_ENCODING_WRAPPERS(BTC,BTC)
#undef ENCODEASM_BTEST_ENCODING_WRAPPERS

	ENCODEASM_FUNCTION_WRAPPER_DST(CMPXCHG8B,CMPXCHG8B,MemT<8>)
	ENCODEASM_FUNCTION_WRAPPER_DST(CMPXCHG16B,CMPXCHG16B,MemT<16>)

#define ENCODEASM_SHIFT_ENCODING_WRAPPERS(FNAME,MNEMONIC) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg8,uint8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg8,reg8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg8_32,uint8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg8_32,reg8_32) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<1>,uint8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<1>,reg8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<1>,reg8_32) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg16,uint8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg16,reg8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg16,reg8_32) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<2>,uint8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<2>,reg8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<2>,reg8_32) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg32,uint8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg32,reg8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg32,reg8_32) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<4>,uint8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<4>,reg8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<4>,reg8_32) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg,uint8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,reg,reg8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<8>,uint8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC(FNAME,MNEMONIC,MemT<8>,reg8) \
	// End of ENCODEASM_SHIFT_ENCODING_WRAPPERS macro

	ENCODEASM_SHIFT_ENCODING_WRAPPERS(ROL,ROL)
	ENCODEASM_SHIFT_ENCODING_WRAPPERS(ROR,ROR)
	ENCODEASM_SHIFT_ENCODING_WRAPPERS(RCL,RCL)
	ENCODEASM_SHIFT_ENCODING_WRAPPERS(RCR,RCR)
	ENCODEASM_SHIFT_ENCODING_WRAPPERS(SHL,SHL)
	ENCODEASM_SHIFT_ENCODING_WRAPPERS(SHR,SHR)
	ENCODEASM_SHIFT_ENCODING_WRAPPERS(SAR,SAR)
#undef ENCODEASM_SHIFT_ENCODING_WRAPPERS

#define ENCODEASM_SHIFTD_ENCODING_WRAPPERS(FNAME,MNEMONIC) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC_SRC(FNAME,MNEMONIC,reg16,reg16,uint8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC_SRC(FNAME,MNEMONIC,MemT<2>,reg16,uint8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC_SRC(FNAME,MNEMONIC,reg16,reg16,reg8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC_SRC(FNAME,MNEMONIC,MemT<2>,reg16,reg8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC_SRC(FNAME,MNEMONIC,reg32,reg32,uint8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC_SRC(FNAME,MNEMONIC,MemT<4>,reg32,uint8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC_SRC(FNAME,MNEMONIC,reg32,reg32,reg8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC_SRC(FNAME,MNEMONIC,MemT<4>,reg32,reg8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC_SRC(FNAME,MNEMONIC,reg,reg,uint8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC_SRC(FNAME,MNEMONIC,MemT<8>,reg,uint8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC_SRC(FNAME,MNEMONIC,reg,reg,reg8) \
	ENCODEASM_FUNCTION_WRAPPER_DST_SRC_SRC(FNAME,MNEMONIC,MemT<8>,reg,reg8) \
	// End of ENCODEASM_SHIFTD_ENCODING_WRAPPERS macro

	ENCODEASM_SHIFTD_ENCODING_WRAPPERS(SHLD,SHLD)
	ENCODEASM_SHIFTD_ENCODING_WRAPPERS(SHRD,SHRD)
#undef ENCODEASM_SHIFTD_ENCODING_WRAPPERS

#undef ENCODEASM_FUNCTION_WRAPPER_NONE
#undef ENCODEASM_FUNCTION_WRAPPER_DST_SRC
#undef ENCODEASM_FUNCTION_WRAPPER_SRC
#undef ENCODEASM_FUNCTION_WRAPPER_DST
#undef ENCODEASM_FUNCTION_WRAPPER_DST_SRC_SRC
#undef ENCODEASM_FUNCTION_WRAPPER_DST_IMM_CHECK
} // namespace core

} // namespace mode64bit
} // namespace encodeasm
