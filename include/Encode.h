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
	constexpr uint8 REXW() noexcept {
		// REX: 0100WRXB (0100W000)
		return 0x48;
	}
	template<typename RegType>
	constexpr uint8 REXWR(RegType r) noexcept {
		// REX: 0100WRXB (0100WR00)
		return 0x48 | ((uint8(r)&0b1000)>>1);
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
}

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
	NEG,
	NOT,

	CALL,
	RET
};

namespace encoders {
	template<int membytes,typename RegType>
	static constexpr int OpcodeAndMem(Instruction &i, uint8 opcode, MemT<membytes> m, RegType r, int start=0) noexcept {
		int index = start;
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
		i.bytes[index] = opcode;
		i.bytes[index+1] = m.modregrm | ((uint8(r)&0b111)<<3);
		index += 2;
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
			return Instruction::create_error("Invalid memory operand");
		}

		Instruction i = Instruction(Instruction::zero_init_tag());
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
	static Instruction error_reg8_32_registers_cant_be_used_with_memory_operand_with_rex() noexcept {
		return Instruction::create_error("Legacy 8-bit registers, like ah, ch, dh, or bh, can't be used with a memory operand using r8, r9, r10, ..., r15");
	}
	/// NOTE: Unordered; opcode determines the operand order.
	static constexpr Instruction commonEncode(const uint8 opcode, const core::reg8_32 r, const MemT<1> rm) noexcept {
		if (rm.hasError()) {
			return Instruction::create_error("Invalid memory operand");
		}
		if (uint8(r) >= 4 && rm.hasrex) {
			return error_reg8_32_registers_cant_be_used_with_memory_operand_with_rex();
		}

		Instruction i = Instruction(Instruction::zero_init_tag());
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
			return Instruction::create_error("Invalid memory operand");
		}

		Instruction i = Instruction(Instruction::zero_init_tag());
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
			return Instruction::create_error("Invalid memory operand");
		}

		Instruction i = Instruction(Instruction::zero_init_tag());
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
			return Instruction::create_error("Invalid memory operand");
		}

		Instruction i = Instruction(Instruction::zero_init_tag());
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
		return Instruction(REXR(r), opcode, ModRegRm(num,r), imm);
	}
	static constexpr Instruction commonEncode(const uint8 opcode, const uint8 num, const core::reg16 r, const int16 imm) noexcept {
		if (uint8(r) < 8) {
			// No REX needed if ax, cx, dx, bx, sp, bp, si, or di.
			return Instruction(memory::SIZE_PREFIX, opcode, ModRegRm(num,r), uint8(imm), uint8(imm>>8));
		}
		// REX is needed for r8w, r9w, r10w, r11w, ...
		return Instruction(memory::SIZE_PREFIX, REXR(r), opcode, ModRegRm(num,r), uint8(imm), uint8(imm>>8));
	}
	static constexpr Instruction commonEncode(const uint8 opcode, const uint8 num, const core::reg32 r, const int32 imm) noexcept {
		if (uint8(r) < 8) {
			// No REX needed if eax, ecx, edx, ebx, esp, ebp, esi, or edi.
			return Instruction(opcode, ModRegRm(num,r), uint8(imm), uint8(imm>>8), uint8(imm>>16), uint8(imm>>24));
		}
		// REX is needed for r8d, r9d, r10d, r11d, ...
		return Instruction(REXR(r), opcode, ModRegRm(num,r), uint8(imm), uint8(imm>>8), uint8(imm>>16), uint8(imm>>24));
	}
	static constexpr Instruction commonEncode(const uint8 opcode, const uint8 num, const core::reg r, const int32 imm) noexcept {
		return Instruction(REXWR(r), opcode, ModRegRm(num,r), uint8(imm), uint8(imm>>8), uint8(imm>>16), uint8(imm>>24));
	}
	static constexpr Instruction commonEncode(const uint8 opcode, const uint8 num, const MemT<1> m,const int8 imm) noexcept {
		if (m.hasError()) {
			return Instruction::create_error("Invalid memory operand");
		}
		Instruction i = Instruction(Instruction::zero_init_tag());
		int index = OpcodeAndMem(i, opcode, m, num);
		i.bytes[index] = imm;
		i.length = index+1;
		return i;
	}
	static constexpr Instruction commonEncode(const uint8 opcode, const uint8 num, const MemT<2> m, const int16 imm) noexcept {
		if (m.hasError()) {
			return Instruction::create_error("Invalid memory operand");
		}
		Instruction i = Instruction(Instruction::zero_init_tag());
		i.bytes[0] = memory::SIZE_PREFIX;
		int index = OpcodeAndMem(i, opcode, m, num, 1);
		i.bytes[index] = uint8(imm);
		i.bytes[index+1] = uint8(imm>>8);
		i.length = index+2;
		return i;
	}
	static constexpr Instruction commonEncode(const uint8 opcode, const uint8 num, const MemT<4> m, const int32 imm) noexcept {
		if (m.hasError()) {
			return Instruction::create_error("Invalid memory operand");
		}
		Instruction i = Instruction(Instruction::zero_init_tag());
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
			return Instruction::create_error("Invalid memory operand");
		}
		Instruction i = Instruction(Instruction::zero_init_tag());
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
			return Instruction(memory::SIZE_PREFIX, REXR(r), 0x83, ModRegRm(num,r), imm);
		}
		static constexpr Instruction encode(const MemT<2> m,const int8 imm) noexcept {
			if (m.hasError()) {
				return Instruction::create_error("Invalid memory operand");;
			}
			Instruction i = Instruction(Instruction::zero_init_tag());
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
			return Instruction(REXR(r), 0x83, ModRegRm(num,r), imm);
		}
		static constexpr Instruction encode(const MemT<4> m,const int8 imm) noexcept {
			if (m.hasError()) {
				return Instruction::create_error("Invalid memory operand");;
			}
			Instruction i = Instruction(Instruction::zero_init_tag());
			int index = OpcodeAndMem(i, 0x83, m, num);
			i.bytes[index] = imm;
			i.length = index+1;
			return i;
		}
		static constexpr Instruction encode(const core::reg r, const int8 imm) noexcept {
			return Instruction(REXWR(r), 0x83, ModRegRm(num,r), uint8(imm));
		}
		static constexpr Instruction encode(const MemT<8> m,const int8 imm) noexcept {
			if (m.hasError()) {
				return Instruction::create_error("Invalid memory operand");;
			}
			Instruction i = Instruction(Instruction::zero_init_tag());
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
				return Instruction(REXR(r), 0xB0 | (uint8(r)&0b111), imm);
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
				return Instruction(memory::SIZE_PREFIX, REXR(r), 0xB8 | uint8(r), uint8(imm), uint8(imm>>8));
			}
			return commonEncode(0xC7, 0, r, imm);
		}
		static constexpr Instruction encode(const core::reg32 r, const int32 imm, const bool alternate_encoding=false) noexcept {
			if (!alternate_encoding) {
				if (uint8(r) < 8) {
					// No REX needed if ax, cx, dx, bx, sp, bp, si, or di.
					return Instruction(0xB8 | uint8(r), uint8(imm), uint8(imm>>8), uint8(imm>>16), uint8(imm>>24));
				}
				// REX is needed for r8w, r9w, r10w, r11w, ...
				return Instruction(REXR(r), 0xB8 | uint8(r), uint8(imm), uint8(imm>>8), uint8(imm>>16), uint8(imm>>24));
			}
			return commonEncode(0xC7, 0, r, imm);
		}
		static constexpr Instruction encode(const core::reg r, const int32 imm, const bool alternate_encoding=false) noexcept {
			return commonEncode(0xC7, 0, r, imm);
		}
		static constexpr Instruction encode(const core::reg r, const int64 imm) noexcept {
			return Instruction(REXWR(r), 0xB8 | uint8(r), uint8(imm), uint8(imm>>8), uint8(imm>>16), uint8(imm>>24), uint8(imm>>32), uint8(imm>>40), uint8(imm>>48), uint8(imm>>56));
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
				return Instruction::create_error("Invalid memory operand");
			}

			m.hasrex = true;
			// Add W bit, since membytes doesn't matter; the register size is what counts in this case.
			m.rex |= 0x48;

			Instruction i = Instruction(Instruction::zero_init_tag());
			// REX is handled automatically, including W from rm.
			i.length = OpcodeAndMem(i, opcode, m, r);
			return i;
		}
		template<int membytes>
		static constexpr Instruction encode(const core::reg32 r, MemT<membytes> m) noexcept {
			if (m.hasError()) {
				return Instruction::create_error("Invalid memory operand");
			}

			if (m.hasrex) {
				// Remove W bit, since membytes doesn't matter; the register size is what counts in this case.
				m.rex &= ~0b1000;
				if (!(m.rex & 0b0111)) {
					m.hasrex = false;
				}
			}

			Instruction i = Instruction(Instruction::zero_init_tag());
			// REX is handled automatically, including W from rm.
			i.length = OpcodeAndMem(i, opcode, m, r);
			return i;
		}
		template<int membytes>
		static constexpr Instruction encode(const core::reg16 r, MemT<membytes> m) noexcept {
			if (m.hasError()) {
				return Instruction::create_error("Invalid memory operand");
			}

			if (m.hasrex) {
				// Remove W bit, since membytes doesn't matter; the register size is what counts in this case.
				m.rex &= ~0b1000;
				if (!(m.rex & 0b0111)) {
					m.hasrex = false;
				}
			}

			Instruction i = Instruction(Instruction::zero_init_tag());
			i.bytes[0] = memory::SIZE_PREFIX;
			// REX is handled automatically, including W from rm.
			i.length = OpcodeAndMem(i, opcode, m, r, 1);
			return i;
		}
	};
}

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

namespace core {
#define ENCODEASM_STANDARD_ENCODING_WRAPPERS(FNAME,MNEMONIC) \
	constexpr Instruction FNAME(const reg8 destination, const int8 source) noexcept { \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg8_32 destination, const int8 source) noexcept { \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const MemT<1> destination, const int8 source) noexcept { \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg16 destination, const int16 source) noexcept { \
		if (source >= -0x0080 && source < 0x007F) { \
			return encoder<mnemonic::MNEMONIC>::encode(destination, int8(source)); \
		} \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const MemT<2> destination, const int16 source) noexcept { \
		if (source >= -0x0080 && source < 0x007F) { \
			return encoder<mnemonic::MNEMONIC>::encode(destination, int8(source)); \
		} \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg32 destination, const int32 source) noexcept { \
		if (source >= -0x00000080 && source < 0x0000007F) { \
			return encoder<mnemonic::MNEMONIC>::encode(destination, int8(source)); \
		} \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const MemT<4> destination, const int32 source) noexcept { \
		if (source >= -0x00000080 && source < 0x0000007F) { \
			return encoder<mnemonic::MNEMONIC>::encode(destination, int8(source)); \
		} \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg destination, const int32 source) noexcept { \
		if (source >= -0x00000080 && source < 0x0000007F) { \
			return encoder<mnemonic::MNEMONIC>::encode(destination, int8(source)); \
		} \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const MemT<8> destination, const int32 source) noexcept { \
		if (source >= -0x00000080 && source < 0x0000007F) { \
			return encoder<mnemonic::MNEMONIC>::encode(destination, int8(source)); \
		} \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg8 destination, const reg8 source) noexcept { \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg8_32 destination, const reg8_32 source) noexcept { \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg8 destination, const MemT<1> source) noexcept { \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg8_32 destination, const MemT<1> source) noexcept { \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const MemT<1> destination, const reg8 source) noexcept { \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const MemT<1> destination, const reg8_32 source) noexcept { \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg16 destination, const reg16 source) noexcept { \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg16 destination, const MemT<2> source) noexcept { \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const MemT<2> destination, const reg16 source) noexcept { \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg32 destination, const reg32 source) noexcept { \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg32 destination, const MemT<4> source) noexcept { \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const MemT<4> destination, const reg32 source) noexcept { \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg destination, const reg source) noexcept { \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg destination, const MemT<8> source) noexcept { \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const MemT<8> destination, const reg source) noexcept { \
		return encoder<mnemonic::MNEMONIC>::encode(destination, source); \
	} \
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

#define ENCODEASM_MOV_ENCODING_WRAPPERS(FNAME) \
	constexpr Instruction FNAME(const reg8 destination, const int8 source) noexcept { \
		return encoder<mnemonic::MOV>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg8_32 destination, const int8 source) noexcept { \
		return encoder<mnemonic::MOV>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const MemT<1> destination, const int8 source) noexcept { \
		return encoder<mnemonic::MOV>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg16 destination, const int16 source) noexcept { \
		return encoder<mnemonic::MOV>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const MemT<2> destination, const int16 source) noexcept { \
		return encoder<mnemonic::MOV>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg32 destination, const int32 source) noexcept { \
		return encoder<mnemonic::MOV>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const MemT<4> destination, const int32 source) noexcept { \
		return encoder<mnemonic::MOV>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg destination, const int64 source) noexcept { \
		if (source >= -0x80000000LL && source < 0x7FFFFFFFLL) { \
			return encoder<mnemonic::MOV>::encode(destination, int32(source)); \
		} \
		return encoder<mnemonic::MOV>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const MemT<8> destination, const int32 source) noexcept { \
		return encoder<mnemonic::MOV>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg8 destination, const reg8 source) noexcept { \
		return encoder<mnemonic::MOV>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg8_32 destination, const reg8_32 source) noexcept { \
		return encoder<mnemonic::MOV>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg8 destination, const MemT<1> source) noexcept { \
		return encoder<mnemonic::MOV>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg8_32 destination, const MemT<1> source) noexcept { \
		return encoder<mnemonic::MOV>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const MemT<1> destination, const reg8 source) noexcept { \
		return encoder<mnemonic::MOV>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const MemT<1> destination, const reg8_32 source) noexcept { \
		return encoder<mnemonic::MOV>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg16 destination, const reg16 source) noexcept { \
		return encoder<mnemonic::MOV>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg16 destination, const MemT<2> source) noexcept { \
		return encoder<mnemonic::MOV>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const MemT<2> destination, const reg16 source) noexcept { \
		return encoder<mnemonic::MOV>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg32 destination, const reg32 source) noexcept { \
		return encoder<mnemonic::MOV>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg32 destination, const MemT<4> source) noexcept { \
		return encoder<mnemonic::MOV>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const MemT<4> destination, const reg32 source) noexcept { \
		return encoder<mnemonic::MOV>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg destination, const reg source) noexcept { \
		return encoder<mnemonic::MOV>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const reg destination, const MemT<8> source) noexcept { \
		return encoder<mnemonic::MOV>::encode(destination, source); \
	} \
	constexpr Instruction FNAME(const MemT<8> destination, const reg source) noexcept { \
		return encoder<mnemonic::MOV>::encode(destination, source); \
	} \
	// End of ENCODEASM_MOV_ENCODING_WRAPPERS macro

	ENCODEASM_MOV_ENCODING_WRAPPERS(MOV)

	// Yes, it's weird to use %= for assignment, but = can't be used here,
	// else we could never actually assign a new value to a variable of type reg,
	// since that would instead just generate an Instruction.  That would be bad.
	ENCODEASM_MOV_ENCODING_WRAPPERS(operator%=)
#undef ENCODEASM_MOV_ENCODING_WRAPPERS

	template<int membytes>
	constexpr Instruction LEA(const core::reg destination,MemT<membytes> source) noexcept {
		return encoder<mnemonic::LEA>::encode(destination, source);
	}
	constexpr Instruction operator%=(const core::reg destination, memory::register_plus source) {
		return encoder<mnemonic::LEA>::encode(destination, Mem(source));
	}
	constexpr Instruction operator%=(const core::reg destination, memory::scaled_register source) {
		return encoder<mnemonic::LEA>::encode(destination, Mem(source));
	}
	constexpr Instruction operator%=(const core::reg destination, memory::scaled_register_plus source) {
		return encoder<mnemonic::LEA>::encode(destination, Mem(source));
	}
	constexpr Instruction operator%=(const core::reg destination, memory::register_scaled_register_plus source) {
		return encoder<mnemonic::LEA>::encode(destination, Mem(source));
	}
}

} // namespace mode64bit
} // namespace encodeasm
