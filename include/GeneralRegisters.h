#pragma once

// GeneralRegisters.h:
// EncodeASM general register enums and namespaced static constexpr variables for convenience.
//
// See LICENSE file for license details.

#include "Types.h"

namespace encodeasm {
namespace mode64bit {
namespace core {

enum class reg8 : uint8 {
	r0b,
	r1b,
	r2b,
	r3b,
	r4b,
	r5b,
	r6b,
	r7b,
	r8b,
	r9b,
	r10b,
	r11b,
	r12b,
	r13b,
	r14b,
	r15b,
	al = 0,
	cl = 1,
	dl = 2,
	bl = 3,
	spl = 4,
	bpl = 5,
	sil = 6,
	dil = 7
};
// One may wonder why there's a namespace with a bunch of static constexpr variables
// in addition to the enum above, because couldn't you just use the enum?
// You can, but the C++ standard, instead of letting people optionally have
// strict typing or strict namespacing of enums, only allows neither (enum)
// or both (enum class), so in order to get strict typing and be able to
// pull the names into the current scope, there needs to be a redundant namespace
// like this.  *sigh*
namespace registers8 {
	static constexpr reg8 r0b = reg8::r0b;
	static constexpr reg8 r1b = reg8::r1b;
	static constexpr reg8 r2b = reg8::r2b;
	static constexpr reg8 r3b = reg8::r3b;
	static constexpr reg8 r4b = reg8::r4b;
	static constexpr reg8 r5b = reg8::r5b;
	static constexpr reg8 r6b = reg8::r6b;
	static constexpr reg8 r7b = reg8::r7b;
	static constexpr reg8 r8b = reg8::r8b;
	static constexpr reg8 r9b = reg8::r9b;
	static constexpr reg8 r10b = reg8::r10b;
	static constexpr reg8 r11b = reg8::r11b;
	static constexpr reg8 r12b = reg8::r12b;
	static constexpr reg8 r13b = reg8::r13b;
	static constexpr reg8 r14b = reg8::r14b;
	static constexpr reg8 r15b = reg8::r15b;
	static constexpr reg8 al = reg8::al;
	static constexpr reg8 cl = reg8::cl;
	static constexpr reg8 dl = reg8::dl;
	static constexpr reg8 bl = reg8::bl;
	static constexpr reg8 spl = reg8::spl;
	static constexpr reg8 bpl = reg8::bpl;
	static constexpr reg8 sil = reg8::sil;
	static constexpr reg8 dil = reg8::dil;
}
enum class reg8_32 : uint8 {
	al = 0,
	cl = 1,
	dl = 2,
	bl = 3,
	ah = 4,
	ch = 5,
	dh = 6,
	bh = 7
};
// NOTE: It's probably not very useful to pull in both this namespace and
//       the registers8 namespace.
namespace registers8_32 {
	static constexpr reg8_32 al = reg8_32::al;
	static constexpr reg8_32 cl = reg8_32::cl;
	static constexpr reg8_32 dl = reg8_32::dl;
	static constexpr reg8_32 bl = reg8_32::bl;
	static constexpr reg8_32 ah = reg8_32::ah;
	static constexpr reg8_32 ch = reg8_32::ch;
	static constexpr reg8_32 dh = reg8_32::dh;
	static constexpr reg8_32 bh = reg8_32::bh;
}
enum class reg16 : uint8 {
	r0w,
	r1w,
	r2w,
	r3w,
	r4w,
	r5w,
	r6w,
	r7w,
	r8w,
	r9w,
	r10w,
	r11w,
	r12w,
	r13w,
	r14w,
	r15w,
	ax = 0,
	cx = 1,
	dx = 2,
	bx = 3,
	sp = 4,
	bp = 5,
	si = 6,
	di = 7
};
namespace registers16 {
	static constexpr reg16 r0w = reg16::r0w;
	static constexpr reg16 r1w = reg16::r1w;
	static constexpr reg16 r2w = reg16::r2w;
	static constexpr reg16 r3w = reg16::r3w;
	static constexpr reg16 r4w = reg16::r4w;
	static constexpr reg16 r5w = reg16::r5w;
	static constexpr reg16 r6w = reg16::r6w;
	static constexpr reg16 r7w = reg16::r7w;
	static constexpr reg16 r8w = reg16::r8w;
	static constexpr reg16 r9w = reg16::r9w;
	static constexpr reg16 r10w = reg16::r10w;
	static constexpr reg16 r11w = reg16::r11w;
	static constexpr reg16 r12w = reg16::r12w;
	static constexpr reg16 r13w = reg16::r13w;
	static constexpr reg16 r14w = reg16::r14w;
	static constexpr reg16 r15w = reg16::r15w;
	static constexpr reg16 ax = reg16::ax;
	static constexpr reg16 cx = reg16::cx;
	static constexpr reg16 dx = reg16::dx;
	static constexpr reg16 bx = reg16::bx;
	static constexpr reg16 sp = reg16::sp;
	static constexpr reg16 bp = reg16::bp;
	static constexpr reg16 si = reg16::si;
	static constexpr reg16 di = reg16::di;
}
enum class reg32 : uint8 {
	r0d,
	r1d,
	r2d,
	r3d,
	r4d,
	r5d,
	r6d,
	r7d,
	r8d,
	r9d,
	r10d,
	r11d,
	r12d,
	r13d,
	r14d,
	r15d,
	eax = 0,
	ecx = 1,
	edx = 2,
	ebx = 3,
	esp = 4,
	ebp = 5,
	esi = 6,
	edi = 7
};
namespace registers32 {
	static constexpr reg32 r0d = reg32::r0d;
	static constexpr reg32 r1d = reg32::r1d;
	static constexpr reg32 r2d = reg32::r2d;
	static constexpr reg32 r3d = reg32::r3d;
	static constexpr reg32 r4d = reg32::r4d;
	static constexpr reg32 r5d = reg32::r5d;
	static constexpr reg32 r6d = reg32::r6d;
	static constexpr reg32 r7d = reg32::r7d;
	static constexpr reg32 r8d = reg32::r8d;
	static constexpr reg32 r9d = reg32::r9d;
	static constexpr reg32 r10d = reg32::r10d;
	static constexpr reg32 r11d = reg32::r11d;
	static constexpr reg32 r12d = reg32::r12d;
	static constexpr reg32 r13d = reg32::r13d;
	static constexpr reg32 r14d = reg32::r14d;
	static constexpr reg32 r15d = reg32::r15d;
	static constexpr reg32 eax = reg32::eax;
	static constexpr reg32 ecx = reg32::ecx;
	static constexpr reg32 edx = reg32::edx;
	static constexpr reg32 ebx = reg32::ebx;
	static constexpr reg32 esp = reg32::esp;
	static constexpr reg32 ebp = reg32::ebp;
	static constexpr reg32 esi = reg32::esi;
	static constexpr reg32 edi = reg32::edi;
}
enum class reg : uint8 {
	r0,
	r1,
	r2,
	r3,
	r4,
	r5,
	r6,
	r7,
	r8,
	r9,
	r10,
	r11,
	r12,
	r13,
	r14,
	r15,
	rax = 0,
	rcx = 1,
	rdx = 2,
	rbx = 3,
	rsp = 4,
	rbp = 5,
	rsi = 6,
	rdi = 7
};
namespace registers {
	static constexpr reg r0 = reg::r0;
	static constexpr reg r1 = reg::r1;
	static constexpr reg r2 = reg::r2;
	static constexpr reg r3 = reg::r3;
	static constexpr reg r4 = reg::r4;
	static constexpr reg r5 = reg::r5;
	static constexpr reg r6 = reg::r6;
	static constexpr reg r7 = reg::r7;
	static constexpr reg r8 = reg::r8;
	static constexpr reg r9 = reg::r9;
	static constexpr reg r10 = reg::r10;
	static constexpr reg r11 = reg::r11;
	static constexpr reg r12 = reg::r12;
	static constexpr reg r13 = reg::r13;
	static constexpr reg r14 = reg::r14;
	static constexpr reg r15 = reg::r15;
	static constexpr reg rax = reg::rax;
	static constexpr reg rcx = reg::rcx;
	static constexpr reg rdx = reg::rdx;
	static constexpr reg rbx = reg::rbx;
	static constexpr reg rsp = reg::rsp;
	static constexpr reg rbp = reg::rbp;
	static constexpr reg rsi = reg::rsi;
	static constexpr reg rdi = reg::rdi;
}

} // namespace core
} // namespace mode64bit
} // namespace encodeasm
