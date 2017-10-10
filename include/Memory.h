#pragma once

// Memory.h:
// EncodeASM memory operand representation implementation.
//
// See LICENSE file for license details.

#include "GeneralRegisters.h"
#include "Types.h"
#include <type_traits>

namespace encodeasm {
namespace mode64bit {

namespace memory {
	/// Type to indicate rip for rip-relative addressing.
	struct instruction_pointer {};

	/// This switches the operand size from 32 bits to 16 bits.
	static constexpr uint8 SIZE_PREFIX = 0x66;

	/// Scale for the index register
	enum class scale : uint8 {
		x1,
		x2,
		x4,
		x8
	};

	/// These are used for allowing a simpler syntax for constructing memory operands.
	/// Hopefully compilers don't get confused and generate slower code when using them,
	/// though I've been awfully disappointed by compilers in the past.
	/// At least if it's in the case where it's being run at compile time, it'll only
	/// mean slightly slower compiling.
	/// @{
	struct scaled_register {
		core::reg r;
		uint8 s;
	};

	constexpr scaled_register operator*(const uint8 scale,const core::reg r) noexcept {
		return scaled_register{r,scale};
	}
	constexpr scaled_register operator*(const core::reg r,const uint8 scale) noexcept {
		return scaled_register{r,scale};
	}

	struct register_plus {
		core::reg r;
		int32 displacement;
	};
	constexpr register_plus operator+(const core::reg r, const int32 displacement) noexcept {
		return register_plus{r,displacement};
	}
	constexpr register_plus operator+(const int32 displacement, const core::reg r) noexcept {
		return register_plus{r,displacement};
	}
	constexpr register_plus operator+(const register_plus &rp, const int32 displacement) noexcept {
		return register_plus{rp.r,rp.displacement+displacement};
	}
	constexpr register_plus operator+(const int32 displacement, const register_plus &rp) noexcept {
		return register_plus{rp.r,rp.displacement+displacement};
	}
	struct scaled_register_plus {
		scaled_register sr;
		int32 displacement;
	};
	constexpr scaled_register_plus operator+(const scaled_register &sr, const int32 displacement) noexcept {
		return scaled_register_plus{sr,displacement};
	}
	constexpr scaled_register_plus operator+(const int32 displacement, const scaled_register &sr) noexcept {
		return scaled_register_plus{sr,displacement};
	}
	constexpr scaled_register_plus operator+(const scaled_register_plus &srp, const int32 displacement) noexcept {
		return scaled_register_plus{srp.sr,srp.displacement+displacement};
	}
	constexpr scaled_register_plus operator+(const int32 displacement, const scaled_register_plus &srp) noexcept {
		return scaled_register_plus{srp.sr,srp.displacement+displacement};
	}
	struct register_scaled_register_plus {
		core::reg base;
		scaled_register scaled_index;
		int32 displacement;
	};
	constexpr register_scaled_register_plus operator+(const core::reg r0, const core::reg r1) noexcept {
		return register_scaled_register_plus{r0,scaled_register{r1,1},0};
	}
	constexpr register_scaled_register_plus operator+(const register_plus &rp0, const register_plus &rp1) noexcept {
		return register_scaled_register_plus{rp0.r,scaled_register{rp1.r,1},rp0.displacement+rp1.displacement};
	}
	constexpr register_scaled_register_plus operator+(const core::reg r, const register_plus &rp) noexcept {
		return register_scaled_register_plus{r,scaled_register{rp.r,1},rp.displacement};
	}
	constexpr register_scaled_register_plus operator+(const register_plus &rp, const core::reg r) noexcept {
		return register_scaled_register_plus{rp.r,scaled_register{r,1},rp.displacement};
	}
	constexpr register_scaled_register_plus operator+(const core::reg r, const scaled_register &sr) noexcept {
		return register_scaled_register_plus{r,sr,0};
	}
	constexpr register_scaled_register_plus operator+(const scaled_register &sr, const core::reg r) noexcept {
		return register_scaled_register_plus{r,sr,0};
	}
	constexpr register_scaled_register_plus operator+(const register_plus &rp, const scaled_register &sr) noexcept {
		return register_scaled_register_plus{rp.r,sr,rp.displacement};
	}
	constexpr register_scaled_register_plus operator+(const scaled_register &sr, const register_plus &rp) noexcept {
		return register_scaled_register_plus{rp.r,sr,rp.displacement};
	}
	constexpr register_scaled_register_plus operator+(const core::reg r, const scaled_register_plus &srp) noexcept {
		return register_scaled_register_plus{r,srp.sr,srp.displacement};
	}
	constexpr register_scaled_register_plus operator+(const scaled_register_plus &srp, const core::reg r) noexcept {
		return register_scaled_register_plus{r,srp.sr,srp.displacement};
	}
	constexpr register_scaled_register_plus operator+(const register_plus &rp, const scaled_register_plus &srp) noexcept {
		return register_scaled_register_plus{rp.r,srp.sr,rp.displacement+srp.displacement};
	}
	constexpr register_scaled_register_plus operator+(const scaled_register_plus &srp, const register_plus &rp) noexcept {
		return register_scaled_register_plus{rp.r,srp.sr,rp.displacement+srp.displacement};
	}
	constexpr register_scaled_register_plus operator+(const register_scaled_register_plus &rsrp, const int32 displacement) noexcept {
		return register_scaled_register_plus{rsrp.base,rsrp.scaled_index,rsrp.displacement+displacement};
	}
	constexpr register_scaled_register_plus operator+(const int32 displacement, const register_scaled_register_plus &rsrp) noexcept {
		return register_scaled_register_plus{rsrp.base,rsrp.scaled_index,rsrp.displacement+displacement};
	}
	/// @}

	namespace os {
		/// This would be difficult to handle properly in one of the OS-related headers,
		/// because it's used in generic functions for encoding memory operands.
		constexpr uint8 getSegmentPrefix(const uint8 segment_number) noexcept {
			// ES: 0 -> 0x26 = 0b00100110
			// CS: 1 -> 0x2E = 0b00101110
			// SS: 2 -> 0x36 = 0b00110110
			// DS: 3 -> 0x3E = 0b00111110
			if (segment_number < 4) {
				return (segment_number<<3) | 0x26;
			}
			// FS: 4 -> 0x64
			// GS: 5 -> 0x65
			return segment_number | 0x60;
		}
	}
}

template<uint32 membytes>
struct alignas(8) MemT {
	/// Number of displacement bytes (0, 1, or 4)
	/// 7 (INVALID_DISP_BYTES) means invalid memory encoding, (e.g. using rsp as an index register)
	uint8 dispbytes:3;
	/// 1 if REX used, else 0
	/// NOTE: This must be the same type as duspbytes and segment_prefix
	///       for the compilers to put them in the same byte.
	uint8 hasrex:1;
	/// 1 if SIB used, else 0
	/// NOTE: This must be the same type as duspbytes and segment_prefix
	///       for the compilers to put them in the same byte.
	uint8 hassib:1;
	/// 0-5 indicate a segment register, 7 (NO_SEGMENT_PREFIX) means no prefix.
	uint8 segment_prefix:3;

	static constexpr uint8 NO_SEGMENT_PREFIX = 7;
	static constexpr uint8 INVALID_DISP_BYTES = 7;

	/// REX byte with 0100WRXB if SIB, else 0100WR0B.
	/// W is 1 if membytes is 8, else 0, though it may be ignored when encoding.  W is 0 if no REX.
	/// This structure doesn't have knowledge of R, so R will be 0.
	/// X is bit 3 of index register if SIB, else 0.  Bit 3 is 0 if no REX.
	/// B is bit 3 of base register.  Bit 3 is 0 if no REX.
	uint8 rex;

	/// Mod-Reg-R/M byte:
	/// high 2 bits mode:
	///     00 no disp (except if mem 101, then rip + disp 4 bytes),
	///     01 disp 1 byte, or
	///     10 disp 4 bytes
	///     (11 not applicable for memory access)
	/// middle 3 bits reg:
	///     000 in this structure, since no knowledge of reg
	/// low 3 bits mem:
	///     100 if has SIB, else base register,
	///     except special case of mode 00 mem 101, for rip + disp 4 bytes
	uint8 modregrm;

	/// Scale-Index-Base byte:
	/// high 2 bits scale (corresponding with memory::scale)
	/// middle 3 bits index register bits 0-2
	/// low 3 bits base register bits 0-2
	uint8 sib;

	/// displacement value (signed integer)
	int32 displacement;

	/// Returns true iff this represented an invalid memory operand,
	/// (e.g. using rsp as an index register)
	constexpr bool hasError() const noexcept {
		return dispbytes == INVALID_DISP_BYTES;
	}

	/// Returns true iff this memory operand has a segment prefix.
	constexpr bool hasSegmentPrefix() const noexcept {
		return segment_prefix != NO_SEGMENT_PREFIX;
	}

	/// Default constructor must be trivial for MemT to be a POD type,
	/// and trivial default constructors can't be constexpr if there are
	/// non-static data members, unfortunately.
	MemT() = default;

	struct zero_init_tag { constexpr zero_init_tag() = default; };
	struct invalid_init_tag { constexpr invalid_init_tag() = default; };

	/// Use this constructor if you need something like a default constructor in constexpr code.
	constexpr MemT(zero_init_tag) noexcept :
		dispbytes(0),
		hasrex(false),
		hassib(false),
		segment_prefix(0),
		rex(0),
		modregrm(0),
		sib(0),
		displacement(0)
	{
		static_assert(sizeof(MemT<membytes>)==8,"The size of MemT should be 8 bytes, so that it fits in a single general register.");
		static_assert(std::is_pod<MemT<membytes> >::value,"MemT should be a POD (Plain Old Data) type, so that compilers can optimize for it more easily.");
	}

	constexpr MemT(invalid_init_tag) noexcept :
		dispbytes(INVALID_DISP_BYTES),
		hasrex(false),
		hassib(false),
		segment_prefix(0),
		rex(0),
		modregrm(0),
		sib(0),
		displacement(0)
	{}

	constexpr MemT(const MemT &) = default;
	constexpr MemT(MemT &&) = default;
	constexpr MemT &operator=(const MemT &) = default;
	constexpr MemT &operator=(MemT &&) = default;
	constexpr bool operator==(const MemT &that) noexcept {
		return dispbytes == that.dispbytes &&
			hasrex == that.hasrex &&
			hassib == that.hassib &&
			segment_prefix == that.segment_prefix &&
			rex == that.rex &&
			modregrm == that.modregrm &&
			sib == that.sib &&
			displacement == that.displacement;
	}
	constexpr bool operator!=(const MemT &that) noexcept {
		return !(*this == that);
	}

	/// [imm32]
	explicit constexpr MemT(int32 displacement_) noexcept :
		dispbytes(4),
		hasrex(membytes == 8),
		hassib(true), // Unlike in 32-bit mode, encoding just a displacement (not rip-relative) requires an SIB byte.
		segment_prefix(NO_SEGMENT_PREFIX),
		rex((membytes == 8) ? 0x48 : 0x40),
		modregrm(0b00000100),
		sib(0b00100101),
		displacement(displacement_)
	{}
	/// [reg]
	explicit constexpr MemT(core::reg base) noexcept : MemT(zero_init_tag()) {
		segment_prefix = NO_SEGMENT_PREFIX;
		rex = ((membytes == 8) ? 0x48 : 0x40) | (uint8(base)>>3);
		const uint8 rm = (uint8(base) & 0b111);
		if (rm == 0b100) {
			modregrm = 0b00000100;
			sib = 0b00100100;
			dispbytes = 0;
			hassib = true;
		}
		else if (rm == 0b101) {
			modregrm = 0b01000101;
			sib = 0;
			dispbytes = 1;
			hassib = false;
		}
		else {
			modregrm = rm;
			sib = 0;
			dispbytes = 0;
			hassib = false;
		}
		hasrex = (membytes == 8) || (uint8(base) & 0b1000);
		displacement = 0;
	}
	/// [reg+imm8]
	constexpr MemT(core::reg base, int8 displacement_) noexcept : MemT(zero_init_tag()) {
		segment_prefix = NO_SEGMENT_PREFIX;
		rex = ((membytes == 8) ? 0x48 : 0x40) | (uint8(base)>>3);
		const uint8 rm = (uint8(base) & 0b111);
		if (rm == 0b100) {
			modregrm = 0b01000100;
			sib = 0b00100100;
			hassib = true;
		}
		else {
			modregrm = 0b01000000 | rm;
			sib = 0;
			hassib = false;
		}
		hasrex = (membytes == 8) || (uint8(base) & 0b1000);
		dispbytes = 1;
		displacement = displacement_;
	}
	/// [reg+imm32]
	constexpr MemT(core::reg base, int32 displacement_) noexcept : MemT(zero_init_tag()) {
		segment_prefix = NO_SEGMENT_PREFIX;
		rex = ((membytes == 8) ? 0x48 : 0x40) | (uint8(base)>>3);
		const uint8 rm = (uint8(base) & 0b111);
		if (rm == 0b100) {
			modregrm = 0b10000100;
			sib = 0b00100100;
			hassib = true;
		}
		else {
			modregrm = 0b10000000 | rm;
			sib = 0;
			hassib = false;
		}
		hasrex = (membytes == 8) || (uint8(base) & 0b1000);
		dispbytes = 4;
		displacement = displacement_;
	}
	/// [reg+reg]
	constexpr MemT(core::reg base, core::reg index) noexcept
		: MemT(base, index, memory::scale::x1)
	{}
	/// [reg+reg+imm8]
	constexpr MemT(core::reg base, core::reg index, int8 displacement) noexcept
		: MemT(base, index, memory::scale::x1, displacement)
	{}
	/// [reg+reg+imm32]
	constexpr MemT(core::reg base, core::reg index, int32 displacement) noexcept
		: MemT(base, index, memory::scale::x1, displacement)
	{}

private:
	/// NOTE: This is intentionally *not* constexpr, to produce a compile
	///       error if hit at compile time.
	void error_rsp_cant_be_memory_index_register_only_base_register() noexcept {
		// This indicates the error at run time.
		dispbytes = INVALID_DISP_BYTES;
	}
public:
	/// [reg + reg*scale]
	constexpr MemT(core::reg base, core::reg index, memory::scale index_scale) noexcept : MemT(zero_init_tag()) {
		hassib = true;
		segment_prefix = NO_SEGMENT_PREFIX;
		// NOTE: rsp can't be an index, but r12 can be, and rsp can be a base.
		if (index == core::reg::rsp) {
			modregrm = 0b00000100;
			dispbytes = 0;
			if (index_scale == memory::scale::x1 && base != core::reg::rsp) {
				// Swap base (now rsp) and index (now not rsp)
				sib = (uint8(index_scale)<<6) | ((uint8(base) & 0b111)<<3) | 0b100;
				rex = ((membytes == 8) ? 0x48 : 0x40) | ((uint8(base)&0b1000)>>2);
				hasrex = (membytes == 8) || (rex !=  0x40);
			}
			else {
				// Caller asked for rsp to be scaled, for which there is
				// no encoding, so error.  This produces a compile-time error
				// if this is being called at compile-time, because the
				// function here is not constexpr.
				// NOTE: DO NOT assign to dispbytes after this!
				error_rsp_cant_be_memory_index_register_only_base_register();

				// Initialize the rest, just in case, even though it's not valid.
				sib = (uint8(index_scale)<<6) | 0b00100000 | (uint8(base) & 0b111);
				rex = ((membytes == 8) ? 0x48 : 0x40) | (uint8(base)>>3);
				hasrex = (membytes == 8) || (rex !=  0x40);
			}
		}
		else {
			const uint8 rm = (uint8(base) & 0b111);
			if (rm == 0b101) {
				modregrm = 0b01000100;
				dispbytes = 1;
			}
			else {
				modregrm = 0b00000100;
				dispbytes = 0;
			}
			sib = (uint8(index_scale)<<6) | ((uint8(index) & 0b111)<<3) | rm;
			rex = ((membytes == 8) ? 0x48 : 0x40) | ((uint8(index)&0b1000)>>2) | (uint8(base)>>3);
			hasrex = (membytes == 8) || (rex !=  0x40);
		}
		displacement = 0;
	}
	/// [reg + reg*scale + imm8]
	constexpr MemT(core::reg base, core::reg index, memory::scale index_scale, int8 displacement_) noexcept : MemT(zero_init_tag()) {
		dispbytes = 1;
		hassib = true;
		segment_prefix = NO_SEGMENT_PREFIX;
		modregrm = 0b01000100;
		// NOTE: rsp can't be an index, but r12 can be, and rsp can be a base.
		if (index == core::reg::rsp) {
			if (index_scale == memory::scale::x1 && base != core::reg::rsp) {
				// Swap base (now rsp) and index (now not rsp)
				sib = (uint8(index_scale)<<6) | ((uint8(base) & 0b111)<<3) | 0b100;
				rex = ((membytes == 8) ? 0x48 : 0x40) | ((uint8(base)&0b1000)>>2);
				hasrex = (membytes == 8) || (rex !=  0x40);
			}
			else {
				// Caller asked for rsp to be scaled, for which there is
				// no encoding, so error.  This produces a compile-time error
				// if this is being called at compile-time, because the
				// function here is not constexpr.
				// NOTE: DO NOT assign to dispbytes after this!
				error_rsp_cant_be_memory_index_register_only_base_register();

				// Initialize the rest, just in case, even though it's not valid.
				sib = (uint8(index_scale)<<6) | 0b00100000 | (uint8(base) & 0b111);
				rex = ((membytes == 8) ? 0x48 : 0x40) | (uint8(base)>>3);
				hasrex = (membytes == 8) || (rex !=  0x40);
			}
		}
		else {
			sib = (uint8(index_scale)<<6) | ((uint8(index) & 0b111)<<3) | (uint8(base) & 0b111);
			rex = ((membytes == 8) ? 0x48 : 0x40) | ((uint8(index)&0b1000)>>2) | (uint8(base)>>3);
			hasrex = (membytes == 8) || (rex !=  0x40);
		}
		displacement = displacement_;
	}
	/// [reg + reg*scale + imm32]
	constexpr MemT(core::reg base, core::reg index, memory::scale index_scale, int32 displacement_) noexcept : MemT(zero_init_tag()) {
		dispbytes = 4;
		hassib = true;
		segment_prefix = NO_SEGMENT_PREFIX;
		modregrm = 0b10000100;
		// NOTE: rsp can't be an index, but r12 can be, and rsp can be a base.
		if (index == core::reg::rsp) {
			if (index_scale == memory::scale::x1 && base != core::reg::rsp) {
				// Swap base (now rsp) and index (now not rsp)
				sib = (uint8(index_scale)<<6) | ((uint8(base) & 0b111)<<3) | 0b100;
				rex = ((membytes == 8) ? 0x48 : 0x40) | ((uint8(base)&0b1000)>>2);
				hasrex = (membytes == 8) || (rex !=  0x40);
			}
			else {
				// Caller asked for rsp to be scaled, for which there is
				// no encoding, so error.  This produces a compile-time error
				// if this is being called at compile-time, because the
				// function here is not constexpr.
				// NOTE: DO NOT assign to dispbytes after this!
				error_rsp_cant_be_memory_index_register_only_base_register();

				// Initialize the rest, just in case, even though it's not valid.
				sib = (uint8(index_scale)<<6) | 0b00100000 | (uint8(base) & 0b111);
				rex = ((membytes == 8) ? 0x48 : 0x40) | (uint8(base)>>3);
				hasrex = (membytes == 8) || (rex !=  0x40);
			}
		}
		else {
			sib = (uint8(index_scale)<<6) | ((uint8(index) & 0b111)<<3) | (uint8(base) & 0b111);
			rex = ((membytes == 8) ? 0x48 : 0x40) | ((uint8(index)&0b1000)>>2) | (uint8(base)>>3);
			hasrex = (membytes == 8) || (rex !=  0x40);
		}
		displacement = displacement_;
	}
	/// [reg*scale]
	constexpr MemT(core::reg index, memory::scale index_scale) noexcept : MemT(zero_init_tag()) {
		// If scale is 1 or 2, we can avoid the redundant imm32
		if (index_scale == memory::scale::x1) {
			*this = MemT(index);
		}
		else if (index_scale == memory::scale::x2) {
			*this = MemT(index, index, memory::scale::x1);
		}
		else {
			*this = MemT(index, index_scale, int32(0));
		}
	}
	/// [reg*scale + imm8]
	constexpr MemT(core::reg index, memory::scale index_scale, int8 displacement_) noexcept : MemT(zero_init_tag()) {
		if (index_scale == memory::scale::x1) {
			// If scale is 1, we can avoid the SIB and use imm8 instead of imm32
			*this = MemT(index, displacement_);
		}
		else {
			*this = MemT(index, index_scale, int32(displacement_));
		}
	}
	/// [reg*scale + imm32]
	constexpr MemT(core::reg index, memory::scale index_scale, int32 displacement_) noexcept : MemT(zero_init_tag()) {
		if (index_scale == memory::scale::x1) {
			// If scale is 1, we can avoid the SIB
			*this = MemT(index, displacement_);
		}
		else {
			segment_prefix = NO_SEGMENT_PREFIX;
			hasrex = (membytes == 8);
			hassib = true;
			dispbytes = 4;
			rex = (membytes == 8) ? 0x48 : 0x40;
			modregrm = 0b00000100;
			sib = (uint8(index_scale)<<6) | ((uint8(index) & 0b111)<<3) | 0b101;
			displacement = displacement_;
			if (index == core::reg::rsp) {
				// Caller asked for rsp to be scaled, for which there is
				// no encoding, so error.  This produces a compile-time error
				// if this is being called at compile-time, because the
				// function here is not constexpr.
				// NOTE: DO NOT assign to dispbytes after this!
				error_rsp_cant_be_memory_index_register_only_base_register();
			}
		}
	}
	/// [rip + imm32]
	constexpr MemT(memory::instruction_pointer rip, int32 displacement_) noexcept :
		dispbytes(4),
		hasrex(membytes == 8),
		hassib(false),
		segment_prefix(NO_SEGMENT_PREFIX),
		rex((membytes == 8) ? 0x48 : 0x40),
		modregrm(0b00000101),
		sib(0),
		displacement(displacement_)
	{}

private:
	/// NOTE: This is intentionally *not* constexpr, to produce a compile
	///       error if hit at compile time.
	void error_invalid_index_register_scale_for_memory_operand() noexcept {
		// This indicates the error at run time.
		dispbytes = INVALID_DISP_BYTES;
	}
public:
	/// [reg*scale]
	constexpr explicit MemT(memory::scaled_register sr) noexcept : MemT(zero_init_tag()) {
		using namespace memory;
		switch (sr.s) {
			case 1: {
				*this = MemT(sr.r);
				return;
			}
			case 2: {
				*this = MemT(sr.r,sr.r);
				return;
			}
			case 3: {
				*this = MemT(sr.r,sr.r,scale::x2);
				return;
			}
			case 4: {
				*this = MemT(sr.r,scale::x4);
				return;
			}
			case 5: {
				*this = MemT(sr.r,sr.r,scale::x4);
				return;
			}
			case 8: {
				*this = MemT(sr.r,scale::x8);
				return;
			}
			case 9: {
				*this = MemT(sr.r,sr.r,scale::x8);
				return;
			}
			default: {
				error_invalid_index_register_scale_for_memory_operand();
				return;
			}
		}
	}
	/// [reg*scale + imm8]
	constexpr MemT(memory::scaled_register sr, int8 displacement_) noexcept : MemT(zero_init_tag()) {
		using namespace memory;
		switch (sr.s) {
			case 1: {
				*this = MemT(sr.r,displacement_);
				return;
			}
			case 2: {
				*this = MemT(sr.r,sr.r,displacement_);
				return;
			}
			case 3: {
				*this = MemT(sr.r,sr.r,scale::x2,displacement_);
				return;
			}
			case 4: {
				*this = MemT(sr.r,scale::x4,displacement_);
				return;
			}
			case 5: {
				*this = MemT(sr.r,sr.r,scale::x4,displacement_);
				return;
			}
			case 8: {
				*this = MemT(sr.r,scale::x8,displacement_);
				return;
			}
			case 9: {
				*this = MemT(sr.r,sr.r,scale::x8,displacement_);
				return;
			}
			default: {
				error_invalid_index_register_scale_for_memory_operand();
				return;
			}
		}
	}
	/// [reg*scale + imm32]
	constexpr MemT(memory::scaled_register sr, int32 displacement_) noexcept : MemT(zero_init_tag()) {
		using namespace memory;
		switch (sr.s) {
			case 1: {
				*this = MemT(sr.r,displacement_);
				return;
			}
			case 2: {
				*this = MemT(sr.r,sr.r,displacement_);
				return;
			}
			case 3: {
				*this = MemT(sr.r,sr.r,scale::x2,displacement_);
				return;
			}
			case 4: {
				*this = MemT(sr.r,scale::x4,displacement_);
				return;
			}
			case 5: {
				*this = MemT(sr.r,sr.r,scale::x4,displacement_);
				return;
			}
			case 8: {
				*this = MemT(sr.r,scale::x8,displacement_);
				return;
			}
			case 9: {
				*this = MemT(sr.r,sr.r,scale::x8,displacement_);
				return;
			}
			default: {
				error_invalid_index_register_scale_for_memory_operand();
				return;
			}
		}
	}
	/// [reg + reg*scale]
	constexpr MemT(core::reg r, memory::scaled_register sr) noexcept : MemT(zero_init_tag()) {
		using namespace memory;
		scale s = scale::x1; // Redundant initialization required by constexpr
		switch (sr.s) {
			case 1: s = scale::x1; break;
			case 2: s = scale::x2; break;
			case 4: s = scale::x4; break;
			case 8: s = scale::x8; break;
			default:
				error_invalid_index_register_scale_for_memory_operand();
				return;
		}
		*this = MemT(r, sr.r, s);
	}
	/// [reg + reg*scale + imm8]
	constexpr MemT(core::reg r, memory::scaled_register sr, int8 displacement_) noexcept : MemT(zero_init_tag()) {
		using namespace memory;
		scale s = scale::x1; // Redundant initialization required by constexpr
		switch (sr.s) {
		case 1: s = scale::x1; break;
		case 2: s = scale::x2; break;
		case 4: s = scale::x4; break;
		case 8: s = scale::x8; break;
		default:
			error_invalid_index_register_scale_for_memory_operand();
			return;
		}
		*this = MemT(r, sr.r, s, displacement_);
	}
	/// [reg + reg*scale + imm8]
	constexpr MemT(core::reg r, memory::scaled_register sr, int32 displacement_) noexcept : MemT(zero_init_tag()) {
		using namespace memory;
		scale s = scale::x1; // Redundant initialization required by constexpr
		switch (sr.s) {
		case 1: s = scale::x1; break;
		case 2: s = scale::x2; break;
		case 4: s = scale::x4; break;
		case 8: s = scale::x8; break;
		default:
			error_invalid_index_register_scale_for_memory_operand();
			return;
		}
		*this = MemT(r, sr.r, s, displacement_);
	}

	constexpr explicit MemT(const memory::register_plus &rp) noexcept : MemT(zero_init_tag()) {
		if (rp.displacement == 0) {
			*this = MemT(rp.r);
		}
		else if (rp.displacement <= 127 && rp.displacement >= -128) {
			*this = MemT(rp.r,int8(rp.displacement));
		}
		else {
			*this = MemT(rp.r,rp.displacement);
		}
	}
	constexpr explicit MemT(const memory::scaled_register_plus &srp) noexcept : MemT(zero_init_tag()) {
		if (srp.displacement == 0) {
			*this = MemT(srp.sr);
		}
		else if (srp.displacement <= 127 && srp.displacement >= -128) {
			*this = MemT(srp.sr,int8(srp.displacement));
		}
		else {
			*this = MemT(srp.sr,srp.displacement);
		}
	}
	constexpr explicit MemT(const memory::register_scaled_register_plus &rsrp) noexcept : MemT(zero_init_tag()) {
		if (rsrp.displacement == 0) {
			*this = MemT(rsrp.base,rsrp.scaled_index);
		}
		else if (rsrp.displacement <= 127 && rsrp.displacement >= -128) {
			*this = MemT(rsrp.base,rsrp.scaled_index,int8(rsrp.displacement));
		}
		else {
			*this = MemT(rsrp.base,rsrp.scaled_index,rsrp.displacement);
		}
	}

protected:
	/// NOTE: This is only used for converting from Mem to MemT<membytes>,
	///       but since Mem inherits from MemT<0>, and we already have a
	///       copy constructor above, we need this constructor to have
	///       a non-zero value in the template argument when membytes is 0.
	constexpr explicit MemT(const MemT<membytes ? 0 : 1> &that) noexcept :
		dispbytes(that.dispbytes),
		hasrex(that.hasrex || (membytes == 8)),
		hassib(that.hassib),
		segment_prefix(that.segment_prefix),
		rex(that.rex | ((membytes == 8) ? 0x48 : 0)),
		modregrm(that.modregrm),
		sib(that.sib),
		displacement(that.displacement)
	{}
	friend struct Mem;
};

struct alignas(8) Mem : public MemT<0> {
	using MemT<0>::MemT;

	/// NOTE: This is intentionally not explicit, so that if the conversion is unambiguous,
	///       it will be automatic, and if it's ambiguous, it will be a compile error.
	template <uint32 membytes>
	constexpr operator MemT<membytes>() noexcept {
		static_assert(sizeof(Mem)==8,"The size of Mem should be 8 bytes, so that it fits in a single general register.");
		static_assert(std::is_pod<Mem>::value,"Mem should be a POD (Plain Old Data) type, so that compilers can optimize for it more easily.");
		return MemT<membytes>(*this);
	}
};

} // namespace mode64bit
} // namespace encodeasm
