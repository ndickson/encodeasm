#pragma once

// Instruction.h:
// EncodeASM encoded x86/x64 instruction representation implementation.
//
// See LICENSE file for license details.

#include "Types.h"
#include <initializer_list>
#include <type_traits>

namespace encodeasm {

/// An instruction encoded in machine code, or an error, line label,
/// alignment statement, or unresolved jump (short or near).
struct alignas(16) Instruction {
	/// The maximum allowed length of an x86 instruction is 15 bytes.
	/// The longest instruction possible with AVX-512 without redundant
	/// prefix bytes is 14 bytes, so we should be safe.
	/// 15 is also chosen here so that sizeof(Instruction)==16.
	static constexpr uint8 MAX_LENGTH = 15;

	/// First byte is length of instruction in the rest of the bytes.
	uint8 length;
	uint8 bytes[MAX_LENGTH];

	/// Default constructor must be trivial for Instruction to be a POD type,
	/// and trivial default constructors can't be constexpr if there are
	/// non-static data members, unfortunately.
	Instruction() = default;

	constexpr Instruction(const Instruction&) = default;
	constexpr Instruction(Instruction&&) = default;
	constexpr Instruction& operator=(const Instruction&) = default;
	constexpr Instruction& operator=(Instruction&&) = default;

	explicit constexpr Instruction(uint8 byte0) noexcept : length(1), bytes{byte0} {}
	constexpr Instruction(uint8 byte0, uint8 byte1) noexcept : length(2), bytes{byte0,byte1} {}
	constexpr Instruction(uint8 byte0, uint8 byte1, uint8 byte2) noexcept : length(3), bytes{byte0,byte1,byte2} {}
	constexpr Instruction(uint8 byte0, uint8 byte1, uint8 byte2, uint8 byte3) noexcept : length(4), bytes{byte0,byte1,byte2,byte3} {}
	constexpr Instruction(uint8 byte0, uint8 byte1, uint8 byte2, uint8 byte3, uint8 byte4) noexcept : length(5), bytes{byte0,byte1,byte2,byte3,byte4} {}
	constexpr Instruction(uint8 byte0, uint8 byte1, uint8 byte2, uint8 byte3, uint8 byte4, uint8 byte5) noexcept : length(6), bytes{byte0,byte1,byte2,byte3,byte4,byte5} {}
	constexpr Instruction(uint8 byte0, uint8 byte1, uint8 byte2, uint8 byte3, uint8 byte4, uint8 byte5, uint8 byte6) noexcept : length(7), bytes{byte0,byte1,byte2,byte3,byte4,byte5,byte6} {}
	constexpr Instruction(uint8 byte0, uint8 byte1, uint8 byte2, uint8 byte3, uint8 byte4, uint8 byte5, uint8 byte6, uint8 byte7) noexcept : length(8), bytes{byte0,byte1,byte2,byte3,byte4,byte5,byte6,byte7} {}
	constexpr Instruction(uint8 byte0, uint8 byte1, uint8 byte2, uint8 byte3, uint8 byte4, uint8 byte5, uint8 byte6, uint8 byte7, uint8 byte8) noexcept : length(9), bytes{byte0,byte1,byte2,byte3,byte4,byte5,byte6,byte7,byte8} {}
	constexpr Instruction(uint8 byte0, uint8 byte1, uint8 byte2, uint8 byte3, uint8 byte4, uint8 byte5, uint8 byte6, uint8 byte7, uint8 byte8, uint8 byte9) noexcept : length(10), bytes{byte0,byte1,byte2,byte3,byte4,byte5,byte6,byte7,byte8,byte9} {}

	template<typename T>
	constexpr Instruction(std::initializer_list<T> in_bytes) noexcept : length(in_bytes.size()), bytes(in_bytes) {}

	struct zero_init_tag { constexpr zero_init_tag() = default; };
	struct align_init_tag { constexpr align_init_tag() = default; };
	struct jump_init_tag { constexpr jump_init_tag() = default; };
	struct jump_short_init_tag { constexpr jump_short_init_tag() = default; };
	struct jump_near_init_tag { constexpr jump_near_init_tag() = default; };
	struct line_label_init_tag { constexpr line_label_init_tag() = default; };
	struct error_init_tag { constexpr error_init_tag() = default; };

	/// Use one of this constructors if you need something like a default constructor in constexpr code.
	/// Zero-length instruction won't be anything, but won't be invalid.
	constexpr Instruction(zero_init_tag) noexcept : length(0), bytes() {
		static_assert(sizeof(Instruction)==16, "The size of Instruction should be 16 bytes, so that it fits in a single SSE register.");
		static_assert(std::is_pod<Instruction>::value,"Instruction should be a POD (Plain Old Data) type, so that compilers can optimize for it more easily.");
	}

	/// Returns true if this is a fully-encoded instruction, as opposed to an
	/// error, line label, unresolved jump, or alignment statement.
	constexpr bool isFinal() const noexcept {
		return length <= MAX_LENGTH;
	}

	/// If length is equal to this, this an alignment statement.
	/// bytes[0] is the exponent of the power of 2 to which this
	/// should align the following code, e.g. 0 for 1-byte alignment (none),
	/// 4 for 16-byte alignment.
	static constexpr uint8 ALIGN_LENGTH = 0xFA;

	/// If length is equal to this, this an unresolved jump instruction
	/// that might be a short jump (2 bytes) or a near jump (5-7 bytes for
	/// 64-bit and 32-bit modes, and 3-5 bytes for 16-bit mode).
	/// bytes[0] is the hint prefix if any, else 0.
	/// bytes[1] is the opcode for a short jump
	/// bytes[2] is the first byte of the opcode for a near jump.
	/// bytes[3] If bytes[2] is 0x0F (conditional jump), this is the second byte
	///          of the opcode for a near jump.
	/// A pointer to the jump target label name is aligned to the end of bytes.
	/// This struct does not own the string.
	static constexpr uint8 JUMP_LENGTH = 0xFB;

	/// If length is equal to this, this an unresolved jump instruction
	/// that must be in range for a short jump, else an error will be produced later.
	/// This layout lines up with the layout for JUMP_LENGTH.
	/// bytes[0] is the hint prefix if any, else 0.
	/// bytes[1] is the opcode for a short jump
	/// A pointer to the jump target label name is aligned to the end of bytes.
	/// This struct does not own the string.
	static constexpr uint8 JUMP_SHORT_LENGTH = 0xFC;

	/// If length is equal to this, this an unresolved jump instruction
	/// that is forced to be encoded as a near jump.
	/// This layout lines up with the layout for JUMP_LENGTH.
	/// bytes[0] is the hint prefix if any, else 0.
	/// bytes[2] is the first byte of the opcode.
	/// bytes[3] If bytes[2] is 0x0F (conditional jump), this is the second byte
	///          of the opcode.
	/// A pointer to the jump target label name is aligned to the end of bytes.
	/// This struct does not own the string.
	static constexpr uint8 JUMP_NEAR_LENGTH = 0xFD;

	/// If length is equal to this, this a line label.
	/// A pointer to the label name is aligned to the end of bytes.
	/// This struct does not own the string.
	static constexpr uint8 LINE_LABEL_LENGTH = 0xFE;

	/// If length is equal to this, this represents an assembly error message.
	/// A pointer to the error message is aligned to the end of bytes.
	/// This struct does not own the string.
	static constexpr uint8 ERROR_LENGTH = 0xFF;

private:
	constexpr const char** getStringPtr() const noexcept {
		return (const char**)(bytes+MAX_LENGTH-sizeof(const char*));
	}
public:
	constexpr Instruction(error_init_tag, const char*const error_message) noexcept : length(ERROR_LENGTH), bytes() {
		*getStringPtr() = error_message;
	}

	static constexpr Instruction createError(const char*const error_message) noexcept {
		return Instruction(error_init_tag(), error_message);
	}

	constexpr Instruction(line_label_init_tag, const char*const label) noexcept : length(LINE_LABEL_LENGTH),bytes() {
		*getStringPtr() = label;
	}

	static constexpr Instruction createLineLabel(const char* label) noexcept {
		return Instruction(line_label_init_tag(), label);
	}

	constexpr Instruction(jump_init_tag, const char*const target_label, const uint8 short_opcode, const uint8 near_opcode0, const uint8 near_opcode1=0, const uint8 prefix=0) noexcept :
		length(JUMP_LENGTH), bytes{prefix,short_opcode,near_opcode0,near_opcode1} {
		*getStringPtr() = target_label;
	}

	constexpr Instruction(jump_short_init_tag, const char*const target_label, const uint8 short_opcode, const uint8 prefix=0) noexcept :
		length(JUMP_SHORT_LENGTH), bytes{prefix, short_opcode} {
		*getStringPtr() = target_label;
	}

	constexpr Instruction(jump_near_init_tag, const char*const target_label, const uint8 near_opcode0, const uint8 near_opcode1=0, const uint8 prefix=0) noexcept :
		length(JUMP_NEAR_LENGTH), bytes{prefix,0,near_opcode0,near_opcode1} {
		*getStringPtr() = target_label;
	}

private:
	/// NOTE: These are intentionally *not* constexpr, to produce a compile
	///       error if hit at compile time.
	/// @{
	static inline void error_cant_align_to_larger_than_4K() noexcept {}
	static inline void error_alignment_must_be_a_power_of_two() noexcept {}
	/// @}
#ifdef __GNUC__
	static constexpr uint8 ilog2(const uint32 input) {
		if (input == 0) {
			return uint8(0);
		}
		return uint8(31^__builtin_clz(input));
	}
#else
	static constexpr uint8 ilog2(uint32 input) {
		// NOTE: Although there should be a special case using _BitScanReverse
		//       in Visual C++, it isn't allowed in constexpr code, sadly,
		//       so we fall back to the slow version, for compilers with no
		//       usable intrinsic.
		// unsigned long bit_index = 0;
		// unsigned char nonzero = _BitScanReverse(&bit_index,input);
		// return uint8(bit_index);

		uint8 bit_index = 0;
		if (input > 0xFFFF) {
			bit_index += 16;
			input >>= 16;
		}
		if (input > 0xFF) {
			bit_index += 8;
			input >>= 8;
		}
		if (input > 0xF) {
			bit_index += 4;
			input >>= 4;
		}
		if (input > 0x3) {
			bit_index += 2 + (input >> 3);
		}
		else {
			bit_index += (input >> 1);
		}
		return bit_index;
	}
#endif
public:
	constexpr Instruction(align_init_tag, const uint32 alignment_in_bytes) noexcept : length(ALIGN_LENGTH), bytes{ilog2(alignment_in_bytes)} {
		if (alignment_in_bytes == 0 || ((alignment_in_bytes-1)&alignment_in_bytes) != 0) {
			error_alignment_must_be_a_power_of_two();
			*this = createError("Can't align to a size that isn't a power of 2");
		}
		else if (alignment_in_bytes > 0x1000) {
			error_cant_align_to_larger_than_4K();
			*this = createError("Can't align to a power of 2 greater than 4096 (i.e. 2 to the power of 12)");
		}
	}

private:
	/// NOTE: This is intentionally *not* constexpr, to produce a compile
	///       error if hit at compile time.
	static inline const char* error_Instruction_only_has_string_for_jumps_labels_and_errors() noexcept {
		return nullptr;
	}
public:
	/// For jumps, labels, or errors, this gets the associated string, else this shouldn't be called,
	/// though if it's called at run time, it will return null in other cases.
	constexpr const char* getString() const noexcept {
		if (length < JUMP_LENGTH) {
			return error_Instruction_only_has_string_for_jumps_labels_and_errors();
		}
		return *getStringPtr();
	}

	/// NOTE: Caller should already have checked is_valid()
	constexpr uint8* copyTo(uint8* destination) const noexcept {
		for (int i = 0; i != length; ++i) {
			destination[i] = bytes[i];
		}
		return destination+length;
	}
};

/// Line label custom string literal suffix.
/// This let's you do things like "loop_start"_label to create a line label.
static constexpr Instruction operator "" _label(const char*const label) {
	return Instruction::createLineLabel(label);
}

static constexpr Instruction ALIGN(const uint32 alignment_in_bytes) {
	return Instruction(Instruction::align_init_tag(), alignment_in_bytes);
}
}
