#pragma once

// Types.h:
// EncodeASM type declarations, including forward declarations, for convenience.
//
// See LICENSE file for license details.

namespace encodeasm {
	using uint8 = unsigned char;
	using int8 = signed char;
	using uint16 = unsigned short int;
	using int16 = signed short int;
	using uint32 = unsigned int;
	using int32 = signed int;
	using uint64 = unsigned long long int;
	using int64 = signed long long int;

	struct Instruction;

	namespace mode64bit {
		namespace memory {
			struct instruction_pointer;
			struct scaled_register;
			struct register_plus;
			struct scaled_register_plus;
			struct register_scaled_register_plus;
		}
		template<uint32 membytes>
		struct MemT;
		struct Mem;
	}
}
