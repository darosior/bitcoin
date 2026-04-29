// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifdef ENABLE_AVX512

#include <array>
#include <cstdint>
#include <immintrin.h>

#include <attributes.h>
#include <crypto/common.h>
#include <crypto/sha256d.h>

namespace sha256d64_avx512 {
struct Ops {
    using Int = __m512i;

    static __m512i ALWAYS_INLINE K(uint32_t x) { return _mm512_set1_epi32(x); }

    static __m512i ALWAYS_INLINE Add(__m512i x, __m512i y) { return _mm512_add_epi32(x, y); }
    static __m512i ALWAYS_INLINE Xor(__m512i x, __m512i y) { return _mm512_xor_si512(x, y); }
    static __m512i ALWAYS_INLINE Or(__m512i x, __m512i y) { return _mm512_or_si512(x, y); }
    static __m512i ALWAYS_INLINE And(__m512i x, __m512i y) { return _mm512_and_si512(x, y); }
    static __m512i ALWAYS_INLINE ShR(__m512i x, int n) { return _mm512_srli_epi32(x, n); }
    static __m512i ALWAYS_INLINE ShL(__m512i x, int n) { return _mm512_slli_epi32(x, n); }

    static __m512i ALWAYS_INLINE Read(const unsigned char* chunk, int offset) {
        return _mm512_set_epi32(
            ReadBE32(chunk + 64 * 0 + offset),
            ReadBE32(chunk + 64 * 1 + offset),
            ReadBE32(chunk + 64 * 2 + offset),
            ReadBE32(chunk + 64 * 3 + offset),
            ReadBE32(chunk + 64 * 4 + offset),
            ReadBE32(chunk + 64 * 5 + offset),
            ReadBE32(chunk + 64 * 6 + offset),
            ReadBE32(chunk + 64 * 7 + offset),
            ReadBE32(chunk + 64 * 8 + offset),
            ReadBE32(chunk + 64 * 9 + offset),
            ReadBE32(chunk + 64 * 10 + offset),
            ReadBE32(chunk + 64 * 11 + offset),
            ReadBE32(chunk + 64 * 12 + offset),
            ReadBE32(chunk + 64 * 13 + offset),
            ReadBE32(chunk + 64 * 14 + offset),
            ReadBE32(chunk + 64 * 15 + offset)
        );
    }

    static void ALWAYS_INLINE Write(unsigned char* out, int offset, __m512i v) {
        alignas(64) std::array<uint32_t, 16> lanes;
        _mm512_store_si512(lanes.data(), v);
        WriteBE32(out + 32 * 0 + offset, lanes[15]);
        WriteBE32(out + 32 * 1 + offset, lanes[14]);
        WriteBE32(out + 32 * 2 + offset, lanes[13]);
        WriteBE32(out + 32 * 3 + offset, lanes[12]);
        WriteBE32(out + 32 * 4 + offset, lanes[11]);
        WriteBE32(out + 32 * 5 + offset, lanes[10]);
        WriteBE32(out + 32 * 6 + offset, lanes[9]);
        WriteBE32(out + 32 * 7 + offset, lanes[8]);
        WriteBE32(out + 32 * 8 + offset, lanes[7]);
        WriteBE32(out + 32 * 9 + offset, lanes[6]);
        WriteBE32(out + 32 * 10 + offset, lanes[5]);
        WriteBE32(out + 32 * 11 + offset, lanes[4]);
        WriteBE32(out + 32 * 12 + offset, lanes[3]);
        WriteBE32(out + 32 * 13 + offset, lanes[2]);
        WriteBE32(out + 32 * 14 + offset, lanes[1]);
        WriteBE32(out + 32 * 15 + offset, lanes[0]);
    }
};

void Transform_16way(unsigned char* out, const unsigned char* in)
{
    SHA256DImpl<Ops>::Transform(out, in);
}

}

#endif // ENABLE_AVX512
