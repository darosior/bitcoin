// Copyright (c) 2018-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifdef ENABLE_SSE41

#include <cstdint>
#include <immintrin.h>

#include <attributes.h>
#include <crypto/common.h>
#include <crypto/sha256d.h>

namespace sha256d64_sse41 {
struct Ops {
    using Int = __m128i;

    static __m128i inline K(uint32_t x) { return _mm_set1_epi32(x); }

    static __m128i inline Add(__m128i x, __m128i y) { return _mm_add_epi32(x, y); }
    static __m128i inline Xor(__m128i x, __m128i y) { return _mm_xor_si128(x, y); }
    static __m128i inline Or(__m128i x, __m128i y) { return _mm_or_si128(x, y); }
    static __m128i inline And(__m128i x, __m128i y) { return _mm_and_si128(x, y); }
    static __m128i inline ShR(__m128i x, int n) { return _mm_srli_epi32(x, n); }
    static __m128i inline ShL(__m128i x, int n) { return _mm_slli_epi32(x, n); }

    static __m128i inline Read(const unsigned char* chunk, int offset) {
        __m128i ret = _mm_set_epi32(
            ReadLE32(chunk + 0 + offset),
            ReadLE32(chunk + 64 + offset),
            ReadLE32(chunk + 128 + offset),
            ReadLE32(chunk + 192 + offset)
        );
        return _mm_shuffle_epi8(ret, _mm_set_epi32(0x0C0D0E0FUL, 0x08090A0BUL, 0x04050607UL, 0x00010203UL));
    }

    static void inline Write(unsigned char* out, int offset, __m128i v) {
        v = _mm_shuffle_epi8(v, _mm_set_epi32(0x0C0D0E0FUL, 0x08090A0BUL, 0x04050607UL, 0x00010203UL));
        WriteLE32(out + 0 + offset, _mm_extract_epi32(v, 3));
        WriteLE32(out + 32 + offset, _mm_extract_epi32(v, 2));
        WriteLE32(out + 64 + offset, _mm_extract_epi32(v, 1));
        WriteLE32(out + 96 + offset, _mm_extract_epi32(v, 0));
    }
};

void Transform_4way(unsigned char* out, const unsigned char* in)
{
    SHA256DImpl<Ops>::Transform(out, in);
}

}

#endif
