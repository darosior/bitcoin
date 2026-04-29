// Copyright (c) 2017-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifdef ENABLE_AVX2

#include <cstdint>
#include <immintrin.h>

#include <attributes.h>
#include <crypto/common.h>
#include <crypto/sha256d.h>

namespace sha256d64_avx2 {
struct Ops {
    using Int = __m256i;

    static __m256i ALWAYS_INLINE K(uint32_t x) { return _mm256_set1_epi32(x); }

    static __m256i ALWAYS_INLINE Add(__m256i x, __m256i y) { return _mm256_add_epi32(x, y); }
    static __m256i ALWAYS_INLINE Xor(__m256i x, __m256i y) { return _mm256_xor_si256(x, y); }
    static __m256i ALWAYS_INLINE Or(__m256i x, __m256i y) { return _mm256_or_si256(x, y); }
    static __m256i ALWAYS_INLINE And(__m256i x, __m256i y) { return _mm256_and_si256(x, y); }
    static __m256i ALWAYS_INLINE ShR(__m256i x, int n) { return _mm256_srli_epi32(x, n); }
    static __m256i ALWAYS_INLINE ShL(__m256i x, int n) { return _mm256_slli_epi32(x, n); }

    static __m256i ALWAYS_INLINE Read(const unsigned char* chunk, int offset) {
        __m256i ret = _mm256_set_epi32(
            ReadLE32(chunk + 0 + offset),
            ReadLE32(chunk + 64 + offset),
            ReadLE32(chunk + 128 + offset),
            ReadLE32(chunk + 192 + offset),
            ReadLE32(chunk + 256 + offset),
            ReadLE32(chunk + 320 + offset),
            ReadLE32(chunk + 384 + offset),
            ReadLE32(chunk + 448 + offset)
        );
        return _mm256_shuffle_epi8(ret, _mm256_set_epi32(0x0C0D0E0FUL, 0x08090A0BUL, 0x04050607UL, 0x00010203UL, 0x0C0D0E0FUL, 0x08090A0BUL, 0x04050607UL, 0x00010203UL));
    }

    static void ALWAYS_INLINE Write(unsigned char* out, int offset, __m256i v) {
        v = _mm256_shuffle_epi8(v, _mm256_set_epi32(0x0C0D0E0FUL, 0x08090A0BUL, 0x04050607UL, 0x00010203UL, 0x0C0D0E0FUL, 0x08090A0BUL, 0x04050607UL, 0x00010203UL));
        WriteLE32(out + 0 + offset, _mm256_extract_epi32(v, 7));
        WriteLE32(out + 32 + offset, _mm256_extract_epi32(v, 6));
        WriteLE32(out + 64 + offset, _mm256_extract_epi32(v, 5));
        WriteLE32(out + 96 + offset, _mm256_extract_epi32(v, 4));
        WriteLE32(out + 128 + offset, _mm256_extract_epi32(v, 3));
        WriteLE32(out + 160 + offset, _mm256_extract_epi32(v, 2));
        WriteLE32(out + 192 + offset, _mm256_extract_epi32(v, 1));
        WriteLE32(out + 224 + offset, _mm256_extract_epi32(v, 0));
    }
};

void Transform_8way(unsigned char* out, const unsigned char* in)
{
    SHA256DImpl<Ops>::Transform(out, in);
}

}

#endif
