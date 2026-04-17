// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifdef ENABLE_ARM_NEON

#include <array>
#include <cstdint>
#include <cstddef>
#include <arm_neon.h>

#include <attributes.h>
#include <crypto/common.h>
#include <crypto/sha256d.h>

namespace sha256d64_neon {

struct Ops {
    using Int = uint32x4_t;

    static uint32x4_t inline K(uint32_t x) { return vdupq_n_u32(x); }

    static uint32x4_t inline Add(uint32x4_t x, uint32x4_t y) { return vaddq_u32(x, y); }
    static uint32x4_t inline Xor(uint32x4_t x, uint32x4_t y) { return veorq_u32(x, y); }
    static uint32x4_t inline Or(uint32x4_t x, uint32x4_t y) { return vorrq_u32(x, y); }
    static uint32x4_t inline And(uint32x4_t x, uint32x4_t y) { return vandq_u32(x, y); }
    static uint32x4_t inline ShR(uint32x4_t x, int n) { return vshrq_n_u32(x, n); }
    static uint32x4_t inline ShL(uint32x4_t x, int n) { return vshlq_n_u32(x, n); }

    static uint32x4_t inline Read(const unsigned char* chunk, int offset) {
        alignas(uint32x4_t) const std::array<uint32_t, 4> lanes{{
            ReadLE32(chunk + 0 + offset),
            ReadLE32(chunk + 64 + offset),
            ReadLE32(chunk + 128 + offset),
            ReadLE32(chunk + 192 + offset),
        }};
        // FIXME: can't this be simply `uint32x4_t v = vrev32q_u32(vld1q_u32(lanes));`
        return vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(reinterpret_cast<const uint8_t*>(lanes.data()))));
    }

    static void inline Write(unsigned char* out, int offset, uint32x4_t v) {
        std::array<uint32_t, 4> lanes;
        v = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(v)));
        vst1q_u32(lanes.data(), v);
        WriteLE32(out + 0 + offset, lanes[0]);
        WriteLE32(out + 32 + offset, lanes[1]);
        WriteLE32(out + 64 + offset, lanes[2]);
        WriteLE32(out + 96 + offset, lanes[3]);
    }
};

void Transform_4way(unsigned char* out, const unsigned char* in)
{
    SHA256DImpl<Ops>::Transform(out, in);
}


/*
alignas(uint32x4_t) static constexpr std::array<uint32_t, 64> K =
{
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

uint32_t inline sigma0(uint32_t x) { return (x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3); }

static uint32x4_t inline sha256_s0(uint32x4_t w03, uint32x4_t w47)
{
    // (x >> 7 | x << 25)
    vsriq_n_u32(w03, vshlq_n_u32(w03, 25), 7);
    // (x >> 18 | x << 14)
    vsriq_n_u32(w03, vshlq_n_u32(w03, 14), 18);
    // (x >> 3)
    vshrq_n_u32(w03, 3);
}
*/

/*
void Transform(uint32_t* s, const unsigned char* chunk, size_t blocks)
{
    uint32x4_t STATE0, STATE1, ABEF_SAVE, CDGH_SAVE;
    uint32x4_t MSG0, MSG1, MSG2, MSG3;
    uint32x4_t W0, W1, W2, W3;
    uint32x4_t TMP0, TMP2;

    // Load state
    STATE0 = vld1q_u32(&s[0]);
    STATE1 = vld1q_u32(&s[4]);

    while (blocks--)
    {
        // Save state
        ABEF_SAVE = STATE0;
        CDGH_SAVE = STATE1;

        // Load and convert input chunk to Big Endian
        MSG0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(chunk + 0)));
        MSG1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(chunk + 16)));
        MSG2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(chunk + 32)));
        MSG3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(chunk + 48)));
        chunk += 64;

        // FIXME: so for the compression function i won't be able to parallelize over i's. But it seems instead i could parallelize same-ops, if the copy overhead doesn't cancel it out.

        // Rounds 1-4
        TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[0]));
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Rounds 5-8
        TMP0 = vaddq_u32(MSG1, vld1q_u32(&K[4]));
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Rounds 9-12
        TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[8]));
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Rounds 13-16
        TMP0 = vaddq_u32(MSG3, vld1q_u32(&K[12]));
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Expansion for rounds 17-32
        // w[i-15] for i = 16; i < 20; ++i
        W0 = vextq_u32(MSG0, MSG1, 1);
        // w[i-7]
        W2 = vextq_u32(MSG2, MSG3, 1);
        // TODO: w[i-2] means can only do 2 by 2, not 4 by 4
        W3 = vextq_u32(MSG3, vdupq_n_u32(0), 2);
        // s0 =          (w[i-15] >> 7 | w[i-15] << 25)         ^           (w[i-15] >> 18 | w[i-15] << 14)         ^  (w[i-15] >> 3)
        TMP0 = veorq_u32(vsriq_n_u32(W0, vshlq_n_u32(W0, 25), 7), veorq_u32(vsriq_n_u32(W0, vshlq_n_u32(W0, 14), 18), vshrq_n_u32(W0, 3)));
        // s1 =          (w[i-2] >> 17 | w[i-2] << 15)           ^            (w[i-2] >> 19 | w[i-2] << 13)          ^  (w[i-2] >> 10)
        TMP2 = veorq_u32(vsriq_n_u32(W3, vshlq_n_u32(W3, 15), 17), veorq_u32(vsriq_n_u32(W3, vshlq_n_u32(W3, 13), 19), vshrq_n_u32(W3, 10))); // FIXME: This does pointless operations on the last two elements of the vector
        MSG0 = vaddq_u32(vaddq_u32(MSG0, TMP0), vaddq_u32(c, TMP2));
        // Get the two other w[i-2]
        W3 = vextq_u32(vdupq_n_u32(0), MSG0, 2);
        // And recompute s1 for them
        TMP2 = veorq_u32(vsriq_n_u32(W3, vshlq_n_u32(W3, 15), 17), veorq_u32(vsriq_n_u32(W3, vshlq_n_u32(W3, 13), 19), vshrq_n_u32(W3, 10))); // FIXME: This does pointless operations on the last two elements of the vector
        // TODO: now get the last two W and store them into MSG0


        // Rounds 17-20


        // Rounds 1-4
        TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[0]));
        TMP2 = STATE0;
        MSG0 = vsha256su0q_u32(MSG0, MSG1);
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

        // Rounds 5-8
        TMP0 = vaddq_u32(MSG1, vld1q_u32(&K[4]));
        TMP2 = STATE0;
        MSG1 = vsha256su0q_u32(MSG1, MSG2);
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

        // Rounds 9-12
        TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[8]));
        TMP2 = STATE0;
        MSG2 = vsha256su0q_u32(MSG2, MSG3);
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

        // Rounds 13-16
        TMP0 = vaddq_u32(MSG3, vld1q_u32(&K[12]));
        TMP2 = STATE0;
        MSG3 = vsha256su0q_u32(MSG3, MSG0);
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

        // Rounds 17-20
        TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[16]));
        TMP2 = STATE0;
        MSG0 = vsha256su0q_u32(MSG0, MSG1);
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

        // Rounds 21-24
        TMP0 = vaddq_u32(MSG1, vld1q_u32(&K[20]));
        TMP2 = STATE0;
        MSG1 = vsha256su0q_u32(MSG1, MSG2);
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

        // Rounds 25-28
        TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[24]));
        TMP2 = STATE0;
        MSG2 = vsha256su0q_u32(MSG2, MSG3);
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

        // Rounds 29-32
        TMP0 = vaddq_u32(MSG3, vld1q_u32(&K[28]));
        TMP2 = STATE0;
        MSG3 = vsha256su0q_u32(MSG3, MSG0);
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

        // Rounds 33-36
        TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[32]));
        TMP2 = STATE0;
        MSG0 = vsha256su0q_u32(MSG0, MSG1);
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

        // Rounds 37-40
        TMP0 = vaddq_u32(MSG1, vld1q_u32(&K[36]));
        TMP2 = STATE0;
        MSG1 = vsha256su0q_u32(MSG1, MSG2);
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

        // Rounds 41-44
        TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[40]));
        TMP2 = STATE0;
        MSG2 = vsha256su0q_u32(MSG2, MSG3);
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

        // Rounds 45-48
        TMP0 = vaddq_u32(MSG3, vld1q_u32(&K[44]));
        TMP2 = STATE0;
        MSG3 = vsha256su0q_u32(MSG3, MSG0);
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

        // Rounds 49-52
        TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[48]));
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Rounds 53-56
        TMP0 = vaddq_u32(MSG1, vld1q_u32(&K[52]));
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Rounds 57-60
        TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[56]));
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Rounds 61-64
        TMP0 = vaddq_u32(MSG3, vld1q_u32(&K[60]));
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Update state
        STATE0 = vaddq_u32(STATE0, ABEF_SAVE);
        STATE1 = vaddq_u32(STATE1, CDGH_SAVE);
    }

    // Save final state
    vst1q_u32(&s[0], STATE0);
    vst1q_u32(&s[4], STATE1);
}*/

} // namespace sha256d64_neon

#endif // ENABLE_ARM_NEON
