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

namespace sha256d64_neon {

namespace {

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

uint32x4_t inline sha256_s0(uint32x4_t w03, uint32x4_t w47)
{
    // (x >> 7 | x << 25)
    vsriq_n_u32(w03, vshlq_n_u32(w03, 25), 7);
    // (x >> 18 | x << 14)
    vsriq_n_u32(w03, vshlq_n_u32(w03, 14), 18);
    // (x >> 3)
    vshrq_n_u32(w03, 3);
}
*/

// TODO: figure out if using a constant isn't better.
uint32x4_t inline K(uint32_t x) { return vdupq_n_u32(x); }

uint32x4_t inline Add(uint32x4_t x, uint32x4_t y) { return vaddq_u32(x, y); }
uint32x4_t inline Add(uint32x4_t x, uint32x4_t y, uint32x4_t z) { return Add(Add(x, y), z); }
uint32x4_t inline Add(uint32x4_t x, uint32x4_t y, uint32x4_t z, uint32x4_t w) { return Add(Add(x, y), Add(z, w)); }
uint32x4_t inline Add(uint32x4_t x, uint32x4_t y, uint32x4_t z, uint32x4_t w, uint32x4_t v) { return Add(Add(x, y, z), Add(w, v)); }
uint32x4_t inline Inc(uint32x4_t& x, uint32x4_t y) { x = Add(x, y); return x; }
uint32x4_t inline Inc(uint32x4_t& x, uint32x4_t y, uint32x4_t z) { x = Add(x, y, z); return x; }
uint32x4_t inline Inc(uint32x4_t& x, uint32x4_t y, uint32x4_t z, uint32x4_t w) { x = Add(x, y, z, w); return x; }
uint32x4_t inline Xor(uint32x4_t x, uint32x4_t y) { return veorq_u32(x, y); }
uint32x4_t inline Xor(uint32x4_t x, uint32x4_t y, uint32x4_t z) { return Xor(Xor(x, y), z); }
uint32x4_t inline Or(uint32x4_t x, uint32x4_t y) { return vorrq_u32(x, y); }
uint32x4_t inline And(uint32x4_t x, uint32x4_t y) { return vandq_u32(x, y); }
uint32x4_t inline ShR(uint32x4_t x, int n) { return vshrq_n_u32(x, n); }
uint32x4_t inline ShL(uint32x4_t x, int n) { return vshlq_n_u32(x, n); } // TODO: figure out is a rotate wouldn't be more efficient (save one instruction on ARM)

uint32x4_t inline Ch(uint32x4_t x, uint32x4_t y, uint32x4_t z) { return Xor(z, And(x, Xor(y, z))); }
uint32x4_t inline Maj(uint32x4_t x, uint32x4_t y, uint32x4_t z) { return Or(And(x, y), And(z, Or(x, y))); }
uint32x4_t inline Sigma0(uint32x4_t x) { return Xor(Or(ShR(x, 2), ShL(x, 30)), Or(ShR(x, 13), ShL(x, 19)), Or(ShR(x, 22), ShL(x, 10))); }
uint32x4_t inline Sigma1(uint32x4_t x) { return Xor(Or(ShR(x, 6), ShL(x, 26)), Or(ShR(x, 11), ShL(x, 21)), Or(ShR(x, 25), ShL(x, 7))); }
uint32x4_t inline sigma0(uint32x4_t x) { return Xor(Or(ShR(x, 7), ShL(x, 25)), Or(ShR(x, 18), ShL(x, 14)), ShR(x, 3)); }
uint32x4_t inline sigma1(uint32x4_t x) { return Xor(Or(ShR(x, 17), ShL(x, 15)), Or(ShR(x, 19), ShL(x, 13)), ShR(x, 10)); }

/** One round of SHA-256. */
void ALWAYS_INLINE Round(uint32x4_t a, uint32x4_t b, uint32x4_t c, uint32x4_t& d, uint32x4_t e, uint32x4_t f, uint32x4_t g, uint32x4_t& h, uint32x4_t k)
{
    uint32x4_t t1 = Add(h, Sigma1(e), Ch(e, f, g), k);
    uint32x4_t t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);
}

uint32x4_t inline Read4(const unsigned char* chunk, int offset) {
    alignas(uint32x4_t) const std::array<uint32_t, 4> lanes{{
        ReadLE32(chunk + 0 + offset),
        ReadLE32(chunk + 64 + offset),
        ReadLE32(chunk + 128 + offset),
        ReadLE32(chunk + 192 + offset),
    }};
    // FIXME: can't this be simply `uint32x4_t v = vrev32q_u32(vld1q_u32(lanes));`
    return vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(reinterpret_cast<const uint8_t*>(lanes.data()))));
}

void inline Write4(unsigned char* out, int offset, uint32x4_t v) {
    std::array<uint32_t, 4> lanes;
    v = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(v)));
    vst1q_u32(lanes.data(), v);
    WriteLE32(out + 0 + offset, lanes[0]);
    WriteLE32(out + 32 + offset, lanes[1]);
    WriteLE32(out + 64 + offset, lanes[2]);
    WriteLE32(out + 96 + offset, lanes[3]);
}

}



void Transform_4way(unsigned char* out, const unsigned char* in)
{
    // Transform 1
    uint32x4_t a = K(0x6a09e667ul);
    uint32x4_t b = K(0xbb67ae85ul);
    uint32x4_t c = K(0x3c6ef372ul);
    uint32x4_t d = K(0xa54ff53aul);
    uint32x4_t e = K(0x510e527ful);
    uint32x4_t f = K(0x9b05688cul);
    uint32x4_t g = K(0x1f83d9abul);
    uint32x4_t h = K(0x5be0cd19ul);

    uint32x4_t w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;

    Round(a, b, c, d, e, f, g, h, Add(K(0x428a2f98ul), w0 = Read4(in, 0)));
    Round(h, a, b, c, d, e, f, g, Add(K(0x71374491ul), w1 = Read4(in, 4)));
    Round(g, h, a, b, c, d, e, f, Add(K(0xb5c0fbcful), w2 = Read4(in, 8)));
    Round(f, g, h, a, b, c, d, e, Add(K(0xe9b5dba5ul), w3 = Read4(in, 12)));
    Round(e, f, g, h, a, b, c, d, Add(K(0x3956c25bul), w4 = Read4(in, 16)));
    Round(d, e, f, g, h, a, b, c, Add(K(0x59f111f1ul), w5 = Read4(in, 20)));
    Round(c, d, e, f, g, h, a, b, Add(K(0x923f82a4ul), w6 = Read4(in, 24)));
    Round(b, c, d, e, f, g, h, a, Add(K(0xab1c5ed5ul), w7 = Read4(in, 28)));
    Round(a, b, c, d, e, f, g, h, Add(K(0xd807aa98ul), w8 = Read4(in, 32)));
    Round(h, a, b, c, d, e, f, g, Add(K(0x12835b01ul), w9 = Read4(in, 36)));
    Round(g, h, a, b, c, d, e, f, Add(K(0x243185beul), w10 = Read4(in, 40)));
    Round(f, g, h, a, b, c, d, e, Add(K(0x550c7dc3ul), w11 = Read4(in, 44)));
    Round(e, f, g, h, a, b, c, d, Add(K(0x72be5d74ul), w12 = Read4(in, 48)));
    Round(d, e, f, g, h, a, b, c, Add(K(0x80deb1feul), w13 = Read4(in, 52)));
    Round(c, d, e, f, g, h, a, b, Add(K(0x9bdc06a7ul), w14 = Read4(in, 56)));
    Round(b, c, d, e, f, g, h, a, Add(K(0xc19bf174ul), w15 = Read4(in, 60)));
    Round(a, b, c, d, e, f, g, h, Add(K(0xe49b69c1ul), Inc(w0, sigma1(w14), w9, sigma0(w1))));
    Round(h, a, b, c, d, e, f, g, Add(K(0xefbe4786ul), Inc(w1, sigma1(w15), w10, sigma0(w2))));
    Round(g, h, a, b, c, d, e, f, Add(K(0x0fc19dc6ul), Inc(w2, sigma1(w0), w11, sigma0(w3))));
    Round(f, g, h, a, b, c, d, e, Add(K(0x240ca1ccul), Inc(w3, sigma1(w1), w12, sigma0(w4))));
    Round(e, f, g, h, a, b, c, d, Add(K(0x2de92c6ful), Inc(w4, sigma1(w2), w13, sigma0(w5))));
    Round(d, e, f, g, h, a, b, c, Add(K(0x4a7484aaul), Inc(w5, sigma1(w3), w14, sigma0(w6))));
    Round(c, d, e, f, g, h, a, b, Add(K(0x5cb0a9dcul), Inc(w6, sigma1(w4), w15, sigma0(w7))));
    Round(b, c, d, e, f, g, h, a, Add(K(0x76f988daul), Inc(w7, sigma1(w5), w0, sigma0(w8))));
    Round(a, b, c, d, e, f, g, h, Add(K(0x983e5152ul), Inc(w8, sigma1(w6), w1, sigma0(w9))));
    Round(h, a, b, c, d, e, f, g, Add(K(0xa831c66dul), Inc(w9, sigma1(w7), w2, sigma0(w10))));
    Round(g, h, a, b, c, d, e, f, Add(K(0xb00327c8ul), Inc(w10, sigma1(w8), w3, sigma0(w11))));
    Round(f, g, h, a, b, c, d, e, Add(K(0xbf597fc7ul), Inc(w11, sigma1(w9), w4, sigma0(w12))));
    Round(e, f, g, h, a, b, c, d, Add(K(0xc6e00bf3ul), Inc(w12, sigma1(w10), w5, sigma0(w13))));
    Round(d, e, f, g, h, a, b, c, Add(K(0xd5a79147ul), Inc(w13, sigma1(w11), w6, sigma0(w14))));
    Round(c, d, e, f, g, h, a, b, Add(K(0x06ca6351ul), Inc(w14, sigma1(w12), w7, sigma0(w15))));
    Round(b, c, d, e, f, g, h, a, Add(K(0x14292967ul), Inc(w15, sigma1(w13), w8, sigma0(w0))));
    Round(a, b, c, d, e, f, g, h, Add(K(0x27b70a85ul), Inc(w0, sigma1(w14), w9, sigma0(w1))));
    Round(h, a, b, c, d, e, f, g, Add(K(0x2e1b2138ul), Inc(w1, sigma1(w15), w10, sigma0(w2))));
    Round(g, h, a, b, c, d, e, f, Add(K(0x4d2c6dfcul), Inc(w2, sigma1(w0), w11, sigma0(w3))));
    Round(f, g, h, a, b, c, d, e, Add(K(0x53380d13ul), Inc(w3, sigma1(w1), w12, sigma0(w4))));
    Round(e, f, g, h, a, b, c, d, Add(K(0x650a7354ul), Inc(w4, sigma1(w2), w13, sigma0(w5))));
    Round(d, e, f, g, h, a, b, c, Add(K(0x766a0abbul), Inc(w5, sigma1(w3), w14, sigma0(w6))));
    Round(c, d, e, f, g, h, a, b, Add(K(0x81c2c92eul), Inc(w6, sigma1(w4), w15, sigma0(w7))));
    Round(b, c, d, e, f, g, h, a, Add(K(0x92722c85ul), Inc(w7, sigma1(w5), w0, sigma0(w8))));
    Round(a, b, c, d, e, f, g, h, Add(K(0xa2bfe8a1ul), Inc(w8, sigma1(w6), w1, sigma0(w9))));
    Round(h, a, b, c, d, e, f, g, Add(K(0xa81a664bul), Inc(w9, sigma1(w7), w2, sigma0(w10))));
    Round(g, h, a, b, c, d, e, f, Add(K(0xc24b8b70ul), Inc(w10, sigma1(w8), w3, sigma0(w11))));
    Round(f, g, h, a, b, c, d, e, Add(K(0xc76c51a3ul), Inc(w11, sigma1(w9), w4, sigma0(w12))));
    Round(e, f, g, h, a, b, c, d, Add(K(0xd192e819ul), Inc(w12, sigma1(w10), w5, sigma0(w13))));
    Round(d, e, f, g, h, a, b, c, Add(K(0xd6990624ul), Inc(w13, sigma1(w11), w6, sigma0(w14))));
    Round(c, d, e, f, g, h, a, b, Add(K(0xf40e3585ul), Inc(w14, sigma1(w12), w7, sigma0(w15))));
    Round(b, c, d, e, f, g, h, a, Add(K(0x106aa070ul), Inc(w15, sigma1(w13), w8, sigma0(w0))));
    Round(a, b, c, d, e, f, g, h, Add(K(0x19a4c116ul), Inc(w0, sigma1(w14), w9, sigma0(w1))));
    Round(h, a, b, c, d, e, f, g, Add(K(0x1e376c08ul), Inc(w1, sigma1(w15), w10, sigma0(w2))));
    Round(g, h, a, b, c, d, e, f, Add(K(0x2748774cul), Inc(w2, sigma1(w0), w11, sigma0(w3))));
    Round(f, g, h, a, b, c, d, e, Add(K(0x34b0bcb5ul), Inc(w3, sigma1(w1), w12, sigma0(w4))));
    Round(e, f, g, h, a, b, c, d, Add(K(0x391c0cb3ul), Inc(w4, sigma1(w2), w13, sigma0(w5))));
    Round(d, e, f, g, h, a, b, c, Add(K(0x4ed8aa4aul), Inc(w5, sigma1(w3), w14, sigma0(w6))));
    Round(c, d, e, f, g, h, a, b, Add(K(0x5b9cca4ful), Inc(w6, sigma1(w4), w15, sigma0(w7))));
    Round(b, c, d, e, f, g, h, a, Add(K(0x682e6ff3ul), Inc(w7, sigma1(w5), w0, sigma0(w8))));
    Round(a, b, c, d, e, f, g, h, Add(K(0x748f82eeul), Inc(w8, sigma1(w6), w1, sigma0(w9))));
    Round(h, a, b, c, d, e, f, g, Add(K(0x78a5636ful), Inc(w9, sigma1(w7), w2, sigma0(w10))));
    Round(g, h, a, b, c, d, e, f, Add(K(0x84c87814ul), Inc(w10, sigma1(w8), w3, sigma0(w11))));
    Round(f, g, h, a, b, c, d, e, Add(K(0x8cc70208ul), Inc(w11, sigma1(w9), w4, sigma0(w12))));
    Round(e, f, g, h, a, b, c, d, Add(K(0x90befffaul), Inc(w12, sigma1(w10), w5, sigma0(w13))));
    Round(d, e, f, g, h, a, b, c, Add(K(0xa4506cebul), Inc(w13, sigma1(w11), w6, sigma0(w14))));
    Round(c, d, e, f, g, h, a, b, Add(K(0xbef9a3f7ul), Inc(w14, sigma1(w12), w7, sigma0(w15))));
    Round(b, c, d, e, f, g, h, a, Add(K(0xc67178f2ul), Inc(w15, sigma1(w13), w8, sigma0(w0))));

    a = Add(a, K(0x6a09e667ul));
    b = Add(b, K(0xbb67ae85ul));
    c = Add(c, K(0x3c6ef372ul));
    d = Add(d, K(0xa54ff53aul));
    e = Add(e, K(0x510e527ful));
    f = Add(f, K(0x9b05688cul));
    g = Add(g, K(0x1f83d9abul));
    h = Add(h, K(0x5be0cd19ul));

    uint32x4_t t0 = a, t1 = b, t2 = c, t3 = d, t4 = e, t5 = f, t6 = g, t7 = h;

    // Transform 2
    Round(a, b, c, d, e, f, g, h, K(0xc28a2f98ul));
    Round(h, a, b, c, d, e, f, g, K(0x71374491ul));
    Round(g, h, a, b, c, d, e, f, K(0xb5c0fbcful));
    Round(f, g, h, a, b, c, d, e, K(0xe9b5dba5ul));
    Round(e, f, g, h, a, b, c, d, K(0x3956c25bul));
    Round(d, e, f, g, h, a, b, c, K(0x59f111f1ul));
    Round(c, d, e, f, g, h, a, b, K(0x923f82a4ul));
    Round(b, c, d, e, f, g, h, a, K(0xab1c5ed5ul));
    Round(a, b, c, d, e, f, g, h, K(0xd807aa98ul));
    Round(h, a, b, c, d, e, f, g, K(0x12835b01ul));
    Round(g, h, a, b, c, d, e, f, K(0x243185beul));
    Round(f, g, h, a, b, c, d, e, K(0x550c7dc3ul));
    Round(e, f, g, h, a, b, c, d, K(0x72be5d74ul));
    Round(d, e, f, g, h, a, b, c, K(0x80deb1feul));
    Round(c, d, e, f, g, h, a, b, K(0x9bdc06a7ul));
    Round(b, c, d, e, f, g, h, a, K(0xc19bf374ul));
    Round(a, b, c, d, e, f, g, h, K(0x649b69c1ul));
    Round(h, a, b, c, d, e, f, g, K(0xf0fe4786ul));
    Round(g, h, a, b, c, d, e, f, K(0x0fe1edc6ul));
    Round(f, g, h, a, b, c, d, e, K(0x240cf254ul));
    Round(e, f, g, h, a, b, c, d, K(0x4fe9346ful));
    Round(d, e, f, g, h, a, b, c, K(0x6cc984beul));
    Round(c, d, e, f, g, h, a, b, K(0x61b9411eul));
    Round(b, c, d, e, f, g, h, a, K(0x16f988faul));
    Round(a, b, c, d, e, f, g, h, K(0xf2c65152ul));
    Round(h, a, b, c, d, e, f, g, K(0xa88e5a6dul));
    Round(g, h, a, b, c, d, e, f, K(0xb019fc65ul));
    Round(f, g, h, a, b, c, d, e, K(0xb9d99ec7ul));
    Round(e, f, g, h, a, b, c, d, K(0x9a1231c3ul));
    Round(d, e, f, g, h, a, b, c, K(0xe70eeaa0ul));
    Round(c, d, e, f, g, h, a, b, K(0xfdb1232bul));
    Round(b, c, d, e, f, g, h, a, K(0xc7353eb0ul));
    Round(a, b, c, d, e, f, g, h, K(0x3069bad5ul));
    Round(h, a, b, c, d, e, f, g, K(0xcb976d5ful));
    Round(g, h, a, b, c, d, e, f, K(0x5a0f118ful));
    Round(f, g, h, a, b, c, d, e, K(0xdc1eeefdul));
    Round(e, f, g, h, a, b, c, d, K(0x0a35b689ul));
    Round(d, e, f, g, h, a, b, c, K(0xde0b7a04ul));
    Round(c, d, e, f, g, h, a, b, K(0x58f4ca9dul));
    Round(b, c, d, e, f, g, h, a, K(0xe15d5b16ul));
    Round(a, b, c, d, e, f, g, h, K(0x007f3e86ul));
    Round(h, a, b, c, d, e, f, g, K(0x37088980ul));
    Round(g, h, a, b, c, d, e, f, K(0xa507ea32ul));
    Round(f, g, h, a, b, c, d, e, K(0x6fab9537ul));
    Round(e, f, g, h, a, b, c, d, K(0x17406110ul));
    Round(d, e, f, g, h, a, b, c, K(0x0d8cd6f1ul));
    Round(c, d, e, f, g, h, a, b, K(0xcdaa3b6dul));
    Round(b, c, d, e, f, g, h, a, K(0xc0bbbe37ul));
    Round(a, b, c, d, e, f, g, h, K(0x83613bdaul));
    Round(h, a, b, c, d, e, f, g, K(0xdb48a363ul));
    Round(g, h, a, b, c, d, e, f, K(0x0b02e931ul));
    Round(f, g, h, a, b, c, d, e, K(0x6fd15ca7ul));
    Round(e, f, g, h, a, b, c, d, K(0x521afacaul));
    Round(d, e, f, g, h, a, b, c, K(0x31338431ul));
    Round(c, d, e, f, g, h, a, b, K(0x6ed41a95ul));
    Round(b, c, d, e, f, g, h, a, K(0x6d437890ul));
    Round(a, b, c, d, e, f, g, h, K(0xc39c91f2ul));
    Round(h, a, b, c, d, e, f, g, K(0x9eccabbdul));
    Round(g, h, a, b, c, d, e, f, K(0xb5c9a0e6ul));
    Round(f, g, h, a, b, c, d, e, K(0x532fb63cul));
    Round(e, f, g, h, a, b, c, d, K(0xd2c741c6ul));
    Round(d, e, f, g, h, a, b, c, K(0x07237ea3ul));
    Round(c, d, e, f, g, h, a, b, K(0xa4954b68ul));
    Round(b, c, d, e, f, g, h, a, K(0x4c191d76ul));

    w0 = Add(t0, a);
    w1 = Add(t1, b);
    w2 = Add(t2, c);
    w3 = Add(t3, d);
    w4 = Add(t4, e);
    w5 = Add(t5, f);
    w6 = Add(t6, g);
    w7 = Add(t7, h);

    // Transform 3
    a = K(0x6a09e667ul);
    b = K(0xbb67ae85ul);
    c = K(0x3c6ef372ul);
    d = K(0xa54ff53aul);
    e = K(0x510e527ful);
    f = K(0x9b05688cul);
    g = K(0x1f83d9abul);
    h = K(0x5be0cd19ul);

    Round(a, b, c, d, e, f, g, h, Add(K(0x428a2f98ul), w0));
    Round(h, a, b, c, d, e, f, g, Add(K(0x71374491ul), w1));
    Round(g, h, a, b, c, d, e, f, Add(K(0xb5c0fbcful), w2));
    Round(f, g, h, a, b, c, d, e, Add(K(0xe9b5dba5ul), w3));
    Round(e, f, g, h, a, b, c, d, Add(K(0x3956c25bul), w4));
    Round(d, e, f, g, h, a, b, c, Add(K(0x59f111f1ul), w5));
    Round(c, d, e, f, g, h, a, b, Add(K(0x923f82a4ul), w6));
    Round(b, c, d, e, f, g, h, a, Add(K(0xab1c5ed5ul), w7));
    Round(a, b, c, d, e, f, g, h, K(0x5807aa98ul));
    Round(h, a, b, c, d, e, f, g, K(0x12835b01ul));
    Round(g, h, a, b, c, d, e, f, K(0x243185beul));
    Round(f, g, h, a, b, c, d, e, K(0x550c7dc3ul));
    Round(e, f, g, h, a, b, c, d, K(0x72be5d74ul));
    Round(d, e, f, g, h, a, b, c, K(0x80deb1feul));
    Round(c, d, e, f, g, h, a, b, K(0x9bdc06a7ul));
    Round(b, c, d, e, f, g, h, a, K(0xc19bf274ul));
    Round(a, b, c, d, e, f, g, h, Add(K(0xe49b69c1ul), Inc(w0, sigma0(w1))));
    Round(h, a, b, c, d, e, f, g, Add(K(0xefbe4786ul), Inc(w1, K(0xa00000ul), sigma0(w2))));
    Round(g, h, a, b, c, d, e, f, Add(K(0x0fc19dc6ul), Inc(w2, sigma1(w0), sigma0(w3))));
    Round(f, g, h, a, b, c, d, e, Add(K(0x240ca1ccul), Inc(w3, sigma1(w1), sigma0(w4))));
    Round(e, f, g, h, a, b, c, d, Add(K(0x2de92c6ful), Inc(w4, sigma1(w2), sigma0(w5))));
    Round(d, e, f, g, h, a, b, c, Add(K(0x4a7484aaul), Inc(w5, sigma1(w3), sigma0(w6))));
    Round(c, d, e, f, g, h, a, b, Add(K(0x5cb0a9dcul), Inc(w6, sigma1(w4), K(0x100ul), sigma0(w7))));
    Round(b, c, d, e, f, g, h, a, Add(K(0x76f988daul), Inc(w7, sigma1(w5), w0, K(0x11002000ul))));
    Round(a, b, c, d, e, f, g, h, Add(K(0x983e5152ul), w8 = Add(K(0x80000000ul), sigma1(w6), w1)));
    Round(h, a, b, c, d, e, f, g, Add(K(0xa831c66dul), w9 = Add(sigma1(w7), w2)));
    Round(g, h, a, b, c, d, e, f, Add(K(0xb00327c8ul), w10 = Add(sigma1(w8), w3)));
    Round(f, g, h, a, b, c, d, e, Add(K(0xbf597fc7ul), w11 = Add(sigma1(w9), w4)));
    Round(e, f, g, h, a, b, c, d, Add(K(0xc6e00bf3ul), w12 = Add(sigma1(w10), w5)));
    Round(d, e, f, g, h, a, b, c, Add(K(0xd5a79147ul), w13 = Add(sigma1(w11), w6)));
    Round(c, d, e, f, g, h, a, b, Add(K(0x06ca6351ul), w14 = Add(sigma1(w12), w7, K(0x400022ul))));
    Round(b, c, d, e, f, g, h, a, Add(K(0x14292967ul), w15 = Add(K(0x100ul), sigma1(w13), w8, sigma0(w0))));
    Round(a, b, c, d, e, f, g, h, Add(K(0x27b70a85ul), Inc(w0, sigma1(w14), w9, sigma0(w1))));
    Round(h, a, b, c, d, e, f, g, Add(K(0x2e1b2138ul), Inc(w1, sigma1(w15), w10, sigma0(w2))));
    Round(g, h, a, b, c, d, e, f, Add(K(0x4d2c6dfcul), Inc(w2, sigma1(w0), w11, sigma0(w3))));
    Round(f, g, h, a, b, c, d, e, Add(K(0x53380d13ul), Inc(w3, sigma1(w1), w12, sigma0(w4))));
    Round(e, f, g, h, a, b, c, d, Add(K(0x650a7354ul), Inc(w4, sigma1(w2), w13, sigma0(w5))));
    Round(d, e, f, g, h, a, b, c, Add(K(0x766a0abbul), Inc(w5, sigma1(w3), w14, sigma0(w6))));
    Round(c, d, e, f, g, h, a, b, Add(K(0x81c2c92eul), Inc(w6, sigma1(w4), w15, sigma0(w7))));
    Round(b, c, d, e, f, g, h, a, Add(K(0x92722c85ul), Inc(w7, sigma1(w5), w0, sigma0(w8))));
    Round(a, b, c, d, e, f, g, h, Add(K(0xa2bfe8a1ul), Inc(w8, sigma1(w6), w1, sigma0(w9))));
    Round(h, a, b, c, d, e, f, g, Add(K(0xa81a664bul), Inc(w9, sigma1(w7), w2, sigma0(w10))));
    Round(g, h, a, b, c, d, e, f, Add(K(0xc24b8b70ul), Inc(w10, sigma1(w8), w3, sigma0(w11))));
    Round(f, g, h, a, b, c, d, e, Add(K(0xc76c51a3ul), Inc(w11, sigma1(w9), w4, sigma0(w12))));
    Round(e, f, g, h, a, b, c, d, Add(K(0xd192e819ul), Inc(w12, sigma1(w10), w5, sigma0(w13))));
    Round(d, e, f, g, h, a, b, c, Add(K(0xd6990624ul), Inc(w13, sigma1(w11), w6, sigma0(w14))));
    Round(c, d, e, f, g, h, a, b, Add(K(0xf40e3585ul), Inc(w14, sigma1(w12), w7, sigma0(w15))));
    Round(b, c, d, e, f, g, h, a, Add(K(0x106aa070ul), Inc(w15, sigma1(w13), w8, sigma0(w0))));
    Round(a, b, c, d, e, f, g, h, Add(K(0x19a4c116ul), Inc(w0, sigma1(w14), w9, sigma0(w1))));
    Round(h, a, b, c, d, e, f, g, Add(K(0x1e376c08ul), Inc(w1, sigma1(w15), w10, sigma0(w2))));
    Round(g, h, a, b, c, d, e, f, Add(K(0x2748774cul), Inc(w2, sigma1(w0), w11, sigma0(w3))));
    Round(f, g, h, a, b, c, d, e, Add(K(0x34b0bcb5ul), Inc(w3, sigma1(w1), w12, sigma0(w4))));
    Round(e, f, g, h, a, b, c, d, Add(K(0x391c0cb3ul), Inc(w4, sigma1(w2), w13, sigma0(w5))));
    Round(d, e, f, g, h, a, b, c, Add(K(0x4ed8aa4aul), Inc(w5, sigma1(w3), w14, sigma0(w6))));
    Round(c, d, e, f, g, h, a, b, Add(K(0x5b9cca4ful), Inc(w6, sigma1(w4), w15, sigma0(w7))));
    Round(b, c, d, e, f, g, h, a, Add(K(0x682e6ff3ul), Inc(w7, sigma1(w5), w0, sigma0(w8))));
    Round(a, b, c, d, e, f, g, h, Add(K(0x748f82eeul), Inc(w8, sigma1(w6), w1, sigma0(w9))));
    Round(h, a, b, c, d, e, f, g, Add(K(0x78a5636ful), Inc(w9, sigma1(w7), w2, sigma0(w10))));
    Round(g, h, a, b, c, d, e, f, Add(K(0x84c87814ul), Inc(w10, sigma1(w8), w3, sigma0(w11))));
    Round(f, g, h, a, b, c, d, e, Add(K(0x8cc70208ul), Inc(w11, sigma1(w9), w4, sigma0(w12))));
    Round(e, f, g, h, a, b, c, d, Add(K(0x90befffaul), Inc(w12, sigma1(w10), w5, sigma0(w13))));
    Round(d, e, f, g, h, a, b, c, Add(K(0xa4506cebul), Inc(w13, sigma1(w11), w6, sigma0(w14))));
    Round(c, d, e, f, g, h, a, b, Add(K(0xbef9a3f7ul), w14, sigma1(w12), w7, sigma0(w15)));
    Round(b, c, d, e, f, g, h, a, Add(K(0xc67178f2ul), w15, sigma1(w13), w8, sigma0(w0)));

    // Output
    Write4(out, 0, Add(a, K(0x6a09e667ul)));
    Write4(out, 4, Add(b, K(0xbb67ae85ul)));
    Write4(out, 8, Add(c, K(0x3c6ef372ul)));
    Write4(out, 12, Add(d, K(0xa54ff53aul)));
    Write4(out, 16, Add(e, K(0x510e527ful)));
    Write4(out, 20, Add(f, K(0x9b05688cul)));
    Write4(out, 24, Add(g, K(0x1f83d9abul)));
    Write4(out, 28, Add(h, K(0x5be0cd19ul)));
}


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
