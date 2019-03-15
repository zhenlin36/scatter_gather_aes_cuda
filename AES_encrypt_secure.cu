#include "util.cu"
//#define TTABLE 256
//#define USE_SMEM
union u32_t {
    uint i;
    uchar c[4];
};

#if TTABLE == 256
#include "tabs/AES_256.tab"
#define TE(tab, offset, state) (_te[(tab)][((offset) << 8) + (state)])

#elif TTABLE == 128
#include "tabs/AES_128.tab"
#define TE_128_LH(tab, offset, state) (_te[(tab)][((offset) << 8) + (state >> 1)      ] >> ((state & 0x1) << 2))
#define TE_128_HH(tab, offset, state) (_te[(tab)][((offset) << 8) + (state >> 1) + 128] >> ((state & 0x1) << 2))
#define TE(tab, offset, state) ((TE_128_LH(tab, offset, state) & 0x0f) | (TE_128_HH(tab, offset, state) << 4))

#elif TTABLE == 64
#include "tabs/AES_64.tab"
#define TE_64_0(tab, offset, state) (_te[(tab)][((offset) << 8) + (state >> 2)      ] >> ((state & 0x3) << 1))
#define TE_64_1(tab, offset, state) (_te[(tab)][((offset) << 8) + (state >> 2) +  64] >> ((state & 0x3) << 1))
#define TE_64_2(tab, offset, state) (_te[(tab)][((offset) << 8) + (state >> 2) + 128] >> ((state & 0x3) << 1))
#define TE_64_3(tab, offset, state) (_te[(tab)][((offset) << 8) + (state >> 2) + 192] >> ((state & 0x3) << 1))
#define TE(tab, offset, state) ((TE_64_0(tab, offset, state) & 0x03)	\
				| ((TE_64_1(tab, offset, state) & 0x03) << 2) \
				| ((TE_64_2(tab, offset, state) & 0x03) << 4) \
				| ((TE_64_3(tab, offset, state) & 0x03) << 6))

#elif TTABLE == 32
#include "tabs/AES_32.tab"
#define TE_32_0(tab, offset, state) (_te[(tab)][((offset) << 8) + (state >> 3)      ] >> (state & 0x7))
#define TE_32_1(tab, offset, state) (_te[(tab)][((offset) << 8) + (state >> 3) +  32] >> (state & 0x7))
#define TE_32_2(tab, offset, state) (_te[(tab)][((offset) << 8) + (state >> 3) +  64] >> (state & 0x7))
#define TE_32_3(tab, offset, state) (_te[(tab)][((offset) << 8) + (state >> 3) +  96] >> (state & 0x7))
#define TE_32_4(tab, offset, state) (_te[(tab)][((offset) << 8) + (state >> 3) + 128] >> (state & 0x7))
#define TE_32_5(tab, offset, state) (_te[(tab)][((offset) << 8) + (state >> 3) + 160] >> (state & 0x7))
#define TE_32_6(tab, offset, state) (_te[(tab)][((offset) << 8) + (state >> 3) + 192] >> (state & 0x7))
#define TE_32_7(tab, offset, state) (_te[(tab)][((offset) << 8) + (state >> 3) + 224] >> (state & 0x7))
#define TE(tab, offset, state) ((TE_32_0(tab, offset, state) & 0x01)	      \
				| ((TE_32_1(tab, offset, state) & 0x01) << 1) \
				| ((TE_32_2(tab, offset, state) & 0x01) << 2) \
				| ((TE_32_3(tab, offset, state) & 0x01) << 3) \
				| ((TE_32_4(tab, offset, state) & 0x01) << 4) \
				| ((TE_32_5(tab, offset, state) & 0x01) << 5) \
				| ((TE_32_6(tab, offset, state) & 0x01) << 6) \
				| ((TE_32_7(tab, offset, state) & 0x01) << 7))		   
#endif


#define LOAD_U8_G0(s, offset) {					\
	m[0].c[offset] = TE(0, offset, s[0].c[3]);			\
	m[1].c[offset] = TE(1, offset, s[1].c[2]);			\
	m[2].c[offset] = TE(2, offset, s[2].c[1]);			\
	m[3].c[offset] = TE(3, offset, s[3].c[0]);			\
    }

#define LOAD_U8_G1(s, offset) {						\
	m[0].c[offset] = TE(0, offset, s[1].c[3]);			\
	m[1].c[offset] = TE(1, offset, s[2].c[2]);			\
	m[2].c[offset] = TE(2, offset, s[3].c[1]);			\
	m[3].c[offset] = TE(3, offset, s[0].c[0]);			\
    }
#define LOAD_U8_G2(s, offset) {						\
	m[0].c[offset] = TE(0, offset, s[2].c[3]);			\
	m[1].c[offset] = TE(1, offset, s[3].c[2]);			\
	m[2].c[offset] = TE(2, offset, s[0].c[1]);			\
	m[3].c[offset] = TE(3, offset, s[1].c[0]);			\
    }
#define LOAD_U8_G3(s, offset) {						\
	m[0].c[offset] = TE(0, offset, s[3].c[3]);			\
	m[1].c[offset] = TE(1, offset, s[0].c[2]);			\
	m[2].c[offset] = TE(2, offset, s[1].c[1]);			\
	m[3].c[offset] = TE(3, offset, s[2].c[0]);			\
    }

#define SROUND(t, s, r) {						\
	int b = r << 2;							\
	u32_t m[4];							\
	LOAD_U8_G0(s, 0); LOAD_U8_G0(s, 1); LOAD_U8_G0(s, 2); LOAD_U8_G0(s, 3); \
	t[0].i = m[0].i ^ m[1].i ^ m[2].i ^ m[3].i ^ _rk[b + 0].i;	\
	LOAD_U8_G1(s, 0); LOAD_U8_G1(s, 1); LOAD_U8_G1(s, 2); LOAD_U8_G1(s, 3);	\
	t[1].i = m[0].i ^ m[1].i ^ m[2].i ^ m[3].i ^ _rk[b + 1].i;	\
	LOAD_U8_G2(s, 0); LOAD_U8_G2(s, 1); LOAD_U8_G2(s, 2); LOAD_U8_G2(s, 3);	\
	t[2].i = m[0].i ^ m[1].i ^ m[2].i ^ m[3].i ^ _rk[b + 2].i;	\
	LOAD_U8_G3(s, 0); LOAD_U8_G3(s, 1); LOAD_U8_G3(s, 2); LOAD_U8_G3(s, 3);	\
	t[3].i = m[0].i ^ m[1].i ^ m[2].i ^ m[3].i ^ _rk[b + 3].i;	\
    }

__global__ void AES_encrypt(const uint *pt, uint *ct, uint *rek, uint Nr, uint size) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    u32_t *_pt = (u32_t *)pt, *_ct = (u32_t *)ct, *_rk = (u32_t *)rek;
    u32_t _s[4], _t[4];
#ifdef USE_SMEM
    __shared__ uchar sTe0[1024], sTe1[1024], sTe2[1024], sTe3[1024];
    uchar* _te[] = {sTe0, sTe1, sTe2, sTe3};
#if TTABLE == 256
    load_smem(sTe0, dTe0_256, sTe1, dTe1_256, sTe2, dTe2_256, sTe3, dTe3_256);
#elif TTABLE == 128
    load_smem(sTe0, dTe0_128, sTe1, dTe1_128, sTe2, dTe2_128, sTe3, dTe3_128);
#elif TTABLE == 64
    load_smem(sTe0, dTe0_64, sTe1, dTe1_64, sTe2, dTe2_64, sTe3, dTe3_64);
#elif TTABLE == 32
    load_smem(sTe0, dTe0_32, sTe1, dTe1_32, sTe2, dTe2_32, sTe3, dTe3_32);
#endif // TTABLE
#else
#if TTABLE == 256
    uchar* _te[] = {dTe0_256, dTe1_256, dTe2_256, dTe3_256};
#elif TTABLE == 128
    uchar* _te[] = {dTe0_128, dTe1_128, dTe2_128, dTe3_128};
#elif TTABLE == 64
    uchar* _te[] = {dTe0_64, dTe1_64, dTe2_64, dTe3_64};
#elif TTABLE == 32
    uchar* _te[] = {dTe0_32, dTe1_32, dTe2_32, dTe3_32};
#endif // TTABLE
#endif // USE_SMEM

    int iter = 0;

 BEGIN:
    int offset = (iter * NUM_THREADS * NUM_BLOCKS + tid) << 2;
    if (offset >= size) return;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    _rk = (u32_t *)rek;
    _s[0].i = _pt[offset + 0].i ^ _rk[0].i;
    _s[1].i = _pt[offset + 1].i ^ _rk[1].i;
    _s[2].i = _pt[offset + 2].i ^ _rk[2].i;
    _s[3].i = _pt[offset + 3].i ^ _rk[3].i;

    SROUND(_t, _s, 1);
    SROUND(_s, _t, 2);
    SROUND(_t, _s, 3);
    SROUND(_s, _t, 4);
    SROUND(_t, _s, 5);
    SROUND(_s, _t, 6);
    SROUND(_t, _s, 7);
    SROUND(_s, _t, 8);
    SROUND(_t, _s, 9);
    if (Nr > 10) {
	SROUND(_s, _t, 10);
	SROUND(_t, _s, 11);
        if (Nr > 12) {
	    SROUND(_s, _t, 12);
	    SROUND(_t, _s, 13);
        }
    }
    /*
     * apply last round and
     * map cipher state to byte array block:
     */
    _rk += (Nr << 2);
    u32_t m;
    m.c[0] = TE(1, 0, _t[3].c[0]);
    m.c[1] = TE(0, 1, _t[2].c[1]);
    m.c[2] = TE(3, 2, _t[1].c[2]);
    m.c[3] = TE(2, 3, _t[0].c[3]);
    _ct[offset + 0].i = m.i ^ _rk[0].i;
    m.c[0] = TE(1, 0, _t[0].c[0]);
    m.c[1] = TE(0, 1, _t[3].c[1]);
    m.c[2] = TE(3, 2, _t[2].c[2]);
    m.c[3] = TE(2, 3, _t[1].c[3]);
    _ct[offset + 1].i = m.i ^ _rk[1].i;
    m.c[0] = TE(1, 0, _t[1].c[0]);
    m.c[1] = TE(0, 1, _t[0].c[1]);
    m.c[2] = TE(3, 2, _t[3].c[2]);
    m.c[3] = TE(2, 3, _t[2].c[3]);
    _ct[offset + 2].i = m.i ^ _rk[2].i;
    m.c[0] = TE(1, 0, _t[2].c[0]);
    m.c[1] = TE(0, 1, _t[1].c[1]);
    m.c[2] = TE(3, 2, _t[0].c[2]);
    m.c[3] = TE(2, 3, _t[3].c[3]);
    _ct[offset + 3].i = m.i ^ _rk[3].i;

    iter++;
    goto BEGIN;
}

