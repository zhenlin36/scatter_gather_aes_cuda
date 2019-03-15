//#define TTABLE 256
//#define USE_SMEM

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

#define ROUND(t, s, r) {						\
	int b = r << 4;							\
	t[ 0] = TE(0, 0, s[ 3]) ^ TE(1, 0, s[ 6]) ^ TE(2, 0, s[ 9]) ^ TE(3, 0, s[12]) ^ _rk[b+ 0]; \
	t[ 1] = TE(0, 1, s[ 3]) ^ TE(1, 1, s[ 6]) ^ TE(2, 1, s[ 9]) ^ TE(3, 1, s[12]) ^ _rk[b+ 1]; \
	t[ 2] = TE(0, 2, s[ 3]) ^ TE(1, 2, s[ 6]) ^ TE(2, 2, s[ 9]) ^ TE(3, 2, s[12]) ^ _rk[b+ 2]; \
	t[ 3] = TE(0, 3, s[ 3]) ^ TE(1, 3, s[ 6]) ^ TE(2, 3, s[ 9]) ^ TE(3, 3, s[12]) ^ _rk[b+ 3]; \
									\
	t[ 4] = TE(0, 0, s[ 7]) ^ TE(1, 0, s[10]) ^ TE(2, 0, s[13]) ^ TE(3, 0, s[ 0]) ^ _rk[b+ 4]; \
	t[ 5] = TE(0, 1, s[ 7]) ^ TE(1, 1, s[10]) ^ TE(2, 1, s[13]) ^ TE(3, 1, s[ 0]) ^ _rk[b+ 5]; \
	t[ 6] = TE(0, 2, s[ 7]) ^ TE(1, 2, s[10]) ^ TE(2, 2, s[13]) ^ TE(3, 2, s[ 0]) ^ _rk[b+ 6]; \
	t[ 7] = TE(0, 3, s[ 7]) ^ TE(1, 3, s[10]) ^ TE(2, 3, s[13]) ^ TE(3, 3, s[ 0]) ^ _rk[b+ 7]; \
									\
	t[ 8] = TE(0, 0, s[11]) ^ TE(1, 0, s[14]) ^ TE(2, 0, s[ 1]) ^ TE(3, 0, s[ 4]) ^ _rk[b+ 8]; \
	t[ 9] = TE(0, 1, s[11]) ^ TE(1, 1, s[14]) ^ TE(2, 1, s[ 1]) ^ TE(3, 1, s[ 4]) ^ _rk[b+ 9]; \
	t[10] = TE(0, 2, s[11]) ^ TE(1, 2, s[14]) ^ TE(2, 2, s[ 1]) ^ TE(3, 2, s[ 4]) ^ _rk[b+10]; \
	t[11] = TE(0, 3, s[11]) ^ TE(1, 3, s[14]) ^ TE(2, 3, s[ 1]) ^ TE(3, 3, s[ 4]) ^ _rk[b+11]; \
									\
	t[12] = TE(0, 0, s[15]) ^ TE(1, 0, s[ 2]) ^ TE(2, 0, s[ 5]) ^ TE(3, 0, s[ 8]) ^ _rk[b+12]; \
	t[13] = TE(0, 1, s[15]) ^ TE(1, 1, s[ 2]) ^ TE(2, 1, s[ 5]) ^ TE(3, 1, s[ 8]) ^ _rk[b+13]; \
	t[14] = TE(0, 2, s[15]) ^ TE(1, 2, s[ 2]) ^ TE(2, 2, s[ 5]) ^ TE(3, 2, s[ 8]) ^ _rk[b+14]; \
	t[15] = TE(0, 3, s[15]) ^ TE(1, 3, s[ 2]) ^ TE(2, 3, s[ 5]) ^ TE(3, 3, s[ 8]) ^ _rk[b+15]; \
}

__device__ void load_smem(uchar *st0, uchar *gt0, uchar *st1, uchar *gt1, uchar *st2, uchar *gt2, uchar *st3, uchar *gt3) {
    int tid = threadIdx.x;
    uint *s, *g;
    s = (uint *)st0; g = (uint *)gt0;
    s[tid] = g[tid];
    s = (uint *)st1; g = (uint *)gt1;
    s[tid] = g[tid];
    s = (uint *)st2; g = (uint *)gt2;
    s[tid] = g[tid];
    s = (uint *)st3; g = (uint *)gt3;
    s[tid] = g[tid];
    
    __syncthreads();
}

__global__ void AES_encrypt_secure(const uint *pt, uint *ct, uint *rek, uint Nr, uint size) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    uchar *_pt = pt, *_ct = ct;
    uchar _s[16], _t[16];
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

    size <<= 2;
    int iter = 0;

 BEGIN:
    int offset = (iter * NUM_THREADS * NUM_BLOCKS + tid) << 4;
    if (offset >= size) return;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    uchar *_rk = rek;
#pragma unroll
    for (int i = 0; i < 16; i++)
	_s[i] = _pt[offset + i] ^ _rk[i];

    ROUND(_t, _s, 1);
    ROUND(_s, _t, 2);
    ROUND(_t, _s, 3);
    ROUND(_s, _t, 4);
    ROUND(_t, _s, 5);
    ROUND(_s, _t, 6);
    ROUND(_t, _s, 7);
    ROUND(_s, _t, 8);
    ROUND(_t, _s, 9);
    if (Nr > 10) {
	ROUND(_s, _t, 10);
	ROUND(_t, _s, 11);
        if (Nr > 12) {
	    ROUND(_s, _t, 12);
	    ROUND(_t, _s, 13);
        }
    }
    /*
     * apply last round and
     * map cipher state to byte array block:
     */
    _rk += (Nr << 4);
    _ct[offset +  0] = TE(1, 0, _t[12]) ^ _rk[ 0];
    _ct[offset +  1] = TE(0, 1, _t[ 9]) ^ _rk[ 1];
    _ct[offset +  2] = TE(3, 2, _t[ 6]) ^ _rk[ 2];
    _ct[offset +  3] = TE(2, 3, _t[ 3]) ^ _rk[ 3];

    _ct[offset +  4] = TE(1, 0, _t[ 0]) ^ _rk[ 4];
    _ct[offset +  5] = TE(0, 1, _t[13]) ^ _rk[ 5];
    _ct[offset +  6] = TE(3, 2, _t[10]) ^ _rk[ 6];
    _ct[offset +  7] = TE(2, 3, _t[ 7]) ^ _rk[ 7];

    _ct[offset +  8] = TE(1, 0, _t[ 4]) ^ _rk[ 8];
    _ct[offset +  9] = TE(0, 1, _t[ 1]) ^ _rk[ 9];
    _ct[offset + 10] = TE(3, 2, _t[14]) ^ _rk[10];
    _ct[offset + 11] = TE(2, 3, _t[11]) ^ _rk[11];

    _ct[offset + 12] = TE(1, 0, _t[ 8]) ^ _rk[12];
    _ct[offset + 13] = TE(0, 1, _t[ 5]) ^ _rk[13];
    _ct[offset + 14] = TE(3, 2, _t[ 2]) ^ _rk[14];
    _ct[offset + 15] = TE(2, 3, _t[15]) ^ _rk[15];

    iter++;
    goto BEGIN;
}

