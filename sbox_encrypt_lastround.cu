//#define TTABLE 256
//#define USE_SMEM
#include "util.cu"
#include "tabs/sbox.tab"
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

#define SECURE_ROUND(t, s, r) {						\
	int b = r << 2;							\
	u32_t m[4];							\
	LOAD_U8_G0(s, 0); LOAD_U8_G0(s, 1); LOAD_U8_G0(s, 2); LOAD_U8_G0(s, 3); \
	t[0].i = m[0].i ^ m[1].i ^ m[2].i ^ m[3].i ^ _rk[b + 0];	\
	LOAD_U8_G1(s, 0); LOAD_U8_G1(s, 1); LOAD_U8_G1(s, 2); LOAD_U8_G1(s, 3);	\
	t[1].i = m[0].i ^ m[1].i ^ m[2].i ^ m[3].i ^ _rk[b + 1];	\
	LOAD_U8_G2(s, 0); LOAD_U8_G2(s, 1); LOAD_U8_G2(s, 2); LOAD_U8_G2(s, 3);	\
	t[2].i = m[0].i ^ m[1].i ^ m[2].i ^ m[3].i ^ _rk[b + 2];	\
	LOAD_U8_G3(s, 0); LOAD_U8_G3(s, 1); LOAD_U8_G3(s, 2); LOAD_U8_G3(s, 3);	\
	t[3].i = m[0].i ^ m[1].i ^ m[2].i ^ m[3].i ^ _rk[b + 3];	\
    }


#if TTABLE == 128
#define STE_128_LH(state) (sbox[(state >> 1)      ] >> ((state & 0x1) << 2))
#define STE_128_HH(state) (sbox[(state >> 1) + 128] >> ((state & 0x1) << 2))
#define STE(state) ((STE_128_LH(state) & 0x0f) | (STE_128_HH(state) << 4))
#elif TTABLE == 64
#define STE_64_0(state) (sbox[(state >> 2)      ] >> ((state & 0x3) << 1))
#define STE_64_1(state) (sbox[(state >> 2) +  64] >> ((state & 0x3) << 1))
#define STE_64_2(state) (sbox[(state >> 2) + 128] >> ((state & 0x3) << 1))
#define STE_64_3(state) (sbox[(state >> 2) + 192] >> ((state & 0x3) << 1))
#define STE(state)                 ((STE_64_0(state) & 0x03)	 \
				| ((STE_64_1(state) & 0x03) << 2) \
				| ((STE_64_2(state) & 0x03) << 4) \
				| ((STE_64_3(state) & 0x03) << 6))
#elif TTABLE == 32
#define STE_32_0(state) (sbox[(state >> 3)      ] >> (state & 0x7))
#define STE_32_1(state) (sbox[(state >> 3) +  32] >> (state & 0x7))
#define STE_32_2(state) (sbox[(state >> 3) +  64] >> (state & 0x7))
#define STE_32_3(state) (sbox[(state >> 3) +  96] >> (state & 0x7))
#define STE_32_4(state) (sbox[(state >> 3) + 128] >> (state & 0x7))
#define STE_32_5(state) (sbox[(state >> 3) + 160] >> (state & 0x7))
#define STE_32_6(state) (sbox[(state >> 3) + 192] >> (state & 0x7))
#define STE_32_7(state) (sbox[(state >> 3) + 224] >> (state & 0x7))
#define STE(state) ((STE_32_0(state) & 0x01)			\
		 | ((STE_32_1(state) & 0x01) << 1)			\
		 | ((STE_32_2(state) & 0x01) << 2)			\
		 | ((STE_32_3(state) & 0x01) << 3)			\
		 | ((STE_32_4(state) & 0x01) << 4)			\
		 | ((STE_32_5(state) & 0x01) << 5)			\
		 | ((STE_32_6(state) & 0x01) << 6)			\
		 | ((STE_32_7(state) & 0x01) << 7))		   
#else
#define STE(state) (sbox[state])
#endif

#define SWAP(a, b) (a) ^= (b); (b) ^= (a); (a) ^= (b);
__device__ void TransposeSelf(uchar *state) {
    SWAP(state[1], state[4]);
    SWAP(state[2], state[8]);
    SWAP(state[3], state[12]);
    SWAP(state[6], state[9]);
    SWAP(state[7], state[13]);
    SWAP(state[11], state[14]);
}

__device__ void Transpose(uchar *dst, uchar *src) {
    for (int i = 0; i < 4; i++) {
	for (int j = 0; j < 4; j++) {
	    dst[j*4+i] = src[i*4+j];
	}
    }
}
__device__ void AddRoundKey(uchar *state, uchar *rek) {
    for (int i = 0; i < 4; i++) {
	for (int j = 0; j < 4; j++) {
	    state[j*4+i] ^= rek[i*4+3-j];
	}
    }
}
__device__ void SubBytes(uchar *state, uchar *sbox) {
    for (int i = 0; i < 16; i++) {
	state[i] = STE(state[i]);//sbox[state[i]];
	//state[i] = Tsbox_256[state[i]];
    }
}

#define xtime(x)   ((x << 1) ^ ((x >> 7) * 0x1b))
__device__ void MixColumns(uchar *state) {
    uchar Tmp, Tm, t;
    for(int i = 0; i < 4; i++) {
	t                  = state[i];
	Tmp                = state[i] ^ state[4+i] ^ state[8+i] ^ state[12+i] ;

	Tm                 = state[i] ^ state[4+i] ; 
	Tm                 = xtime(Tm); 
	state[i] ^= Tm ^ Tmp ;

	Tm                 = state[4+i] ^ state[8+i] ; 
	Tm                 = xtime(Tm); 
	state[4+i] ^= Tm ^ Tmp ;

	Tm                 = state[8+i] ^ state[12+i] ; 
	Tm                 = xtime(Tm); 
	state[8+i] ^= Tm ^ Tmp ;

	Tm                 = state[12+i] ^ t ; 
	Tm                 = xtime(Tm); 
	state[12+i] ^= Tm ^ Tmp ;
    }
}

__device__ void ShiftRows(uchar *state) {
    uchar temp;
    // Rotate first row 1 columns to left    
    temp     = state[4];
    state[4] = state[5];
    state[5] = state[6];
    state[6] = state[7];
    state[7] = temp;
    
    // Rotate second row 2 columns to left    
    temp        = state[8];
    state[8] = state[10];
    state[10] = temp;
    
    temp       = state[9];
    state[9] = state[11];
    state[11] = temp;
    
    // Rotate third row 3 columns to left
    temp              = state[12];
    state[12] = state[15];
    state[15] = state[14];
    state[14] = state[13];
    state[13] = temp;
}

#define REV_ENDIAN(x) (((x)>>24)&0x000000FF) | (((x)>>8)&0x0000FF00) | (((x)<<8)&0x00FF0000) | (((x)<<24)&0xFF000000)


__global__ void AES_encrypt(const uint *pt, uint *ct, uint *rek, uint Nr, uint size) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    u32_t state[4];
//    uchar state[16];
    u32_t _s[4], _t[4];
    uint s0, s1, s2, s3, t0, t1, t2, t3;
#ifdef USE_SMEM
    __shared__ uchar sbox[256];
    __shared__ uchar sTe0[1024], sTe1[1024], sTe2[1024], sTe3[1024];
    uchar* _te[] = {sTe0, sTe1, sTe2, sTe3};
    __shared__ uint Te0[256], Te1[256], Te2[256], Te3[256];
    load_smem(Te0, cTe0, Te1, cTe1, Te2, cTe2, Te3, cTe3);
#if TTABLE == 256
    load_smem_sbox(sbox, Tsbox_256);
    load_smem(sTe0, dTe0_256, sTe1, dTe1_256, sTe2, dTe2_256, sTe3, dTe3_256);
#elif TTABLE == 128
    load_smem_sbox(sbox, Tsbox_128);
    load_smem(sTe0, dTe0_128, sTe1, dTe1_128, sTe2, dTe2_128, sTe3, dTe3_128);
#elif TTABLE == 64
    load_smem_sbox(sbox, Tsbox_64);
    load_smem(sTe0, dTe0_64, sTe1, dTe1_64, sTe2, dTe2_64, sTe3, dTe3_64);
#elif TTABLE == 32
    load_smem_sbox(sbox, Tsbox_32);
    load_smem(sTe0, dTe0_32, sTe1, dTe1_32, sTe2, dTe2_32, sTe3, dTe3_32);
#endif // TTABLE
#else
    uint *Te0 = cTe0, *Te1 = cTe1, *Te2 = cTe2, *Te3 = cTe3;
#if TTABLE == 256
    uchar *sbox = Tsbox_256;
    uchar* _te[] = {dTe0_256, dTe1_256, dTe2_256, dTe3_256};
#elif TTABLE == 128
    uchar *sbox = Tsbox_128;
    uchar* _te[] = {dTe0_128, dTe1_128, dTe2_128, dTe3_128};
#elif TTABLE == 64
    uchar *sbox = Tsbox_64;
    uchar* _te[] = {dTe0_64, dTe1_64, dTe2_64, dTe3_64};
#elif TTABLE == 32
    uchar *sbox = Tsbox_32;
    uchar* _te[] = {dTe0_32, dTe1_32, dTe2_32, dTe3_32};
#endif // TTABLE
#endif // USE_SMEM

    int iter = 0;

 BEGIN:
    int offset = (iter * NUM_THREADS * NUM_BLOCKS + tid) << 2;
    if (offset >= size) return;

    uint *_rk = rek;
    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    s0 = pt[offset + 0] ^ _rk[0];
    s1 = pt[offset + 1] ^ _rk[1];
    s2 = pt[offset + 2] ^ _rk[2];
    s3 = pt[offset + 3] ^ _rk[3];

    /* round 1: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ _rk[ 4];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ _rk[ 5];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ _rk[ 6];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ _rk[ 7];
    /* round 2: */
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ _rk[ 8];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ _rk[ 9];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ _rk[10];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ _rk[11];
    /* round 3: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ _rk[12];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ _rk[13];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ _rk[14];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ _rk[15];
    /* round 4: */
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ _rk[16];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ _rk[17];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ _rk[18];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ _rk[19];
    /* round 5: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ _rk[20];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ _rk[21];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ _rk[22];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ _rk[23];
    /* round 6: */
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ _rk[24];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ _rk[25];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ _rk[26];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ _rk[27];
    /* round 7: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ _rk[28];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ _rk[29];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ _rk[30];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ _rk[31];
    /* round 8: */
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ _rk[32];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ _rk[33];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ _rk[34];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ _rk[35];
    /* round 9: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ _rk[36];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ _rk[37];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ _rk[38];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ _rk[39];
    if (Nr > 10) {
	// round 10
        s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ _rk[40];
        s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ _rk[41];
        s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ _rk[42];
        s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ _rk[43];
	// round 11
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ _rk[44];
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ _rk[45];
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ _rk[46];
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ _rk[47];
        if (Nr > 12) {
	    // round 12
            s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ _rk[48];
            s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ _rk[49];
            s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ _rk[50];
            s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ _rk[51];
	    // round 13
            t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ _rk[52];
            t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ _rk[53];
            t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ _rk[54];
            t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ _rk[55];
        }
    }
    /*
     * apply last round and
     * map cipher state to byte array block:
     */
    _rk += (Nr << 2);

    state[0].i = REV_ENDIAN(t0);
    state[1].i = REV_ENDIAN(t1);
    state[2].i = REV_ENDIAN(t2);
    state[3].i = REV_ENDIAN(t3);
    TransposeSelf((uchar*)state);
    SubBytes((uchar*)state, sbox);
    ShiftRows((uchar*)state);
    AddRoundKey((uchar*)state, (uchar*)(_rk));
    TransposeSelf((uchar*)state);
    ct[offset + 0] = REV_ENDIAN(state[0].i);
    ct[offset + 1] = REV_ENDIAN(state[1].i);
    ct[offset + 2] = REV_ENDIAN(state[2].i);
    ct[offset + 3] = REV_ENDIAN(state[3].i);

    iter++;
    goto BEGIN;
}

