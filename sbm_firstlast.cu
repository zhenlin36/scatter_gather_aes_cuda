#include "util.cu"
#include "tabs/sbox.tab"
union u32_t {
    uint i;
    uchar c[4];
};

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
__device__ void SubBytesSecure(uchar *state, uchar *sbox) {
    for (int i = 0; i < 16; i++) {
	state[i] = STE(state[i]);//sbox[state[i]];
    }
}
__device__ void SubBytes(uchar *state, uchar *sbox) {
    for (int i = 0; i < 16; i++) {
	state[i] = sbox[state[i]];
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
    //uchar state[16];
    uchar *_rk = (uchar *)rek;
#ifdef USE_SMEM
    __shared__ uchar sbox[256];
#if TTABLE == 256
    load_smem_sbox(sbox, Tsbox_256);
#elif TTABLE == 128
    load_smem_sbox(sbox, Tsbox_128);
#elif TTABLE == 64
    load_smem_sbox(sbox, Tsbox_64);
#elif TTABLE == 32
    load_smem_sbox(sbox, Tsbox_32);
#endif // TTABLE
#else
#if TTABLE == 256
    uchar *sbox = Tsbox_256;
#elif TTABLE == 128
    uchar *sbox = Tsbox_128;
#elif TTABLE == 64
    uchar *sbox = Tsbox_64;
#elif TTABLE == 32
    uchar *sbox = Tsbox_32;
#endif // TTABLE
#endif // USE_SMEM
    uchar *sbox_256 = Tsbox_256;
    int iter = 0;

 BEGIN:
    int offset = (iter * NUM_THREADS * NUM_BLOCKS + tid) << 2;
    if (offset >= size) return;
    
    state[0].i = REV_ENDIAN(pt[offset + 0]);
    state[1].i = REV_ENDIAN(pt[offset + 1]);
    state[2].i = REV_ENDIAN(pt[offset + 2]);
    state[3].i = REV_ENDIAN(pt[offset + 3]);
    TransposeSelf((uchar*)state);

    AddRoundKey((uchar*)state, (uchar*)_rk);

    SubBytesSecure((uchar*)state, sbox);
    ShiftRows((uchar*)state);
    MixColumns((uchar*)state);
    AddRoundKey((uchar*)state, (uchar*)(rek + 4));
    for (int i = 2; i < Nr; i++) 
    {
	SubBytes((uchar*)state, sbox_256);
	ShiftRows((uchar*)state);
	MixColumns((uchar*)state);
	AddRoundKey((uchar*)state, (uchar*)(rek + i*4));
    }
    SubBytesSecure((uchar*)state, sbox);
    ShiftRows((uchar*)state);
    AddRoundKey((uchar*)state, (uchar*)(rek + Nr*4));

    TransposeSelf((uchar*)state);
    ct[offset + 0] = REV_ENDIAN(state[0].i);
    ct[offset + 1] = REV_ENDIAN(state[1].i);
    ct[offset + 2] = REV_ENDIAN(state[2].i);
    ct[offset + 3] = REV_ENDIAN(state[3].i);

    iter++;
    goto BEGIN;
}
