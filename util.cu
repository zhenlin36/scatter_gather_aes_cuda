#ifndef UTIL_CU_
#define UTIL_CU_

// GTX 1080: smem 40x1024, gmem 80x512
// GTX 980: 32x1024
// K40: 30x1024
// TRX 2080: smem 92x1024
#ifndef NUM_BLOCKS
#define NUM_BLOCKS 30
#endif

#define NUM_THREADS 1024

#define MAX_RK_SIZE 182

__device__ void load_roundkey(uint *s, uint *rk) {
    int tid = threadIdx.x;
    if (tid < MAX_RK_SIZE)
	s[tid] = rk[tid];
    __syncthreads();
}

__device__ void load_smem_sbox(uchar *smem, uchar *gmem) {
    int tid = threadIdx.x;
    if (tid < 256)
	smem[tid] = gmem[tid];
    __syncthreads();
}

#if NUM_THREADS == 1024
__device__ void load_smem(uchar *st0, uchar *gt0, uchar *st1, uchar *gt1, uchar *st2, uchar *gt2, uchar *st3, uchar *gt3) {
    int tid = threadIdx.x;
    uint *s, *g;
    if (tid < 256) {
	s = (uint *)st0; g = (uint *)gt0;
	s[tid] = g[tid];
    } else if (tid < 512) {
	tid -= 256;
	s = (uint *)st1; g = (uint *)gt1;
	s[tid] = g[tid];
    } else if (tid < 768) {
	tid -= 512;
	s = (uint *)st2; g = (uint *)gt2;
	s[tid] = g[tid];
    } else {
	tid -= 768;
	s = (uint *)st3; g = (uint *)gt3;
	s[tid] = g[tid];
    }
    
    __syncthreads();
}
__device__ void load_smem(uint *st0, uint *gt0, uint *st1, uint *gt1, uint *st2, uint *gt2, uint *st3, uint *gt3) {
    int tid = threadIdx.x;
    if (tid < 256) {
	st0[tid] = gt0[tid];
    } else if (tid < 512) {
	tid -= 256;
	st1[tid] = gt1[tid];
    } else if (tid < 768) {
	tid -= 512;
	st2[tid] = gt2[tid];
    } else {
	tid -= 768;
	st3[tid] = gt3[tid];
    }
    
    __syncthreads();
}
#elif NUM_THREADS == 512
__device__ void load_smem(uchar *st0, uchar *gt0, uchar *st1, uchar *gt1, uchar *st2, uchar *gt2, uchar *st3, uchar *gt3) {
    int tid = threadIdx.x;
    uint *s, *g;
    if (tid < 256) {
	s = (uint *)st0; g = (uint *)gt0;
	s[tid] = g[tid];
	s = (uint *)st2; g = (uint *)gt2;
	s[tid] = g[tid];
    } else {
	tid -= 256;
	s = (uint *)st1; g = (uint *)gt1;
	s[tid] = g[tid];
	s = (uint *)st3; g = (uint *)gt3;
	s[tid] = g[tid];
    }
    
    __syncthreads();
}
__device__ void load_smem(uint *st0, uint *gt0, uint *st1, uint *gt1, uint *st2, uint *gt2, uint *st3, uint *gt3) {
    int tid = threadIdx.x;
    if (tid < 256) {
	st0[tid] = gt0[tid];
	st2[tid] = gt2[tid];
    } else {
	tid -= 256;
	st1[tid] = gt1[tid];
	st3[tid] = gt3[tid];
    }
    
    __syncthreads();
}

#elif NUM_THREADS == 256
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
__device__ void load_smem(uint *st0, uint *gt0, uint *st1, uint *gt1, uint *st2, uint *gt2, uint *st3, uint *gt3) {
    int tid = threadIdx.x;
    st0[tid] = gt0[tid];
    st1[tid] = gt1[tid];
    st2[tid] = gt2[tid];
    st3[tid] = gt3[tid];
    
    __syncthreads();
}
#else 
#error NUM_THREADS must be 256, 512 or 1024
#endif // NUM_THREADS

#endif

