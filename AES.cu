/**
 * AES.cpp
 *
 * The Advanced Encryption Standard (AES, aka AES) block cipher,
 * designed by J. Daemen and V. Rijmen.
 *
 * @author Paulo S. L. M. Barreto
 *
 * This software is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include <stdio.h>
#include <time.h>

#include "AES.h"
#include "helper_cuda.h"
#include <sys/time.h>

#include "tabs/AES.tab"
#include "AES_decrypt.cu"
#if defined HYBRID
#include "AES_encrypt_hybrid.cu"
const char *g_mode = "hybrid";
#elif defined SECURE
#include "AES_encrypt_secure.cu"
const char *g_mode = "secure";
#elif defined LASTROUND
#include "AES_encrypt_lastround.cu"
const char *g_mode = "lastround";
#elif defined BASELINE
#include "AES_encrypt.cu"
const char *g_mode = "base";
#elif defined SBOX
#include "sbox_encrypt.cu"
const char *g_mode = "sbox";
#elif defined SHYBRID
#include "sbox_encrypt_hybrid.cu"
const char *g_mode = "sbox_hybrid";
#elif defined SLASTROUND
#include "sbox_encrypt_lastround.cu"
const char *g_mode = "sbox_lastround";
#elif defined SFTL
#include "AES_encrypt_sftl.cu"
const char *g_mode = "sftl";
#elif defined SBM_L
#include "sbm_lastround.cu"
const char *g_mode = "sbm_lastround";
#elif defined SBM_FL
#include "sbm_firstlast.cu"
const char *g_mode = "sbm_firstlast";
#elif defined SBM_SFTL
#include "sbm_sftl.cu"
const char *g_mode = "sbm_sftl";
#endif


#define FULL_UNROLL

#ifdef _MSC_VER
#define SWAP(x) (_lrotl(x, 8) & 0x00ff00ff | _lrotr(x, 8) & 0xff00ff00)
#define GETWORD(p) SWAP(*((uint *)(p)))
#define PUTWORD(ct, st) (*((uint *)(ct)) = SWAP((st)))
#else
#define GETWORD(pt) (((uint)(pt)[0] << 24) ^ ((uint)(pt)[1] << 16) ^ ((uint)(pt)[2] <<  8) ^ ((uint)(pt)[3]))
#define PUTWORD(ct, st) ((ct)[0] = (uchar)((st) >> 24), (ct)[1] = (uchar)((st) >> 16), (ct)[2] = (uchar)((st) >>  8), (ct)[3] = (uchar)(st), (st))
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

AES::AES() {
    checkCudaErrors(cudaMalloc((void**)&ce_sched, sizeof(e_sched)));
    checkCudaErrors(cudaMalloc((void**)&cd_sched, sizeof(d_sched)));
}

AES::~AES() {
    Nr = 0;
    memset(e_sched, 0, sizeof(e_sched));
    memset(d_sched, 0, sizeof(d_sched));

    checkCudaErrors(cudaFree(ce_sched));
    checkCudaErrors(cudaFree(cd_sched));
}

//////////////////////////////////////////////////////////////////////
// Support methods
//////////////////////////////////////////////////////////////////////

void AES::ExpandKey(const uchar *cipherKey, uint keyBits) {
    uint *rek = e_sched;
    uint i = 0;
    uint temp;
    rek[0] = GETWORD(cipherKey     );
    rek[1] = GETWORD(cipherKey +  4);
    rek[2] = GETWORD(cipherKey +  8);
    rek[3] = GETWORD(cipherKey + 12);
    if (keyBits == 128) {
        for (;;) {
            temp  = rek[3];
            rek[4] = rek[0] ^
                (Te4[(temp >> 16) & 0xff] & 0xff000000) ^
                (Te4[(temp >>  8) & 0xff] & 0x00ff0000) ^
                (Te4[(temp      ) & 0xff] & 0x0000ff00) ^
                (Te4[(temp >> 24)       ] & 0x000000ff) ^
                rcon[i];
            rek[5] = rek[1] ^ rek[4];
            rek[6] = rek[2] ^ rek[5];
            rek[7] = rek[3] ^ rek[6];
            if (++i == 10) {
                Nr = 10;
                return;
            }
            rek += 4;
        }
    }
    rek[4] = GETWORD(cipherKey + 16);
    rek[5] = GETWORD(cipherKey + 20);
    if (keyBits == 192) {
        for (;;) {
            temp = rek[ 5];
            rek[ 6] = rek[ 0] ^
                (Te4[(temp >> 16) & 0xff] & 0xff000000) ^
                (Te4[(temp >>  8) & 0xff] & 0x00ff0000) ^
                (Te4[(temp      ) & 0xff] & 0x0000ff00) ^
                (Te4[(temp >> 24)       ] & 0x000000ff) ^
                rcon[i];
            rek[ 7] = rek[ 1] ^ rek[ 6];
            rek[ 8] = rek[ 2] ^ rek[ 7];
            rek[ 9] = rek[ 3] ^ rek[ 8];
            if (++i == 8) {
                Nr = 12;
                return;
            }
            rek[10] = rek[ 4] ^ rek[ 9];
            rek[11] = rek[ 5] ^ rek[10];
            rek += 6;
        }
    }
    rek[6] = GETWORD(cipherKey + 24);
    rek[7] = GETWORD(cipherKey + 28);
    if (keyBits == 256) {
        for (;;) {
            temp = rek[ 7];
            rek[ 8] = rek[ 0] ^
                (Te4[(temp >> 16) & 0xff] & 0xff000000) ^
                (Te4[(temp >>  8) & 0xff] & 0x00ff0000) ^
                (Te4[(temp      ) & 0xff] & 0x0000ff00) ^
                (Te4[(temp >> 24)       ] & 0x000000ff) ^
                rcon[i];
            rek[ 9] = rek[ 1] ^ rek[ 8];
            rek[10] = rek[ 2] ^ rek[ 9];
            rek[11] = rek[ 3] ^ rek[10];
            if (++i == 7) {
                Nr = 14;
                return;
            }
            temp = rek[11];
            rek[12] = rek[ 4] ^
                (Te4[(temp >> 24)       ] & 0xff000000) ^
                (Te4[(temp >> 16) & 0xff] & 0x00ff0000) ^
                (Te4[(temp >>  8) & 0xff] & 0x0000ff00) ^
                (Te4[(temp      ) & 0xff] & 0x000000ff);
            rek[13] = rek[ 5] ^ rek[12];
            rek[14] = rek[ 6] ^ rek[13];
            rek[15] = rek[ 7] ^ rek[14];
            rek += 8;
        }
    }
    Nr = 0; // this should never happen
}

void AES::InvertKey() {
    uint *rek = e_sched;
    uint *rdk = d_sched;
    assert(Nr == 10 || Nr == 12 || Nr == 14);
    rek += 4*Nr;
    /* apply the inverse MixColumn transform to all round keys but the first and the last: */
    memcpy(rdk, rek, 16);
    rdk += 4;
    rek -= 4;
    for (uint r = 1; r < Nr; r++) {
        rdk[0] =
            Td0[Te4[(rek[0] >> 24)       ] & 0xff] ^
            Td1[Te4[(rek[0] >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(rek[0] >>  8) & 0xff] & 0xff] ^
            Td3[Te4[(rek[0]      ) & 0xff] & 0xff];
        rdk[1] =
            Td0[Te4[(rek[1] >> 24)       ] & 0xff] ^
            Td1[Te4[(rek[1] >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(rek[1] >>  8) & 0xff] & 0xff] ^
            Td3[Te4[(rek[1]      ) & 0xff] & 0xff];
        rdk[2] =
            Td0[Te4[(rek[2] >> 24)       ] & 0xff] ^
            Td1[Te4[(rek[2] >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(rek[2] >>  8) & 0xff] & 0xff] ^
            Td3[Te4[(rek[2]      ) & 0xff] & 0xff];
        rdk[3] =
            Td0[Te4[(rek[3] >> 24)       ] & 0xff] ^
            Td1[Te4[(rek[3] >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(rek[3] >>  8) & 0xff] & 0xff] ^
            Td3[Te4[(rek[3]      ) & 0xff] & 0xff];
        rdk += 4;
        rek -= 4;
    }
    memcpy(rdk, rek, 16);
}

//////////////////////////////////////////////////////////////////////
// Public Interface
//////////////////////////////////////////////////////////////////////

/**
 * Convert one data block from uchar[] to int[] representation.
 */
void AES::uchar2int(const uchar *b, uint *i) {
    i[0] = GETWORD(b     );
    i[1] = GETWORD(b +  4);
    i[2] = GETWORD(b +  8);
    i[3] = GETWORD(b + 12);
}

/**
 * Convert one data block from int[] to uchar[] representation.
 */
void AES::int2uchar(const uint *i, uchar *b) {
    PUTWORD(b     , i[0]);
    PUTWORD(b +  4, i[1]);
    PUTWORD(b +  8, i[2]);
    PUTWORD(b + 12, i[3]);
}

void printHexArray(uint *array, uint size);
void AES::makeKey(const uchar *cipherKey, uint keySize, uint dir) {
    switch (keySize) {
    case 16:
    case 24:
    case 32:
        keySize <<= 3; // key size is now in bits
        break;
    case 128:
    case 192:
    case 256:
        break;
    default:
        throw "Invalid AES key size";
    }
    // assert(dir >= DIR_NONE && dir <= DIR_BOTH);
    assert(dir <= DIR_BOTH);
    if (dir != DIR_NONE) {
        ExpandKey(cipherKey, keySize);

	//printHexArray(e_sched, 44);
        checkCudaErrors(cudaMemcpy(ce_sched, e_sched, sizeof(e_sched), cudaMemcpyHostToDevice));
        if (dir & DIR_DECRYPT) {
            InvertKey();
            checkCudaErrors(cudaMemcpy(cd_sched, d_sched, sizeof(e_sched), cudaMemcpyHostToDevice));
        }
    }
}

void AES::encrypt(const uint *pt, uint *ct) {
    uint *cpt, *cct;
    uint size = 4*sizeof(uint);

    checkCudaErrors(cudaMalloc((void**)&cpt, size));
    checkCudaErrors(cudaMalloc((void**)&cct, size));
    checkCudaErrors(cudaMemcpy(cpt, pt, size, cudaMemcpyHostToDevice));

    AES_encrypt<<<1,1>>>(cpt, cct, ce_sched, Nr, size >> 2);

    checkCudaErrors(cudaMemcpy(ct, cct, size, cudaMemcpyDeviceToHost));

    checkCudaErrors(cudaFree(cpt));
    checkCudaErrors(cudaFree(cct));
}

void AES::encrypt_ecb(const uint *pt, uint *ct, uint n) {
    uint *cpt, *cct;
    uint size = n*sizeof(uint);

    cudaDeviceSynchronize();
    checkCudaErrors(cudaMalloc((void**)&cpt, size));
    checkCudaErrors(cudaMalloc((void**)&cct, size));
    checkCudaErrors(cudaMemcpy(cpt, pt, size, cudaMemcpyHostToDevice));

    struct cudaDeviceProp prop;
    cudaGetDeviceProperties(&prop, 0);

    dim3 dimBlock(NUM_THREADS, 1, 1);
    dim3 dimGrid(NUM_BLOCKS, 1, 1);

    //cudaFuncSetCacheConfig(MyKernel, cudaFuncCachePreferShared);
    //cudaFuncSetCacheConfig(AES_encrypt, cudaFuncCachePreferL1);
    AES_encrypt<<<dimGrid, dimBlock>>>(cpt, cct, ce_sched, Nr, n);

    //debug<<<1, 1>>>();
    for (int i = 0; i < 1; i++) {
    cudaDeviceSynchronize();
    struct timeval start, end;
    gettimeofday(&start, NULL);
    AES_encrypt<<<dimGrid, dimBlock>>>(cpt, cct, ce_sched, Nr, n);
    cudaDeviceSynchronize();
    //exit(0);
    getLastCudaError("AES_encrypt");
    gettimeofday(&end, NULL);
    long long usec = (end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec);
    long long size_in_MB = size / 1024 / 1024;
#ifdef USE_SMEM
    const char *gors = "smem";
#else
    const char *gors = "gmem";
#endif
    printf("%s %s %d %d MB %lld usec %lf Gbps\n", g_mode, gors, TTABLE, size_in_MB, usec, ((double)size_in_MB*8/1024) / ((double)usec/1000000));
    }
    checkCudaErrors(cudaMemcpy(ct, cct, size, cudaMemcpyDeviceToHost));
	
    checkCudaErrors(cudaFree(cpt));
    checkCudaErrors(cudaFree(cct));
    cudaDeviceSynchronize();
}

#define STREAMS 8

void AES::encrypt_ecb_async(const uint *pt, uint *ct, uint n = 1) {
    uint *cpt, *cct;
    uint i, size = (n << 2)*sizeof(uint);
    uint streamSize = size / STREAMS;
    uint streamMem  = (n << 2) / STREAMS;

    cudaMalloc((void**)&cpt, size);
    cudaMalloc((void**)&cct, size);

    cudaStream_t stream[STREAMS];

    struct cudaDeviceProp prop;
    cudaGetDeviceProperties(&prop, 0);

    uint threads = 1;
    if(n != 1) {
	threads = (n < prop.maxThreadsPerBlock*2) ? n / 2 : prop.maxThreadsPerBlock;
    }
    uint blocks = (n/STREAMS) / threads;

    dim3 dimBlock(threads, 1, 1);
    dim3 dimGrid(blocks, 1, 1);

    for(i = 0; i < STREAMS; i++) {
	cudaStreamCreate(&stream[i]);
    }
    for(i = 0; i < STREAMS; i++) {
	uint offset = i*streamMem;
	cudaError_t r = cudaMemcpyAsync(cpt + offset, pt + offset, streamSize, cudaMemcpyHostToDevice, stream[i]);
    }
    for(i = 0; i < STREAMS; i++) {
	uint offset = i*streamMem;
	AES_encrypt<<<dimGrid, dimBlock, 0, stream[i]>>>(cpt + offset, cct + offset, ce_sched, Nr, size >> 2);
    }
    for(i = 0; i < STREAMS; i++) {
	uint offset = i*streamMem;
	cudaError_t r = cudaMemcpyAsync(ct + offset, cct + offset, streamSize, cudaMemcpyDeviceToHost, stream[i]);
    }

    cudaDeviceSynchronize();

    cudaFree(cpt);
    cudaFree(cct);
}

void AES::decrypt(const uint *ct, uint *pt) {
}


