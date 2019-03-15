#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string>
#include <assert.h>

typedef unsigned int uint;
typedef unsigned char uchar;
#include "AES.tab"
#include "sbox_original.tab"

#define FOUR 4 // assume sizeof(uint) / sizeof(uchar) is 4
#define KEY_VALUE_MAX 256

void trans_256B_to_2x128B(uchar *tab256) {
    uchar tmp[KEY_VALUE_MAX];
    memcpy(tmp, tab256, KEY_VALUE_MAX * sizeof(uchar));
    /*
    printf("sbox\n");
    for (int i = 0; i < KEY_VALUE_MAX; i++) {
	printf("%x\t", tab256[i]);
	if ((i+1)%16 == 0) printf("\n");
    }
    */
    for (int i = 0; i < KEY_VALUE_MAX; i += 2) {
	//uchar lower_half  = (tmp[i] & 0x0f) | ((tmp[i+1] & 0x0f) << 4);
	//uchar higher_half = ((tmp[i] & 0xf0) >> 4) | (tmp[i+1] & 0xf0);
	uchar lower_half  =  (tmp[i] & 0x0f)       | ((tmp[i+1] & 0x0f) << 4);
	uchar higher_half = ((tmp[i] & 0xf0) >> 4) |  (tmp[i+1] & 0xf0);
	tab256[i >> 1       ] = lower_half;
	tab256[i >> 1 | 0x80] = higher_half;
    }
    /*
    printf("sbox2\n");
    for (int i = 0; i < KEY_VALUE_MAX; i++) {
	printf("%x\t", tab256[i]);
	if ((i+1)%16 == 0) printf("\n");
    }
    */
}


void trans_256B_to_4x64B_backup(uchar *tab256) {
    uchar tmp[KEY_VALUE_MAX];
    memcpy(tmp, tab256, KEY_VALUE_MAX * sizeof(uchar));
    for (int i = 0; i < KEY_VALUE_MAX; i += 4) {
	uchar q[4] = {0};
	for (int j = 0; j < 4; j++) {
	    uint mask = 0xc0c0 >> (j * 2);
	    q[j] |= tmp[i] & mask; mask >>= 2;
	    q[j] |= tmp[i+1] & mask; mask >>= 2;
	    q[j] |= tmp[i+2] & mask; mask >>= 2;
	    q[j] |= tmp[i+3] & mask;
	}
	for (int j = 0; j < 4; j++) {
	    tab256[j*64 + i/4] = q[j];
	}
    }
}

void trans_256B_to_8x32B_backup(uchar *tab256) {
    uchar tmp[KEY_VALUE_MAX];
    memcpy(tmp, tab256, KEY_VALUE_MAX * sizeof(uchar));
    for (int i = 0; i < KEY_VALUE_MAX; i += 8) {
	uchar q[8] = {0};
	for (int j = 0; j < 8; j++) {
	    uint mask = 0x8080 >> j;
	    q[j] |= tmp[i+0] & mask; mask >>= 1;
	    q[j] |= tmp[i+1] & mask; mask >>= 1;
	    q[j] |= tmp[i+2] & mask; mask >>= 1;
	    q[j] |= tmp[i+3] & mask; mask >>= 1;
	    q[j] |= tmp[i+4] & mask; mask >>= 1;
	    q[j] |= tmp[i+5] & mask; mask >>= 1;
	    q[j] |= tmp[i+6] & mask; mask >>= 1;
	    q[j] |= tmp[i+7] & mask;
	}
	for (int j = 0; j < 8; j++) {
	    tab256[j*32 + i/8] = q[j];
	}
    }
}

void trans_256B_to_4x64B(uchar *tab256) {
    uchar tmp[KEY_VALUE_MAX];
    memcpy(tmp, tab256, KEY_VALUE_MAX * sizeof(uchar));
    for (int i = 0; i < KEY_VALUE_MAX; i += 4) {
	uchar q[4] = {0};
	uchar mask = 0x03, shift = 0;
	for (int j = 0; j < 4; j++) {
	    for (int k = 0; k < 4; k++) {
		q[j] |= (((tmp[i+k] & mask) >> shift) << (k << 1));
	    }
	    mask <<= 2;
	    shift += 2;
	    tab256[j*64 + i/4] = q[j];
	}
    }
}
void trans_256B_to_8x32B(uchar *tab256) {
    uchar tmp[KEY_VALUE_MAX];
    memcpy(tmp, tab256, KEY_VALUE_MAX * sizeof(uchar));
    for (int i = 0; i < KEY_VALUE_MAX; i += 8) {
	uchar q[8] = {0};
	uchar mask = 0x01, shift = 0;
	for (int j = 0; j < 8; j++) {
	    for (int k = 0; k < 8; k++) {
		q[j] |= (((tmp[i+k] & mask) >> shift) << k);
	    }
	    mask <<= 1;
	    shift++;
	    tab256[j*32 + i/8] = q[j];
	}
    }
}

void reformat(uchar *tab, int mode) {
    memcpy(tab, Tsbox, 256 * sizeof(uchar));
    if (mode == 128) {
	trans_256B_to_2x128B(tab);
    } else if (mode == 64) {
	trans_256B_to_4x64B(tab);
    } else if (mode == 32) {
	trans_256B_to_8x32B(tab);
    }
}

void print_table_256B(const uchar *tab, int mode) {
    static const char *str = "#ifdef USE_CONSTANT\n__constant__\n#endif\n__device__\n";
    printf("%suchar %s_%d[1024] = {\n", str, "Tsbox", mode);
    for (int i = 0; i < KEY_VALUE_MAX; i++) {
	printf("0x%02x,%s", tab[i], (i % 16 == 15) ? "\n" : " ");
    }
    printf("};\n");
}

int main(int argc, char** argv) {

    uchar tab[KEY_VALUE_MAX];
    printf("#ifndef __SBOX_TAB\n");
    printf("#define __SBOX_TAB\n");
    reformat(tab, 256);
    print_table_256B(tab, 256);
    reformat(tab, 128);
    print_table_256B(tab, 128);
    reformat(tab, 64);
    print_table_256B(tab, 64);
    reformat(tab, 32);
    print_table_256B(tab, 32);
    printf("#endif //__SBOX_TAB\n");
    

    return 0;
}
