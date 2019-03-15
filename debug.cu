__global__ void debug() {
#if TTABLE == 256
    uchar* _te[] = {dTe0_256, dTe1_256, dTe2_256, dTe3_256};
#elif TTABLE == 128
    uchar* _te[] = {dTe0_128, dTe1_128, dTe2_128, dTe3_128};
#elif TTABLE == 64
    uchar* _te[] = {dTe0_64, dTe1_64, dTe2_64, dTe3_64};
#elif TTABLE == 32
    uchar* _te[] = {dTe0_32, dTe1_32, dTe2_32, dTe3_32};
#endif
    for (int i = 0; i < 16; i++) {
	for (int j = 0; j < 16; j++) {
	    printf("%02x ", TE(3, 3, (i*16+j)));
	}
	printf("\n");
    }
}


    /*
    ct[offset +  0] = TE(4, 0, _t[12]) ^ _rk[ 0];
    ct[offset +  1] = TE(4, 0, _t[ 9]) ^ _rk[ 1];
    ct[offset +  2] = TE(4, 0, _t[ 6]) ^ _rk[ 2];
    ct[offset +  3] = TE(4, 0, _t[ 3]) ^ _rk[ 3];

    ct[offset +  4] = TE(4, 0, _t[ 0]) ^ _rk[ 4];
    ct[offset +  5] = TE(4, 0, _t[13]) ^ _rk[ 5];
    ct[offset +  6] = TE(4, 0, _t[10]) ^ _rk[ 6];
    ct[offset +  7] = TE(4, 0, _t[ 7]) ^ _rk[ 7];

    ct[offset +  8] = TE(4, 0, _t[ 4]) ^ _rk[ 8];
    ct[offset +  9] = TE(4, 0, _t[ 1]) ^ _rk[ 9];
    ct[offset + 10] = TE(4, 0, _t[14]) ^ _rk[10];
    ct[offset + 11] = TE(4, 0, _t[11]) ^ _rk[11];

    ct[offset + 12] = TE(4, 0, _t[ 8]) ^ _rk[12];
    ct[offset + 13] = TE(4, 0, _t[ 5]) ^ _rk[13];
    ct[offset + 14] = TE(4, 0, _t[ 2]) ^ _rk[14];
    ct[offset + 15] = TE(4, 0, _t[15]) ^ _rk[15];
    */
