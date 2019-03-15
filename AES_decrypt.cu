__global__ void AES_decrypt(const uint *ct, uint *pt, uint *rdk, uint Nr) {
    uint s0, s1, s2, s3, t0, t1, t2, t3;
    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    s0 = ct[0] ^ rdk[0];
    s1 = ct[1] ^ rdk[1];
    s2 = ct[2] ^ rdk[2];
    s3 = ct[3] ^ rdk[3];

    /* round 1: */
    t0 = cTd0[s0 >> 24] ^ cTd1[(s3 >> 16) & 0xff] ^ cTd2[(s2 >>  8) & 0xff] ^ cTd3[s1 & 0xff] ^ rdk[ 4];
    t1 = cTd0[s1 >> 24] ^ cTd1[(s0 >> 16) & 0xff] ^ cTd2[(s3 >>  8) & 0xff] ^ cTd3[s2 & 0xff] ^ rdk[ 5];
    t2 = cTd0[s2 >> 24] ^ cTd1[(s1 >> 16) & 0xff] ^ cTd2[(s0 >>  8) & 0xff] ^ cTd3[s3 & 0xff] ^ rdk[ 6];
    t3 = cTd0[s3 >> 24] ^ cTd1[(s2 >> 16) & 0xff] ^ cTd2[(s1 >>  8) & 0xff] ^ cTd3[s0 & 0xff] ^ rdk[ 7];
    /* round 2: */
    s0 = cTd0[t0 >> 24] ^ cTd1[(t3 >> 16) & 0xff] ^ cTd2[(t2 >>  8) & 0xff] ^ cTd3[t1 & 0xff] ^ rdk[ 8];
    s1 = cTd0[t1 >> 24] ^ cTd1[(t0 >> 16) & 0xff] ^ cTd2[(t3 >>  8) & 0xff] ^ cTd3[t2 & 0xff] ^ rdk[ 9];
    s2 = cTd0[t2 >> 24] ^ cTd1[(t1 >> 16) & 0xff] ^ cTd2[(t0 >>  8) & 0xff] ^ cTd3[t3 & 0xff] ^ rdk[10];
    s3 = cTd0[t3 >> 24] ^ cTd1[(t2 >> 16) & 0xff] ^ cTd2[(t1 >>  8) & 0xff] ^ cTd3[t0 & 0xff] ^ rdk[11];
    /* round 3: */
    t0 = cTd0[s0 >> 24] ^ cTd1[(s3 >> 16) & 0xff] ^ cTd2[(s2 >>  8) & 0xff] ^ cTd3[s1 & 0xff] ^ rdk[12];
    t1 = cTd0[s1 >> 24] ^ cTd1[(s0 >> 16) & 0xff] ^ cTd2[(s3 >>  8) & 0xff] ^ cTd3[s2 & 0xff] ^ rdk[13];
    t2 = cTd0[s2 >> 24] ^ cTd1[(s1 >> 16) & 0xff] ^ cTd2[(s0 >>  8) & 0xff] ^ cTd3[s3 & 0xff] ^ rdk[14];
    t3 = cTd0[s3 >> 24] ^ cTd1[(s2 >> 16) & 0xff] ^ cTd2[(s1 >>  8) & 0xff] ^ cTd3[s0 & 0xff] ^ rdk[15];
    /* round 4: */
    s0 = cTd0[t0 >> 24] ^ cTd1[(t3 >> 16) & 0xff] ^ cTd2[(t2 >>  8) & 0xff] ^ cTd3[t1 & 0xff] ^ rdk[16];
    s1 = cTd0[t1 >> 24] ^ cTd1[(t0 >> 16) & 0xff] ^ cTd2[(t3 >>  8) & 0xff] ^ cTd3[t2 & 0xff] ^ rdk[17];
    s2 = cTd0[t2 >> 24] ^ cTd1[(t1 >> 16) & 0xff] ^ cTd2[(t0 >>  8) & 0xff] ^ cTd3[t3 & 0xff] ^ rdk[18];
    s3 = cTd0[t3 >> 24] ^ cTd1[(t2 >> 16) & 0xff] ^ cTd2[(t1 >>  8) & 0xff] ^ cTd3[t0 & 0xff] ^ rdk[19];
    /* round 5: */
    t0 = cTd0[s0 >> 24] ^ cTd1[(s3 >> 16) & 0xff] ^ cTd2[(s2 >>  8) & 0xff] ^ cTd3[s1 & 0xff] ^ rdk[20];
    t1 = cTd0[s1 >> 24] ^ cTd1[(s0 >> 16) & 0xff] ^ cTd2[(s3 >>  8) & 0xff] ^ cTd3[s2 & 0xff] ^ rdk[21];
    t2 = cTd0[s2 >> 24] ^ cTd1[(s1 >> 16) & 0xff] ^ cTd2[(s0 >>  8) & 0xff] ^ cTd3[s3 & 0xff] ^ rdk[22];
    t3 = cTd0[s3 >> 24] ^ cTd1[(s2 >> 16) & 0xff] ^ cTd2[(s1 >>  8) & 0xff] ^ cTd3[s0 & 0xff] ^ rdk[23];
    /* round 6: */
    s0 = cTd0[t0 >> 24] ^ cTd1[(t3 >> 16) & 0xff] ^ cTd2[(t2 >>  8) & 0xff] ^ cTd3[t1 & 0xff] ^ rdk[24];
    s1 = cTd0[t1 >> 24] ^ cTd1[(t0 >> 16) & 0xff] ^ cTd2[(t3 >>  8) & 0xff] ^ cTd3[t2 & 0xff] ^ rdk[25];
    s2 = cTd0[t2 >> 24] ^ cTd1[(t1 >> 16) & 0xff] ^ cTd2[(t0 >>  8) & 0xff] ^ cTd3[t3 & 0xff] ^ rdk[26];
    s3 = cTd0[t3 >> 24] ^ cTd1[(t2 >> 16) & 0xff] ^ cTd2[(t1 >>  8) & 0xff] ^ cTd3[t0 & 0xff] ^ rdk[27];
    /* round 7: */
    t0 = cTd0[s0 >> 24] ^ cTd1[(s3 >> 16) & 0xff] ^ cTd2[(s2 >>  8) & 0xff] ^ cTd3[s1 & 0xff] ^ rdk[28];
    t1 = cTd0[s1 >> 24] ^ cTd1[(s0 >> 16) & 0xff] ^ cTd2[(s3 >>  8) & 0xff] ^ cTd3[s2 & 0xff] ^ rdk[29];
    t2 = cTd0[s2 >> 24] ^ cTd1[(s1 >> 16) & 0xff] ^ cTd2[(s0 >>  8) & 0xff] ^ cTd3[s3 & 0xff] ^ rdk[30];
    t3 = cTd0[s3 >> 24] ^ cTd1[(s2 >> 16) & 0xff] ^ cTd2[(s1 >>  8) & 0xff] ^ cTd3[s0 & 0xff] ^ rdk[31];
    /* round 8: */
    s0 = cTd0[t0 >> 24] ^ cTd1[(t3 >> 16) & 0xff] ^ cTd2[(t2 >>  8) & 0xff] ^ cTd3[t1 & 0xff] ^ rdk[32];
    s1 = cTd0[t1 >> 24] ^ cTd1[(t0 >> 16) & 0xff] ^ cTd2[(t3 >>  8) & 0xff] ^ cTd3[t2 & 0xff] ^ rdk[33];
    s2 = cTd0[t2 >> 24] ^ cTd1[(t1 >> 16) & 0xff] ^ cTd2[(t0 >>  8) & 0xff] ^ cTd3[t3 & 0xff] ^ rdk[34];
    s3 = cTd0[t3 >> 24] ^ cTd1[(t2 >> 16) & 0xff] ^ cTd2[(t1 >>  8) & 0xff] ^ cTd3[t0 & 0xff] ^ rdk[35];
    /* round 9: */
    t0 = cTd0[s0 >> 24] ^ cTd1[(s3 >> 16) & 0xff] ^ cTd2[(s2 >>  8) & 0xff] ^ cTd3[s1 & 0xff] ^ rdk[36];
    t1 = cTd0[s1 >> 24] ^ cTd1[(s0 >> 16) & 0xff] ^ cTd2[(s3 >>  8) & 0xff] ^ cTd3[s2 & 0xff] ^ rdk[37];
    t2 = cTd0[s2 >> 24] ^ cTd1[(s1 >> 16) & 0xff] ^ cTd2[(s0 >>  8) & 0xff] ^ cTd3[s3 & 0xff] ^ rdk[38];
    t3 = cTd0[s3 >> 24] ^ cTd1[(s2 >> 16) & 0xff] ^ cTd2[(s1 >>  8) & 0xff] ^ cTd3[s0 & 0xff] ^ rdk[39];
    if (Nr > 10) {
        /* round 10: */
        s0 = cTd0[t0 >> 24] ^ cTd1[(t3 >> 16) & 0xff] ^ cTd2[(t2 >>  8) & 0xff] ^ cTd3[t1 & 0xff] ^ rdk[40];
        s1 = cTd0[t1 >> 24] ^ cTd1[(t0 >> 16) & 0xff] ^ cTd2[(t3 >>  8) & 0xff] ^ cTd3[t2 & 0xff] ^ rdk[41];
        s2 = cTd0[t2 >> 24] ^ cTd1[(t1 >> 16) & 0xff] ^ cTd2[(t0 >>  8) & 0xff] ^ cTd3[t3 & 0xff] ^ rdk[42];
        s3 = cTd0[t3 >> 24] ^ cTd1[(t2 >> 16) & 0xff] ^ cTd2[(t1 >>  8) & 0xff] ^ cTd3[t0 & 0xff] ^ rdk[43];
        /* round 11: */
        t0 = cTd0[s0 >> 24] ^ cTd1[(s3 >> 16) & 0xff] ^ cTd2[(s2 >>  8) & 0xff] ^ cTd3[s1 & 0xff] ^ rdk[44];
        t1 = cTd0[s1 >> 24] ^ cTd1[(s0 >> 16) & 0xff] ^ cTd2[(s3 >>  8) & 0xff] ^ cTd3[s2 & 0xff] ^ rdk[45];
        t2 = cTd0[s2 >> 24] ^ cTd1[(s1 >> 16) & 0xff] ^ cTd2[(s0 >>  8) & 0xff] ^ cTd3[s3 & 0xff] ^ rdk[46];
        t3 = cTd0[s3 >> 24] ^ cTd1[(s2 >> 16) & 0xff] ^ cTd2[(s1 >>  8) & 0xff] ^ cTd3[s0 & 0xff] ^ rdk[47];
        if (Nr > 12) {
            /* round 12: */
            s0 = cTd0[t0 >> 24] ^ cTd1[(t3 >> 16) & 0xff] ^ cTd2[(t2 >>  8) & 0xff] ^ cTd3[t1 & 0xff] ^ rdk[48];
            s1 = cTd0[t1 >> 24] ^ cTd1[(t0 >> 16) & 0xff] ^ cTd2[(t3 >>  8) & 0xff] ^ cTd3[t2 & 0xff] ^ rdk[49];
            s2 = cTd0[t2 >> 24] ^ cTd1[(t1 >> 16) & 0xff] ^ cTd2[(t0 >>  8) & 0xff] ^ cTd3[t3 & 0xff] ^ rdk[50];
            s3 = cTd0[t3 >> 24] ^ cTd1[(t2 >> 16) & 0xff] ^ cTd2[(t1 >>  8) & 0xff] ^ cTd3[t0 & 0xff] ^ rdk[51];
            /* round 13: */
            t0 = cTd0[s0 >> 24] ^ cTd1[(s3 >> 16) & 0xff] ^ cTd2[(s2 >>  8) & 0xff] ^ cTd3[s1 & 0xff] ^ rdk[52];
            t1 = cTd0[s1 >> 24] ^ cTd1[(s0 >> 16) & 0xff] ^ cTd2[(s3 >>  8) & 0xff] ^ cTd3[s2 & 0xff] ^ rdk[53];
            t2 = cTd0[s2 >> 24] ^ cTd1[(s1 >> 16) & 0xff] ^ cTd2[(s0 >>  8) & 0xff] ^ cTd3[s3 & 0xff] ^ rdk[54];
            t3 = cTd0[s3 >> 24] ^ cTd1[(s2 >> 16) & 0xff] ^ cTd2[(s1 >>  8) & 0xff] ^ cTd3[s0 & 0xff] ^ rdk[55];
        }
    }
    rdk += Nr << 2;

    /*
     * apply last round and
     * map cipher state to byte array block:
     */
    pt[0] =
        (cTd4[(t0 >> 24)       ] & 0xff000000) ^
        (cTd4[(t3 >> 16) & 0xff] & 0x00ff0000) ^
        (cTd4[(t2 >>  8) & 0xff] & 0x0000ff00) ^
        (cTd4[(t1      ) & 0xff] & 0x000000ff) ^
        rdk[0];
    pt[1] =
        (cTd4[(t1 >> 24)       ] & 0xff000000) ^
        (cTd4[(t0 >> 16) & 0xff] & 0x00ff0000) ^
        (cTd4[(t3 >>  8) & 0xff] & 0x0000ff00) ^
        (cTd4[(t2      ) & 0xff] & 0x000000ff) ^
        rdk[1];
    pt[2] =
        (cTd4[(t2 >> 24)       ] & 0xff000000) ^
        (cTd4[(t1 >> 16) & 0xff] & 0x00ff0000) ^
        (cTd4[(t0 >>  8) & 0xff] & 0x0000ff00) ^
        (cTd4[(t3      ) & 0xff] & 0x000000ff) ^
        rdk[2];
    pt[3] =
        (cTd4[(t3 >> 24)       ] & 0xff000000) ^
        (cTd4[(t2 >> 16) & 0xff] & 0x00ff0000) ^
        (cTd4[(t1 >>  8) & 0xff] & 0x0000ff00) ^
        (cTd4[(t0      ) & 0xff] & 0x000000ff) ^
        rdk[3];
}
