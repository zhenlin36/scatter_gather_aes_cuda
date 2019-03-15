#!/bin/sh

rm hehe.txt
#TESTDIR=./
TESTDIR=../../research/text_generator/

make clean
mode=SFTL
make MODE=$mode TT=256
for size in 10MB 100MB 1GB; do
#for size in 16MB; do
#    ./gbench $TESTDIR/pt_${size}.txt >> hehe.txt
    ./sbench $TESTDIR/pt_${size}.txt >> hehe.txt
done

: <<'END'

mode=HYBRID
for tt in 256 128 64 32; do
    make clean
    make TT=$tt MODE=$mode
    for size in 10MB 100MB 1GB; do
	./gbench $TESTDIR/pt_${size}.txt >> test_hybrid_gmem.log
	./sbench $TESTDIR/pt_${size}.txt >> test_hybrid_smem.log
    done
done

mode=SECURE
for tt in 256 128 64 32; do
    make clean
    make TT=$tt MODE=$mode
    for size in 10MB 100MB 1GB; do
	./gbench $TESTDIR/pt_${size}.txt >> test_secure_gmem.log
	./sbench $TESTDIR/pt_${size}.txt >> test_secure_smem.log
    done
done

END

