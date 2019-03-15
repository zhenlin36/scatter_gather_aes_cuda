#!/bin/sh

TESTDIR=../../research/text_generator/
#mode=BASELINE
#mode=LASTROUND
#mode=HYBRID
#mode=SECURE
mode=SBOX
GLOG=test_${mode}_gmem.log
SLOG=test_${mode}_smem.log

rm $GLOG $SLOG
for tt in 256 128 64 32; do
    make clean
    make TT=$tt MODE=$mode
#    for size in 10MB 100MB 1GB; do
    for size in 1GB; do
	./gbench $TESTDIR/pt_${size}.txt >> $GLOG
	./sbench $TESTDIR/pt_${size}.txt >> $SLOG
    done
    if [ "$mode" == "BASELINE" ]  || [ "$mode" == "SBOX" ] ; then
	break
    fi
done

