#!/bin/sh

TESTDIR=./
mode=BASELINE
#mode=LASTROUND
#mode=HYBRID
#mode=SECURE
tt=1024
GLOG=test_${mode}_gmem.log
SLOG=test_${mode}_smem.log

rm $GLOG $SLOG
make clean
make TT=$tt MODE=$mode
for size in 16MB; do
    ./gbench $TESTDIR/pt_${size}.txt >> $GLOG
    ./sbench $TESTDIR/pt_${size}.txt >> $SLOG
done
