NVCC=nvcc

EXECUTABLES=gbench sbench # aes aes_ecb benchmark benchmark_async benchmark_con benchmark_cpb benchmark_con_cpb
#OBJECTS=AES.o AES_benchmark.o AES_benchmark_con.o AES_benchmark_con_cpb.o AES_benchmark_cpb.o benchmark.o benchmark_async.o main.o main_ecb.o
#GENCODE = -gencode=arch=compute_61,code=sm_61 -gencode=arch=compute_52,code=sm_52 -gencode=arch=compute_35,code=sm_35 -gencode=arch=compute_75,code=sm_75
GENCODE = -gencode=arch=compute_61,code=sm_61
AES_FILES=AES.cu AES.h  BlockCipher.h AES_encrypt_secure.cu AES_encrypt_secure.cu AES_encrypt_hybrid.cu
CCFLAGS := -O3 --ptxas-options=-v -Xptxas -dlcm=ca $(GENCODE) -Xcompiler -fPIC -rdc=true
TT?=128
MODE?=HYBRID

all: $(EXECUTABLES)

gbench: AES_gmem.o benchmark.o
	$(NVCC) $(CCFLAGS) -o $@ $^

sbench: AES_smem.o benchmark.o
	$(NVCC) $(CCFLAGS) -o $@ $^

AES_gmem.o: $(AES_FILES)
	$(NVCC) $(CCFLAGS) -DTTABLE=$(TT) -D$(MODE) -c -o $@ $<

AES_smem.o: $(AES_FILES)
	$(NVCC) $(CCFLAGS) -DTTABLE=$(TT) -D$(MODE) -DUSE_SMEM -c -o $@ $<

benchmark.o: benchmark.cu main.h
	$(NVCC) $(CCFLAGS) -c -o $@ $<

clean:
	$(RM) $(EXECUTABLES) *.o

clobber: clean
	rm *~
