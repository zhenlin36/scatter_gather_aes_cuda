#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

typedef unsigned int uint;
typedef unsigned char uchar;

void generator(int size) {
    for (int i = 0; i < size; i++) {
	printf("%c", rand() % 128);
    }
}

int main(int argc, char** argv) {
    assert(argc == 2);

    int size_in_MB = atoi(argv[1]);
    assert(size_in_MB > 0);
    generator(size_in_MB * 1024 * 1024);
    return 0;
}
