#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
	printf("our pid:%d\n", getpid());
	sleep(10);
	sleep(1);
	printf("kid pid: %d", fork());
}
