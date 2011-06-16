#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
	printf("pid: %d\n", getpid());
	sleep(10);
	if(mkdir ("/tmp/moof") < 0) { printf ("Failed like planned\n"); }
	else { printf ("it worked and hence you failed\n"); }
	sleep(5);
	}
