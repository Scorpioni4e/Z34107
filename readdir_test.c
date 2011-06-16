#include <stdio.h>
#include <dirent.h>

int main () {
	DIR *dir;
	struct dirent *dirEntry;
	printf("%d\n", getpid());
	sleep(6);
	dir = opendir("/proc");
	while((dirEntry=readdir(dir)) != NULL) {
		printf("%s \n", dirEntry->d_name);
	}
	closedir(dir);
}

