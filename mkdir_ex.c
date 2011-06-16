/*
 * Proggy to change a return value of a system call on another process
 */

#include <linux/user.h>
#include <sys/reg.h> // <-- i hate this file
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <linux/user.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <asm/unistd.h>

int main (int argc, char **argv) {
	int pid, w, syscall,in=0;
	long new_ret=-1;
	struct user_regs_struct regz;
	pid=atoi(argv[1]);
	if(!pid) { printf ("you can't not attach to a pid!\n"); exit(-1); }
	if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0) { printf ("ptrace() phailed and so did you\n"); exit(-1); }
	while(1) {
		wait(&w);
		if(WIFEXITED(w)) break;
		if(ptrace(PTRACE_GETREGS, pid, 0, &regz) < 0) printf("failed@1\n");
		syscall=regz.orig_eax;
		if(syscall == __NR_mkdir) {
			if(in==0) {
			in=1;
			printf ("We've caught teh mkdir!\n");
			}
			else { // out of the syscall
				in=0;
			 	printf("ret:%ld\n", ptrace(PTRACE_PEEKUSER, pid, EAX*4, NULL));
				regz.eax = new_ret;
 	                        if(ptrace(PTRACE_SETREGS, pid, 0, &regz) < 0) printf("failed@2\n");
			}
		}
		
		ptrace(PTRACE_SYSCALL, pid, 0, 0);
	}
}

