---
title: "[pwnable] random"
date: 2024-12-01 23:56:00 +0900
categories: [pwnable]
tags: [pwnable]
description: pwnable, system hack
---

# [pwnable] random

```shell
$ ls
flag  random  random.c
```

random이 실행가능한 파일로 보여서 실행후 아무 입력이나 넣어보았다.

```shell
$ ./random
3
Wrong, maybe you should try 2^32 cases.
```

올바른 숫자를 넣어야 flag를 얻을 수 있는 것처럼 보였다.\
다음으로 random.c 파일을 열어보았다.

```shell
$ cat random.c

#include <stdio.h>

int main(){
	unsigned int random;
	random = rand();	// random value!
	unsigned int key=0;
	scanf("%d", &key);
	if( (key ^ random) == 0xdeadbeef ){
		printf("Good!\n");
		system("/bin/cat flag");
		return 0;
	}

	printf("Wrong, maybe you should try 2^32 cases.\n");
	return 0;
}
```
seed를 지정해 주지 않으면 random 값이 프로그램 실행마다 동일한 sequence로 나온다고 알고 있어서 직접 출력해 보았다.
```c
#include <stdio.h>

int main(){
	unsigned int random;
	random = rand();	// random value!
	printf("%x\n", random); // print random
	unsigned int key=0;
	scanf("%d", &key);
	if( (key ^ random) == 0xdeadbeef ){
		printf("Good!\n");
		system("/bin/cat flag");
		return 0;
	}

	printf("Wrong, maybe you should try 2^32 cases.\n");
	return 0;
}
```
```shell
$ ./random
6b8b4567
```
몇번을 실행해도 결과는 0x6b8b4567 으로 똑같았다.\
따라서 정답은 0x6b8b4567과 0xdeadbeef를 xor 연산한 0xb526fb88이다.\
(0xb526fb88 = 3039230856)

### 정답
```
$ ./random
3039230856
```