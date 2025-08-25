---
title: '[러스트] Rust IO for Problem Solving '
date: 2024-09-24 22:56:00 +0900
categories: [Rust, PS]
tags: [Rust, PS]
description: rust, rust io
---

# Rust IO for Problem Solving

> Rust는 제한된 시간 안에 수많은 입출력을 해야하는 ps 문제에 적합한가요?

## Rust 기본 입출력 방법
Rust의 스탠다드 라이브러리에 구현되어 있는 입출력은 기본적으로 버퍼를 사용하지 않고, 매번 flush를 진행합니다.
따라서 기본 입출력 함수만 가지고 입출력이 많은 문제를 푸는 것은 핸디캡을 가지게 되는 것과 같습니다.

``` rust
fn main() {
    let mut line = String::new();

    std::io::stdin().read_line(&mut line).expect("Fail to read line");
    
    let n = line.trim().parse::<usize>().unwrap();

    for i in 0..n {
        ...
    }
}
```
(또한 공백 처리, 예외 처리를 매번 해줘야 한다는 것이 귀찮기도 합니다.)

## Rust의 추상화
Rust는 (class 문법, 상속과 같은 개념은 없지만) struct와 impl을 통해 클래스를 흉내내서 추상화를 할 수 있습니다.

``` rust
struct Person {
  name: String,
  age: usize,
  email: String,
  ...
}

impl Person {
  fn new(name: String, age: usize, email: String) -> Self {
    Person{ name, age, email }
  }

  fn introduce(&self) {
    println!("Hello, my name is {}!", self.name);
  }
  
  ...
}
```

## Rust IO 개선 구조체
위의 추상화 개념을 통해 Buffer를 사용한 stdin, stdout 핸들러를 구현해보도록 하겠습니다.
``` rust
use std::io::{ Write, BufRead };

struct Stdin {
  stdin: std::io::BufReader<std::io::StdinLock<'static>>,
}

impl Stdin {
  fn new() -> Self {
    let stdin = std::io::stdin();
    let stdin = stdin.lock();
    let stdin = std::io::BufReader::new(stdin);
    
    Stdin { stdin }
  }

  fn read_line(&mut self) -> String {
    let mut input = String::new();
    self.stdin.read_line(&mut input).unwrap();

    input
  }
}

struct Stdout {
  stdout: std::io::BufWriter<std::io::StdoutLock<'static>>
}

impl Stdout {
  fn new() -> Self {
    let stdout = std::io::stdout();
    let stdout = stdout.lock();
    let stdout = std::io::BufWriter::new(stdout);

    Stdout { stdout }
  }

  fn write_line(&mut self, str: String) {
    writeln!(self.stdout, "{}", str).unwrap();
  }
}

fn main() {
    let mut stdin = Stdin::new();
    let mut stdout = Stdout::new();

    let line = stdin.read_line();

    stdout.write_line(
      format!("Your Input is \"{}\"", line.trim().to_string())
    );
}
```
우선 Stdin 구조체에 대해 살펴봅시다. Stdin 구조체는 하나의 stdin 핸들러를 멤버로 가지고 있습니다. `Stdin.new()`를 통해 새로운 구조체를 할당받게 되면 기본 stdin 핸들러에 lock을 적용하고, 입력 버퍼를 사용하는 BufReader가 저장이 됩니다. (stdin 변수를 동일하게 여러번 선언하는 것은 shadowing 입니다. [참고](https://hynseok.github.io/posts/%EB%9F%AC%EC%8A%A4%ED%8A%B8-rustlings-variables/#shadowing)) 이후 `read_line()`메서드를 통해 입력되는 한 줄을 String 형태로 받을 수 있습니다.

Stdout 구조체도 마찬가지로 버퍼를 사용하는 BufWriter를 사용합니다. `write_line()`메서드로 하나의 String 오브젝트를 한 줄에 출력할 수 있습니다.

## PS
위 구조체 template를 [깃허브](https://github.com/hynseok/ps-template)에 업로드하였습니다. 

clone을 하여 여러 PS 문제를 풀어보도록 합시다!