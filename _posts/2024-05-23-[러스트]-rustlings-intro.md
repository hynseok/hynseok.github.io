---
title: '[러스트] rustlings intro'
date: 2024-05-23 12:15:33 +0900
categories: [Rust]
tags: [Rust, rustlings]
description: rust, rustlings, formatted print
---

# rustlings - intro

> 러스트에서는 콘솔에 텍스트를 출력하기 위해 'print!' 또는 'println!' 매크로를 사용합니다. 

## Formatted Print
println 매크로는 formatted macro의 한 종류로, `std::fmt`에 정의되어 있다.
* format! : 문자열을 포맷팅한다. 
* print! : 문자열을 포맷팅하여 콘솔(stdout)에 출력한다.
* println! : 문자열을 포맷팅하여 콘솔에 출력하며, 끝에 new line을 붙인다.
* eprint! : print!와 동일하나, stderr에 출력한다.
* eprintln! : println!과 동일하나, stderr에 출력한다.

## intro exercises
### intro2
```
fn main() {
    println!("Hello {}!", "world");
}

```
"Hello {}!" 문자열을 println! 매크로를 사용하여 "Hello world!"로 출력하는 문제. 