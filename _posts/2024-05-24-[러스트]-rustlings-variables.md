---
title: '[러스트] rustlings variables'
date: 2024-05-24 14:27:33 +0900
categories: [Rust]
tags: [Rust, rustlings]
description: rust, rustlings, variables
---

# rustlings - variables

> 러스트에서 변수는 기본적으로 `immutable` 입니다.

## 변수 선언
let 키워드를 통해 변수 선언을 할 수 있습니다.
```
fn main() {
    let x = 5;
    println!("{}",x);
}
```

기본적으로 `immutable`이기 때문에 한번 바인딩한 값을 변경할 수 없습니다. 
```
fn main() {
    let x = 5;
    println!("{}",x);
    x = 6; // 오류 발생
}
```

따라서, 바인딩을 변경할 필요가 있는 변수는 mut 키워드를 사용하여 mutable 변수로 만들어 줘야 합니다.
```
fn main() {
    let mut x = 5;
    println!("{}",x);
    x = 6;
}
```

## Constants
상수는 immutable 변수와 마찬가지로, 값을 변경하지 못하는 값입니다. 그러나, 상수를 사용할 때에는 mut 키워드를 사용할 수 없으며, 타입 annotation이 필수적입니다.
```
const BLKS_PER_PAGES : u32 = PAGESZ / BLKSZ;
```

## Shadowing
let 키워드를 통해 같은 변수명을 사용하여 변수를 선언한다면, 해당 스코프 내에서 가장 가까이에 있는 변수를 사용하게 됩니다.

```
fn main() {
    let x = 5;

    let x = x + 1;

    {
        let x = x * 2;
        println!("The value of x in the inner scope is: {x}");
    }

    println!("The value of x is: {x}");
}
```

```
The value of x in the inner scope is: 12
The value of x is: 6
```


## variables exercises
### variables2
```
fn main() {
    // let x : u32;
    let x : u32 = 9;
    if x == 10 {
        println!("x is ten!");
    } else {
        println!("x is not ten!");
    }
}
```
러스트에서는 변수에 초기값을 바인딩을 하지 않으면 오류가 발생한다.

### variables3
```
fn main() {
    // let x = 3;
    let mut x = 3;
    println!("Number {}", x);
    x = 5; // don't change this line
    println!("Number {}", x);
}
```
mutable 변수를 만들기 위해 mut 키워드를 사용한다.

### variables5
```
fn main() {
    let number = "T-H-R-E-E"; // don't change this line
    println!("Spell a Number : {}", number);
    //number = 3;
    let number = 3; // don't rename this variable
    println!("Number plus two is : {}", number + 2);
}
```

`println!("Number plus two is : {}", number + 2);` 에서 number를 정수형 변수로 여기고 덧셈 연산을 하기 때문에, 바로 윗줄에서 let 키워드를 붙여 shadowing을 해 주어야 한다.

### variables6
```
// const NUMBER = 3;
const NUMBER : i32 = 3;
fn main() {
    println!("Number {}", NUMBER);
}
```
상수를 사용할 때에는 type annotation을 해 주어야 한다.

