# Fundamentos de Rust

{{#include ../banners/hacktricks-training.md}}

### Propriedade das variáveis

A memória é gerenciada por meio de um sistema de propriedade, com as seguintes regras verificadas pelo compilador em tempo de compilação:

1. Cada valor em Rust tem uma variável chamada de seu proprietário.
2. Só pode haver um proprietário por vez.
3. Quando o proprietário sai do escopo, o valor é descartado.

```rust
fn main() {
    let student_age: u32 = 20;
    { // Scope of a variable is within the block it is declared in, which is denoted by brackets
        let teacher_age: u32 = 41;
        println!("The student is {} and teacher is {}", student_age, teacher_age);
    } // when an owning variable goes out of scope, it will be dropped

    // println!("the teacher is {}", teacher_age); // this will not work as teacher_age has been dropped
}
```



### Tipos Genéricos

Crie uma struct em que um de seus valores possa ser de qualquer tipo

```rust
struct Wrapper<T> {
    value: T,
}

impl<T> Wrapper<T> {
    pub fn new(value: T) -> Self {
        Wrapper { value }
    }
}

Wrapper::new(42).value
Wrapper::new("Foo").value, "Foo"
```

### Option, Some & None

O tipo Option significa que o valor pode ser do tipo Some (há algo) ou None:

```rust
pub enum Option<T> {
    None,
    Some(T),
}
```

Você pode usar funções como `is_some()` ou `is_none()` para verificar o valor de `Option`.


### Result, Ok & Err

Usado para retornar e propagar erros

```rust
pub enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

Você pode usar funções como `is_ok()` ou `is_err()` para verificar o valor do resultado

O enum `Option` deve ser usado em situações em que um valor talvez não exista (seja `None`).
O enum `Result` deve ser usado em situações em que algo que você faz pode dar errado


### Macros

Macros são mais poderosas do que funções porque são expandidas para produzir mais código do que aquele que você escreveu manualmente. Por exemplo, a assinatura de uma função precisa declarar o número e o tipo dos parâmetros da função. Já as macros podem receber um número variável de parâmetros: podemos chamar `println!("hello")` com um argumento ou `println!("hello {}", name)` com dois argumentos. Além disso, as macros são expandidas antes de o compilador interpretar o significado do código, então uma macro pode, por exemplo, implementar uma trait em um determinado tipo. Uma função não pode fazer isso, pois é chamada em tempo de execução e uma trait precisa ser implementada em tempo de compilação.

```rust
macro_rules! my_macro {
    () => {
        println!("Check out my macro!");
    };
    ($val:expr) => {
        println!("Look at this other macro: {}", $val);
    }
}
fn main() {
    my_macro!();
    my_macro!(7777);
}

// Export a macro from a module
mod macros {
    #[macro_export]
    macro_rules! my_macro {
        () => {
            println!("Check out my macro!");
        };
    }
}
```

### Iteração

```rust
// Iterate through a vector
let my_fav_fruits = vec!["banana", "raspberry"];
let mut my_iterable_fav_fruits = my_fav_fruits.iter();
assert_eq!(my_iterable_fav_fruits.next(), Some(&"banana"));
assert_eq!(my_iterable_fav_fruits.next(), Some(&"raspberry"));
assert_eq!(my_iterable_fav_fruits.next(), None); // When it's over, it's none
 
// One line iteration with action
my_fav_fruits.iter().map(|x| capitalize_first(x)).collect()

// Hashmap iteration
for (key, hashvalue) in &*map {
for key in map.keys() {
for value in map.values() {
```

### Box Recursivo

Um enum recursivo precisa de indireção para que seu tamanho seja conhecido em tempo de compilação; armazenar `List` diretamente dentro de `List` não compila.<sup>[[10]](#references)</sup>

```rust
enum List {
    Cons(i32, Box<List>),
    Nil,
}

use List::{Cons, Nil};

fn main() {
    let _list = Cons(1, Box::new(Cons(2, Box::new(Cons(3, Box::new(Nil))))));
}
```

### Condicionais

#### if

```rust
let n = 5;
if n < 0 {
    print!("{} is negative", n);
} else if n > 0 {
    print!("{} is positive", n);
} else {
    print!("{} is zero", n);
}
```

#### match

```rust
match number {
    // Match a single value
    1 => println!("One!"),
    // Match several values
    2 | 3 | 5 | 7 | 11 => println!("This is a prime"),
    // TODO ^ Try adding 13 to the list of prime values
    // Match an inclusive range
    13..=19 => println!("A teen"),
    // Handle the rest of cases
    _ => println!("Ain't special"),
}

let boolean = true;
// Match is an expression too
let binary = match boolean {
    // The arms of a match must cover all the possible values
    false => 0,
    true => 1,
    // TODO ^ Try commenting out one of these arms
};
```

#### loop (infinito)

```rust
loop {
    count += 1;
    if count == 3 {
        println!("three");
        continue;
    }
    println!("{}", count);
    if count == 5 {
        println!("OK, that's enough");
        break;
    }
}
```

#### while

```rust
let mut n = 1;
while n < 101 {
    if n % 15 == 0 {
        println!("fizzbuzz");
    } else if n % 5 == 0 {
        println!("buzz");
    } else {
        println!("{}", n);
    }
    n += 1;
}
```

#### for

```rust
for n in 1..101 {
    if n % 15 == 0 {
        println!("fizzbuzz");
    } else {
        println!("{}", n);
    }
}

// Use "..=" to make inclusive both ends
for n in 1..=100 {
    if n % 15 == 0 {
        println!("fizzbuzz");
    } else if n % 3 == 0 {
        println!("fizz");
    } else if n % 5 == 0 {
        println!("buzz");
    } else {
        println!("{}", n);
    }
}

// ITERATIONS

let names = vec!["Bob", "Frank", "Ferris"];
//iter - Doesn't consume the collection
for name in names.iter() {
    match name {
        &"Ferris" => println!("There is a rustacean among us!"),
        _ => println!("Hello {}", name),
    }
}
//into_iter - COnsumes the collection
for name in names.into_iter() {
    match name {
        "Ferris" => println!("There is a rustacean among us!"),
        _ => println!("Hello {}", name),
    }
}
//iter_mut - This mutably borrows each element of the collection
for name in names.iter_mut() {
    *name = match name {
        &mut "Ferris" => "There is a rustacean among us!",
        _ => "Hello",
    }
}
```

#### if let

Faça match com `Some` para vincular seu valor interno; um padrão com variável simples corresponde tanto a `Some` quanto a `None`, então o ramo `else` nunca seria executado.<sup>[[11]](#references)</sup>

```rust
let optional_word = Some(String::from("rustlings"));
if let Some(word) = optional_word {
    println!("The word is: {}", word);
} else {
    println!("The optional word doesn't contain anything");
}
```

#### while let

```rust
let mut optional = Some(0);
// This reads: "while `let` destructures `optional` into
// `Some(i)`, evaluate the block (`{}`). Else `break`.
while let Some(i) = optional {
    if i > 9 {
        println!("Greater than 9, quit!");
        optional = None;
    } else {
        println!("`i` is `{:?}`. Try again.", i);
        optional = Some(i + 1);
    }
    // ^ Less rightward drift and doesn't require
    // explicitly handling the failing case.
}
```

### Traits

Crie um novo método para um tipo

```rust
trait AppendBar {
    fn append_bar(self) -> Self;
}

impl AppendBar for String {
    fn append_bar(self) -> Self{
        format!("{}Bar", self)
    }
}

let s = String::from("Foo");
let s = s.append_bar();
println!("s: {}", s);
```

### Testes

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn you_can_assert() {
        assert!(true);
        assert_eq!(true, true);
        assert_ne!(true, false);
    }
}
```

### Threading

#### Arc

Um Arc pode usar Clone para criar mais referências ao objeto e passá-las para as threads. Quando o último ponteiro de referência para um valor sai do escopo, a variável é descartada.

```rust
use std::sync::Arc;
let apple = Arc::new("the same apple");
for _ in 0..10 {
    let apple = Arc::clone(&apple);
    thread::spawn(move || {
        println!("{:?}", apple);
    });
}
```

#### Threads

Neste caso, passaremos à thread uma variável que ela poderá modificar.

```rust
fn main() {
    let status = Arc::new(Mutex::new(JobStatus { jobs_completed: 0 }));
    let status_shared = Arc::clone(&status);
    thread::spawn(move || {
        for _ in 0..10 {
            thread::sleep(Duration::from_millis(250));
            let mut status = status_shared.lock().unwrap();
            status.jobs_completed += 1;
        }
    });
    while status.lock().unwrap().jobs_completed < 10 {
        println!("waiting... ");
        thread::sleep(Duration::from_millis(500));
    }
}
```


### Fundamentos de segurança

Rust oferece fortes garantias de segurança de memória por padrão, mas ainda é possível introduzir vulnerabilidades críticas por meio de código `unsafe`, problemas em dependências ou erros de lógica. A minifolha de consulta a seguir reúne as primitivas que você provavelmente encontrará com mais frequência em revisões de segurança ofensivas ou defensivas de software Rust. Para ferramentas específicas de outras linguagens, consulte [Ferramentas de revisão de código](../network-services-pentesting/pentesting-web/code-review-tools.md#rust).

#### Código unsafe e segurança de memória

`unsafe` permite operações cujos contratos de segurança o compilador não consegue comprovar; isso **não** desativa as verificações comuns de empréstimo ou de limites. A corrupção de memória se torna possível quando uma operação unsafe viola seu contrato, inclusive dentro de uma função exposta como API segura.<sup>[[3]](#references)</sup>

Em uma revisão do código-fonte, localize as operações sem verificações e rastreie os ponteiros e comprimentos controlados pelo atacante desde seus chamadores públicos:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
rg -n 'unsafe|from_raw_parts|set_len|copy_nonoverlapping|transmute|unsafe impl|extern "C"' src
```

* Para `slice::from_raw_parts`, prove que o ponteiro não é nulo nem desalinhado, que o intervalo **inteiro** inicializado está dentro de uma única alocação ativa e que a slice retornada não pode sobreviver a ela. Mesmo uma slice de comprimento zero não pode usar um ponteiro nulo.
* Para `Vec::set_len`, prove que o novo comprimento cabe na capacidade real e que cada elemento recém-exposto foi inicializado. Rastreie tanto o tamanho da alocação quanto a quantidade copiada; `with_capacity` não inicializa elementos.
* Verifique cada `unsafe impl` de `Send` ou `Sync` e cada assinatura FFI em relação às invariantes prometidas a quem usa APIs seguras. `#![forbid(unsafe_code)]` rejeita código unsafe em uma crate; `#![deny(unsafe_op_in_unsafe_fn)]`, por sua vez, exige blocos unsafe explícitos **dentro** de funções unsafe, mas não proíbe código unsafe. Este último lint gera avisos por padrão no Rust 2024.<sup>[[3]](#references)[[7]](#references)[[12]](#references)</sup>

Exemplo de overflow criado com ponteiros brutos:
```rust
use std::ptr;

fn vuln_copy(src: &[u8]) -> Vec<u8> {
    let mut dst = Vec::with_capacity(4);
    unsafe {
        // ❌ copies *src.len()* bytes, the destination only reserves 4.
        ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), src.len());
        dst.set_len(src.len());
    }
    dst
}
```
Uma entrada maior que `dst.capacity()` viola tanto o limite de cópia quanto o contrato de `set_len` no exemplo acima. Adicione um teste com uma entrada excessivamente grande para o allocator alvo e, em seguida, execute-o no Miri. O Miri verifica os caminhos executados em busca de comportamento indefinido, mas chamadas externas não suportadas podem impedi-lo de exercitar um limite de FFI.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
rustup +nightly component add miri
cargo +nightly miri test
```

#### Auditando dependências com RustSec / cargo-audit

A maioria das vulnerabilidades reais em Rust está em crates de terceiros. É possível consultar localmente o banco de avisos do RustSec, mantido pela comunidade:<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Integre-o ao CI e falhe com `--deny warnings`.

`cargo deny check advisories` oferece funcionalidades semelhantes, além de verificações de licenças e listas de bloqueio.

#### Cobertura de código com cargo-tarpaulin

`cargo tarpaulin` é uma ferramenta de geração de relatórios de cobertura de código para o sistema de build do Cargo

```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
No Linux, o backend de tracing padrão do Tarpaulin ainda é Ptrace e só funciona em processadores x86_64. Ele pode ser alterado para a instrumentação de cobertura do llvm com `--engine llvm`. No Mac e no Windows, esse é o método de coleta padrão.

#### Verificação da cadeia de suprimentos com cargo-vet

`cargo vet` verifica as dependências em relação aos critérios de auditoria configurados, usando auditorias locais, imports confiáveis ou isenções explícitas. `cargo vet init` cria metadados em `supply-chain/` e isenta as dependências existentes que não foram auditadas; portanto, uma verificação inicialmente aprovada **não** significa que todos os crates foram revisados. Examine as isenções e use `cargo vet suggest` para analisá-las; `--locked` evita atualizar os conjuntos de auditoria importados.<sup>[[8]](#references)</sup>

```bash
cargo install cargo-vet
cargo vet init
cargo vet suggest
cargo vet --locked
```

#### Fuzzing da superfície da sua API (cargo-fuzz)

Os alvos de fuzzing exercitam a API com entradas geradas e podem revelar panics e falhas de segurança de memória. O alvo gerado fica em `fuzz/fuzz_targets/`; substitua o corpo padrão por uma chamada à API em análise antes de executá-lo.<sup>[[9]](#references)</sup>
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz/fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Adicione o alvo de fuzz ao seu repositório e execute-o no seu pipeline.



## References

- [1] [Banco de dados de avisos RustSec](https://rustsec.org)
- [2] [Cargo-vet: "Auditando suas dependências Rust"](https://mozilla.github.io/cargo-vet/)
- [3] [A linguagem de programação Rust: Rust inseguro](https://doc.rust-lang.org/stable/book/ch20-01-unsafe-rust.html)
- [4] [Rust std: slice::from_raw_parts](https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html)
- [5] [Rust std: Vec](https://doc.rust-lang.org/std/vec/struct.Vec.html)
- [6] [README do Miri](https://github.com/rust-lang/miri/blob/master/README.md)
- [7] [Rust 2024: aviso unsafe_op_in_unsafe_fn](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-op-in-unsafe-fn.html)
- [8] [Comandos do Cargo Vet](https://mozilla.github.io/cargo-vet/commands.html)
- [9] [Livro Rust Fuzz: tutorial do cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz/tutorial.html)
- [10] [A linguagem de programação Rust: Box e tipos recursivos](https://doc.rust-lang.org/book/ch15-01-box.html)
- [11] [A linguagem de programação Rust: if let](https://doc.rust-lang.org/book/ch06-03-if-let.html)
- [12] [Rust 2024: blocos extern inseguros](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-extern.html)
{{#include ../banners/hacktricks-training.md}}
