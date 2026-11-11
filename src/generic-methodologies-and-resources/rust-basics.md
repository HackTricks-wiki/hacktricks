# Conceptos básicos de Rust

{{#include ../banners/hacktricks-training.md}}

### Propiedad de las variables

La memoria se gestiona mediante un sistema de propiedad con las siguientes reglas, que el compilador comprueba en tiempo de compilación:

1. Cada valor en Rust tiene una variable llamada su propietaria.
2. Solo puede haber una propietaria a la vez.
3. Cuando la propietaria sale del ámbito, el valor se libera.

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



### Tipos genéricos

Crea un struct donde uno de sus valores pueda ser de cualquier tipo

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

### Option, Some y None

El tipo Option significa que el valor puede ser de tipo Some (hay algo) o None:

```rust
pub enum Option<T> {
    None,
    Some(T),
}
```

Puedes usar funciones como `is_some()` o `is_none()` para comprobar el valor de `Option`.


### Result, Ok y Err

Se usan para devolver y propagar errores

```rust
pub enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

Puedes usar funciones como `is_ok()` o `is_err()` para comprobar el valor del resultado.

El enum `Option` debe usarse cuando un valor podría no existir (ser `None`).
El enum `Result` debe usarse cuando haces algo que podría fallar.


### Macros

Las macros son más potentes que las funciones porque se expanden para generar más código que el que has escrito manualmente. Por ejemplo, la firma de una función debe declarar el número y el tipo de sus parámetros. En cambio, las macros pueden aceptar un número variable de parámetros: podemos llamar a `println!("hello")` con un argumento o a `println!("hello {}", name)` con dos argumentos. Además, las macros se expanden antes de que el compilador interprete el significado del código, así que una macro puede, por ejemplo, implementar un trait para un tipo determinado. Una función no puede hacerlo, porque se ejecuta en tiempo de ejecución y un trait debe implementarse en tiempo de compilación.

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

### Iterar

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

### Box recursivo

Un enum recursivo necesita indirección para que su tamaño se conozca en tiempo de compilación; almacenar `List` directamente dentro de `List` no compila.<sup>[[10]](#references)</sup>

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

### Condicionales

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

Haz coincidir `Some` para vincular su valor interno; un patrón de variable simple coincide tanto con `Some` como con `None`, por lo que la rama `else` nunca se ejecutaría.<sup>[[11]](#references)</sup>

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

Crear un nuevo método para un tipo

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

### Pruebas

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

Un Arc puede usar Clone para crear más referencias al objeto y pasárselas a los hilos. Cuando el último puntero de referencia a un valor sale del ámbito, se descarta la variable.

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

#### Hilos

En este caso, le pasaremos al hilo una variable que podrá modificar.

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


### Fundamentos de seguridad

Rust ofrece sólidas garantías de seguridad de memoria de forma predeterminada, pero aun así puedes introducir vulnerabilidades críticas mediante código `unsafe`, problemas con dependencias o errores lógicos. La siguiente hoja de referencia reúne las primitivas que más probablemente usarás al realizar revisiones de seguridad ofensivas o defensivas de software Rust. Para consultar otras herramientas específicas de cada lenguaje, visita [Herramientas de revisión de código](../network-services-pentesting/pentesting-web/code-review-tools.md#rust).

#### Código `unsafe` y seguridad de memoria

`unsafe` permite operaciones cuyos contratos de seguridad el compilador no puede demostrar; **no** desactiva las comprobaciones habituales del borrow checker ni las de límites. La corrupción de memoria puede producirse cuando una operación `unsafe` incumple su contrato, incluso dentro de una función expuesta como API segura.<sup>[[3]](#references)</sup>

Al revisar el código fuente, busca las operaciones sin comprobaciones y rastrea los punteros y longitudes controlados por el atacante desde sus llamadores públicos:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
rg -n 'unsafe|from_raw_parts|set_len|copy_nonoverlapping|transmute|unsafe impl|extern "C"' src
```

* Para `slice::from_raw_parts`, demuestra que el puntero no es nulo y está alineado, que **todo** el rango inicializado está dentro de una única asignación activa y que el slice devuelto no puede sobrevivir a ella. Ni siquiera un slice de longitud cero puede usar un puntero nulo.
* Para `Vec::set_len`, demuestra que la nueva longitud cabe en la capacidad real y que todos los elementos recién expuestos se inicializaron. Rastrea tanto el tamaño de la asignación como cualquier cantidad de elementos copiados; `with_capacity` no inicializa elementos.
* Comprueba cada `unsafe impl` de `Send` o `Sync` y cada firma FFI frente a las invariantes prometidas a los llamadores seguros. `#![forbid(unsafe_code)]` rechaza el código unsafe en un crate; `#![deny(unsafe_op_in_unsafe_fn)]`, en cambio, exige bloques unsafe explícitos **dentro** de las funciones unsafe, pero no prohíbe el código unsafe. Esta última lint advierte de forma predeterminada en Rust 2024.<sup>[[3]](#references)[[7]](#references)[[12]](#references)</sup>

Ejemplo de desbordamiento creado con punteros sin procesar:
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
Una entrada más larga que `dst.capacity()` infringe tanto el límite de copia como el contrato de `set_len` del ejemplo anterior. Añade una prueba con una entrada demasiado larga para el asignador de destino y luego ejecútala con Miri. Miri comprueba las rutas ejecutadas en busca de comportamiento indefinido, pero las llamadas externas no compatibles pueden impedir que pruebe un límite FFI.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
rustup +nightly component add miri
cargo +nightly miri test
```

#### Auditar dependencias con RustSec / cargo-audit

La mayoría de las vulnerabilidades de Rust en el mundo real se encuentran en crates de terceros. Se puede consultar localmente la base de datos de avisos de RustSec (impulsada por la comunidad):<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Intégralo en CI y haz que falle con `--deny warnings`.

`cargo deny check advisories` ofrece una funcionalidad similar, además de comprobaciones de licencias y listas de bloqueo.

#### Cobertura de código con cargo-tarpaulin

`cargo tarpaulin` es una herramienta de informes de cobertura de código para el sistema de compilación Cargo.

```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
En Linux, el backend de tracing predeterminado de Tarpaulin sigue siendo Ptrace y solo funciona en procesadores x86_64. Se puede cambiar a la instrumentación de cobertura de llvm con `--engine llvm`. En Mac y Windows, este es el método de recopilación predeterminado.

#### Verificación de la cadena de suministro con cargo-vet

`cargo vet` verifica las dependencias según criterios de auditoría configurados mediante auditorías locales, importaciones de confianza o exenciones explícitas. `cargo vet init` crea metadatos en `supply-chain/` y exime las dependencias existentes que no se hayan auditado, por lo que una verificación inicialmente satisfactoria **no** significa que se haya revisado cada crate. Examina las exenciones y usa `cargo vet suggest` para revisarlas; `--locked` evita actualizar los conjuntos de auditorías importados.<sup>[[8]](#references)</sup>

```bash
cargo install cargo-vet
cargo vet init
cargo vet suggest
cargo vet --locked
```

#### Fuzzing de la superficie de tu API (cargo-fuzz)

Los objetivos de fuzzing ejercitan la API con entradas generadas y pueden revelar pánicos y fallos de seguridad de memoria. El objetivo generado se encuentra en `fuzz/fuzz_targets/`; reemplaza su cuerpo predeterminado por una llamada a la API que estés revisando antes de ejecutarlo.<sup>[[9]](#references)</sup>
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz/fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Añade el target de fuzzing a tu repositorio y ejecútalo en tu pipeline.



## References

- [1] [Base de datos de avisos de RustSec](https://rustsec.org)
- [2] [Cargo-vet: «Auditar tus dependencias de Rust»](https://mozilla.github.io/cargo-vet/)
- [3] [El lenguaje de programación Rust: Rust inseguro](https://doc.rust-lang.org/stable/book/ch20-01-unsafe-rust.html)
- [4] [Rust std: slice::from_raw_parts](https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html)
- [5] [Rust std: Vec](https://doc.rust-lang.org/std/vec/struct.Vec.html)
- [6] [README de Miri](https://github.com/rust-lang/miri/blob/master/README.md)
- [7] [Rust 2024: advertencia unsafe_op_in_unsafe_fn](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-op-in-unsafe-fn.html)
- [8] [Comandos de Cargo Vet](https://mozilla.github.io/cargo-vet/commands.html)
- [9] [Libro de Rust Fuzz: tutorial de cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz/tutorial.html)
- [10] [El lenguaje de programación Rust: Box y tipos recursivos](https://doc.rust-lang.org/book/ch15-01-box.html)
- [11] [El lenguaje de programación Rust: if let](https://doc.rust-lang.org/book/ch06-03-if-let.html)
- [12] [Rust 2024: bloques extern inseguros](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-extern.html)
{{#include ../banners/hacktricks-training.md}}
