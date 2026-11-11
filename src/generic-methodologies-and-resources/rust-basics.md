# Bases de Rust

{{#include ../banners/hacktricks-training.md}}

### Propriété des variables

La mémoire est gérée par un système de propriété qui suit les règles suivantes, vérifiées par le compilateur à la compilation :

1. Chaque valeur en Rust possède une variable appelée son propriétaire.
2. Une valeur ne peut avoir qu’un seul propriétaire à la fois.
3. Lorsque le propriétaire sort de portée, la valeur est détruite.

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



### Types génériques

Créez une struct dont l’une des valeurs peut être de n’importe quel type.

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

Le type Option signifie que la valeur peut être de type Some (il y a quelque chose) ou None :

```rust
pub enum Option<T> {
    None,
    Some(T),
}
```

Vous pouvez utiliser des fonctions telles que `is_some()` ou `is_none()` pour vérifier la valeur de l’Option.


### Result, Ok & Err

Utilisé pour retourner et propager les erreurs

```rust
pub enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

Vous pouvez utiliser des fonctions telles que `is_ok()` ou `is_err()` pour vérifier la valeur du résultat

L’énumération `Option` doit être utilisée lorsque une valeur peut ne pas exister (être `None`).
L’énumération `Result` doit être utilisée lorsque vous effectuez une opération susceptible d’échouer


### Macros

Les macros sont plus puissantes que les fonctions, car elles se développent pour produire davantage de code que celui que vous avez écrit manuellement. Par exemple, la signature d’une fonction doit déclarer le nombre et le type de ses paramètres. Les macros, quant à elles, peuvent accepter un nombre variable de paramètres : on peut appeler `println!("hello")` avec un argument ou `println!("hello {}", name)` avec deux arguments. De plus, les macros sont développées avant que le compilateur n’interprète le code. Ainsi, une macro peut, par exemple, implémenter un trait pour un type donné. Une fonction ne le peut pas, car elle est appelée à l’exécution et un trait doit être implémenté à la compilation.

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

### Itérer

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

### Boîte récursive

Une enum récursive nécessite une indirection pour que sa taille soit connue à la compilation ; stocker directement une `List` dans une `List` ne compile pas.<sup>[[10]](#references)</sup>

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

### Instructions conditionnelles

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

#### boucle (infinie)

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

Faites correspondre `Some` pour lier sa valeur interne ; un motif de variable simple correspond à la fois à `Some` et à `None`, donc la branche `else` ne serait jamais exécutée.<sup>[[11]](#references)</sup>

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

Créer une nouvelle méthode pour un type

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

### Tests

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

Un Arc peut utiliser Clone pour créer d’autres références vers l’objet et les transmettre aux threads. Lorsque le dernier pointeur de référence vers une valeur sort de portée, la variable est détruite.

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

#### Fils d’exécution

Dans ce cas, nous passerons au thread une variable qu’il pourra modifier.

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


### Principes essentiels de sécurité

Rust offre par défaut de solides garanties de sécurité mémoire, mais vous pouvez tout de même introduire des vulnérabilités critiques avec du code `unsafe`, des problèmes de dépendances ou des erreurs de logique. Cette mini-fiche récapitulative rassemble les primitives que vous rencontrerez le plus souvent lors d’audits de sécurité offensifs ou défensifs de logiciels Rust. Pour découvrir d’autres outils propres à certains langages, consultez [Code Review Tools](../network-services-pentesting/pentesting-web/code-review-tools.md#rust).

#### Code unsafe et sécurité mémoire

`unsafe` autorise des opérations dont le compilateur ne peut pas prouver le respect des garanties de sécurité ; il ne désactive **pas** les vérifications habituelles d’emprunt ou de limites. Une opération unsafe qui ne respecte pas ses garanties peut entraîner une corruption mémoire, y compris dans une fonction exposée via une API sûre.<sup>[[3]](#references)</sup>

Lors de l’examen du code source, repérez les opérations sans vérification et suivez les pointeurs et longueurs contrôlés par un attaquant depuis leurs appelants publics :<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
rg -n 'unsafe|from_raw_parts|set_len|copy_nonoverlapping|transmute|unsafe impl|extern "C"' src
```

* Pour `slice::from_raw_parts`, prouvez que le pointeur est non nul et correctement aligné, que la plage initialisée **entière** se trouve dans une seule allocation vivante et que la tranche renvoyée ne peut pas lui survivre. Même une tranche de longueur nulle ne peut pas utiliser un pointeur nul.
* Pour `Vec::set_len`, prouvez que la nouvelle longueur ne dépasse pas la capacité réelle et que chaque élément nouvellement exposé a été initialisé. Suivez à la fois la taille de l’allocation et le nombre de copies ; `with_capacity` n’initialise pas les éléments.
* Vérifiez chaque `unsafe impl` de `Send` ou `Sync` ainsi que chaque signature FFI par rapport aux invariants promis aux appelants de code sûr. `#![forbid(unsafe_code)]` rejette le code unsafe dans une crate ; `#![deny(unsafe_op_in_unsafe_fn)]` exige plutôt des blocs unsafe explicites **à l’intérieur** des fonctions unsafe, sans interdire le code unsafe. Ce dernier lint avertit par défaut dans Rust 2024.<sup>[[3]](#references)[[7]](#references)[[12]](#references)</sup>

Exemple de dépassement créé avec des pointeurs bruts :
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
Une entrée plus longue que `dst.capacity()` enfreint à la fois la limite de copie et le contrat de `set_len` dans l’exemple ci-dessus. Ajoutez un test avec une entrée trop longue pour l’allocateur cible, puis exécutez-le sous Miri. Miri vérifie les chemins exécutés pour détecter les comportements indéfinis, mais les appels externes non pris en charge peuvent l’empêcher de tester une frontière FFI.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
rustup +nightly component add miri
cargo +nightly miri test
```

#### Audit des dépendances avec RustSec / cargo-audit

La plupart des vulnérabilités Rust réelles se trouvent dans des crates tierces. La base de données d’avis RustSec (alimentée par la communauté) peut être interrogée localement :<sup>[[1]](#references)</sup>
```bash
cargo install cargo-audit
cargo audit              # flags vulnerable versions listed in Cargo.lock
```
Intégrez-le dans CI et faites échouer le pipeline avec `--deny warnings`.

`cargo deny check advisories` offre des fonctionnalités similaires, ainsi que des vérifications des licences et des listes d’interdiction.

#### Couverture de code avec cargo-tarpaulin

`cargo tarpaulin` est un outil de mesure de la couverture de code pour le système de build Cargo.

```bash
cargo binstall cargo-tarpaulin
cargo tarpaulin              # no options are required, if no root directory is defined Tarpaulin will run in the current working directory.
```
Sous Linux, le backend de traçage par défaut de Tarpaulin est toujours Ptrace et ne fonctionne que sur les processeurs x86_64. Il est possible d’utiliser à la place l’instrumentation de couverture llvm avec `--engine llvm`. Sur Mac et Windows, il s’agit de la méthode de collecte par défaut.

#### Vérification de la chaîne d’approvisionnement avec cargo-vet

`cargo vet` vérifie les dépendances selon les critères d’audit configurés, à l’aide d’audits locaux, d’importations fiables ou de dérogations explicites. `cargo vet init` crée les métadonnées `supply-chain/` et exempte les dépendances existantes qui n’ont pas été auditées ; ainsi, une vérification initialement réussie **ne signifie pas** que chaque crate a été examiné. Examinez les dérogations et utilisez `cargo vet suggest` pour les traiter ; `--locked` évite d’actualiser les ensembles d’audits importés.<sup>[[8]](#references)</sup>

```bash
cargo install cargo-vet
cargo vet init
cargo vet suggest
cargo vet --locked
```

#### Fuzzing de votre surface d’API (cargo-fuzz)

Les fuzz targets exercent l’API avec des entrées générées et peuvent révéler des panics et des défauts de sûreté mémoire. La cible générée se trouve sous `fuzz/fuzz_targets/` ; remplacez son corps par défaut par un appel à l’API examinée avant de la lancer.<sup>[[9]](#references)</sup>
```bash
cargo install cargo-fuzz
cargo fuzz init              # creates fuzz/fuzz_targets/
cargo fuzz run fuzz_target_1 # builds with libFuzzer & runs continuously
```
Ajoutez la cible de fuzzing à votre dépôt et exécutez-la dans votre pipeline.



## References

- [1] [Base de données des avis de sécurité RustSec](https://rustsec.org)
- [2] [Cargo-vet : « Auditer vos dépendances Rust »](https://mozilla.github.io/cargo-vet/)
- [3] [Le langage de programmation Rust : Rust non sécurisé](https://doc.rust-lang.org/stable/book/ch20-01-unsafe-rust.html)
- [4] [Rust std : slice::from_raw_parts](https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html)
- [5] [Rust std : Vec](https://doc.rust-lang.org/std/vec/struct.Vec.html)
- [6] [Fichier README de Miri](https://github.com/rust-lang/miri/blob/master/README.md)
- [7] [Rust 2024 : avertissement unsafe_op_in_unsafe_fn](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-op-in-unsafe-fn.html)
- [8] [Commandes de Cargo Vet](https://mozilla.github.io/cargo-vet/commands.html)
- [9] [Livre Rust Fuzz : tutoriel cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz/tutorial.html)
- [10] [Le langage de programmation Rust : Box et types récursifs](https://doc.rust-lang.org/book/ch15-01-box.html)
- [11] [Le langage de programmation Rust : if let](https://doc.rust-lang.org/book/ch06-03-if-let.html)
- [12] [Rust 2024 : blocs extern non sécurisés](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-extern.html)
{{#include ../banners/hacktricks-training.md}}
