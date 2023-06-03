# Rust Básico

### Tipos Genéricos

Crea una estructura donde uno de sus valores pueda ser de cualquier tipo.
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

El tipo Option significa que el valor puede ser del tipo Some (hay algo) o None (nada):
```rust
pub enum Option<T> {
    None,
    Some(T),
}
```
Puedes usar funciones como `is_some()` o `is_none()` para comprobar el valor de la opción.

### Macros

Las macros son más poderosas que las funciones porque se expanden para producir más código que el que has escrito manualmente. Por ejemplo, una firma de función debe declarar el número y el tipo de parámetros que tiene la función. Las macros, por otro lado, pueden tomar un número variable de parámetros: podemos llamar a `println!("hello")` con un argumento o `println!("hello {}", name)` con dos argumentos. Además, las macros se expanden antes de que el compilador interprete el significado del código, por lo que una macro puede, por ejemplo, implementar un rasgo en un tipo dado. Una función no puede hacerlo, porque se llama en tiempo de ejecución y un rasgo debe implementarse en tiempo de compilación.
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
### Caja Recursiva
```rust
enum List {
    Cons(i32, List),
    Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
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

El operador `match` en Rust es una forma de comparar un valor con una serie de patrones y ejecutar código en función de qué patrón coincida. Es similar a un switch en otros lenguajes de programación, pero con algunas diferencias clave. 

La sintaxis básica de `match` es la siguiente:

```rust
match valor {
    patrón1 => {
        // código a ejecutar si el valor coincide con el patrón1
    },
    patrón2 => {
        // código a ejecutar si el valor coincide con el patrón2
    },
    _ => {
        // código a ejecutar si el valor no coincide con ninguno de los patrones anteriores
    }
}
```

Cada patrón puede ser una constante, una variable o una expresión más compleja. El guión bajo `_` se utiliza como un comodín para capturar cualquier valor que no coincida con los patrones anteriores. 

El operador `match` es muy útil para manejar diferentes casos en una función, especialmente cuando se trabaja con tipos de datos enumerados o estructuras de datos complejas.
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
#### bucle (infinito)
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

Mientras que la condición especificada sea verdadera, el bucle `while` ejecutará repetidamente un bloque de código. La sintaxis es la siguiente:

```rust
while condición {
    // Código a ejecutar mientras la condición sea verdadera
}
```

La condición puede ser cualquier expresión booleana. Si la condición es verdadera, el código dentro del bloque se ejecutará. Si la condición es falsa, el bucle se detendrá y la ejecución continuará con el código que sigue al bloque `while`.
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

El bucle `for` se utiliza para iterar sobre una colección de elementos. La sintaxis básica es la siguiente:

```rust
for variable in coleccion {
    // Código a ejecutar en cada iteración
}
```

Donde `variable` es una variable que se actualizará en cada iteración con el valor del siguiente elemento de la `coleccion`. El código dentro del bloque de `for` se ejecutará una vez por cada elemento de la `coleccion`.
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

Si bien `if let` se puede usar para hacer coincidir patrones, su uso principal es verificar si una variable es `Some(valor)` y, si es así, desempaquetar el valor y ejecutar el bloque de código. Si la variable es `None`, el bloque de código no se ejecutará. 

La sintaxis es la siguiente:

```rust
if let Some(valor) = variable {
    // Código a ejecutar si la variable es Some(valor)
} else {
    // Código a ejecutar si la variable es None
}
```

También se puede usar `if let` con `Result<T, E>` para manejar errores de manera más concisa.
```rust
let optional_word = Some(String::from("rustlings"));
if let word = optional_word {
    println!("The word is: {}", word);
} else {
    println!("The optional word doesn't contain anything");
}
```
#### while let

Mientras que

`while let` es una forma abreviada de escribir un bucle `while` que desempaqueta los valores de un patrón. Es útil cuando se trabaja con iteradores y se desea desempaquetar los valores de forma segura sin tener que preocuparse por los valores `None`.

Por ejemplo, el siguiente código utiliza un bucle `while` para desempaquetar los valores de un iterador:

```rust
let mut iter = vec![1, 2, 3].into_iter();

loop {
    match iter.next() {
        Some(x) => println!("{}", x),
        None => break,
    }
}
```

Este código se puede simplificar utilizando `while let`:

```rust
let mut iter = vec![1, 2, 3].into_iter();

while let Some(x) = iter.next() {
    println!("{}", x);
}
```

En este ejemplo, el bucle `while let` desempaqueta los valores de `iter` en la variable `x` hasta que `iter` se agota y devuelve `None`.
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
### Hilos

#### Arc

Un Arc puede usar Clone para crear más referencias sobre el objeto para pasarlas a los hilos. Cuando el último puntero de referencia a un valor está fuera de alcance, la variable se elimina.
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

En este caso pasaremos al hilo una variable que podrá modificar.
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

