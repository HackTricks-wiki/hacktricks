# Rust Basics

### Generic Types

एक स्ट्रक्ट बनाएं जहां उनके 1 मान किसी भी प्रकार का हो सकता है
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

Option प्रकार का अर्थ है कि मान Some (कुछ है) या None का हो सकता है:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
आप `is_some()` या `is_none()` जैसी फ़ंक्शंस का उपयोग करके Option के मान की जांच कर सकते हैं।

### मैक्रोज़

मैक्रोज़ फ़ंक्शंस की तुलना में अधिक शक्तिशाली होते हैं क्योंकि ये उस कोड को उत्पन्न करने के लिए विस्तारित होते हैं जो आपने मैन्युअल रूप से लिखा है। उदाहरण के लिए, एक फ़ंक्शन सिग्नेचर को फ़ंक्शन के पास मौजूद पैरामीटर की संख्या और प्रकार को घोषित करना चाहिए। दूसरी ओर, मैक्रोज़ एक परिवर्तनीय संख्या में पैरामीटर ले सकते हैं: हम `println!("hello")` को एक तर्क के साथ या `println!("hello {}", name)` को दो तर्कों के साथ कॉल कर सकते हैं। इसके अलावा, मैक्रोज़ कोड के अर्थ की व्याख्या करने से पहले विस्तारित होते हैं, इसलिए एक मैक्रो, उदाहरण के लिए, एक दिए गए प्रकार पर एक trait को लागू कर सकता है। एक फ़ंक्शन ऐसा नहीं कर सकता, क्योंकि इसे रनटाइम पर कॉल किया जाता है और एक trait को संकलन समय पर लागू करने की आवश्यकता होती है।
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
### पुनरावृत्ति
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
### पुनरावृत्त बॉक्स
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
### शर्तें

#### यदि
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
#### मिलान
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
#### लूप (अनंत)
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
#### जबकि
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
#### के लिए
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
#### यदि तो
```rust
let optional_word = Some(String::from("rustlings"));
if let word = optional_word {
println!("The word is: {}", word);
} else {
println!("The optional word doesn't contain anything");
}
```
#### जबकि let
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

एक प्रकार के लिए एक नई विधि बनाएं
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
### परीक्षण
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
### थ्रेडिंग

#### आर्क

एक Arc Clone का उपयोग करके वस्तु पर अधिक संदर्भ बनाने के लिए उपयोग कर सकता है ताकि उन्हें थ्रेड्स को पास किया जा सके। जब किसी मान के लिए अंतिम संदर्भ पॉइंटर स्कोप से बाहर होता है, तो चर हटा दिया जाता है।
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

इस मामले में हम थ्रेड को एक वेरिएबल पास करेंगे जिसे वह संशोधित कर सकेगा।
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

