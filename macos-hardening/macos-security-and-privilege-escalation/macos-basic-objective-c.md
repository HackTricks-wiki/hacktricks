# macOS Objective-C

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* あなたは**サイバーセキュリティ会社**で働いていますか？ HackTricksであなたの**会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricksのスウェット**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## Objective-C

{% hint style="danger" %}
Objective-Cで書かれたプログラムは、[Mach-Oバイナリ](macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)にコンパイルされるときに、クラスの宣言が**保持**されます。このクラスの宣言には、以下の情報が含まれます：
{% endhint %}

* クラス
* クラスメソッド
* クラスのインスタンス変数

これらの情報は[class-dump](https://github.com/nygard/class-dump)を使用して取得できます：
```bash
class-dump Kindle.app
```
## クラス、メソッド、オブジェクト

### インターフェース、プロパティ、メソッド
```objectivec
// Declare the interface of the class
@interface MyVehicle : NSObject

// Declare the properties
@property NSString *vehicleType;
@property int numberOfWheels;

// Declare the methods
- (void)startEngine;
- (void)addWheels:(int)value;

@end
```
### **クラス**

A class is a blueprint for creating objects in Objective-C. It defines the properties and methods that an object of that class will have. In Objective-C, classes are defined using the `@interface` and `@implementation` keywords.

クラスは、Objective-Cでオブジェクトを作成するための設計図です。そのクラスのオブジェクトが持つプロパティとメソッドを定義します。Objective-Cでは、クラスは`@interface`と`@implementation`キーワードを使用して定義されます。

### **Properties**

Properties are the variables that hold the state of an object. They define the characteristics of an object and can be accessed and modified using dot notation. Properties can be declared as `readwrite`, which means they can be both read and written to, or `readonly`, which means they can only be read.

プロパティは、オブジェクトの状態を保持する変数です。プロパティはオブジェクトの特性を定義し、ドット表記を使用してアクセスおよび変更することができます。プロパティは`readwrite`として宣言することもできます（読み書き可能）、または`readonly`として宣言することもできます（読み取り専用）。

### **Methods**

Methods are the actions that an object can perform. They define the behavior of an object and can be called to perform specific tasks. Methods are declared in the `@interface` section of a class and implemented in the `@implementation` section.

メソッドは、オブジェクトが実行できるアクションです。メソッドはオブジェクトの振る舞いを定義し、特定のタスクを実行するために呼び出すことができます。メソッドはクラスの`@interface`セクションで宣言され、`@implementation`セクションで実装されます。

### **Inheritance**

Inheritance allows one class to inherit the properties and methods of another class. The class that is being inherited from is called the superclass, and the class that inherits from it is called the subclass. In Objective-C, inheritance is denoted by using the `:` symbol.

継承により、あるクラスは別のクラスのプロパティとメソッドを継承することができます。継承元のクラスはスーパークラスと呼ばれ、それを継承するクラスはサブクラスと呼ばれます。Objective-Cでは、継承は`:`記号を使用して示されます。

### **Polymorphism**

Polymorphism allows objects of different classes to be treated as objects of a common superclass. This means that a variable of the superclass type can hold objects of different subclasses, and the appropriate method will be called based on the actual type of the object.

ポリモーフィズムにより、異なるクラスのオブジェクトを共通のスーパークラスのオブジェクトとして扱うことができます。つまり、スーパークラスの型の変数は、異なるサブクラスのオブジェクトを保持することができ、適切なメソッドがオブジェクトの実際の型に基づいて呼び出されます。

### **Encapsulation**

Encapsulation is the practice of hiding the internal details of an object and providing a public interface for interacting with the object. This helps to ensure that the object's internal state is not accidentally modified and allows for better code organization and maintenance.

カプセル化は、オブジェクトの内部の詳細を隠し、オブジェクトとの対話のための公開インターフェースを提供することです。これにより、オブジェクトの内部状態が誤って変更されることを防ぎ、より良いコードの組織化とメンテナンスが可能になります。
```objectivec
@implementation MyVehicle : NSObject

// No need to indicate the properties, only define methods

- (void)startEngine {
NSLog(@"Engine started");
}

- (void)addWheels:(int)value {
self.numberOfWheels += value;
}

@end
```
### **オブジェクトとメソッドの呼び出し**

クラスのインスタンスを作成するには、**`alloc`**メソッドを呼び出します。このメソッドは各**プロパティのメモリを割り当て**、それらの割り当てを**ゼロ**にします。その後、**`init`**が呼び出され、プロパティを**必要な値**で**初期化**します。
```objectivec
// Something like this:
MyVehicle *newVehicle = [[MyVehicle alloc] init];

// Which is usually expressed as:
MyVehicle *newVehicle = [MyVehicle new];

// To call a method
// [myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]
[newVehicle addWheels:4];
```
### **クラスメソッド**

クラスメソッドは、インスタンスメソッドで使用されるハイフン（-）ではなく、**プラス記号**（+）で定義されます。例えば、**NSString**クラスのメソッド**`stringWithString`**は以下のようになります：
```objectivec
+ (id)stringWithString:(NSString *)aString;
```
### Setter & Getter

プロパティを**設定**および**取得**するには、**ドット表記**または**メソッドの呼び出し**のように行うことができます。
```objectivec
// Set
newVehicle.numberOfWheels = 2;
[newVehicle setNumberOfWheels:3];

// Get
NSLog(@"Number of wheels: %i", newVehicle.numberOfWheels);
NSLog(@"Number of wheels: %i", [newVehicle numberOfWheels]);
```
### **インスタンス変数**

セッターとゲッターメソッドの代わりに、インスタンス変数を使用することもできます。これらの変数は、プロパティと同じ名前で始まる "\_" で始まります。
```objectivec
- (void)makeLongTruck {
_numberOfWheels = +10000;
NSLog(@"Number of wheels: %i", self.numberOfLeaves);
}
```
### プロトコル

プロトコルは、メソッドの宣言の集まりです（プロパティは含まれません）。プロトコルを実装するクラスは、宣言されたメソッドを実装します。

メソッドには2つのタイプがあります: **必須**と**オプション**です。**デフォルト**では、メソッドは**必須**です（ただし、**`@required`** タグを使用しても指定できます）。メソッドがオプションであることを示すには、**`@optional`** を使用します。
```objectivec
@protocol myNewProtocol
- (void) method1; //mandatory
@required
- (void) method2; //mandatory
@optional
- (void) method3; //optional
@end
```
### すべて一緒に

Objective-C is the primary programming language used for macOS and iOS development. Understanding Objective-C is essential for analyzing and exploiting vulnerabilities in macOS applications. In this chapter, we will cover the basics of Objective-C and how it is used in macOS development.

#### Objective-C Basics

Objective-C is an object-oriented programming language that is a superset of the C programming language. It adds syntax and features for object-oriented programming, such as classes, objects, and messaging.

#### Classes and Objects

In Objective-C, a class is a blueprint for creating objects. It defines the properties and behaviors that objects of that class will have. An object is an instance of a class, and it represents a specific entity or concept.

#### Messaging

Messaging is a fundamental concept in Objective-C. It is the primary way to interact with objects and invoke methods. In Objective-C, you send a message to an object, and the object responds by executing the appropriate method.

#### Memory Management

Objective-C uses reference counting for memory management. Each object has a reference count, and when the count reaches zero, the object is deallocated. Developers need to manage memory properly to avoid memory leaks and crashes.

#### Objective-C Runtime

The Objective-C runtime is a library that provides support for dynamic method dispatch, introspection, and other runtime features. It allows developers to perform tasks such as dynamically adding methods to classes or inspecting the properties of an object at runtime.

#### Objective-C and macOS Security

Understanding Objective-C is crucial for analyzing and exploiting vulnerabilities in macOS applications. By understanding how Objective-C works, you can identify potential security weaknesses and develop effective exploit techniques.

In the next chapter, we will dive deeper into Objective-C and explore advanced topics such as method swizzling, class posing, and runtime manipulation. These techniques are commonly used in macOS privilege escalation and security research.
```objectivec
// gcc -framework Foundation test_obj.m -o test_obj
#import <Foundation/Foundation.h>

@protocol myVehicleProtocol
- (void) startEngine; //mandatory
@required
- (void) addWheels:(int)value; //mandatory
@optional
- (void) makeLongTruck; //optional
@end

@interface MyVehicle : NSObject <myVehicleProtocol>

@property int numberOfWheels;

- (void)startEngine;
- (void)addWheels:(int)value;
- (void)makeLongTruck;

@end

@implementation MyVehicle : NSObject

- (void)startEngine {
NSLog(@"Engine started");
}

- (void)addWheels:(int)value {
self.numberOfWheels += value;
}

- (void)makeLongTruck {
_numberOfWheels = +10000;
NSLog(@"Number of wheels: %i", self.numberOfWheels);
}

@end

int main() {
MyVehicle* mySuperCar = [MyVehicle new];
[mySuperCar startEngine];
mySuperCar.numberOfWheels = 4;
NSLog(@"Number of wheels: %i", mySuperCar.numberOfWheels);
[mySuperCar setNumberOfWheels:3];
NSLog(@"Number of wheels: %i", mySuperCar.numberOfWheels);
[mySuperCar makeLongTruck];
}
```
### 基本クラス

#### 文字列

{% code overflow="wrap" %}
```objectivec
// NSString
NSString *bookTitle = @"The Catcher in the Rye";
NSString *bookAuthor = [[NSString alloc] initWithCString:"J.D. Salinger" encoding:NSUTF8StringEncoding];
NSString *bookPublicationYear = [NSString stringWithCString:"1951" encoding:NSUTF8StringEncoding];
```
{% endcode %}

基本的なクラスは**不変**ですので、既存の文字列に文字列を追加するには**新しいNSStringを作成する必要があります**。

{% code overflow="wrap" %}
```objectivec
NSString *bookDescription = [NSString stringWithFormat:@"%@ by %@ was published in %@", bookTitle, bookAuthor, bookPublicationYear];
```
{% endcode %}

または、**mutable**文字列クラスを使用することもできます：

{% code overflow="wrap" %}
```objectivec
NSMutableString *mutableString = [NSMutableString stringWithString:@"The book "];
[mutableString appendString:bookTitle];
[mutableString appendString:@" was written by "];
[mutableString appendString:bookAuthor];
[mutableString appendString:@" and published in "];
[mutableString appendString:bookPublicationYear];
```
{% endcode %}

#### 数字

{% code overflow="wrap" %}
```objectivec
// character literals.
NSNumber *theLetterZ = @'Z'; // equivalent to [NSNumber numberWithChar:'Z']

// integral literals.
NSNumber *fortyTwo = @42; // equivalent to [NSNumber numberWithInt:42]
NSNumber *fortyTwoUnsigned = @42U; // equivalent to [NSNumber numberWithUnsignedInt:42U]
NSNumber *fortyTwoLong = @42L; // equivalent to [NSNumber numberWithLong:42L]
NSNumber *fortyTwoLongLong = @42LL; // equivalent to [NSNumber numberWithLongLong:42LL]

// floating point literals.
NSNumber *piFloat = @3.141592654F; // equivalent to [NSNumber numberWithFloat:3.141592654F]
NSNumber *piDouble = @3.1415926535; // equivalent to [NSNumber numberWithDouble:3.1415926535]

// BOOL literals.
NSNumber *yesNumber = @YES; // equivalent to [NSNumber numberWithBool:YES]
NSNumber *noNumber = @NO; // equivalent to [NSNumber numberWithBool:NO]
```
#### 配列、セット、辞書

{% code overflow="wrap" %}
```objectivec
// Inmutable arrays
NSArray *colorsArray1 = [NSArray arrayWithObjects:@"red", @"green", @"blue", nil];
NSArray *colorsArray2 = @[@"yellow", @"cyan", @"magenta"];
NSArray *colorsArray3 = @[firstColor, secondColor, thirdColor];

// Mutable arrays
NSMutableArray *mutColorsArray = [NSMutableArray array];
[mutColorsArray addObject:@"red"];
[mutColorsArray addObject:@"green"];
[mutColorsArray addObject:@"blue"];
[mutColorsArray addObject:@"yellow"];
[mutColorsArray replaceObjectAtIndex:0 withObject:@"purple"];

// Inmutable Sets
NSSet *fruitsSet1 = [NSSet setWithObjects:@"apple", @"banana", @"orange", nil];
NSSet *fruitsSet2 = [NSSet setWithArray:@[@"apple", @"banana", @"orange"]];

// Mutable sets
NSMutableSet *mutFruitsSet = [NSMutableSet setWithObjects:@"apple", @"banana", @"orange", nil];
[mutFruitsSet addObject:@"grape"];
[mutFruitsSet removeObject:@"apple"];


// Dictionary
NSDictionary *fruitColorsDictionary = @{
@"apple" : @"red",
@"banana" : @"yellow",
@"orange" : @"orange",
@"grape" : @"purple"
};

// In dictionaryWithObjectsAndKeys you specify the value and then the key:
NSDictionary *fruitColorsDictionary2 = [NSDictionary dictionaryWithObjectsAndKeys:
@"red", @"apple",
@"yellow", @"banana",
@"orange", @"orange",
@"purple", @"grape",
nil];

// Mutable dictionary
NSMutableDictionary *mutFruitColorsDictionary = [NSMutableDictionary dictionaryWithDictionary:fruitColorsDictionary];
[mutFruitColorsDictionary setObject:@"green" forKey:@"apple"];
[mutFruitColorsDictionary removeObjectForKey:@"grape"];
```
{% endcode %}

### ブロック

ブロックは、関数のように振る舞い、関数に渡したり、配列や辞書に格納したりすることができる**オブジェクトとして機能する**関数です。また、値が与えられた場合には値を表すこともできるため、ラムダに似ています。
```objectivec
returnType (^blockName)(argumentType1, argumentType2, ...) = ^(argumentType1 param1, argumentType2 param2, ...){
//Perform operations here
};

// For example

int (^suma)(int, int) = ^(int a, int b){
return a+b;
};
NSLog(@"3+4 = %d", suma(3,4));
```
{% endcode %}

関数のパラメータとして使用するために、**ブロックタイプを定義することも可能です**：
```objectivec
// Define the block type
typedef void (^callbackLogger)(void);

// Create a bloack with the block type
callbackLogger myLogger = ^{
NSLog(@"%@", @"This is my block");
};

// Use it inside a function as a param
void genericLogger(callbackLogger blockParam) {
NSLog(@"%@", @"This is my function");
blockParam();
}
genericLogger(myLogger);

// Call it inline
genericLogger(^{
NSLog(@"%@", @"This is my second block");
});
```
### ファイル

{% code overflow="wrap" %}
```objectivec
// Manager to manage files
NSFileManager *fileManager = [NSFileManager defaultManager];

// Check if file exists:
if ([fileManager fileExistsAtPath:@"/path/to/file.txt" ] == YES) {
NSLog (@"File exists");
}

// copy files
if ([fileManager copyItemAtPath: @"/path/to/file1.txt" toPath: @"/path/to/file2.txt" error:nil] == YES) {
NSLog (@"Copy successful");
}

// Check if the content of 2 files match
if ([fileManager contentsEqualAtPath:@"/path/to/file1.txt" andPath:@"/path/to/file2.txt"] == YES) {
NSLog (@"File contents match");
}

// Delete file
if ([fileManager removeItemAtPath:@"/path/to/file1.txt" error:nil]) {
NSLog(@"Removed successfully");
}
```
{% endcode %}

`NSString`オブジェクトの代わりに`NSURL`オブジェクトを使用してファイルを管理することも可能です。メソッド名は似ていますが、`Path`の代わりに`URL`を使用します。
```objectivec
NSURL *fileSrc = [NSURL fileURLWithPath:@"/path/to/file1.txt"];
NSURL *fileDst = [NSURL fileURLWithPath:@"/path/to/file2.txt"];
[fileManager moveItemAtURL:fileSrc toURL:fileDst error: nil];
```
ほとんどの基本クラスには、直接ファイルに書き込むことができるメソッド `writeToFile:<path> atomically:<YES> encoding:<encoding> error:nil` が定義されています。

{% code overflow="wrap" %}
```objectivec
NSString* tmp = @"something temporary";
[tmp writeToFile:@"/tmp/tmp1.txt" atomically:YES encoding:NSASCIIStringEncoding error:nil];
```
{% endcode %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
