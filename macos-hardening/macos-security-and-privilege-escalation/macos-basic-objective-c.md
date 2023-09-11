# macOS Objective-C

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Objective-C

{% hint style="danger" %}
Note that programs written in Objective-C **retain** their class declarations **when** **compiled** into [Mach-O binaries](macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Such class declarations **include** the name and type of:
{% endhint %}

* The class
* The class methods
* The class instance variables

You can get this information using [**class-dump**](https://github.com/nygard/class-dump):

```bash
class-dump Kindle.app
```

Note that this names could be obfuscated to make the reversing of the binary more difficult.

## Classes, Methods & Objects

### Interface, Properties & Methods

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

### **Class**

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

### **Object & Call Method**

To create an instance of a class the **`alloc`** method is called which **allocate memory** for each **property** and **zero** those allocations. Then **`init`** is called, which **initilize the properties** to the **required values**.

```objectivec
// Something like this:
MyVehicle *newVehicle = [[MyVehicle alloc] init];

// Which is usually expressed as:
MyVehicle *newVehicle = [MyVehicle new];

// To call a method
// [myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]
[newVehicle addWheels:4];
```

### **Class Methods**

Class methods are defined with the **plus sign** (+) not the hyphen (-) that is used with instance methods. Like the **NSString** class method **`stringWithString`**:

```objectivec
+ (id)stringWithString:(NSString *)aString;
```

### Setter & Getter

To **set** & **get** properties, you could do it with a **dot notation** or like if you were **calling a method**:

```objectivec
// Set
newVehicle.numberOfWheels = 2;
[newVehicle setNumberOfWheels:3];

// Get
NSLog(@"Number of wheels: %i", newVehicle.numberOfWheels);
NSLog(@"Number of wheels: %i", [newVehicle numberOfWheels]);
```

### **Instance Variables**

Alternatively to setter & getter methods you can use instance variables. These variables have the same name as the properties but starting with a "\_":

```objectivec
- (void)makeLongTruck {
    _numberOfWheels = +10000;
    NSLog(@"Number of wheels: %i", self.numberOfLeaves);
}
```

### Protocols

Protocols are set of method declarations (without properties). A class that implements a protocol implement the declared methods.

There are 2 types of methods: **mandatory** and **optional**. By **default** a method is **mandatory** (but you can also indicate it with a **`@required`** tag). To indicate that a method is optional use **`@optional`**.

```objectivec
@protocol myNewProtocol
- (void) method1; //mandatory
@required
- (void) method2; //mandatory
@optional
- (void) method3; //optional
@end
```

### All together

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

### Basic Classes

#### String

{% code overflow="wrap" %}
```objectivec
// NSString
NSString *bookTitle = @"The Catcher in the Rye";
NSString *bookAuthor = [[NSString alloc] initWithCString:"J.D. Salinger" encoding:NSUTF8StringEncoding];
NSString *bookPublicationYear = [NSString stringWithCString:"1951" encoding:NSUTF8StringEncoding];
```
{% endcode %}

Basic classes are **immutable**, so to append a string to an existing one a **new NSString needs to be created**.

{% code overflow="wrap" %}
```objectivec
NSString *bookDescription = [NSString stringWithFormat:@"%@ by %@ was published in %@", bookTitle, bookAuthor, bookPublicationYear];
```
{% endcode %}

Or you could also use a **mutable** string class:

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

#### Number

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
{% endcode %}

#### Array, Sets & Dictionary

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

### Blocks

Blocks are **functions that behaves as objects** so they can be passed to functions or **stored** in **arrays** or **dictionaries**. Also, they can **represent a value if they are given values** so it's similar to lambdas.

{% code overflow="wrap" %}
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

It's also possible to **define a block type to be used as a parameter** in functions:

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

### Files

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

It's also possible to manage files **using `NSURL` objects instead of `NSString`** objects. The method names are similar, but **with `URL` instead of `Path`**.

```objectivec
NSURL *fileSrc = [NSURL fileURLWithPath:@"/path/to/file1.txt"];
NSURL *fileDst = [NSURL fileURLWithPath:@"/path/to/file2.txt"];
[fileManager moveItemAtURL:fileSrc toURL:fileDst error: nil];
```

Most basic classes has a method `writeToFile:<path> atomically:<YES> encoding:<encoding> error:nil` defined that allows them to be directly be written to a file:

{% code overflow="wrap" %}
```objectivec
NSString* tmp = @"something temporary";
[tmp writeToFile:@"/tmp/tmp1.txt" atomically:YES encoding:NSASCIIStringEncoding error:nil];
```
{% endcode %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
