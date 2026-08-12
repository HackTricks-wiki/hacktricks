# macOS Objective-C

{{#include ../../banners/hacktricks-training.md}}

## Objective-C

> [!CAUTION]
> Programs written in Objective-C retain runtime metadata when compiled into [Mach-O binaries](macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). This metadata includes class names, method names and type encodings, and instance-variable names and types that support Objective-C's dynamic runtime. <sup>[[1]](#references)</sup>

You can inspect this information using [**class-dump**](https://github.com/nygard/class-dump):

```bash
class-dump Kindle.app
```

These names may be obfuscated to make reverse engineering more difficult.

## Classes, Methods & Objects

### Interface, Properties & Methods

```objectivec
// Declare the interface of the class
@interface MyVehicle : NSObject

// Declare the properties
@property (copy) NSString *vehicleType;
@property int numberOfWheels;

// Declare the methods
- (void)startEngine;
- (void)addWheels:(int)value;

@end
```

### **Class**

```objectivec
@implementation MyVehicle

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

To create an instance, **`alloc`** allocates and zero-initializes the object's storage. An **`init`** method then establishes the object's initial state. <sup>[[2]](#references)</sup>

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

Properties can be **set** and **read** with dot notation or by calling their accessor methods directly:

```objectivec
// Set
newVehicle.numberOfWheels = 2;
[newVehicle setNumberOfWheels:3];

// Get
NSLog(@"Number of wheels: %i", newVehicle.numberOfWheels);
NSLog(@"Number of wheels: %i", [newVehicle numberOfWheels]);
```

### **Instance Variables**

As an alternative to accessor methods, code inside a class can use the instance variable synthesized for a property. By default, its name is the property name prefixed with an underscore:

```objectivec
- (void)makeLongTruck {
    _numberOfWheels = +10000;
    NSLog(@"Number of wheels: %i", self.numberOfWheels);
}
```

### Protocols

Protocols declare methods that are independent of a particular class hierarchy. A class that adopts a protocol must implement its required methods. <sup>[[2]](#references)</sup>

Protocol methods are **required** by default; `@required` makes that state explicit, while `@optional` marks the following declarations as optional.

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

int main(void) {
    @autoreleasepool {
        MyVehicle *mySuperCar = [MyVehicle new];
        [mySuperCar startEngine];
        mySuperCar.numberOfWheels = 4;
        NSLog(@"Number of wheels: %i", mySuperCar.numberOfWheels);
        [mySuperCar setNumberOfWheels:3];
        NSLog(@"Number of wheels: %i", mySuperCar.numberOfWheels);
        [mySuperCar makeLongTruck];
    }
    return 0;
}
```

### Basic Classes

#### String

```objectivec
// NSString
NSString *bookTitle = @"The Catcher in the Rye";
NSString *bookAuthor = [[NSString alloc] initWithCString:"J.D. Salinger" encoding:NSUTF8StringEncoding];
NSString *bookPublicationYear = [NSString stringWithCString:"1951" encoding:NSUTF8StringEncoding];
```

`NSString` instances are **immutable**, so appending content produces a new string.

```objectivec
NSString *bookDescription = [NSString stringWithFormat:@"%@ by %@ was published in %@", bookTitle, bookAuthor, bookPublicationYear];
```

Or you could also use a **mutable** string class:

```objectivec
NSMutableString *mutableString = [NSMutableString stringWithString:@"The book "];
[mutableString appendString:bookTitle];
[mutableString appendString:@" was written by "];
[mutableString appendString:bookAuthor];
[mutableString appendString:@" and published in "];
[mutableString appendString:bookPublicationYear];
```

#### Number

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

#### Array, Sets & Dictionary

```objectivec
// Immutable arrays
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

// Immutable sets
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

### Blocks

Blocks are closures that package executable code together with captured state. They can be passed as arguments and stored in collections, making them similar to lambdas in other languages. <sup>[[2]](#references)</sup>

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

It's also possible to **define a block type to be used as a parameter** in functions:

```objectivec
// Define the block type
typedef void (^callbackLogger)(void);

// Create a block with the block type
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

Files can also be managed with `NSURL` objects instead of `NSString` paths. Many Foundation APIs expose corresponding method names using `URL` instead of `Path`, such as `copyItemAtURL:toURL:error:`. Apple recommends URLs for filesystem locations because they provide a more efficient internal representation. <sup>[[3]](#references)</sup>

```objectivec
NSURL *sourceURL = [NSURL fileURLWithPath:@"/path/to/file1.txt"];
NSURL *destinationURL = [NSURL fileURLWithPath:@"/path/to/file2.txt"];

if ([fileManager copyItemAtURL:sourceURL toURL:destinationURL error:nil]) {
    NSLog(@"Copy successful");
}
```

## References

- [1] [Apple Developer - Objective-C runtime](https://developer.apple.com/documentation/objectivec/objective-c_runtime)
- [2] [Apple - Programming with Objective-C](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/ProgrammingWithObjectiveC/)
- [3] [Apple Developer - FileManager](https://developer.apple.com/documentation/foundation/filemanager)

{{#include ../../banners/hacktricks-training.md}}
