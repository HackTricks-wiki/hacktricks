# macOS Objective-C

{{#include ../../banners/hacktricks-training.md}}

## Objective-C

> [!CAUTION]
> Let op dat programme wat in Objective-C geskryf is **behou** hul klasverklarings **wanneer** **gecompileer** word in [Mach-O binaries](macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Sulke klasverklarings **sluit** die naam en tipe van in:

- Die klas
- Die klasmetodes
- Die klasinstansie veranderlikes

Jy kan hierdie inligting verkry met behulp van [**class-dump**](https://github.com/nygard/class-dump):
```bash
class-dump Kindle.app
```
Let wel dat hierdie name obfuskeer kan word om die omkering van die binêre meer moeilik te maak.

## Klasse, Metodes & Objekte

### Koppelvlak, Eienskappe & Metodes
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
### **Klas**
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
### **Objek & Roep Metode**

Om 'n instansie van 'n klas te skep, word die **`alloc`** metode aangeroep wat **geheue toewys** vir elke **eienskap** en **maak** daardie toewysings nul. Dan word **`init`** aangeroep, wat die **eienskappe** tot die **vereiste waardes** **initaliseer**.
```objectivec
// Something like this:
MyVehicle *newVehicle = [[MyVehicle alloc] init];

// Which is usually expressed as:
MyVehicle *newVehicle = [MyVehicle new];

// To call a method
// [myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]
[newVehicle addWheels:4];
```
### **Klas Metodes**

Klas metodes word gedefinieer met die **plusteken** (+) en nie die koppelteken (-) wat met instansiemetodes gebruik word nie. Soos die **NSString** klas metode **`stringWithString`**:
```objectivec
+ (id)stringWithString:(NSString *)aString;
```
### Setter & Getter

Om **te stel** & **te kry** eienskappe, kan jy dit doen met 'n **puntnotasie** of soos asof jy 'n **metode aanroep**:
```objectivec
// Set
newVehicle.numberOfWheels = 2;
[newVehicle setNumberOfWheels:3];

// Get
NSLog(@"Number of wheels: %i", newVehicle.numberOfWheels);
NSLog(@"Number of wheels: %i", [newVehicle numberOfWheels]);
```
### **Instansveranderlikes**

Alternatiewelik vir setter- en getter-metodes kan jy instansveranderlikes gebruik. Hierdie veranderlikes het dieselfde naam as die eienskappe, maar begin met 'n "\_":
```objectivec
- (void)makeLongTruck {
_numberOfWheels = +10000;
NSLog(@"Number of wheels: %i", self.numberOfLeaves);
}
```
### Protokolle

Protokolle is 'n stel metodeverklarings (sonder eienskappe). 'n Klas wat 'n protokol implementeer, implementeer die verklaarde metodes.

Daar is 2 tipes metodes: **verpligtend** en **opsioneel**. Deur **default** is 'n metode **verpligtend** (maar jy kan dit ook met 'n **`@required`** etiket aandui). Om aan te dui dat 'n metode opsioneel is, gebruik **`@optional`**.
```objectivec
@protocol myNewProtocol
- (void) method1; //mandatory
@required
- (void) method2; //mandatory
@optional
- (void) method3; //optional
@end
```
### Alles saam
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
### Basiese Klasse

#### String
```objectivec
// NSString
NSString *bookTitle = @"The Catcher in the Rye";
NSString *bookAuthor = [[NSString alloc] initWithCString:"J.D. Salinger" encoding:NSUTF8StringEncoding];
NSString *bookPublicationYear = [NSString stringWithCString:"1951" encoding:NSUTF8StringEncoding];
```
Basisklasse is **onveranderlik**, so om 'n string aan 'n bestaande een toe te voeg, moet 'n **nuwe NSString geskep word**.
```objectivec
NSString *bookDescription = [NSString stringWithFormat:@"%@ by %@ was published in %@", bookTitle, bookAuthor, bookPublicationYear];
```
Of jy kan ook 'n **mutable** string klas gebruik:
```objectivec
NSMutableString *mutableString = [NSMutableString stringWithString:@"The book "];
[mutableString appendString:bookTitle];
[mutableString appendString:@" was written by "];
[mutableString appendString:bookAuthor];
[mutableString appendString:@" and published in "];
[mutableString appendString:bookPublicationYear];
```
#### Nommer
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
### Blokke

Blokke is **funksies wat as objekte optree** sodat hulle aan funksies oorgedra kan word of **gestoor** kan word in **arrays** of **woordeboeke**. Ook, hulle kan **'n waarde verteenwoordig as hulle waardes gegee word** so dit is soortgelyk aan lambdas.
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
Dit is ook moontlik om **'n bloktipe te definieer wat as 'n parameter in funksies gebruik kan word**:
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
### Lêers
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
Dit is ook moontlik om lêers te bestuur **met `NSURL`-objekte in plaas van `NSString`-objekte**. Die metode name is soortgelyk, maar **met `URL` in plaas van `Path`**.
```objectivec


```
{{#include ../../banners/hacktricks-training.md}}
