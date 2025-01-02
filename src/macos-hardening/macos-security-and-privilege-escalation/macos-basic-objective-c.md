# macOS Objective-C

{{#include ../../banners/hacktricks-training.md}}

## Objective-C

> [!CAUTION]
> Beachten Sie, dass Programme, die in Objective-C geschrieben sind, ihre Klassendeklarationen **beibehalten**, **wenn** sie in [Mach-O-Binärdateien](macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) **kompiliert** werden. Solche Klassendeklarationen **beinhaltet** den Namen und Typ von:

- Der Klasse
- Den Klassenmethoden
- Den Instanzvariablen der Klasse

Sie können diese Informationen mit [**class-dump**](https://github.com/nygard/class-dump) erhalten:
```bash
class-dump Kindle.app
```
Beachten Sie, dass diese Namen obfuskiert werden könnten, um das Reverse Engineering des Binaries zu erschweren.

## Klassen, Methoden & Objekte

### Schnittstelle, Eigenschaften & Methoden
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
### **Klasse**
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
### **Objekt & Methodenaufruf**

Um eine Instanz einer Klasse zu erstellen, wird die **`alloc`**-Methode aufgerufen, die **Speicher** für jede **Eigenschaft** **zuweist** und diese Zuweisungen **nullt**. Dann wird **`init`** aufgerufen, das die **Eigenschaften** auf die **erforderlichen Werte** **initialisiert**.
```objectivec
// Something like this:
MyVehicle *newVehicle = [[MyVehicle alloc] init];

// Which is usually expressed as:
MyVehicle *newVehicle = [MyVehicle new];

// To call a method
// [myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]
[newVehicle addWheels:4];
```
### **Klassenmethoden**

Klassenmethoden werden mit dem **Pluszeichen** (+) definiert, nicht mit dem Bindestrich (-), der bei Instanzmethoden verwendet wird. Wie die **NSString** Klassenmethode **`stringWithString`**:
```objectivec
+ (id)stringWithString:(NSString *)aString;
```
### Setter & Getter

Um Eigenschaften zu **setzen** und zu **bekommen**, können Sie dies mit einer **Punktnotation** oder so tun, als ob Sie **eine Methode aufrufen** würden:
```objectivec
// Set
newVehicle.numberOfWheels = 2;
[newVehicle setNumberOfWheels:3];

// Get
NSLog(@"Number of wheels: %i", newVehicle.numberOfWheels);
NSLog(@"Number of wheels: %i", [newVehicle numberOfWheels]);
```
### **Instanzvariablen**

Alternativ zu Setter- und Getter-Methoden können Sie Instanzvariablen verwenden. Diese Variablen haben denselben Namen wie die Eigenschaften, beginnen jedoch mit einem "\_":
```objectivec
- (void)makeLongTruck {
_numberOfWheels = +10000;
NSLog(@"Number of wheels: %i", self.numberOfLeaves);
}
```
### Protokolle

Protokolle sind eine Reihe von Methodendeklarationen (ohne Eigenschaften). Eine Klasse, die ein Protokoll implementiert, implementiert die deklarierten Methoden.

Es gibt 2 Arten von Methoden: **verpflichtend** und **optional**. Standardmäßig ist eine Methode **verpflichtend** (aber Sie können dies auch mit einem **`@required`** Tag angeben). Um anzugeben, dass eine Methode optional ist, verwenden Sie **`@optional`**.
```objectivec
@protocol myNewProtocol
- (void) method1; //mandatory
@required
- (void) method2; //mandatory
@optional
- (void) method3; //optional
@end
```
### Alles zusammen
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
### Grundlegende Klassen

#### Zeichenfolge
```objectivec
// NSString
NSString *bookTitle = @"The Catcher in the Rye";
NSString *bookAuthor = [[NSString alloc] initWithCString:"J.D. Salinger" encoding:NSUTF8StringEncoding];
NSString *bookPublicationYear = [NSString stringWithCString:"1951" encoding:NSUTF8StringEncoding];
```
Basis-Klassen sind **unveränderlich**, daher muss eine **neue NSString erstellt werden**, um einen String an einen bestehenden anzuhängen.
```objectivec
NSString *bookDescription = [NSString stringWithFormat:@"%@ by %@ was published in %@", bookTitle, bookAuthor, bookPublicationYear];
```
Oder Sie könnten auch eine **veränderbare** Zeichenfolgenklasse verwenden:
```objectivec
NSMutableString *mutableString = [NSMutableString stringWithString:@"The book "];
[mutableString appendString:bookTitle];
[mutableString appendString:@" was written by "];
[mutableString appendString:bookAuthor];
[mutableString appendString:@" and published in "];
[mutableString appendString:bookPublicationYear];
```
#### Nummer
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
#### Array, Mengen & Wörterbuch
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
### Blocks

Blocks sind **Funktionen, die sich wie Objekte verhalten**, sodass sie an Funktionen übergeben oder in **Arrays** oder **Dictionaries** **gespeichert** werden können. Außerdem können sie **einen Wert darstellen, wenn ihnen Werte gegeben werden**, sodass sie ähnlich wie Lambdas sind.
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
Es ist auch möglich, **einen Blocktyp zu definieren, der als Parameter** in Funktionen verwendet wird:
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
### Dateien
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
Es ist auch möglich, Dateien **mit `NSURL`-Objekten anstelle von `NSString`-Objekten** zu verwalten. Die Methodennamen sind ähnlich, aber **mit `URL` anstelle von `Path`**.
```objectivec


```
{{#include ../../banners/hacktricks-training.md}}
