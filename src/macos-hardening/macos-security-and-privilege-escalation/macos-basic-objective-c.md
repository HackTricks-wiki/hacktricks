# macOS Objective-C

{{#include ../../banners/hacktricks-training.md}}

## Objective-C

> [!CAUTION]
> Objective-C ile yazılmış programların, [Mach-O ikili dosyalarına](macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) **derlendiğinde** sınıf bildirimlerini **koruduğunu** unutmayın. Bu tür sınıf bildirimleri **şunları içerir**:

- Sınıf adı
- Sınıf yöntemleri
- Sınıf örnek değişkenleri

Bu bilgileri [**class-dump**](https://github.com/nygard/class-dump) kullanarak alabilirsiniz:
```bash
class-dump Kindle.app
```
Bu isimlerin, ikili dosyanın tersine mühendisliğini daha zor hale getirmek için obfuscate edilebileceğini unutmayın.

## Sınıflar, Yöntemler & Nesneler

### Arayüz, Özellikler & Yöntemler
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
### **Sınıf**
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
### **Nesne & Metod Çağrısı**

Bir sınıfın örneğini oluşturmak için **`alloc`** metodu çağrılır, bu **her bir özellik için bellek ayırır** ve bu tahsisatları **sıfırlar**. Ardından **`init`** çağrılır, bu da **özellikleri gerekli değerlere** **başlatır**.
```objectivec
// Something like this:
MyVehicle *newVehicle = [[MyVehicle alloc] init];

// Which is usually expressed as:
MyVehicle *newVehicle = [MyVehicle new];

// To call a method
// [myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]
[newVehicle addWheels:4];
```
### **Sınıf Yöntemleri**

Sınıf yöntemleri, örnek yöntemleriyle kullanılan **eksi işareti** (-) yerine **artı işareti** (+) ile tanımlanır. **NSString** sınıf yöntemi **`stringWithString`** gibi:
```objectivec
+ (id)stringWithString:(NSString *)aString;
```
### Setter & Getter

Özellikleri **ayarlamak** ve **almak** için, bunu **nokta notasyonu** ile veya bir **metodu çağırıyormuş** gibi yapabilirsiniz:
```objectivec
// Set
newVehicle.numberOfWheels = 2;
[newVehicle setNumberOfWheels:3];

// Get
NSLog(@"Number of wheels: %i", newVehicle.numberOfWheels);
NSLog(@"Number of wheels: %i", [newVehicle numberOfWheels]);
```
### **Örnek Değişkenler**

Setter ve getter yöntemlerine alternatif olarak, örnek değişkenleri kullanabilirsiniz. Bu değişkenler, özelliklerle aynı isme sahiptir ancak "\_" ile başlar:
```objectivec
- (void)makeLongTruck {
_numberOfWheels = +10000;
NSLog(@"Number of wheels: %i", self.numberOfLeaves);
}
```
### Protokoller

Protokoller, (özellikler olmadan) yöntem bildirimleri kümesidir. Bir protokolü uygulayan bir sınıf, bildirilen yöntemleri uygular.

2 tür yöntem vardır: **zorunlu** ve **isteğe bağlı**. **Varsayılan** olarak bir yöntem **zorunludur** (ancak bunu **`@required`** etiketiyle de belirtebilirsiniz). Bir yöntemin isteğe bağlı olduğunu belirtmek için **`@optional`** kullanın.
```objectivec
@protocol myNewProtocol
- (void) method1; //mandatory
@required
- (void) method2; //mandatory
@optional
- (void) method3; //optional
@end
```
### Hepsi Bir Arada
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
### Temel Sınıflar

#### Dize
```objectivec
// NSString
NSString *bookTitle = @"The Catcher in the Rye";
NSString *bookAuthor = [[NSString alloc] initWithCString:"J.D. Salinger" encoding:NSUTF8StringEncoding];
NSString *bookPublicationYear = [NSString stringWithCString:"1951" encoding:NSUTF8StringEncoding];
```
Temel sınıflar **değişmezdir**, bu nedenle mevcut bir dizeye bir dize eklemek için **yeni bir NSString oluşturulması gerekir**.
```objectivec
NSString *bookDescription = [NSString stringWithFormat:@"%@ by %@ was published in %@", bookTitle, bookAuthor, bookPublicationYear];
```
Ya da **mutable** bir dize sınıfı da kullanabilirsiniz:
```objectivec
NSMutableString *mutableString = [NSMutableString stringWithString:@"The book "];
[mutableString appendString:bookTitle];
[mutableString appendString:@" was written by "];
[mutableString appendString:bookAuthor];
[mutableString appendString:@" and published in "];
[mutableString appendString:bookPublicationYear];
```
#### Numara
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
#### Dizi, Küme ve Sözlük
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

Blocks, **nesne gibi davranan fonksiyonlardır** bu nedenle fonksiyonlara geçirilebilir veya **dizilerde** ya da **sözlüklerde** **saklanabilirler**. Ayrıca, **değerler verildiğinde bir değeri temsil edebilirler** bu nedenle lambdalara benzerdir.
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
Ayrıca, **fonksiyonlarda parametre olarak kullanılacak bir blok türü tanımlamak** da mümkündür:
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
### Dosyalar
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
Ayrıca dosyaları **`NSString`** nesneleri yerine **`NSURL`** nesneleri kullanarak yönetmek de mümkündür. Metot adları benzerdir, ancak **`Path`** yerine **`URL`** ile birlikte kullanılır.
```objectivec


```
{{#include ../../banners/hacktricks-training.md}}
