# macOS Objective-C

{{#include ../../banners/hacktricks-training.md}}

## Objective-C

> [!CAUTION]
> ध्यान दें कि Objective-C में लिखे गए प्रोग्राम **रखते** हैं अपनी क्लास घोषणाएँ **जब** **संकलित** होते हैं [Mach-O बाइनरीज़](macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) में। ऐसी क्लास घोषणाएँ **शामिल** करती हैं नाम और प्रकार के:

- क्लास
- क्लास विधियाँ
- क्लास उदाहरण चर

आप इस जानकारी को [**class-dump**](https://github.com/nygard/class-dump) का उपयोग करके प्राप्त कर सकते हैं:
```bash
class-dump Kindle.app
```
ध्यान दें कि इन नामों को बाइनरी के रिवर्सिंग को अधिक कठिन बनाने के लिए ओबफस्केट किया जा सकता है।

## क्लासेस, मेथड्स और ऑब्जेक्ट्स

### इंटरफेस, प्रॉपर्टीज और मेथड्स
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
### **क्लास**
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
### **ऑब्जेक्ट और कॉल मेथड**

क्लास का एक उदाहरण बनाने के लिए **`alloc`** मेथड को कॉल किया जाता है जो प्रत्येक **प्रॉपर्टी** के लिए **मेमोरी आवंटित** करता है और उन आवंटनों को **शून्य** करता है। फिर **`init`** को कॉल किया जाता है, जो **प्रॉपर्टीज** को **आवश्यक मानों** पर **आरंभ** करता है।
```objectivec
// Something like this:
MyVehicle *newVehicle = [[MyVehicle alloc] init];

// Which is usually expressed as:
MyVehicle *newVehicle = [MyVehicle new];

// To call a method
// [myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]
[newVehicle addWheels:4];
```
### **क्लास मेथड्स**

क्लास मेथड्स को **प्लस साइन** (+) के साथ परिभाषित किया जाता है, न कि हाइफन (-) के साथ जो इंस्टेंस मेथड्स के लिए उपयोग किया जाता है। जैसे कि **NSString** क्लास मेथड **`stringWithString`**:
```objectivec
+ (id)stringWithString:(NSString *)aString;
```
### Setter & Getter

गुणों को **सेट** और **गेट** करने के लिए, आप इसे **डॉट नोटेशन** के साथ या जैसे कि आप **एक विधि को कॉल** कर रहे हों, कर सकते हैं:
```objectivec
// Set
newVehicle.numberOfWheels = 2;
[newVehicle setNumberOfWheels:3];

// Get
NSLog(@"Number of wheels: %i", newVehicle.numberOfWheels);
NSLog(@"Number of wheels: %i", [newVehicle numberOfWheels]);
```
### **इंस्टेंस वेरिएबल्स**

Setter और getter मेथड्स के विकल्प के रूप में आप इंस्टेंस वेरिएबल्स का उपयोग कर सकते हैं। ये वेरिएबल्स प्रॉपर्टीज के समान नाम रखते हैं लेकिन "\_" से शुरू होते हैं:
```objectivec
- (void)makeLongTruck {
_numberOfWheels = +10000;
NSLog(@"Number of wheels: %i", self.numberOfLeaves);
}
```
### प्रोटोकॉल

प्रोटोकॉल विधि घोषणाओं का सेट होते हैं (बिना गुणों के)। एक वर्ग जो प्रोटोकॉल को लागू करता है, घोषित विधियों को लागू करता है।

विधियों के 2 प्रकार होते हैं: **अनिवार्य** और **वैकल्पिक**। **डिफ़ॉल्ट** रूप से एक विधि **अनिवार्य** होती है (लेकिन आप इसे **`@required`** टैग के साथ भी संकेत कर सकते हैं)। यह संकेत करने के लिए कि एक विधि वैकल्पिक है, **`@optional`** का उपयोग करें।
```objectivec
@protocol myNewProtocol
- (void) method1; //mandatory
@required
- (void) method2; //mandatory
@optional
- (void) method3; //optional
@end
```
### सभी एक साथ
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
### मूल वर्ग

#### स्ट्रिंग
```objectivec
// NSString
NSString *bookTitle = @"The Catcher in the Rye";
NSString *bookAuthor = [[NSString alloc] initWithCString:"J.D. Salinger" encoding:NSUTF8StringEncoding];
NSString *bookPublicationYear = [NSString stringWithCString:"1951" encoding:NSUTF8StringEncoding];
```
बुनियादी कक्षाएँ **अपरिवर्तनीय** होती हैं, इसलिए एक मौजूदा स्ट्रिंग में एक स्ट्रिंग जोड़ने के लिए **एक नई NSString बनानी होगी**।
```objectivec
NSString *bookDescription = [NSString stringWithFormat:@"%@ by %@ was published in %@", bookTitle, bookAuthor, bookPublicationYear];
```
या आप एक **mutable** स्ट्रिंग क्लास का भी उपयोग कर सकते हैं:
```objectivec
NSMutableString *mutableString = [NSMutableString stringWithString:@"The book "];
[mutableString appendString:bookTitle];
[mutableString appendString:@" was written by "];
[mutableString appendString:bookAuthor];
[mutableString appendString:@" and published in "];
[mutableString appendString:bookPublicationYear];
```
#### संख्या
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
#### एरे, सेट और डिक्शनरी
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

Blocks **एक्सप्रेशन हैं जो ऑब्जेक्ट्स की तरह व्यवहार करते हैं** इसलिए इन्हें फ़ंक्शंस में पास किया जा सकता है या **arrays** या **dictionaries** में **स्टोर** किया जा सकता है। इसके अलावा, यदि इन्हें मान दिए जाएं तो ये **एक मान का प्रतिनिधित्व कर सकते हैं** इसलिए यह lambdas के समान है।
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
यह भी संभव है कि **एक ब्लॉक प्रकार को एक पैरामीटर के रूप में उपयोग करने के लिए परिभाषित किया जाए** फ़ंक्शनों में:
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
### फ़ाइलें
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
यह फ़ाइलों को **`NSString`** ऑब्जेक्ट्स के बजाय **`NSURL`** ऑब्जेक्ट्स का उपयोग करके प्रबंधित करना भी संभव है। विधि नाम समान हैं, लेकिन **`Path`** के बजाय **`URL`** के साथ।
```objectivec


```
{{#include ../../banners/hacktricks-training.md}}
