# macOS Objective-C

{{#include ../../banners/hacktricks-training.md}}

## Objective-C

> [!CAUTION]
> Σημειώστε ότι τα προγράμματα που έχουν γραφτεί σε Objective-C **διατηρούν** τις δηλώσεις κλάσης τους **όταν** **μεταγλωττίζονται** σε [Mach-O binaries](macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Τέτοιες δηλώσεις κλάσης **περιλαμβάνουν** το όνομα και τον τύπο των:

- Της κλάσης
- Των μεθόδων της κλάσης
- Των μεταβλητών στιγμής της κλάσης

Μπορείτε να αποκτήσετε αυτές τις πληροφορίες χρησιμοποιώντας [**class-dump**](https://github.com/nygard/class-dump):
```bash
class-dump Kindle.app
```
Σημειώστε ότι αυτά τα ονόματα θα μπορούσαν να είναι κρυπτογραφημένα για να καταστήσουν την αναστροφή του δυαδικού πιο δύσκολη.

## Κλάσεις, Μέθοδοι & Αντικείμενα

### Διεπαφή, Ιδιότητες & Μέθοδοι
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
### **Κλάση**
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
### **Αντικείμενο & Κλήση Μεθόδου**

Για να δημιουργήσετε μια παρουσία μιας κλάσης, καλείται η μέθοδος **`alloc`**, η οποία **κατανέμει μνήμη** για κάθε **ιδιότητα** και **μηδενίζει** αυτές τις κατανομές. Στη συνέχεια, καλείται η **`init`**, η οποία **αρχικοποιεί τις ιδιότητες** στις **απαιτούμενες τιμές**.
```objectivec
// Something like this:
MyVehicle *newVehicle = [[MyVehicle alloc] init];

// Which is usually expressed as:
MyVehicle *newVehicle = [MyVehicle new];

// To call a method
// [myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]
[newVehicle addWheels:4];
```
### **Μέθοδοι Κλάσης**

Οι μέθοδοι κλάσης ορίζονται με το **συν (+)** και όχι με την παύλα (-) που χρησιμοποιείται με τις μεθόδους στιγμής. Όπως η μέθοδος κλάσης **NSString** **`stringWithString`**:
```objectivec
+ (id)stringWithString:(NSString *)aString;
```
### Setter & Getter

Για να **ορίσετε** & **πάρετε** ιδιότητες, μπορείτε να το κάνετε με **σημειογραφία τελείας** ή σαν να **καλείτε μια μέθοδο**:
```objectivec
// Set
newVehicle.numberOfWheels = 2;
[newVehicle setNumberOfWheels:3];

// Get
NSLog(@"Number of wheels: %i", newVehicle.numberOfWheels);
NSLog(@"Number of wheels: %i", [newVehicle numberOfWheels]);
```
### **Μεταβλητές Στιγμής**

Εναλλακτικά προς τις μεθόδους setter & getter μπορείτε να χρησιμοποιήσετε μεταβλητές στιγμής. Αυτές οι μεταβλητές έχουν το ίδιο όνομα με τις ιδιότητες αλλά ξεκινούν με ένα "\_":
```objectivec
- (void)makeLongTruck {
_numberOfWheels = +10000;
NSLog(@"Number of wheels: %i", self.numberOfLeaves);
}
```
### Πρωτόκολλα

Τα πρωτόκολλα είναι σύνολα δηλώσεων μεθόδων (χωρίς ιδιότητες). Μια κλάση που υλοποιεί ένα πρωτόκολλο υλοποιεί τις δηλωμένες μεθόδους.

Υπάρχουν 2 τύποι μεθόδων: **υποχρεωτικές** και **προαιρετικές**. Από **προεπιλογή**, μια μέθοδος είναι **υποχρεωτική** (αλλά μπορείτε επίσης να το υποδείξετε με μια ετικέτα **`@required`**). Για να υποδείξετε ότι μια μέθοδος είναι προαιρετική, χρησιμοποιήστε **`@optional`**.
```objectivec
@protocol myNewProtocol
- (void) method1; //mandatory
@required
- (void) method2; //mandatory
@optional
- (void) method3; //optional
@end
```
### Όλα μαζί
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
### Βασικές Κλάσεις

#### Συμβολοσειρά
```objectivec
// NSString
NSString *bookTitle = @"The Catcher in the Rye";
NSString *bookAuthor = [[NSString alloc] initWithCString:"J.D. Salinger" encoding:NSUTF8StringEncoding];
NSString *bookPublicationYear = [NSString stringWithCString:"1951" encoding:NSUTF8StringEncoding];
```
Οι βασικές κλάσεις είναι **αμετάβλητες**, οπότε για να προστεθεί μια συμβολοσειρά σε μια υπάρχουσα, πρέπει να **δημιουργηθεί μια νέα NSString**.
```objectivec
NSString *bookDescription = [NSString stringWithFormat:@"%@ by %@ was published in %@", bookTitle, bookAuthor, bookPublicationYear];
```
Ή θα μπορούσατε επίσης να χρησιμοποιήσετε μια **mutable** κλάση συμβολοσειράς:
```objectivec
NSMutableString *mutableString = [NSMutableString stringWithString:@"The book "];
[mutableString appendString:bookTitle];
[mutableString appendString:@" was written by "];
[mutableString appendString:bookAuthor];
[mutableString appendString:@" and published in "];
[mutableString appendString:bookPublicationYear];
```
#### Αριθμός
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
#### Πίνακες, Σύνολα & Λεξικά
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

Τα Blocks είναι **συναρτήσεις που συμπεριφέρονται ως αντικείμενα** έτσι ώστε να μπορούν να περαστούν σε συναρτήσεις ή να **αποθηκευτούν** σε **πίνακες** ή **λεξικά**. Επίσης, μπορούν να **αντιπροσωπεύουν μια τιμή αν τους δοθούν τιμές** οπότε είναι παρόμοια με τα lambdas.
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
Είναι επίσης δυνατό να **ορίσετε έναν τύπο μπλοκ για να χρησιμοποιηθεί ως παράμετρος** σε συναρτήσεις:
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
### Αρχεία
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
Είναι επίσης δυνατό να διαχειριστείτε αρχεία **χρησιμοποιώντας αντικείμενα `NSURL` αντί για αντικείμενα `NSString`**. Τα ονόματα μεθόδων είναι παρόμοια, αλλά **με `URL` αντί για `Path`**.
```objectivec


```
{{#include ../../banners/hacktricks-training.md}}
