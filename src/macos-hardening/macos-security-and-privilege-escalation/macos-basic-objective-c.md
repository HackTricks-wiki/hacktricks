# macOS Objective-C

{{#include ../../banners/hacktricks-training.md}}

## Objective-C

> [!CAUTION]
> Các chương trình được viết bằng Objective-C vẫn giữ lại siêu dữ liệu runtime khi được biên dịch thành [Mach-O binaries](macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Siêu dữ liệu này bao gồm tên lớp, tên phương thức và mã hóa kiểu, cùng tên và kiểu của biến instance, hỗ trợ runtime động của Objective-C. <sup>[[1]](#references)</sup>

Bạn có thể kiểm tra thông tin này bằng [**class-dump**](https://github.com/nygard/class-dump):

```bash
class-dump Kindle.app
```

Các tên này có thể bị làm rối để khiến việc reverse engineering trở nên khó khăn hơn.

## Lớp, Phương thức & Đối tượng

### Interface, Thuộc tính & Phương thức

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

### **Lớp**

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

### **Đối tượng và phương thức gọi**

Để tạo một instance, **`alloc`** cấp phát và khởi tạo bộ nhớ của đối tượng về 0. Sau đó, một phương thức **`init`** thiết lập trạng thái ban đầu của đối tượng. <sup>[[2]](#references)</sup>

```objectivec
// Something like this:
MyVehicle *newVehicle = [[MyVehicle alloc] init];

// Which is usually expressed as:
MyVehicle *newVehicle = [MyVehicle new];

// To call a method
// [myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]
[newVehicle addWheels:4];
```

### **Phương thức lớp**

Phương thức lớp được định nghĩa bằng **dấu cộng** (+), không phải dấu gạch nối (-) được dùng với phương thức thực thể. Ví dụ như phương thức lớp **`stringWithString`** của lớp **NSString**:

```objectivec
+ (id)stringWithString:(NSString *)aString;
```

### Setter & Getter

Có thể **đặt** và **đọc** các thuộc tính bằng cú pháp dấu chấm hoặc gọi trực tiếp các phương thức truy cập của chúng:

```objectivec
// Set
newVehicle.numberOfWheels = 2;
[newVehicle setNumberOfWheels:3];

// Get
NSLog(@"Number of wheels: %i", newVehicle.numberOfWheels);
NSLog(@"Number of wheels: %i", [newVehicle numberOfWheels]);
```

### **Biến thực thể**

Thay vì sử dụng các phương thức truy cập, mã bên trong một class có thể dùng biến thực thể được tổng hợp cho một property. Theo mặc định, tên biến là tên property với dấu gạch dưới đặt phía trước:

```objectivec
- (void)makeLongTruck {
    _numberOfWheels = +10000;
    NSLog(@"Number of wheels: %i", self.numberOfWheels);
}
```

### Protocols

Protocol khai báo các phương thức độc lập với một hệ thống phân cấp lớp cụ thể. Một lớp áp dụng protocol phải triển khai các phương thức bắt buộc của protocol đó. <sup>[[2]](#references)</sup>

Các phương thức trong protocol mặc định là **bắt buộc**; `@required` làm rõ trạng thái đó, trong khi `@optional` đánh dấu các khai báo tiếp theo là tùy chọn.

```objectivec
@protocol myNewProtocol
- (void) method1; //mandatory
@required
- (void) method2; //mandatory
@optional
- (void) method3; //optional
@end
```

### Tổng hợp lại

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

### Các lớp cơ bản

#### String

```objectivec
// NSString
NSString *bookTitle = @"The Catcher in the Rye";
NSString *bookAuthor = [[NSString alloc] initWithCString:"J.D. Salinger" encoding:NSUTF8StringEncoding];
NSString *bookPublicationYear = [NSString stringWithCString:"1951" encoding:NSUTF8StringEncoding];
```

Các instance `NSString` là **bất biến**, nên việc nối thêm nội dung sẽ tạo ra một chuỗi mới.

```objectivec
NSString *bookDescription = [NSString stringWithFormat:@"%@ by %@ was published in %@", bookTitle, bookAuthor, bookPublicationYear];
```

Hoặc bạn cũng có thể sử dụng một lớp chuỗi **có thể thay đổi**:

```objectivec
NSMutableString *mutableString = [NSMutableString stringWithString:@"The book "];
[mutableString appendString:bookTitle];
[mutableString appendString:@" was written by "];
[mutableString appendString:bookAuthor];
[mutableString appendString:@" and published in "];
[mutableString appendString:bookPublicationYear];
```

#### Số

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

#### Mảng, Tập hợp & Từ điển

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

Blocks là các closure đóng gói mã có thể thực thi cùng với trạng thái được capture. Chúng có thể được truyền làm đối số và lưu trữ trong các collection, nên tương tự như lambda trong những ngôn ngữ khác. <sup>[[2]](#references)</sup>

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

Cũng có thể **định nghĩa một kiểu block để dùng làm tham số** trong các hàm:

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

### Tệp

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

Các tệp cũng có thể được quản lý bằng các đối tượng `NSURL` thay vì các đường dẫn `NSString`. Nhiều API của Foundation cung cấp các phương thức tương ứng dùng `URL` thay cho `Path`, chẳng hạn như `copyItemAtURL:toURL:error:`. Apple khuyến nghị dùng URL cho các vị trí trong hệ thống tệp vì chúng có cách biểu diễn nội bộ hiệu quả hơn. <sup>[[3]](#references)</sup>

```objectivec
NSURL *sourceURL = [NSURL fileURLWithPath:@"/path/to/file1.txt"];
NSURL *destinationURL = [NSURL fileURLWithPath:@"/path/to/file2.txt"];

if ([fileManager copyItemAtURL:sourceURL toURL:destinationURL error:nil]) {
    NSLog(@"Copy successful");
}
```

## References

- [1] [Apple Developer - môi trường thực thi Objective-C](https://developer.apple.com/documentation/objectivec/objective-c_runtime)
- [2] [Apple - Lập trình với Objective-C](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/ProgrammingWithObjectiveC/)
- [3] [Apple Developer - FileManager](https://developer.apple.com/documentation/foundation/filemanager)
{{#include ../../banners/hacktricks-training.md}}
