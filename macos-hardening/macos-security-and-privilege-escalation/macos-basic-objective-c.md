## Objective-C

{% hint style="danger" %}
Observe que programas escritos em Objective-C **mantêm** suas declarações de classe **quando** **compilados** em [binários Mach-O](macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Tais declarações de classe **incluem** o nome e o tipo de:
{% endhint %}

* A classe
* Os métodos da classe
* As variáveis de instância da classe

Você pode obter essas informações usando [**class-dump**](https://github.com/nygard/class-dump):
```bash
class-dump Kindle.app
```
Observe que esses nomes podem ser ofuscados para tornar a reversão do binário mais difícil.

## Classes, Métodos e Objetos

### Interface, Propriedades e Métodos
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
### **Classe**
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
### **Objeto e Chamada de Método**

Para criar uma instância de uma classe, o método **`alloc`** é chamado, o qual **aloca memória** para cada **propriedade** e **zera** essas alocações. Em seguida, o método **`init`** é chamado, o qual **inicializa as propriedades** com os **valores necessários**.
```objectivec
// Something like this:
MyVehicle *newVehicle = [[MyVehicle alloc] init];

// Which is usually expressed as:
MyVehicle *newVehicle = [MyVehicle new];

// To call a method
// [myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]
[newVehicle addWheels:4];
```
### **Métodos de Classe**

Métodos de classe são definidos com o **sinal de mais** (+) e não com o hífen (-) que é usado com métodos de instância. Como o método de classe da classe **NSString** **`stringWithString`**:
```objectivec
+ (id)stringWithString:(NSString *)aString;
```
### Setter e Getter

Para **definir** e **obter** propriedades, você pode fazê-lo com uma **notação de ponto** ou como se estivesse **chamando um método**:
```objectivec
// Set
newVehicle.numberOfWheels = 2;
[newVehicle setNumberOfWheels:3];

// Get
NSLog(@"Number of wheels: %i", newVehicle.numberOfWheels);
NSLog(@"Number of wheels: %i", [newVehicle numberOfWheels]);
```
### **Variáveis de Instância**

Alternativamente aos métodos setter e getter, você pode usar variáveis de instância. Essas variáveis têm o mesmo nome que as propriedades, mas começam com um "\_":
```objectivec
- (void)makeLongTruck {
    _numberOfWheels = +10000;
    NSLog(@"Number of wheels: %i", self.numberOfLeaves);
}
```
### Protocolos

Protocolos são conjuntos de declarações de métodos (sem propriedades). Uma classe que implementa um protocolo implementa os métodos declarados.

Existem 2 tipos de métodos: **obrigatórios** e **opcionais**. Por **padrão**, um método é **obrigatório** (mas você também pode indicá-lo com uma tag **`@required`**). Para indicar que um método é opcional, use **`@optional`**.
```objectivec
@protocol myNewProtocol
- (void) method1; //mandatory
@required
- (void) method2; //mandatory
@optional
- (void) method3; //optional
@end
```
### Tudo junto
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
### Classes Básicas

#### String

{% code overflow="wrap" %}
```objectivec
// NSString
NSString *bookTitle = @"The Catcher in the Rye";
NSString *bookAuthor = [[NSString alloc] initWithCString:"J.D. Salinger" encoding:NSUTF8StringEncoding];
NSString *bookPublicationYear = [NSString stringWithCString:"1951" encoding:NSUTF8StringEncoding];
```
As classes básicas são **imutáveis**, então para adicionar uma string a uma já existente, uma **nova NSString precisa ser criada**. 

{% code overflow="wrap" %}
```objectivec
NSString *bookDescription = [NSString stringWithFormat:@"%@ by %@ was published in %@", bookTitle, bookAuthor, bookPublicationYear];
```
{% endcode %}

Ou você também pode usar uma classe de string **mutável**. 

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

#### Número

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
#### Array, Conjuntos e Dicionários

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

// Sets
NSSet *fruitsSet1 = [NSSet setWithObjects:@"apple", @"banana", @"orange", nil];
NSSet *fruitsSet2 = [NSSet setWithArray:@[@"apple", @"banana", @"orange"]];

// Inmutable sets
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
### Blocos

Blocos são **funções que se comportam como objetos**, então eles podem ser passados para funções ou **armazenados** em **arrays** ou **dicionários**. Além disso, eles podem **representar um valor se forem dados valores**, então é semelhante a lambdas. 

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

Também é possível **definir um tipo de bloco para ser usado como parâmetro** em funções:
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
### Arquivos

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

Também é possível gerenciar arquivos **usando objetos `NSURL` em vez de objetos `NSString`**. Os nomes dos métodos são semelhantes, mas **com `URL` em vez de `Path`**.
```objectivec
NSURL *fileSrc = [NSURL fileURLWithPath:@"/path/to/file1.txt"];
NSURL *fileDst = [NSURL fileURLWithPath:@"/path/to/file2.txt"];
[fileManager moveItemAtURL:fileSrc toURL:fileDst error: nil];
```
A maioria das classes básicas tem um método `writeToFile:<path> atomically:<YES> encoding:<encoding> error:nil` definido que permite que elas sejam diretamente escritas em um arquivo:

{% code overflow="wrap" %}
```objectivec
NSString* tmp = @"something temporary";
[tmp writeToFile:@"/tmp/tmp1.txt" atomically:YES encoding:NSASCIIStringEncoding error:nil];
```
{% endcode %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
