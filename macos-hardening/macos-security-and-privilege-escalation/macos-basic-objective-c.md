# macOS Objective-C

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Objective-C

{% hint style="danger" %}
Ten en cuenta que los programas escritos en Objective-C **mantienen** sus declaraciones de clase **cuando** se **compilan** en [binarios Mach-O](macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Estas declaraciones de clase **incluyen** el nombre y tipo de:
{% endhint %}

* La clase
* Los métodos de clase
* Las variables de instancia de clase

Puedes obtener esta información utilizando [**class-dump**](https://github.com/nygard/class-dump):
```bash
class-dump Kindle.app
```
## Clases, Métodos y Objetos

### Interfaz, Propiedades y Métodos
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
### **Clase**
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
### **Objeto y Método de Llamada**

Para crear una instancia de una clase se llama al método **`alloc`** que **asigna memoria** para cada **propiedad** y **pone a cero** esas asignaciones. Luego se llama a **`init`**, que **inicializa las propiedades** con los **valores requeridos**.
```objectivec
// Something like this:
MyVehicle *newVehicle = [[MyVehicle alloc] init];

// Which is usually expressed as:
MyVehicle *newVehicle = [MyVehicle new];

// To call a method
// [myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]
[newVehicle addWheels:4];
```
### **Métodos de Clase**

Los métodos de clase se definen con el **signo más** (+) y no con el guión (-) que se utiliza con los métodos de instancia. Por ejemplo, el método de clase **`stringWithString`** de la clase **NSString**:
```objectivec
+ (id)stringWithString:(NSString *)aString;
```
### Setter y Getter

Para **establecer** y **obtener** propiedades, puedes hacerlo con una **notación de punto** o como si estuvieras **llamando a un método**:
```objectivec
// Set
newVehicle.numberOfWheels = 2;
[newVehicle setNumberOfWheels:3];

// Get
NSLog(@"Number of wheels: %i", newVehicle.numberOfWheels);
NSLog(@"Number of wheels: %i", [newVehicle numberOfWheels]);
```
### **Variables de instancia**

Alternativamente a los métodos setter y getter, puedes usar variables de instancia. Estas variables tienen el mismo nombre que las propiedades, pero comienzan con un "\_":
```objectivec
- (void)makeLongTruck {
_numberOfWheels = +10000;
NSLog(@"Number of wheels: %i", self.numberOfLeaves);
}
```
### Protocolos

Los protocolos son conjuntos de declaraciones de métodos (sin propiedades). Una clase que implementa un protocolo implementa los métodos declarados.

Existen 2 tipos de métodos: **obligatorios** y **opcionales**. Por **defecto**, un método es **obligatorio** (pero también se puede indicar con la etiqueta **`@required`**). Para indicar que un método es opcional, utiliza **`@optional`**.
```objectivec
@protocol myNewProtocol
- (void) method1; //mandatory
@required
- (void) method2; //mandatory
@optional
- (void) method3; //optional
@end
```
### Todo junto

Cuando se trata de asegurar un sistema macOS, es importante abordar varios aspectos clave para fortalecer la seguridad y prevenir la escalada de privilegios. A continuación se presentan algunas medidas básicas que se pueden tomar:

#### 1. Actualizar el sistema operativo

Mantener el sistema operativo macOS actualizado es fundamental para protegerse contra vulnerabilidades conocidas. Asegúrese de instalar las actualizaciones de software y los parches de seguridad más recientes proporcionados por Apple.

#### 2. Configurar el firewall

El firewall integrado en macOS puede ayudar a bloquear el tráfico no deseado y proteger el sistema contra ataques externos. Asegúrese de habilitar el firewall y configurarlo para permitir solo las conexiones necesarias.

#### 3. Desactivar servicios no utilizados

Desactivar los servicios y protocolos no utilizados puede reducir la superficie de ataque y minimizar las posibilidades de explotación. Revise la lista de servicios habilitados y desactive aquellos que no sean necesarios para su caso de uso específico.

#### 4. Configurar cuentas de usuario

Crear cuentas de usuario separadas para diferentes usuarios y asignar los privilegios adecuados puede ayudar a limitar el acceso no autorizado y prevenir la escalada de privilegios. Evite utilizar una cuenta de administrador para tareas diarias y utilice cuentas de usuario estándar en su lugar.

#### 5. Utilizar contraseñas seguras

Las contraseñas fuertes son esenciales para proteger las cuentas de usuario. Asegúrese de utilizar contraseñas únicas y complejas que sean difíciles de adivinar. Considere el uso de un administrador de contraseñas para generar y almacenar contraseñas seguras.

#### 6. Habilitar FileVault

FileVault es una función de cifrado de disco completo integrada en macOS que puede ayudar a proteger los datos almacenados en su disco duro. Asegúrese de habilitar FileVault para cifrar su disco y proteger sus datos confidenciales.

#### 7. Configurar Gatekeeper

Gatekeeper es una función de seguridad de macOS que ayuda a prevenir la ejecución de software malicioso. Asegúrese de configurar Gatekeeper para permitir solo la ejecución de aplicaciones descargadas de fuentes confiables.

#### 8. Utilizar Time Machine

Time Machine es una función de copia de seguridad integrada en macOS que puede ayudar a proteger sus datos en caso de pérdida o corrupción. Asegúrese de configurar y utilizar Time Machine para realizar copias de seguridad regulares de sus archivos importantes.

#### 9. Limitar los permisos de las aplicaciones

Revise y ajuste los permisos de las aplicaciones instaladas en su sistema macOS. Asegúrese de otorgar solo los permisos necesarios y revocar los permisos innecesarios para minimizar el riesgo de abuso de las aplicaciones.

#### 10. Estar atento a las amenazas

Manténgase informado sobre las últimas amenazas de seguridad y las técnicas de ataque utilizadas por los hackers. Esté atento a las actualizaciones de seguridad y siga las mejores prácticas recomendadas para proteger su sistema macOS.
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
### Clases básicas

#### String

{% code overflow="wrap" %}
```objectivec
// NSString
NSString *bookTitle = @"The Catcher in the Rye";
NSString *bookAuthor = [[NSString alloc] initWithCString:"J.D. Salinger" encoding:NSUTF8StringEncoding];
NSString *bookPublicationYear = [NSString stringWithCString:"1951" encoding:NSUTF8StringEncoding];
```
{% endcode %}

Las clases básicas son **inmutables**, por lo que para agregar una cadena a una existente se necesita crear una **nueva NSString**.

{% code overflow="wrap" %}
```objectivec
NSString *bookDescription = [NSString stringWithFormat:@"%@ by %@ was published in %@", bookTitle, bookAuthor, bookPublicationYear];
```
{% endcode %}

O también podrías usar una clase de cadena **mutable**:

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

### Bloques

Los bloques son **funciones que se comportan como objetos**, por lo que pueden ser pasados a funciones o **almacenados** en **arrays** o **dictionaries**. Además, pueden **representar un valor si se les dan valores**, por lo que es similar a las lambdas.
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

También es posible **definir un tipo de bloque para ser utilizado como parámetro** en funciones:
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
### Archivos

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

También es posible administrar archivos **utilizando objetos `NSURL` en lugar de objetos `NSString`**. Los nombres de los métodos son similares, pero **con `URL` en lugar de `Path`**.
```objectivec
NSURL *fileSrc = [NSURL fileURLWithPath:@"/path/to/file1.txt"];
NSURL *fileDst = [NSURL fileURLWithPath:@"/path/to/file2.txt"];
[fileManager moveItemAtURL:fileSrc toURL:fileDst error: nil];
```
La mayoría de las clases básicas tienen un método `writeToFile:<path> atomically:<YES> encoding:<encoding> error:nil` definido que les permite ser escritas directamente en un archivo:

{% code overflow="wrap" %}
```objectivec
NSString* tmp = @"something temporary";
[tmp writeToFile:@"/tmp/tmp1.txt" atomically:YES encoding:NSASCIIStringEncoding error:nil];
```
{% endcode %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
