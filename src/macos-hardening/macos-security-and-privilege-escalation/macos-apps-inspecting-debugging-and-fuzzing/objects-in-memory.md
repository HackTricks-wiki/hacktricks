# Objects in memory

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

Об’єкти CF* походять із CoreFoundation, який надає понад 50 класів об’єктів, таких як `CFString`, `CFNumber` або `CFAllocator`.

Усі ці класи є екземплярами класу `CFRuntimeClass`, який під час виклику повертає індекс до `__CFRuntimeClassTable`. `CFRuntimeClass` визначено у [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
```objectivec
// Some comments were added to the original code

enum { // Version field constants
_kCFRuntimeScannedObject =     (1UL << 0),
_kCFRuntimeResourcefulObject = (1UL << 2),  // tells CFRuntime to make use of the reclaim field
_kCFRuntimeCustomRefCount =    (1UL << 3),  // tells CFRuntime to make use of the refcount field
_kCFRuntimeRequiresAlignment = (1UL << 4),  // tells CFRuntime to make use of the requiredAlignment field
};

typedef struct __CFRuntimeClass {
CFIndex version;  // This is made a bitwise OR with the relevant previous flags

const char *className; // must be a pure ASCII string, nul-terminated
void (*init)(CFTypeRef cf);  // Initializer function
CFTypeRef (*copy)(CFAllocatorRef allocator, CFTypeRef cf); // Copy function, taking CFAllocatorRef and CFTypeRef to copy
void (*finalize)(CFTypeRef cf); // Finalizer function
Boolean (*equal)(CFTypeRef cf1, CFTypeRef cf2); // Function to be called by CFEqual()
CFHashCode (*hash)(CFTypeRef cf); // Function to be called by CFHash()
CFStringRef (*copyFormattingDesc)(CFTypeRef cf, CFDictionaryRef formatOptions); // Provides a CFStringRef with a textual description of the object// return str with retain
CFStringRef (*copyDebugDesc)(CFTypeRef cf);	// CFStringRed with textual description of the object for CFCopyDescription

#define CF_RECLAIM_AVAILABLE 1
void (*reclaim)(CFTypeRef cf); // Or in _kCFRuntimeResourcefulObject in the .version to indicate this field should be used
// It not null, it's called when the last reference to the object is released

#define CF_REFCOUNT_AVAILABLE 1
// If not null, the following is called when incrementing or decrementing reference count
uint32_t (*refcount)(intptr_t op, CFTypeRef cf); // Or in _kCFRuntimeCustomRefCount in the .version to indicate this field should be used
// this field must be non-NULL when _kCFRuntimeCustomRefCount is in the .version field
// - if the callback is passed 1 in 'op' it should increment the 'cf's reference count and return 0
// - if the callback is passed 0 in 'op' it should return the 'cf's reference count, up to 32 bits
// - if the callback is passed -1 in 'op' it should decrement the 'cf's reference count; if it is now zero, 'cf' should be cleaned up and deallocated (the finalize callback above will NOT be called unless the process is running under GC, and CF does not deallocate the memory for you; if running under GC, finalize should do the object tear-down and free the object memory); then return 0
// remember to use saturation arithmetic logic and stop incrementing and decrementing when the ref count hits UINT32_MAX, or you will have a security bug
// remember that reference count incrementing/decrementing must be done thread-safely/atomically
// objects should be created/initialized with a custom ref-count of 1 by the class creation functions
// do not attempt to use any bits within the CFRuntimeBase for your reference count; store that in some additional field in your CF object

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#define CF_REQUIRED_ALIGNMENT_AVAILABLE 1
// If not 0, allocation of object must be on this boundary
uintptr_t requiredAlignment; // Or in _kCFRuntimeRequiresAlignment in the .version field to indicate this field should be used; the allocator to _CFRuntimeCreateInstance() will be ignored in this case; if this is less than the minimum alignment the system supports, you'll get higher alignment; if this is not an alignment the system supports (e.g., most systems will only support powers of two, or if it is too high), the result (consequences) will be up to CF or the system to decide

} CFRuntimeClass;
```
## Objective-C

### Секції пам’яті, що використовуються

Більшість даних, які використовує runtime Objective‑C, змінюються під час виконання, тому він використовує низку секцій із сімейства сегментів Mach‑O `__DATA` у пам’яті. Історично до них належали:

- `__objc_msgrefs` (`message_ref_t`): Посилання на повідомлення
- `__objc_ivar` (`ivar`): Змінні екземпляра
- `__objc_data` (`...`): Змінювані дані
- `__objc_classrefs` (`Class`): Посилання на класи
- `__objc_superrefs` (`Class`): Посилання на суперкласи
- `__objc_protorefs` (`protocol_t *`): Посилання на протоколи
- `__objc_selrefs` (`SEL`): Посилання на селектори
- `__objc_const` (`...`): Дані класів лише для читання та інші (сподіваємося) константні дані
- `__objc_imageinfo` (`version, flags`): Використовується під час завантаження image: поточна версія — `0`; Flags визначають підтримку попередньо оптимізованого GC тощо
- `__objc_protolist` (`protocol_t *`): Список протоколів
- `__objc_nlcatlist` (`category_t`): Вказівник на Non-Lazy Categories, визначені в цьому binary
- `__objc_catlist` (`category_t`): Вказівник на Categories, визначені в цьому binary
- `__objc_nlclslist` (`classref_t`): Вказівник на Non-Lazy Objective‑C класи, визначені в цьому binary
- `__objc_classlist` (`classref_t`): Вказівники на всі Objective‑C класи, визначені в цьому binary

Також він використовує кілька секцій у сегменті `__TEXT` для зберігання констант:

- `__objc_methname` (C‑String): Назви методів
- `__objc_classname` (C‑String): Назви класів
- `__objc_methtype` (C‑String): Типи методів

Сучасні macOS/iOS (особливо на Apple Silicon) також розміщують метадані Objective‑C/Swift у:

- `__DATA_CONST`: незмінювані метадані Objective‑C, якими можна спільно користуватися між процесами в режимі лише для читання (наприклад, багато списків `__objc_*` тепер розміщуються тут).
- `__AUTH` / `__AUTH_CONST`: сегменти, що містять вказівники, які мають бути автентифіковані під час завантаження або використання на arm64e (Pointer Authentication). У сучасних binaries ви також побачите `__auth_got` у `__AUTH_CONST` замість лише legacy `__la_symbol_ptr`/`__got`. Під час instrumenting або hooking враховуйте записи як `__got`, так і `__auth_got` у сучасних binaries.

Щоб отримати довідкову інформацію про dyld pre‑optimization (наприклад, selector uniquing і попереднє обчислення класів/протоколів), а також зрозуміти, чому багато з цих секцій є «already fixed up», якщо вони походять зі shared cache, перегляньте Apple `objc-opt` sources і нотатки щодо dyld shared cache. Це впливає на те, де і як можна patch-ити метадані під час виконання.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Type Encoding

Objective‑C використовує mangling для кодування типів селекторів і змінних простих та складних типів:

- Primitive types використовують першу літеру типу: `i` для `int`, `c` для `char`, `l` для `long`... і використовують велику літеру, якщо тип unsigned (`L` для `unsigned long`).
- Інші типи даних використовують інші літери або символи, наприклад `q` для `long long`, `b` для bitfields, `B` для booleans, `#` для класів, `@` для `id`, `*` для `char *`, `^` для generic pointers і `?` для undefined.
- Масиви, структури та unions використовують відповідно `[`, `{` і `(`.

#### Приклад оголошення методу
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Селектором буде `processString:withOptions:andError:`

#### Кодування типів

- `id` кодується як `@`
- `char *` кодується як `*`

Повне кодування типів для методу:
```less
@24@0:8@16*20^@24
```
#### Детальний розбір

1. Тип повернення (`NSString *`): кодується як `@` із довжиною 24
2. `self` (екземпляр об’єкта): кодується як `@`, зі зміщенням 0
3. `_cmd` (селектор): кодується як `:`, зі зміщенням 8
4. Перший аргумент (`char * input`): кодується як `*`, зі зміщенням 16
5. Другий аргумент (`NSDictionary * options`): кодується як `@`, зі зміщенням 20
6. Третій аргумент (`NSError ** error`): кодується як `^@`, зі зміщенням 24

За допомогою селектора та encoding можна відновити метод.

### Класи

Класи в Objective‑C є C-структурами з властивостями, покажчиками на методи тощо. Структуру `objc_class` можна знайти у [**вихідному коді**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
```objectivec
struct objc_class : objc_object {
// Class ISA;
Class superclass;
cache_t cache;             // formerly cache pointer and vtable
class_data_bits_t bits;    // class_rw_t * plus custom rr/alloc flags

class_rw_t *data() {
return bits.data();
}
void setData(class_rw_t *newData) {
bits.setData(newData);
}

void setInfo(uint32_t set) {
assert(isFuture()  ||  isRealized());
data()->setFlags(set);
}
[...]
```
Цей клас використовує деякі біти поля `isa` для позначення інформації про клас.

Потім структура містить вказівник на структуру `class_ro_t`, збережену на диску, яка містить атрибути класу, як-от його ім’я, базові методи, властивості та змінні екземпляра. Під час виконання додатково використовується структура `class_rw_t`, яка містить вказівники, що можуть змінюватися, зокрема методи, протоколи та властивості.

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## Сучасні представлення об’єктів у пам’яті (arm64e, tagged pointers, Swift)

### Non-pointer `isa` і Pointer Authentication (arm64e)

На Apple Silicon і в сучасних runtime-середовищах Objective-C `isa` не завжди є необробленим вказівником на клас. В arm64e це упакована структура, яка також може містити Pointer Authentication Code (PAC). Залежно від платформи вона може містити такі поля, як `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc`, а також сам вказівник на клас (зі зсувом або підписаний). Це означає, що безпосереднє розіменування перших 8 байтів об’єкта Objective-C не завжди дасть коректний вказівник `Class`.<sup>[[2]](#references)</sup>

Практичні примітки для debugging в arm64e:

- LLDB зазвичай видаляє біти PAC за вас під час виведення об’єктів Objective-C за допомогою `po`, але під час роботи з raw pointers може знадобитися вручну видалити authentication:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Багато function/data pointers у Mach-O розташовуються в `__AUTH`/`__AUTH_CONST` і потребують authentication перед використанням. Якщо ви виконуєте interposing або re-binding (наприклад, у стилі fishhook), переконайтеся, що також обробляєте `__auth_got` на додачу до застарілого `__got`.

Для детального ознайомлення з гарантіями мови/ABI та intrinsics `<ptrauth.h>`, доступними з Clang/LLVM, дивіться reference наприкінці цієї сторінки.<sup>[[1]](#references)</sup>

### Tagged pointer objects

Деякі класи Foundation уникають виділення пам’яті в heap, кодуючи payload об’єкта безпосередньо в значенні вказівника (tagged pointers). Виявлення відрізняється залежно від платформи (наприклад, most-significant bit в arm64 і least-significant bit в x86_64 macOS). Tagged objects не мають звичайного `isa`, збереженого в пам’яті; runtime визначає клас за tag bits.<sup>[[2]](#references)</sup> Під час перевірки довільних значень `id`:

- Використовуйте runtime APIs замість безпосереднього звернення до поля `isa`: `object_getClass(obj)` / `[obj class]`.
- У LLDB простий виклик `po (id)0xADDR` коректно виведе tagged pointer instances, оскільки runtime використовується для визначення класу.

### Swift heap objects і metadata

Чисті Swift-класи також є об’єктами із заголовком, який вказує на Swift metadata, а не на Objective-C `isa`. Для introspection активних Swift-процесів без їх модифікації можна використовувати `swift-inspect` з toolchain Swift, який застосовує бібліотеку Remote Mirror для читання runtime metadata:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Це дуже корисно для мапування Swift heap objects і protocol conformances під час reverse engineering змішаних Swift/ObjC apps.

---

## Шпаргалка з runtime inspection (LLDB / Frida)

### LLDB

- Вивести object або class із raw pointer:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- Переглянути Objective‑C class за вказівником на `self` object method у breakpoint:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Dump секції, що містять метадані Objective-C (примітка: багато з них тепер знаходяться в `__DATA_CONST` / `__AUTH_CONST`):
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- Прочитайте пам’ять відомого об’єкта класу, щоб перейти до `class_ro_t` / `class_rw_t` під час реверс-аналізу списків методів:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective‑C та Swift)

Frida надає високорівневі runtime bridges, які дуже зручні для виявлення та інструментування живих об'єктів без символів:

- Перераховувати класи й методи, визначати фактичні назви класів під час runtime та перехоплювати Objective‑C селектори:
```js
if (ObjC.available) {
// List a class' methods
console.log(ObjC.classes.NSFileManager.$ownMethods);

// Intercept and inspect arguments/return values
const impl = ObjC.classes.NSFileManager['- fileExistsAtPath:isDirectory:'].implementation;
Interceptor.attach(impl, {
onEnter(args) {
this.path = new ObjC.Object(args[2]).toString();
},
onLeave(retval) {
console.log('fileExistsAtPath:', this.path, '=>', retval);
}
});
}
```
- Swift bridge: enumerate Swift types and interact with Swift instances (потребує recent Frida; дуже корисно для targets на Apple Silicon).

---

## Посилання


- [1] [Clang/LLVM: Pointer Authentication and the ptrauth.h intrinsics (arm64e ABI)](https://clang.llvm.org/docs/PointerAuthentication.html)
- [2] [Apple objc runtime headers - objc-object.h (tagged pointers, non‑pointer isa, etc.)](https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html)

{{#include ../../../banners/hacktricks-training.md}}
