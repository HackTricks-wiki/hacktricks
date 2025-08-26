# Об'єкти в пам'яті

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF*-об'єкти походять із CoreFoundation, який містить понад 50 класів об'єктів, таких як `CFString`, `CFNumber` або `CFAllocator`.

Усі ці класи є екземплярами класу `CFRuntimeClass`, який при виклику повертає індекс у таблицю `__CFRuntimeClassTable`. CFRuntimeClass визначено в [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
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

### Memory sections used

Більшість даних, які використовує Objective‑C runtime, змінюються під час виконання, тому в пам'яті використовуються кілька секцій з сімейства сегментів Mach‑O `__DATA`. Історично це включало:

- `__objc_msgrefs` (`message_ref_t`): посилання на повідомлення
- `__objc_ivar` (`ivar`): поля екземпляра
- `__objc_data` (`...`): змінні дані
- `__objc_classrefs` (`Class`): посилання на класи
- `__objc_superrefs` (`Class`): посилання на суперкласи
- `__objc_protorefs` (`protocol_t *`): посилання на протоколи
- `__objc_selrefs` (`SEL`): посилання на селектори
- `__objc_const` (`...`): r/o дані класів та інші (сподіваємося) константні дані
- `__objc_imageinfo` (`version, flags`): використовується під час завантаження образу: версія наразі `0`; прапорці вказують підтримку попередньої оптимізації GC тощо
- `__objc_protolist` (`protocol_t *`): список протоколів
- `__objc_nlcatlist` (`category_t`): вказівник на Non-Lazy Categories, визначені в цьому бінарнику
- `__objc_catlist` (`category_t`): вказівник на Categories, визначені в цьому бінарнику
- `__objc_nlclslist` (`classref_t`): вказівник на Non-Lazy Objective‑C класи, визначені в цьому бінарнику
- `__objc_classlist` (`classref_t`): вказівники на всі Objective‑C класи, визначені в цьому бінарнику

Воно також використовує кілька секцій у сегменті `__TEXT` для зберігання констант:

- `__objc_methname` (C‑String): імена методів
- `__objc_classname` (C‑String): імена класів
- `__objc_methtype` (C‑String): типи методів

Сучасні macOS/iOS (особливо на Apple Silicon) також розміщують Objective‑C/Swift метадані в:

- `__DATA_CONST`: незмінні Objective‑C метадані, які можуть бути розділені read‑only між процесами (наприклад, багато списків `__objc_*` тепер знаходяться тут).
- `__AUTH` / `__AUTH_CONST`: сегменти, що містять вказівники, які повинні бути автентифіковані при завантаженні або під час використання на arm64e (Pointer Authentication). Ви також побачите `__auth_got` в `__AUTH_CONST` замість старих `__la_symbol_ptr`/`__got` тільки. При instrumenting або hooking пам'ятайте враховувати як `__got`, так і `__auth_got` записи в сучасних бінарниках.

Для довідки про dyld pre‑optimization (наприклад, selector uniquing та попередні обчислення класів/протоколів) і чому багато з цих секцій вже "виправлені" при походженні з shared cache, перегляньте Apple `objc-opt` джерела та примітки dyld shared cache. Це впливає на те, де і як ви можете патчити метадані під час виконання.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Type Encoding

Objective‑C використовує манглінг для кодування типів селекторів та змінних для простих і складних типів:

- Примітивні типи використовують першу літеру типу: `i` для `int`, `c` для `char`, `l` для `long`... і використовують велику літеру у випадку беззнакового типу (наприклад `L` для `unsigned long`).
- Інші типи даних використовують інші літери або символи, наприклад `q` для `long long`, `b` для bitfields, `B` для булевих, `#` для класів, `@` для `id`, `*` для `char *`, `^` для загальних вказівників і `?` для невизначеного.
- Масиви, структури та союзи використовують `[`, `{` та `(` відповідно.

#### Example Method Declaration
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Селектор буде `processString:withOptions:andError:`

#### Кодування типів

- `id` кодується як `@`
- `char *` кодується як `*`

Повне кодування типів для методу:
```less
@24@0:8@16*20^@24
```
#### Детальний розбір

1. Тип повернення (`NSString *`): Кодується як `@` з довжиною 24
2. `self` (екземпляр об'єкта): Кодується як `@`, зі зсувом 0
3. `_cmd` (селектор): Кодується як `:`, зі зсувом 8
4. Перший аргумент (`char * input`): Кодується як `*`, зі зсувом 16
5. Другий аргумент (`NSDictionary * options`): Кодується як `@`, зі зсувом 20
6. Третій аргумент (`NSError ** error`): Кодується як `^@`, зі зсувом 24

За допомогою селектора + кодування можна відновити метод.

### Класи

Класи в Objective‑C — це C structs з властивостями, вказівниками на методи тощо. Можна знайти struct `objc_class` у [**source code**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
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
Цей клас використовує деякі біти поля `isa`, щоб позначати інформацію про клас.

Далі структура має вказівник на структуру `class_ro_t`, збережену на диску, яка містить атрибути класу, такі як його назва, базові методи, властивості та змінні екземпляру. Під час виконання використовується додаткова структура `class_rw_t`, що містить вказівники, які можна змінювати — наприклад, методи, протоколи, властивості.

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## Сучасні представлення об’єктів в пам'яті (arm64e, tagged pointers, Swift)

### Non‑pointer `isa` and Pointer Authentication (arm64e)

На Apple Silicon і в сучасних рантаймах Objective‑C `isa` не завжди є звичайним вказівником на клас. На arm64e це фасетована структура, яка може також містити Pointer Authentication Code (PAC). Залежно від платформи вона може включати поля на кшталт `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc` і сам вказівник на клас (зміщений або зі знаком). Це означає, що сліпе дереференсування перших 8 байтів Objective‑C об’єкта не завжди дасть дійсний вказівник `Class`.

Практичні зауваги під час відладки на arm64e:

- LLDB зазвичай видаляє біти PAC при друку Objective‑C об’єктів за допомогою `po`, але при роботі з сирими вказівниками може знадобитися вручну зняти аутентифікацію:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Багато вказівників на функції/дані в Mach‑O розташовані в `__AUTH`/`__AUTH_CONST` і вимагають аутентифікації перед використанням. Якщо ви робите interposing або re‑binding (наприклад, у стилі fishhook), переконайтесь, що ви також обробляєте `__auth_got` на додаток до застарілого `__got`.

Для детального вивчення гарантій мови/ABI та `<ptrauth.h>` intrinsics, доступних у Clang/LLVM, див. посилання в кінці цієї сторінки.

### Tagged pointer objects

Деякі класи Foundation уникають розміщення в купі шляхом кодування корисного навантаження об’єкта безпосередньо у значенні вказівника (tagged pointers). Виявлення відрізняється залежно від платформи (наприклад, найстарший біт на arm64, найменш значущий на x86_64 macOS). Tagged objects не мають звичайного `isa`, збереженого в пам'яті; runtime визначає клас за бітами тегу. Під час інспектування довільних значень `id`:

- Використовуйте runtime API замість доступу до поля `isa`: `object_getClass(obj)` / `[obj class]`.
- У LLDB просто `po (id)0xADDR` правильно надрукує інстанси tagged pointer, оскільки runtime залучається для визначення класу.

### Swift heap objects and metadata

Чисті класи Swift також є об’єктами з заголовком, що вказує на Swift metadata (не Objective‑C `isa`). Для інспектування живих процесів Swift без їх модифікації можна використовувати інструментарій Swift — `swift-inspect`, який використовує бібліотеку Remote Mirror для читання runtime metadata:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Це дуже корисно для відображення heap-об'єктів Swift та відповідностей протоколам під час реверсінгу змішаних Swift/ObjC додатків.

---

## Шпаргалка з інспекції часу виконання (LLDB / Frida)

### LLDB

- Вивести об'єкт або клас за сирим вказівником:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- Переглянути клас Objective‑C за вказівником на `self` методу об'єкта в брейкпоінті:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Dump секції, що несуть Objective‑C метадані (примітка: багато тепер у `__DATA_CONST` / `__AUTH_CONST`):
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- Зчитайте пам'ять відомого об'єкта класу, щоб перейти до `class_ro_t` / `class_rw_t` під час реверсінгу списків методів:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective‑C and Swift)

Frida надає високорівневі runtime-бріджі, які дуже корисні для виявлення та інструментування живих об'єктів без символів:

- Перераховувати класи та методи, визначати фактичні імена класів під час виконання (runtime) та перехоплювати Objective‑C selectors:
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
- Swift bridge: перераховує типи Swift та взаємодіє з екземплярами Swift (потребує останньої версії Frida; дуже корисно на Apple Silicon цілях).

---

## Посилання

- Clang/LLVM: Pointer Authentication і `<ptrauth.h>` intrinsics (arm64e ABI). https://clang.llvm.org/docs/PointerAuthentication.html
- Apple objc runtime заголовки (tagged pointers, non‑pointer `isa`, etc.) наприклад, `objc-object.h`. https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html

{{#include ../../../banners/hacktricks-training.md}}
