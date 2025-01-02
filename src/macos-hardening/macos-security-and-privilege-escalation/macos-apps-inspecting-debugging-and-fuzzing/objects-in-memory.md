# Voorwerpe in geheue

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF\* voorwerpe kom van CoreFoundation, wat meer as 50 klasse van voorwerpe soos `CFString`, `CFNumber` of `CFAllocator` bied.

Al hierdie klasse is instansies van die klas `CFRuntimeClass`, wat wanneer dit aangeroep word, 'n indeks na die `__CFRuntimeClassTable` teruggee. Die CFRuntimeClass is gedefinieer in [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
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

### Geheue seksies wat gebruik word

Die meeste van die data wat deur die ObjectiveC runtime gebruik word, sal tydens die uitvoering verander, daarom gebruik dit 'n paar seksies van die **\_\_DATA** segment in geheue:

- **`__objc_msgrefs`** (`message_ref_t`): Boodskap verwysings
- **`__objc_ivar`** (`ivar`): Instansie veranderlikes
- **`__objc_data`** (`...`): Veranderlike data
- **`__objc_classrefs`** (`Class`): Klas verwysings
- **`__objc_superrefs`** (`Class`): Superklas verwysings
- **`__objc_protorefs`** (`protocol_t *`): Protokol verwysings
- **`__objc_selrefs`** (`SEL`): Selektor verwysings
- **`__objc_const`** (`...`): Klas `r/o` data en ander (hopelik) konstante data
- **`__objc_imageinfo`** (`version, flags`): Gebruik tydens beeld laai: Huidige weergawe `0`; Vlaggies spesifiseer voor-geoptimaliseerde GC ondersteuning, ens.
- **`__objc_protolist`** (`protocol_t *`): Protokol lys
- **`__objc_nlcatlist`** (`category_t`): Wysiger na Nie-Lui Kategoriene gedefinieer in hierdie binêre
- **`__objc_catlist`** (`category_t`): Wysiger na Kategoriene gedefinieer in hierdie binêre
- **`__objc_nlclslist`** (`classref_t`): Wysiger na Nie-Lui Objective-C klasse gedefinieer in hierdie binêre
- **`__objc_classlist`** (`classref_t`): Wysigers na alle Objective-C klasse gedefinieer in hierdie binêre

Dit gebruik ook 'n paar seksies in die **`__TEXT`** segment om konstante waardes te stoor as dit nie moontlik is om in hierdie seksie te skryf nie:

- **`__objc_methname`** (C-String): Metode name
- **`__objc_classname`** (C-String): Klas name
- **`__objc_methtype`** (C-String): Metode tipes

### Tipe Kodering

Objective-C gebruik 'n paar mangeling om selektor en veranderlike tipes van eenvoudige en komplekse tipes te kodeer:

- Primitive tipes gebruik die eerste letter van die tipe `i` vir `int`, `c` vir `char`, `l` vir `long`... en gebruik die hoofletter in die geval dit ongetekend is (`L` vir `unsigned Long`).
- Ander datatipes waarvan die letters gebruik word of spesiaal is, gebruik ander letters of simbole soos `q` vir `long long`, `b` vir `bitfields`, `B` vir `booleans`, `#` vir `klas`, `@` vir `id`, `*` vir `char wysigers`, `^` vir generiese `wysigers` en `?` vir `onbepaald`.
- Arrays, strukture en unies gebruik `[`, `{` en `(`

#### Voorbeeld Metode Deklarasie
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Die selektor sou wees `processString:withOptions:andError:`

#### Tipe Kodering

- `id` word gekodeer as `@`
- `char *` word gekodeer as `*`

Die volledige tipe kodering vir die metode is:
```less
@24@0:8@16*20^@24
```
#### Gedetailleerde Ontleding

1. **Terugkeer tipe (`NSString *`)**: Gecodeer as `@` met lengte 24
2. **`self` (objekinstansie)**: Gecodeer as `@`, by offset 0
3. **`_cmd` (selektor)**: Gecodeer as `:`, by offset 8
4. **Eerste argument (`char * input`)**: Gecodeer as `*`, by offset 16
5. **Tweede argument (`NSDictionary * options`)**: Gecodeer as `@`, by offset 20
6. **Derde argument (`NSError ** error`)**: Gecodeer as `^@`, by offset 24

**Met die selektor + die kodering kan jy die metode herbou.**

### **Klasse**

Klasse in Objective-C is 'n struktuur met eienskappe, metode wysers... Dit is moontlik om die struktuur `objc_class` in die [**bron kode**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
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
Hierdie klas gebruik 'n paar bits van die isa-veld om inligting oor die klas aan te dui.

Dan het die struktuur 'n wysiger na die struktuur `class_ro_t` wat op skyf gestoor is en wat eienskappe van die klas bevat soos sy naam, basismetodes, eienskappe en instansie veranderlikes.\
Tydens uitvoering word 'n addisionele struktuur `class_rw_t` gebruik wat wysigers bevat wat verander kan word soos metodes, protokolle, eienskappe...

{{#include ../../../banners/hacktricks-training.md}}
