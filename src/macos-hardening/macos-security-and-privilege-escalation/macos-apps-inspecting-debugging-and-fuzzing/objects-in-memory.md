# Vitu katika kumbukumbu

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF\* vitu vinatoka CoreFoundation, ambayo inatoa zaidi ya madarasa 50 ya vitu kama `CFString`, `CFNumber` au `CFAllocator`.

Madarasa haya yote ni mifano ya darasa `CFRuntimeClass`, ambalo linapoitwa linarejesha kiashiria kwa `__CFRuntimeClassTable`. CFRuntimeClass imefafanuliwa katika [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
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

### Sehemu za Kumbukumbu zinazotumika

Sehemu nyingi za data zinazotumiwa na ObjectiveC runtime zitabadilika wakati wa utekelezaji, kwa hivyo inatumia baadhi ya sehemu kutoka kwa **\_\_DATA** segment katika kumbukumbu:

- **`__objc_msgrefs`** (`message_ref_t`): Marejeleo ya ujumbe
- **`__objc_ivar`** (`ivar`): Vigezo vya mfano
- **`__objc_data`** (`...`): Data inayoweza kubadilishwa
- **`__objc_classrefs`** (`Class`): Marejeleo ya darasa
- **`__objc_superrefs`** (`Class`): Marejeleo ya darasa la juu
- **`__objc_protorefs`** (`protocol_t *`): Marejeleo ya itifaki
- **`__objc_selrefs`** (`SEL`): Marejeleo ya mteule
- **`__objc_const`** (`...`): Data ya darasa `r/o` na nyingine (kwa matumaini) data thabiti
- **`__objc_imageinfo`** (`version, flags`): Inatumika wakati wa kupakia picha: Toleo kwa sasa `0`; Bendera zinaelezea msaada wa GC uliopangwa mapema, nk.
- **`__objc_protolist`** (`protocol_t *`): Orodha ya itifaki
- **`__objc_nlcatlist`** (`category_t`): Kielelezo cha Jamii zisizo za Lazy zilizofafanuliwa katika hii binary
- **`__objc_catlist`** (`category_t`): Kielelezo cha Jamii zilizofafanuliwa katika hii binary
- **`__objc_nlclslist`** (`classref_t`): Kielelezo cha Darasa zisizo za Lazy zilizofafanuliwa katika hii binary
- **`__objc_classlist`** (`classref_t`): Viashiria vya darasa zote za Objective-C zilizofafanuliwa katika hii binary

Inatumia pia sehemu chache katika **`__TEXT`** segment kuhifadhi thamani thabiti ikiwa haiwezekani kuandika katika sehemu hii:

- **`__objc_methname`** (C-String): Majina ya mbinu
- **`__objc_classname`** (C-String): Majina ya darasa
- **`__objc_methtype`** (C-String): Aina za mbinu

### Uandishi wa Aina

Objective-c inatumia baadhi ya mabadiliko ili kuandika mteule na aina za vigezo vya aina rahisi na ngumu:

- Aina za msingi zinatumia herufi yao ya kwanza ya aina `i` kwa `int`, `c` kwa `char`, `l` kwa `long`... na inatumia herufi kubwa ikiwa ni isiyo na alama (`L` kwa `unsigned Long`).
- Aina nyingine za data ambazo herufi zao zinatumika au ni maalum, zinatumia herufi au alama nyingine kama `q` kwa `long long`, `b` kwa `bitfields`, `B` kwa `booleans`, `#` kwa `classes`, `@` kwa `id`, `*` kwa `char pointers`, `^` kwa `pointers` za jumla na `?` kwa `undefined`.
- Mifumo, muundo na muungano hutumia `[`, `{` na `(`

#### Mfano wa Matangazo ya Mbinu
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Mchaguzi ungekuwa `processString:withOptions:andError:`

#### Uandishi wa Aina

- `id` imeandikwa kama `@`
- `char *` imeandikwa kama `*`

Uandishi kamili wa aina kwa njia ni:
```less
@24@0:8@16*20^@24
```
#### Maelezo ya Kina

1. **Aina ya Kurudi (`NSString *`)**: Imeandikwa kama `@` yenye urefu wa 24
2. **`self` (kigezo cha kitu)**: Imeandikwa kama `@`, kwenye ofset 0
3. **`_cmd` (mchaguzi)**: Imeandikwa kama `:`, kwenye ofset 8
4. **Kigezo cha kwanza (`char * input`)**: Imeandikwa kama `*`, kwenye ofset 16
5. **Kigezo cha pili (`NSDictionary * options`)**: Imeandikwa kama `@`, kwenye ofset 20
6. **Kigezo cha tatu (`NSError ** error`)**: Imeandikwa kama `^@`, kwenye ofset 24

**Kwa mchaguzi + uandishi unaweza kujenga upya njia.**

### **Darasa**

Darasa katika Objective-C ni muundo wenye mali, viashiria vya njia... Inawezekana kupata muundo `objc_class` katika [**kanuni ya chanzo**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
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
Darasa hili linatumia baadhi ya bits za uwanja wa isa kuonyesha taarifa fulani kuhusu darasa hilo.

Kisha, struct ina kiashiria kwa struct `class_ro_t` kilichohifadhiwa kwenye diski ambacho kina sifa za darasa kama jina lake, mbinu za msingi, mali na mabadiliko ya mfano.\
Wakati wa wakati wa kukimbia, muundo wa ziada `class_rw_t` unatumika ukiwa na viashiria ambavyo vinaweza kubadilishwa kama mbinu, itifaki, mali... 

{{#include ../../../banners/hacktricks-training.md}}
