# मेमोरी में ऑब्जेक्ट्स

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

CF* objects CoreFoundation से आते हैं, जो `CFString`, `CFNumber` या `CFAllocator` जैसे 50 से अधिक क्लास ऑब्जेक्ट्स प्रदान करता है।

ये सभी क्लासें `CFRuntimeClass` क्लास के instances हैं, जो कॉल किए जाने पर `__CFRuntimeClassTable` का एक index लौटाता है। CFRuntimeClass [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html) में परिभाषित है:
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

### उपयोग किए जाने वाले मेमोरी सेक्शन

Objective‑C runtime द्वारा उपयोग किया जाने वाला अधिकांश डेटा निष्पादन के दौरान बदलता रहता है, इसलिए यह मेमोरी में Mach‑O `__DATA` परिवार के कई सेक्शनों का उपयोग करता है। ऐतिहासिक रूप से इनमें शामिल थे:

- `__objc_msgrefs` (`message_ref_t`): संदेश संदर्भ
- `__objc_ivar` (`ivar`): इंस्टेंस वेरिएबल्स
- `__objc_data` (`...`): परिवर्तनीय डेटा
- `__objc_classrefs` (`Class`): क्लास संदर्भ
- `__objc_superrefs` (`Class`): सुपरक्लास संदर्भ
- `__objc_protorefs` (`protocol_t *`): प्रोटोकॉल संदर्भ
- `__objc_selrefs` (`SEL`): सेलेक्टर संदर्भ
- `__objc_const` (`...`): क्लास रीड‑ओनली डेटा और अन्य (आशा है कि) स्थिर डेटा
- `__objc_imageinfo` (`version, flags`): इमेज लोड के दौरान उपयोग होता है: Version वर्तमान में `0`; Flags प्रीऑप्टिमाइज़्ड GC सपोर्ट आदि को निर्दिष्ट करते हैं।
- `__objc_protolist` (`protocol_t *`): प्रोटोकॉल सूची
- `__objc_nlcatlist` (`category_t`): इस बाइनरी में परिभाषित Non-Lazy Categories का पॉइंटर
- `__objc_catlist` (`category_t`): इस बाइनरी में परिभाषित Categories का पॉइंटर
- `__objc_nlclslist` (`classref_t`): इस बाइनरी में परिभाषित Non-Lazy Objective‑C classes का पॉइंटर
- `__objc_classlist` (`classref_t`): इस बाइनरी में परिभाषित सभी Objective‑C classes के पॉइंटर

यह constants संग्रहीत करने के लिए `__TEXT` सेगमेंट के कुछ सेक्शनों का भी उपयोग करता है:

- `__objc_methname` (C‑String): मेथड नाम
- `__objc_classname` (C‑String): क्लास नाम
- `__objc_methtype` (C‑String): मेथड प्रकार

आधुनिक macOS/iOS (विशेषकर Apple Silicon पर) Objective‑C/Swift मेटाडेटा को निम्न में भी रखता है:

- `__DATA_CONST`: immutable Objective‑C metadata जो processes के बीच read‑only रूप में साझा किया जा सकता है (उदाहरण के लिए कई `__objc_*` सूचियाँ अब यहाँ रहती हैं).
- `__AUTH` / `__AUTH_CONST`: ऐसे सेगमेंट जिनमें पॉइंटर्स होते हैं जिन्हें arm64e पर लोड या उपयोग के समय authenticated होना चाहिए (Pointer Authentication). आप `__AUTH_CONST` में पारंपरिक `__la_symbol_ptr`/`__got` की जगह `__auth_got` भी देखेंगे. When instrumenting or hooking, modern बाइनरीज़ में दोनों `__got` और `__auth_got` एंट्रीज़ को ध्यान में रखें.

For background on dyld pre‑optimization (e.g., selector uniquing and class/protocol precomputation) and why many of these sections are "already fixed up" when coming from the shared cache, check the Apple `objc-opt` sources and dyld shared cache notes. यह प्रभावित करता है कि आप runtime में मेटाडेटा को कहाँ और कैसे patch कर सकते हैं.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### टाइप एन्कोडिंग

Objective‑C सरल और जटिल प्रकारों के selector और variable प्रकारों को encode करने के लिए mangling का उपयोग करता है:

- Primitive types उनके प्रकार के पहले अक्षर का उपयोग करते हैं — `i` for `int`, `c` for `char`, `l` for `long`... और unsigned होने पर capital letter का उपयोग होता है (`L` for `unsigned long`).
- अन्य डेटा प्रकार अन्य अक्षरों या प्रतीकों का उपयोग करते हैं जैसे `q` for `long long`, `b` for bitfields, `B` for booleans, `#` for classes, `@` for `id`, `*` for `char *`, `^` for generic pointers और `?` for undefined.
- Arrays, structures and unions क्रमशः `[`, `{` और `(` का उपयोग करते हैं।

#### उदाहरण मेथड घोषणा
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
सेलेक्टर होगा `processString:withOptions:andError:`

#### टाइप एन्कोडिंग

- `id` को `@` के रूप में एन्कोड किया जाता है
- `char *` को `*` के रूप में एन्कोड किया जाता है

मेथड के लिए पूर्ण टाइप एन्कोडिंग:
```less
@24@0:8@16*20^@24
```
#### विस्तृत विवरण

1. रिटर्न प्रकार (`NSString *`): एन्कोडेड के रूप में `@` लंबाई 24 के साथ  
2. `self` (ऑब्जेक्ट उदाहरण): एन्कोडेड के रूप में `@`, ऑफ़सेट 0 पर  
3. `_cmd` (सेलेक्टर): एन्कोडेड के रूप में `:`, ऑफ़सेट 8 पर  
4. पहला आर्ग्युमेंट (`char * input`): एन्कोडेड के रूप में `*`, ऑफ़सेट 16 पर  
5. दूसरा आर्ग्युमेंट (`NSDictionary * options`): एन्कोडेड के रूप में `@`, ऑफ़सेट 20 पर  
6. तीसरा आर्ग्युमेंट (`NSError ** error`): एन्कोडेड के रूप में `^@`, ऑफ़सेट 24 पर

selector + एन्कोडिंग के साथ आप मेथड को पुनर्निर्मित कर सकते हैं।

### क्लासेस

Objective‑C में क्लासेस C structs होते हैं जिनमें properties, method pointers, आदि होते हैं। यह struct `objc_class` [**source code**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html) में पाया जा सकता है:
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
यह क्लास `isa` फील्ड के कुछ बिट्स का उपयोग क्लास के बारे में जानकारी संकेत करने के लिए करती है।

फिर, struct में डिस्क पर स्टोर किए गए struct `class_ro_t` का एक पॉइंटर होता है जिसमें क्लास के नाम, बेस मेथड्स, प्रॉपर्टीज और इंस्टेंस वेरिएबल्स जैसे एट्रिब्यूट्स होते हैं। रनटाइम के दौरान एक अतिरिक्त संरचना `class_rw_t` उपयोग में ली जाती है जिसमें ऐसे पॉइंटर्स होते हैं जिन्हें बदला जा सकता है जैसे methods, protocols, properties।

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## मेमोरी में आधुनिक ऑब्जेक्ट प्रतिनिधित्व (arm64e, tagged pointers, Swift)

### Non‑pointer `isa` और Pointer Authentication (arm64e)

Apple Silicon और हाल के runtimes पर Objective‑C `isa` हमेशा कच्चा क्लास पॉइंटर नहीं होता। arm64e पर यह एक packed संरचना है जो Pointer Authentication Code (PAC) भी रख सकती है। प्लेटफॉर्म के अनुसार इसमें `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc` जैसे फील्ड और क्लास पॉइंटर स्वयं (shifted या signed) शामिल हो सकते हैं। इसका मतलब है कि किसी Objective‑C ऑब्जेक्ट के पहले 8 बाइट्स को अंधाधुंध dereference करने पर हमेशा वैध `Class` पॉइंटर प्राप्त नहीं होगा।

arm64e पर debugging के दौरान व्यावहारिक नोट्स:

- LLDB आमतौर पर `po` के साथ Objective‑C ऑब्जेक्ट्स प्रिंट करते समय आपके लिए PAC बिट्स हटा देता है, लेकिन raw pointers के साथ काम करते समय आपको मैन्युअली authentication हटानी पड़ सकती है:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Mach‑O में कई function/data pointers `__AUTH`/`__AUTH_CONST` में रहेंगे और उपयोग से पहले authentication की आवश्यकता होगी। यदि आप interposing या re‑binding कर रहे हैं (उदा., fishhook‑style), तो legacy `__got` के अलावा `__auth_got` को भी हैंडल करना सुनिश्चित करें।

भाषा/ABI गारंटियों और Clang/LLVM से उपलब्ध `<ptrauth.h>` intrinsics में गहरा उतरने के लिए, पृष्ठ के अंत में दिए गए संदर्भ को देखें।

### Tagged pointer objects

कुछ Foundation क्लासेस heap allocation से बचने के लिए ऑब्जेक्ट का payload सीधे pointer value में encode कर देती हैं (tagged pointers)। detection प्लेटफॉर्म के अनुसार अलग होती है (उदा., arm64 पर most‑significant bit, x86_64 macOS पर least‑significant)। Tagged objects के पास मेमोरी में नियमित `isa` स्टोर नहीं होता; runtime टैग बिट्स से क्लास को resolve करता है। arbitrary `id` मानों का निरीक्षण करते समय:

- `isa` फील्ड को छेड़ने के बजाय runtime APIs का उपयोग करें: `object_getClass(obj)` / `[obj class]`.
- LLDB में, सिर्फ `po (id)0xADDR` tagged pointer instances को ठीक से प्रिंट करेगा क्योंकि क्लास resolve करने के लिए runtime से परामर्श किया जाता है।

### Swift heap objects and metadata

Pure Swift classes भी ऐसे ऑब्जेक्ट्स हैं जिनके हेडर में Swift metadata की ओर पॉइंटर होता है (Objective‑C `isa` नहीं)। बिना उन्हें मॉडिफाई किए लाइव Swift processes का introspect करने के लिए आप Swift toolchain का `swift-inspect` उपयोग कर सकते हैं, जो runtime metadata पढ़ने के लिए Remote Mirror library का लाभ उठाता है:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
यह mixed Swift/ObjC apps को reversing करते समय Swift हीप ऑब्जेक्ट्स और प्रोटोकॉल अनुरूपताओं को मैप करने के लिए बहुत उपयोगी है।

---

## रनटाइम निरीक्षण चीटशीट (LLDB / Frida)

### LLDB

- Raw pointer से object या class प्रिंट करें:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- breakpoint में object method के `self` pointer से Objective‑C class को जांचें:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- उन सेक्शनों को डंप करें जो Objective‑C मेटाडेटा रखते हैं (नोट: कई अब `__DATA_CONST` / `__AUTH_CONST` में हैं):
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- एक ज्ञात class object की memory पढ़ें ताकि method lists को reversing करते समय `class_ro_t` / `class_rw_t` पर pivot कर सकें:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective‑C and Swift)

Frida उच्च‑स्तरीय runtime bridges प्रदान करता है जो बिना symbols के लाइव ऑब्जेक्ट्स को खोजने और instrument करने के लिए बहुत उपयोगी हैं:

- क्लास और मेथड्स को सूचीबद्ध करना, रनटाइम पर वास्तविक क्लास नामों का पता लगाना, और Objective‑C selectors को इंटरसेप्ट करना:
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
- Swift bridge: Swift प्रकारों की सूची बनाएं और Swift instances के साथ इंटरैक्ट करें (हाल के Frida की आवश्यकता; Apple Silicon लक्षित सिस्टम पर बहुत उपयोगी)।

---

## संदर्भ

- Clang/LLVM: Pointer Authentication and the `<ptrauth.h>` intrinsics (arm64e ABI). https://clang.llvm.org/docs/PointerAuthentication.html
- Apple objc runtime headers (tagged pointers, non‑pointer `isa`, etc.) e.g., `objc-object.h`. https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html

{{#include ../../../banners/hacktricks-training.md}}
