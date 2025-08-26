# Objets en mémoire

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

Les objets CF* proviennent de CoreFoundation, qui fournit plus de 50 classes d'objets telles que `CFString`, `CFNumber` ou `CFAllocator`.

Toutes ces classes sont des instances de la classe `CFRuntimeClass`, qui, lorsqu'elle est appelée, renvoie un indice vers `__CFRuntimeClassTable`. Le CFRuntimeClass est défini dans [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
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

### Sections mémoire utilisées

La plupart des données utilisées par l'Objective‑C runtime changent pendant l'exécution ; il utilise donc un certain nombre de sections du Mach‑O de la famille de segments `__DATA` en mémoire. Historiquement, celles‑ci incluaient :

- `__objc_msgrefs` (`message_ref_t`): Références de messages
- `__objc_ivar` (`ivar`): Variables d'instance
- `__objc_data` (`...`): Données modifiables
- `__objc_classrefs` (`Class`): Références de classe
- `__objc_superrefs` (`Class`): Références de superclasse
- `__objc_protorefs` (`protocol_t *`): Références de protocole
- `__objc_selrefs` (`SEL`): Références de sélecteur
- `__objc_const` (`...`): Données de classe en lecture seule et autres données (espérées) constantes
- `__objc_imageinfo` (`version, flags`): Utilisé lors du chargement de l'image : Version actuellement `0` ; les flags spécifient le support GC préoptimisé, etc.
- `__objc_protolist` (`protocol_t *`): Liste de protocoles
- `__objc_nlcatlist` (`category_t`): Pointeur vers les Non‑Lazy Categories définies dans ce binaire
- `__objc_catlist` (`category_t`): Pointeur vers les Categories définies dans ce binaire
- `__objc_nlclslist` (`classref_t`): Pointeur vers les classes Objective‑C Non‑Lazy définies dans ce binaire
- `__objc_classlist` (`classref_t`): Pointeurs vers toutes les classes Objective‑C définies dans ce binaire

Il utilise aussi quelques sections dans le segment `__TEXT` pour stocker des constantes :

- `__objc_methname` (C‑String): Noms de méthodes
- `__objc_classname` (C‑String): Noms de classes
- `__objc_methtype` (C‑String): Types de méthodes

Les macOS/iOS modernes (surtout sur Apple Silicon) placent aussi des métadonnées Objective‑C/Swift dans :

- `__DATA_CONST`: métadonnées Objective‑C immutables pouvant être partagées en lecture seule entre processus (par exemple, beaucoup de listes `__objc_*` résident maintenant ici).
- `__AUTH` / `__AUTH_CONST`: segments contenant des pointeurs qui doivent être authentifiés au chargement ou à l'utilisation sur arm64e (Pointer Authentication). Vous verrez aussi `__auth_got` dans `__AUTH_CONST` au lieu des hérités `__la_symbol_ptr`/`__got` seulement. Lors de l'instrumentation ou du hooking, pensez à prendre en compte à la fois les entrées `__got` et `__auth_got` dans les binaires modernes.

Pour le contexte sur la pré‑optimisation de dyld (par ex. selector uniquing et pré‑calcul des classes/protocols) et pourquoi beaucoup de ces sections sont « déjà fixées » lorsqu'elles proviennent du shared cache, consultez les sources Apple `objc-opt` et les notes sur dyld shared cache. Cela influence où et comment vous pouvez patcher les métadonnées à l'exécution.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Encodage de type

Objective‑C utilise le mangling pour encoder les types des sélecteurs et des variables, simples et complexes :

- Les types primitifs utilisent la première lettre du type : `i` pour `int`, `c` pour `char`, `l` pour `long`... et la lettre majuscule en cas de non signé (`L` pour `unsigned long`).
- D'autres types utilisent d'autres lettres ou symboles comme `q` pour `long long`, `b` pour les bitfields, `B` pour les booléens, `#` pour les classes, `@` pour `id`, `*` pour `char *`, `^` pour pointeurs génériques et `?` pour indéfini.
- Les tableaux, structures et unions utilisent respectivement `[`, `{` et `(`.

#### Exemple de déclaration de méthode
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Le sélecteur serait `processString:withOptions:andError:`

#### Encodage de type

- `id` est encodé comme `@`
- `char *` est encodé comme `*`

L'encodage de type complet pour la méthode est :
```less
@24@0:8@16*20^@24
```
#### Analyse détaillée

1. Type de retour (`NSString *`): Encodé comme `@` avec une longueur de 24
2. `self` (instance d'objet): Encodé comme `@`, à l'offset 0
3. `_cmd` (sélecteur): Encodé comme `:`, à l'offset 8
4. Premier argument (`char * input`): Encodé comme `*`, à l'offset 16
5. Deuxième argument (`NSDictionary * options`): Encodé comme `@`, à l'offset 20
6. Troisième argument (`NSError ** error`): Encodé comme `^@`, à l'offset 24

Avec le sélecteur + l'encodage, vous pouvez reconstruire la méthode.

### Classes

Les classes en Objective‑C sont des structures C contenant des propriétés, des pointeurs de méthode, etc. Il est possible de trouver la struct `objc_class` dans le [**source code**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
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
Cette classe utilise certains bits du champ `isa` pour indiquer des informations sur la classe.

Ensuite, la struct a un pointeur vers la struct `class_ro_t` stockée sur disque qui contient des attributs de la classe comme son nom, les méthodes de base, les propriétés et les variables d'instance. À l'exécution, une structure additionnelle `class_rw_t` est utilisée et contient des pointeurs modifiables tels que les méthodes, les protocols et les propriétés.

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## Représentations modernes d'objets en mémoire (arm64e, tagged pointers, Swift)

### Non‑pointer `isa` and Pointer Authentication (arm64e)

Sur Apple Silicon et dans les runtimes récents le `isa` Objective‑C n'est pas toujours un simple pointeur de classe. Sur arm64e il s'agit d'une structure empaquetée qui peut aussi porter un Pointer Authentication Code (PAC). Selon la plateforme elle peut inclure des champs comme `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc`, et le pointeur de classe lui‑même (décalé ou signé). Cela signifie que déréférencer aveuglément les 8 premiers octets d'un objet Objective‑C ne donnera pas toujours un pointeur `Class` valide.

Notes pratiques lors du débogage sur arm64e :

- LLDB supprimera généralement les bits PAC pour vous lorsque vous affichez des objets Objective‑C avec `po`, mais quand vous travaillez avec des pointeurs bruts vous devrez peut‑être enlever l'authentification manuellement :

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- De nombreux pointeurs de fonction/données dans Mach‑O résident dans `__AUTH`/`__AUTH_CONST` et requièrent une authentification avant utilisation. Si vous interposez ou ré‑assignez (par ex., style fishhook), assurez‑vous de gérer également `__auth_got` en plus de l'ancien `__got`.

Pour un approfondissement sur les garanties langage/ABI et les intrinsics `<ptrauth.h>` disponibles via Clang/LLVM, voir la référence à la fin de cette page.

### Objets à pointeurs étiquetés

Certaines classes Foundation évitent l'allocation sur le tas en encodant la charge utile de l'objet directement dans la valeur du pointeur (tagged pointers). La détection diffère selon la plateforme (par ex., le bit de poids fort sur arm64, le bit de poids faible sur x86_64 macOS). Les objets taggés n'ont pas de `isa` classique stocké en mémoire ; le runtime résout la classe à partir des bits de tag. Lors de l'inspection de valeurs `id` arbitraires :

- Utilisez les API du runtime au lieu de tripoter le champ `isa` : `object_getClass(obj)` / `[obj class]`.
- Dans LLDB, simplement `po (id)0xADDR` affichera correctement les instances tagged pointer car le runtime est consulté pour résoudre la classe.

### Objets Swift sur le heap et métadonnées

Les classes Swift pures sont aussi des objets avec un en‑tête pointant vers les métadonnées Swift (et non le `isa` Objective‑C). Pour introspecter des processus Swift en direct sans les modifier vous pouvez utiliser `swift-inspect` de la toolchain Swift, qui s'appuie sur la bibliothèque Remote Mirror pour lire les métadonnées du runtime :
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Ceci est très utile pour cartographier les objets du tas Swift et les conformances de protocoles lors de la rétro-ingénierie d'apps Swift/ObjC mixtes.

---

## Aide-mémoire d'inspection du runtime (LLDB / Frida)

### LLDB

- Afficher un objet ou une classe depuis un pointeur brut :
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- Inspecter la classe Objective‑C à partir d'un pointeur vers le `self` d'une méthode d'objet dans un point d'arrêt :
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Dump des sections qui portent des métadonnées Objective‑C (note : beaucoup sont maintenant dans `__DATA_CONST` / `__AUTH_CONST`) :
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- Lire la mémoire d'un objet de classe connu pour basculer vers `class_ro_t` / `class_rw_t` lors de l'analyse des listes de méthodes :
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective‑C and Swift)

Frida fournit des passerelles d'exécution de haut niveau, très pratiques pour découvrir et instrumenter des objets en mémoire sans symboles :

- Énumérer les classes et méthodes, résoudre les noms de classes réels à l'exécution, et intercepter les sélecteurs Objective‑C :
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
- Swift bridge : énumérer les types Swift et interagir avec les instances Swift (requiert une version récente de Frida ; très utile sur des cibles Apple Silicon).

---

## Références

- Clang/LLVM : Authentification des pointeurs et les intrinsèques `<ptrauth.h>` (arm64e ABI). https://clang.llvm.org/docs/PointerAuthentication.html
- En-têtes du runtime objc d'Apple (pointeurs taggés, `isa` non‑pointeur, etc.), p.ex. `objc-object.h`. https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html

{{#include ../../../banners/hacktricks-training.md}}
