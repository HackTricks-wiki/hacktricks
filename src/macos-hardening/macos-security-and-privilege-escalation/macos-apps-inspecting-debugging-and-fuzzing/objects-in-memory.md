# Objects in memory

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

Les objets CF* proviennent de CoreFoundation, qui fournit plus de 50 classes d'objets comme `CFString`, `CFNumber` ou `CFAllocator`.

Toutes ces classes sont des instances de la classe `CFRuntimeClass` qui, lorsqu'elle est appelée, renvoie un index vers `__CFRuntimeClassTable`. La CFRuntimeClass est définie dans [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html) :
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

La plupart des données utilisées par le runtime Objective-C changent pendant l'exécution. Il utilise donc plusieurs sections de la famille de segments Mach-O `__DATA` en mémoire. Historiquement, celles-ci comprenaient :

- `__objc_msgrefs` (`message_ref_t`) : Références de messages
- `__objc_ivar` (`ivar`) : Variables d'instance
- `__objc_data` (`...`) : Données mutables
- `__objc_classrefs` (`Class`) : Références de classes
- `__objc_superrefs` (`Class`) : Références de classes parentes
- `__objc_protorefs` (`protocol_t *`) : Références de protocoles
- `__objc_selrefs` (`SEL`) : Références de selectors
- `__objc_const` (`...`) : Données de classes en lecture seule et autres données (espérons-le) constantes
- `__objc_imageinfo` (`version, flags`) : Utilisée lors du chargement de l'image : la version est actuellement `0` ; les flags indiquent notamment la prise en charge du GC préoptimisé
- `__objc_protolist` (`protocol_t *`) : Liste de protocoles
- `__objc_nlcatlist` (`category_t`) : Pointeur vers les Non-Lazy Categories définies dans ce binaire
- `__objc_catlist` (`category_t`) : Pointeur vers les Categories définies dans ce binaire
- `__objc_nlclslist` (`classref_t`) : Pointeur vers les classes Objective-C Non-Lazy définies dans ce binaire
- `__objc_classlist` (`classref_t`) : Pointeurs vers toutes les classes Objective-C définies dans ce binaire

Il utilise également quelques sections du segment `__TEXT` pour stocker des constantes :

- `__objc_methname` (C-String) : Noms des méthodes
- `__objc_classname` (C-String) : Noms des classes
- `__objc_methtype` (C-String) : Types des méthodes

Les versions modernes de macOS/iOS (en particulier sur Apple Silicon) placent également les métadonnées Objective-C/Swift dans :

- `__DATA_CONST` : Métadonnées Objective-C immuables pouvant être partagées en lecture seule entre les processus (par exemple, de nombreuses listes `__objc_*` s'y trouvent désormais).
- `__AUTH` / `__AUTH_CONST` : Segments contenant des pointeurs qui doivent être authentifiés lors du chargement ou de l'utilisation sur arm64e (Pointer Authentication). Vous verrez également `__auth_got` dans `__AUTH_CONST`, au lieu des seuls `__la_symbol_ptr`/`__got` hérités. Lors de l'instrumentation ou du hooking, pensez à prendre en compte à la fois les entrées `__got` et `__auth_got` dans les binaires modernes.

Pour des informations générales sur la pré-optimisation de dyld (par exemple, l'unification des selectors et le précalcul des classes/protocoles), ainsi que sur la raison pour laquelle nombre de ces sections sont « déjà corrigées » lorsqu'elles proviennent du shared cache, consultez les sources Apple `objc-opt` et les notes du dyld shared cache. Cela affecte l'endroit et la manière dont vous pouvez patcher les métadonnées au runtime.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Encodage des types

Objective-C utilise le mangling pour encoder les types des selectors et des variables, qu'il s'agisse de types simples ou complexes :

- Les types primitifs utilisent la première lettre du type : `i` pour `int`, `c` pour `char`, `l` pour `long`... et utilisent la lettre majuscule lorsqu'ils sont unsigned (`L` pour `unsigned long`).
- Les autres types de données utilisent d'autres lettres ou symboles, comme `q` pour `long long`, `b` pour les bitfields, `B` pour les booleans, `#` pour les classes, `@` pour `id`, `*` pour `char *`, `^` pour les pointeurs génériques et `?` pour les types indéfinis.
- Les arrays, structures et unions utilisent respectivement `[`, `{` et `(`.

#### Exemple de déclaration de méthode
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Le selector serait `processString:withOptions:andError:`

#### Type Encoding

- `id` est encodé comme `@`
- `char *` est encodé comme `*`

L’encodage complet du type pour la méthode est :
```less
@24@0:8@16*20^@24
```
#### Analyse détaillée

1. Type de retour (`NSString *`) : Encodé en `@` avec une longueur de 24
2. `self` (instance de l'objet) : Encodé en `@`, à l'offset 0
3. `_cmd` (selector) : Encodé en `:`, à l'offset 8
4. Premier argument (`char * input`) : Encodé en `*`, à l'offset 16
5. Deuxième argument (`NSDictionary * options`) : Encodé en `@`, à l'offset 20
6. Troisième argument (`NSError ** error`) : Encodé en `^@`, à l'offset 24

Avec le selector et l'encodage, vous pouvez reconstruire la méthode.

### Classes

Les classes en Objective-C sont des structures C avec des propriétés, des pointeurs de méthode, etc. Il est possible de trouver la structure `objc_class` dans le [**code source**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html) :
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

Ensuite, la structure contient un pointeur vers la structure `class_ro_t` stockée sur le disque, qui contient des attributs de la classe tels que son nom, ses méthodes de base, ses propriétés et ses variables d’instance. Pendant l’exécution, une structure supplémentaire `class_rw_t` est utilisée ; elle contient des pointeurs qui peuvent être modifiés, tels que les méthodes, les protocoles et les propriétés.

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## Représentations modernes des objets en mémoire (arm64e, tagged pointers, Swift)

### `isa` sans pointeur et Pointer Authentication (arm64e)

Sur Apple Silicon et avec les runtimes récents, le `isa` d’Objective-C n’est pas toujours un pointeur de classe brut. Sur arm64e, il s’agit d’une structure empaquetée qui peut également contenir un Pointer Authentication Code (PAC). Selon la plateforme, elle peut inclure des champs tels que `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc`, ainsi que le pointeur vers la classe lui-même (décalé ou signé). Cela signifie que déréférencer aveuglément les 8 premiers octets d’un objet Objective-C ne renverra pas toujours un pointeur `Class` valide.<sup>[[2]](#references)</sup>

Remarques pratiques lors du debugging sur arm64e :

- LLDB supprime généralement les bits PAC pour vous lorsqu’il affiche des objets Objective-C avec `po`, mais lorsque vous travaillez avec des pointeurs bruts, vous devrez peut-être supprimer manuellement l’authentification :

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- De nombreux pointeurs de fonctions/données dans Mach-O se trouvent dans `__AUTH`/`__AUTH_CONST` et nécessitent une authentification avant utilisation. Si vous effectuez de l’interposition ou du re-binding (par exemple, dans le style de fishhook), assurez-vous également de gérer `__auth_got` en plus de l’ancien `__got`.

Pour une analyse approfondie des garanties du langage/ABI et des intrinsèques `<ptrauth.h>` disponibles dans Clang/LLVM, consultez la référence à la fin de cette page.<sup>[[1]](#references)</sup>

### Tagged pointer objects

Certaines classes Foundation évitent l’allocation sur le heap en encodant directement la charge utile de l’objet dans la valeur du pointeur (tagged pointers). La détection diffère selon la plateforme (par exemple, le bit de poids fort sur arm64 et le bit de poids faible sur x86_64 macOS). Les tagged objects ne possèdent pas de `isa` classique stocké en mémoire ; le runtime détermine la classe à partir des bits du tag.<sup>[[2]](#references)</sup> Lors de l’inspection de valeurs `id` arbitraires :

- Utilisez les APIs du runtime au lieu d’inspecter directement le champ `isa` : `object_getClass(obj)` / `[obj class]`.
- Dans LLDB, `po (id)0xADDR` affichera correctement les instances tagged pointer, car le runtime est consulté pour déterminer la classe.

### Objets Swift du heap et métadonnées

Les classes Swift pures sont également des objets dont l’en-tête pointe vers les métadonnées Swift (et non vers un `isa` Objective-C). Pour introspecter des processus Swift en cours d’exécution sans les modifier, vous pouvez utiliser `swift-inspect` de la toolchain Swift, qui exploite la bibliothèque Remote Mirror pour lire les métadonnées du runtime :
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
C'est très utile pour cartographier les objets du tas Swift et les conformités aux protocoles lors de la rétro-ingénierie d'apps Swift/ObjC mixtes.

---

## Aide-mémoire d'inspection du runtime (LLDB / Frida)

### LLDB

- Afficher un objet ou une classe à partir d'un pointeur brut :
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- Inspecter la classe Objective-C à partir d’un pointeur vers le `self` d’une méthode d’objet lors d’un breakpoint :
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Dump les sections qui contiennent des métadonnées Objective-C (note : beaucoup se trouvent désormais dans `__DATA_CONST` / `__AUTH_CONST`) :
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- Lire la mémoire d’un objet de classe connu pour pivoter vers `class_ro_t` / `class_rw_t` lors de la rétro-ingénierie des listes de méthodes :
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective-C et Swift)

Frida fournit des bridges runtime de haut niveau très pratiques pour découvrir et instrumenter des objets en mémoire sans symboles :

- Énumérer les classes et les méthodes, résoudre les noms de classes réels au runtime et intercepter les selectors Objective-C :
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
- Swift bridge : énumérer les types Swift et interagir avec les instances Swift (nécessite une version récente de Frida ; très utile sur les cibles Apple Silicon).

---

## Références


- [1] [Clang/LLVM : authentification des pointeurs et intrinsèques de ptrauth.h (ABI arm64e)](https://clang.llvm.org/docs/PointerAuthentication.html)
- [2] [En-têtes du runtime objc d’Apple - objc-object.h (tagged pointers, non-pointer isa, etc.)](https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html)

{{#include ../../../banners/hacktricks-training.md}}
