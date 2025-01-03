# Objets en mémoire

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

Les objets CF\* proviennent de CoreFoundation, qui fournit plus de 50 classes d'objets comme `CFString`, `CFNumber` ou `CFAllocator`.

Toutes ces classes sont des instances de la classe `CFRuntimeClass`, qui lorsqu'elle est appelée, renvoie un index à la `__CFRuntimeClassTable`. La CFRuntimeClass est définie dans [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
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

### Sections de mémoire utilisées

La plupart des données utilisées par le runtime ObjectiveC changeront pendant l'exécution, c'est pourquoi il utilise certaines sections du segment **\_\_DATA** en mémoire :

- **`__objc_msgrefs`** (`message_ref_t`): Références de message
- **`__objc_ivar`** (`ivar`): Variables d'instance
- **`__objc_data`** (`...`): Données mutables
- **`__objc_classrefs`** (`Class`): Références de classe
- **`__objc_superrefs`** (`Class`): Références de superclasse
- **`__objc_protorefs`** (`protocol_t *`): Références de protocole
- **`__objc_selrefs`** (`SEL`): Références de sélecteur
- **`__objc_const`** (`...`): Données `r/o` de classe et autres données (espérons-le) constantes
- **`__objc_imageinfo`** (`version, flags`): Utilisé lors du chargement de l'image : Version actuellement `0`; Les drapeaux spécifient le support GC préoptimisé, etc.
- **`__objc_protolist`** (`protocol_t *`): Liste de protocoles
- **`__objc_nlcatlist`** (`category_t`): Pointeur vers des catégories non paresseuses définies dans ce binaire
- **`__objc_catlist`** (`category_t`): Pointeur vers des catégories définies dans ce binaire
- **`__objc_nlclslist`** (`classref_t`): Pointeur vers des classes Objective-C non paresseuses définies dans ce binaire
- **`__objc_classlist`** (`classref_t`): Pointeurs vers toutes les classes Objective-C définies dans ce binaire

Il utilise également quelques sections dans le segment **`__TEXT`** pour stocker des valeurs constantes s'il n'est pas possible d'écrire dans cette section :

- **`__objc_methname`** (C-String): Noms de méthode
- **`__objc_classname`** (C-String): Noms de classe
- **`__objc_methtype`** (C-String): Types de méthode

### Encodage des types

Objective-C utilise un certain mangle pour encoder les sélecteurs et les types de variables de types simples et complexes :

- Les types primitifs utilisent leur première lettre du type `i` pour `int`, `c` pour `char`, `l` pour `long`... et utilisent la lettre majuscule dans le cas où c'est non signé (`L` pour `unsigned Long`).
- D'autres types de données dont les lettres sont utilisées ou sont spéciales, utilisent d'autres lettres ou symboles comme `q` pour `long long`, `b` pour `bitfields`, `B` pour `booleans`, `#` pour `classes`, `@` pour `id`, `*` pour `char pointers`, `^` pour `pointers` génériques et `?` pour `undefined`.
- Les tableaux, structures et unions utilisent `[`, `{` et `(`

#### Exemple de déclaration de méthode
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
Le sélecteur serait `processString:withOptions:andError:`

#### Encodage de Type

- `id` est encodé comme `@`
- `char *` est encodé comme `*`

L'encodage de type complet pour la méthode est :
```less
@24@0:8@16*20^@24
```
#### Détail

1. **Type de retour (`NSString *`)** : Encodé comme `@` avec une longueur de 24
2. **`self` (instance d'objet)** : Encodé comme `@`, à l'offset 0
3. **`_cmd` (sélecteur)** : Encodé comme `:`, à l'offset 8
4. **Premier argument (`char * input`)** : Encodé comme `*`, à l'offset 16
5. **Deuxième argument (`NSDictionary * options`)** : Encodé comme `@`, à l'offset 20
6. **Troisième argument (`NSError ** error`)** : Encodé comme `^@`, à l'offset 24

**Avec le sélecteur + l'encodage, vous pouvez reconstruire la méthode.**

### **Classes**

Les classes en Objective-C sont une structure avec des propriétés, des pointeurs de méthode... Il est possible de trouver la structure `objc_class` dans le [**code source**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html) :
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
Cette classe utilise certains bits du champ isa pour indiquer des informations sur la classe.

Ensuite, la structure a un pointeur vers la structure `class_ro_t` stockée sur le disque qui contient des attributs de la classe comme son nom, ses méthodes de base, ses propriétés et ses variables d'instance.\
Pendant l'exécution, une structure supplémentaire `class_rw_t` est utilisée, contenant des pointeurs qui peuvent être modifiés tels que des méthodes, des protocoles, des propriétés... 

{{#include ../../../banners/hacktricks-training.md}}
