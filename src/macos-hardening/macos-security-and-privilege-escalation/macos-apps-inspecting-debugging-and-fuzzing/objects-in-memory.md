# Objetos na memória

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

Os objetos CF\* vêm do CoreFoundation, que fornece mais de 50 classes de objetos como `CFString`, `CFNumber` ou `CFAllocator`.

Todas essas classes são instâncias da classe `CFRuntimeClass`, que quando chamada retorna um índice para a `__CFRuntimeClassTable`. A CFRuntimeClass é definida em [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
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

### Seções de memória usadas

A maior parte dos dados usados pelo tempo de execução do ObjectiveC mudará durante a execução, portanto, ele utiliza algumas seções do segmento **\_\_DATA** na memória:

- **`__objc_msgrefs`** (`message_ref_t`): Referências de mensagem
- **`__objc_ivar`** (`ivar`): Variáveis de instância
- **`__objc_data`** (`...`): Dados mutáveis
- **`__objc_classrefs`** (`Class`): Referências de classe
- **`__objc_superrefs`** (`Class`): Referências de superclasse
- **`__objc_protorefs`** (`protocol_t *`): Referências de protocolo
- **`__objc_selrefs`** (`SEL`): Referências de seletor
- **`__objc_const`** (`...`): Dados de classe `r/o` e outros dados (esperançosamente) constantes
- **`__objc_imageinfo`** (`version, flags`): Usado durante o carregamento da imagem: Versão atualmente `0`; Flags especificam suporte a GC pré-otimizado, etc.
- **`__objc_protolist`** (`protocol_t *`): Lista de protocolos
- **`__objc_nlcatlist`** (`category_t`): Ponteiro para Categorias Não-Lazy definidas neste binário
- **`__objc_catlist`** (`category_t`): Ponteiro para Categorias definidas neste binário
- **`__objc_nlclslist`** (`classref_t`): Ponteiro para classes Objective-C Não-Lazy definidas neste binário
- **`__objc_classlist`** (`classref_t`): Ponteiros para todas as classes Objective-C definidas neste binário

Ele também usa algumas seções no segmento **`__TEXT`** para armazenar valores constantes, pois não é possível escrever nesta seção:

- **`__objc_methname`** (C-String): Nomes de métodos
- **`__objc_classname`** (C-String): Nomes de classes
- **`__objc_methtype`** (C-String): Tipos de métodos

### Codificação de Tipo

Objective-C usa algumas codificações para codificar seletores e tipos de variáveis de tipos simples e complexos:

- Tipos primitivos usam a primeira letra do tipo `i` para `int`, `c` para `char`, `l` para `long`... e usam a letra maiúscula no caso de ser sem sinal (`L` para `unsigned Long`).
- Outros tipos de dados cujas letras são usadas ou são especiais, usam outras letras ou símbolos como `q` para `long long`, `b` para `bitfields`, `B` para `booleans`, `#` para `classes`, `@` para `id`, `*` para `char pointers`, `^` para `pointers` genéricos e `?` para `indefinido`.
- Arrays, estruturas e uniões usam `[`, `{` e `(`

#### Exemplo de Declaração de Método
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
O seletor seria `processString:withOptions:andError:`

#### Codificação de Tipo

- `id` é codificado como `@`
- `char *` é codificado como `*`

A codificação de tipo completa para o método é:
```less
@24@0:8@16*20^@24
```
#### Análise Detalhada

1. **Tipo de Retorno (`NSString *`)**: Codificado como `@` com comprimento 24
2. **`self` (instância do objeto)**: Codificado como `@`, no deslocamento 0
3. **`_cmd` (seletor)**: Codificado como `:`, no deslocamento 8
4. **Primeiro argumento (`char * input`)**: Codificado como `*`, no deslocamento 16
5. **Segundo argumento (`NSDictionary * options`)**: Codificado como `@`, no deslocamento 20
6. **Terceiro argumento (`NSError ** error`)**: Codificado como `^@`, no deslocamento 24

**Com o seletor + a codificação você pode reconstruir o método.**

### **Classes**

Classes em Objective-C são uma struct com propriedades, ponteiros de método... É possível encontrar a struct `objc_class` no [**código-fonte**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
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
Esta classe usa alguns bits do campo isa para indicar algumas informações sobre a classe.

Então, a struct tem um ponteiro para a struct `class_ro_t` armazenada no disco, que contém atributos da classe, como seu nome, métodos base, propriedades e variáveis de instância.\
Durante a execução, uma estrutura adicional `class_rw_t` é usada, contendo ponteiros que podem ser alterados, como métodos, protocolos, propriedades... 

{{#include ../../../banners/hacktricks-training.md}}
