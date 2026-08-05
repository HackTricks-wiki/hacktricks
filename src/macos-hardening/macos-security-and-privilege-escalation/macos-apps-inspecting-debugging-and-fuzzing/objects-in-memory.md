# Objetos na memória

{{#include ../../../banners/hacktricks-training.md}}

## CFRuntimeClass

Os objetos `CF*` vêm do CoreFoundation, que fornece mais de 50 classes de objetos, como `CFString`, `CFNumber` ou `CFAllocator`.

Todas essas classes são instâncias da classe `CFRuntimeClass`, que, quando chamada, retorna um índice para a `__CFRuntimeClassTable`. A CFRuntimeClass é definida em [**CFRuntime.h**](https://opensource.apple.com/source/CF/CF-1153.18/CFRuntime.h.auto.html):
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

A maioria dos dados usados pelo runtime do Objective-C será alterada durante a execução; portanto, ele usa várias seções da família de segmentos Mach-O `__DATA` na memória. Historicamente, elas incluíam:

- `__objc_msgrefs` (`message_ref_t`): Referências de mensagens
- `__objc_ivar` (`ivar`): Variáveis de instância
- `__objc_data` (`...`): Dados mutáveis
- `__objc_classrefs` (`Class`): Referências de classes
- `__objc_superrefs` (`Class`): Referências de superclasses
- `__objc_protorefs` (`protocol_t *`): Referências de protocolos
- `__objc_selrefs` (`SEL`): Referências de seletores
- `__objc_const` (`...`): Dados somente leitura de classes e outros dados (esperadamente) constantes
- `__objc_imageinfo` (`version, flags`): Usada durante o carregamento da imagem: a versão é atualmente `0`; os flags especificam suporte a GC pré-otimizado etc.
- `__objc_protolist` (`protocol_t *`): Lista de protocolos
- `__objc_nlcatlist` (`category_t`): Ponteiro para Categories Non-Lazy definidas neste binário
- `__objc_catlist` (`category_t`): Ponteiro para Categories definidas neste binário
- `__objc_nlclslist` (`classref_t`): Ponteiro para classes Objective-C Non-Lazy definidas neste binário
- `__objc_classlist` (`classref_t`): Ponteiros para todas as classes Objective-C definidas neste binário

Ele também usa algumas seções no segmento `__TEXT` para armazenar constantes:

- `__objc_methname` (C-String): Nomes de métodos
- `__objc_classname` (C-String): Nomes de classes
- `__objc_methtype` (C-String): Tipos de métodos

As versões modernas do macOS/iOS (especialmente no Apple Silicon) também armazenam metadados de Objective-C/Swift em:

- `__DATA_CONST`: metadados imutáveis do Objective-C que podem ser compartilhados como somente leitura entre processos (por exemplo, muitas listas `__objc_*` agora ficam aqui).
- `__AUTH` / `__AUTH_CONST`: segmentos que contêm ponteiros que precisam ser autenticados no carregamento ou no momento do uso em arm64e (Pointer Authentication). Você também verá `__auth_got` em `__AUTH_CONST`, em vez de apenas o `__la_symbol_ptr`/`__got` legado. Ao instrumentar ou fazer hooking, lembre-se de considerar tanto as entradas `__got` quanto as `__auth_got` nos binários modernos.

Para obter informações básicas sobre a pré-otimização do dyld (por exemplo, a unificação de seletores e o pré-cálculo de classes/protocolos) e entender por que muitas dessas seções já estão "corrigidas" quando vêm do shared cache, consulte os fontes do Apple `objc-opt` e as notas do dyld shared cache. Isso afeta onde e como você pode aplicar patches aos metadados em runtime.

{{#ref}}
../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md
{{#endref}}

### Codificação de tipos

O Objective-C usa mangling para codificar tipos de seletores e variáveis de tipos simples e complexos:

- Os tipos primitivos usam a primeira letra do tipo: `i` para `int`, `c` para `char`, `l` para `long`... e usam a letra maiúscula quando são unsigned (`L` para `unsigned long`).
- Outros tipos de dados usam outras letras ou símbolos, como `q` para `long long`, `b` para bitfields, `B` para booleanos, `#` para classes, `@` para `id`, `*` para `char *`, `^` para ponteiros genéricos e `?` para indefinido.
- Arrays, structures e unions usam `[` , `{` e `(`, respectivamente.

#### Exemplo de declaração de método
```objectivec
- (NSString *)processString:(id)input withOptions:(char *)options andError:(id)error;
```
O selector seria `processString:withOptions:andError:`

#### Codificação de tipos

- `id` é codificado como `@`
- `char *` é codificado como `*`

A codificação completa de tipos do método é:
```less
@24@0:8@16*20^@24
```
#### Detalhamento

1. Tipo de retorno (`NSString *`): Codificado como `@` com comprimento 24
2. `self` (instância do objeto): Codificado como `@`, no deslocamento 0
3. `_cmd` (selector): Codificado como `:`, no deslocamento 8
4. Primeiro argumento (`char * input`): Codificado como `*`, no deslocamento 16
5. Segundo argumento (`NSDictionary * options`): Codificado como `@`, no deslocamento 20
6. Terceiro argumento (`NSError ** error`): Codificado como `^@`, no deslocamento 24

Com o selector e o encoding, é possível reconstruir o método.

### Classes

Classes em Objective-C são structs C com propriedades, ponteiros para métodos etc. É possível encontrar a struct `objc_class` no [**código-fonte**](https://opensource.apple.com/source/objc4/objc4-756.2/runtime/objc-runtime-new.h.auto.html):
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
Esta classe usa alguns bits do campo `isa` para indicar informações sobre a classe.

Em seguida, a struct contém um ponteiro para a struct `class_ro_t`, armazenada no disco, que contém atributos da classe, como seu nome, métodos base, propriedades e variáveis de instância. Durante o runtime, uma estrutura adicional, `class_rw_t`, é usada, contendo ponteiros que podem ser alterados, como métodos, protocolos e propriedades.

{{#ref}}
../macos-basic-objective-c.md
{{#endref}}

---

## Representações modernas de objetos na memória (arm64e, tagged pointers, Swift)

### `isa` sem ponteiro e Pointer Authentication (arm64e)

Nos Apple Silicon e em runtimes recentes, o `isa` de Objective-C nem sempre é um ponteiro bruto para uma classe. No arm64e, ele é uma estrutura compactada que também pode conter um Pointer Authentication Code (PAC). Dependendo da plataforma, ele pode incluir campos como `nonpointer`, `has_assoc`, `weakly_referenced`, `extra_rc` e o próprio ponteiro da classe (deslocado ou assinado). Isso significa que desreferenciar cegamente os primeiros 8 bytes de um objeto Objective-C nem sempre produzirá um ponteiro `Class` válido.<sup>[[2]](#references)</sup>

Notas práticas ao fazer debugging no arm64e:

- O LLDB normalmente remove os bits PAC para você ao imprimir objetos Objective-C com `po`, mas, ao trabalhar com ponteiros brutos, talvez seja necessário remover manualmente a autenticação:

```lldb
(lldb) expr -l objc++ -- #include <ptrauth.h>
(lldb) expr -l objc++ -- void *raw = ptrauth_strip((void*)0x000000016f123abc, ptrauth_key_asda);
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)raw)
```

- Muitos ponteiros de funções/dados em Mach-O estarão em `__AUTH`/`__AUTH_CONST` e exigirão autenticação antes do uso. Se você estiver fazendo interposição ou re-binding (por exemplo, no estilo fishhook), certifique-se também de lidar com `__auth_got`, além do `__got` legado.

Para uma análise aprofundada das garantias de linguagem/ABI e dos intrinsics de `<ptrauth.h>` disponíveis no Clang/LLVM, consulte a referência no final desta página.<sup>[[1]](#references)</sup>

### Tagged pointer objects

Algumas classes do Foundation evitam a alocação no heap codificando o payload do objeto diretamente no valor do ponteiro (tagged pointers). A detecção varia conforme a plataforma (por exemplo, o bit mais significativo no arm64 e o menos significativo no x86_64 macOS). Tagged objects não possuem um `isa` regular armazenado na memória; o runtime resolve a classe a partir dos bits da tag.<sup>[[2]](#references)</sup> Ao inspecionar valores `id` arbitrários:

- Use APIs do runtime em vez de acessar diretamente o campo `isa`: `object_getClass(obj)` / `[obj class]`.
- No LLDB, basta usar `po (id)0xADDR` para imprimir corretamente instâncias de tagged pointers, pois o runtime é consultado para resolver a classe.

### Swift heap objects e metadata

Classes puramente Swift também são objetos, com um header que aponta para metadata do Swift (e não para um `isa` de Objective-C). Para fazer introspection de processos Swift ativos sem modificá-los, você pode usar o `swift-inspect` do Swift toolchain, que utiliza a biblioteca Remote Mirror para ler metadata do runtime:
```bash
# Xcode toolchain (or Swift.org toolchain) provides swift-inspect
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
# On Darwin additionally:
swift-inspect dump-concurrency <pid-or-name>
```
Isso é muito útil para mapear objetos de heap do Swift e conformidades de protocolos ao fazer reverse engineering de apps mistos Swift/ObjC.

---

## Cheatsheet de inspeção do runtime (LLDB / Frida)

### LLDB

- Imprimir o objeto ou a classe a partir de um ponteiro bruto:
```lldb
(lldb) expr -l objc++ -O -- (id)0x0000000101234560
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)0x0000000101234560)
```
- Inspecionar a classe Objective-C a partir de um ponteiro para o `self` de um método de objeto em um breakpoint:
```lldb
(lldb) br se -n '-[NSFileManager fileExistsAtPath:]'
(lldb) r
... breakpoint hit ...
(lldb) po (id)$x0                 # self
(lldb) expr -l objc++ -O -- (Class)object_getClass((id)$x0)
```
- Despeje as seções que contêm metadados Objective-C (observação: muitas agora estão em `__DATA_CONST` / `__AUTH_CONST`):
```lldb
(lldb) image dump section --section __DATA_CONST.__objc_classlist
(lldb) image dump section --section __DATA_CONST.__objc_selrefs
(lldb) image dump section --section __AUTH_CONST.__auth_got
```
- Leia a memória de um objeto de classe conhecido para fazer pivot para `class_ro_t` / `class_rw_t` ao fazer reversing de listas de métodos:
```lldb
(lldb) image lookup -r -n _OBJC_CLASS_$_NSFileManager
(lldb) memory read -fx -s8 0xADDRESS_OF_CLASS_OBJECT
```
### Frida (Objective-C e Swift)

Frida fornece bridges de alto nível para runtime que são muito úteis para descobrir e instrumentar objetos ativos sem symbols:

- Enumerar classes e métodos, resolver nomes reais de classes em runtime e interceptar seletores Objective-C:
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
- Swift bridge: enumerar tipos Swift e interagir com instâncias Swift (requer uma versão recente do Frida; muito útil em alvos Apple Silicon).

---

## Referências

- [1] [Clang/LLVM: Pointer Authentication and the ptrauth.h intrinsics (arm64e ABI)](https://clang.llvm.org/docs/PointerAuthentication.html)
- [2] [Apple objc runtime headers - objc-object.h (tagged pointers, non‑pointer isa, etc.)](https://opensource.apple.com/source/objc4/objc4-818.2/runtime/objc-object.h.auto.html)

{{#include ../../../banners/hacktricks-training.md}}
