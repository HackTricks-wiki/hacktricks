# Processo Dyld do macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Informações básicas

O **entrypoint** real de um binário Mach-o é o linked dynamic, definido em `LC_LOAD_DYLINKER`, que normalmente é `/usr/lib/dyld`.<sup>[[3]](#references)</sup>

Esse linker precisará localizar todas as libraries executáveis, mapeá-las na memória e fazer o link de todas as libraries não lazy. Somente após esse processo o entry-point do binário será executado.

É claro que o **`dyld`** não possui dependências (ele usa syscalls e trechos de libSystem).

> [!CAUTION]
> Se esse linker contiver alguma vulnerabilidade, como ele é executado antes da execução de qualquer binário (até mesmo os altamente privilegiados), seria possível **escalar privilégios**.

### Fluxo

O Dyld será carregado por **`dyldboostrap::start`**, que também carregará itens como o **stack canary**. Isso ocorre porque essa função receberá, em seu vetor de argumentos **`apple`**, esse e outros **valores** **sensíveis**.<sup>[[1]](#references)</sup>

**`dyls::_main()`** é o entry point do dyld, e sua primeira tarefa é executar `configureProcessRestrictions()`, que normalmente restringe as variáveis de ambiente **`DYLD_*`** explicadas em:<sup>[[2]](#references)</sup>


{{#ref}}
./
{{#endref}}

Em seguida, ele mapeia o dyld shared cache, que faz o prelink de todas as libraries importantes do sistema; depois, mapeia as libraries das quais o binário depende e continua recursivamente até que todas as libraries necessárias sejam carregadas. Portanto:

1. ele começa carregando as libraries inseridas com `DYLD_INSERT_LIBRARIES` (se permitido)
2. depois, as que estão no shared cache
3. depois, as importadas
1. depois, continua importando libraries recursivamente

Após todas serem carregadas, os **initialisers** dessas libraries são executados. Eles são codificados usando **`__attribute__((constructor))`**, definido em `LC_ROUTINES[_64]` (agora deprecated), ou por um pointer em uma section marcada com `S_MOD_INIT_FUNC_POINTERS` (normalmente: **`__DATA.__MOD_INIT_FUNC`**).

Os terminators são codificados com **`__attribute__((destructor))`** e estão localizados em uma section marcada com `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

### Stubs

Todos os binários no macOS são linked dinamicamente. Portanto, eles contêm algumas sections de stubs que ajudam o binário a saltar para o código correto em diferentes máquinas e contextos. Quando o binário é executado, é o dyld que atua como o cérebro responsável por resolver esses endereços (pelo menos os não lazy).

Algumas sections de stubs no binário:

- **`__TEXT.__[auth_]stubs`**: Pointers provenientes das sections `__DATA`
- **`__TEXT.__stub_helper`**: Pequeno código que invoca o linking dinâmico com informações sobre a função a ser chamada
- **`__DATA.__[auth_]got`**: Global Offset Table (endereços de funções importadas; quando resolvidos, são vinculados durante o load time, pois estão marcados com a flag `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__nl_symbol_ptr`**: Pointers de símbolos não lazy (vinculados durante o load time, pois estão marcados com a flag `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__la_symbol_ptr`**: Pointers de símbolos lazy (vinculados no primeiro acesso)

> [!WARNING]
> Observe que os pointers com o prefixo "auth\_" usam uma chave de criptografia em processo para protegê-los (PAC). Além disso, é possível usar a instrução arm64 `BLRA[A/B]` para verificar o pointer antes de segui-lo. E `RETA\[A/B]` pode ser usada no lugar de um endereço RET.\
> Na verdade, o código em **`__TEXT.__auth_stubs`** usará **`braa`** em vez de **`bl`** para chamar a função solicitada e autenticar o pointer.
>
> Observe também que as versões atuais do dyld carregam tudo como não lazy.

### Encontrando símbolos lazy
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
Parte interessante da desassemblagem:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
É possível ver que o salto para chamar **`printf`** vai para **`__TEXT.__stubs`**:
```bash
objdump --section-headers ./load

./load:	file format mach-o arm64

Sections:
Idx Name          Size     VMA              Type
0 __text        00000038 0000000100003f60 TEXT
1 __stubs       0000000c 0000000100003f98 TEXT
2 __cstring     00000004 0000000100003fa4 DATA
3 __unwind_info 00000058 0000000100003fa8 DATA
4 __got         00000008 0000000100004000 DATA
```
Na desmontagem da seção **`__stubs`**:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
você pode ver que estamos **saltando para o endereço da GOT**, que, neste caso, é resolvido de forma non-lazy e conterá o endereço da função printf.

Em outras situações, em vez de saltar diretamente para a GOT, ele poderia saltar para **`__DATA.__la_symbol_ptr`**, que carregará um valor que representa a função que está tentando carregar; em seguida, saltará para **`__TEXT.__stub_helper`**, que salta para **`__DATA.__nl_symbol_ptr`**, que contém o endereço de **`dyld_stub_binder`**, que recebe como parâmetros o número da função e um endereço.\
Essa última função, depois de encontrar o endereço da função pesquisada, escreve-o no local correspondente em **`__TEXT.__stub_helper`** para evitar fazer novas buscas no futuro.

> [!TIP]
> No entanto, observe que as versões atuais do dyld carregam tudo como non-lazy.

#### Dyld opcodes

Por fim, **`dyld_stub_binder`** precisa encontrar a função indicada e escrevê-la no endereço apropriado para não precisar pesquisá-la novamente. Para isso, ele usa opcodes (uma máquina de estados finitos) dentro do dyld.

## apple\[] vetor de argumentos

No macOS, a função principal recebe, na verdade, 4 argumentos em vez de 3. O quarto é chamado apple, e cada entrada está no formato `key=value`. Por exemplo:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
Resultado:
```
0: executable_path=./a
1:
2:
3:
4: ptr_munge=
5: main_stack=
6: executable_file=0x1a01000012,0x5105b6a
7: dyld_file=0x1a01000012,0xfffffff0009834a
8: executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b
9: executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa
10: arm64e_abi=os
11: th_port=
```
> [!TIP]
> Quando esses valores chegam à função principal, as informações sensíveis já foram removidas deles; caso contrário, isso seria um data leak.

é possível visualizar todos esses valores interessantes durante a depuração, antes de entrar em main, com:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Current executable set to '/tmp/a' (arm64).
(lldb) process launch -s
[..]

<strong>(lldb) mem read $sp
</strong>0x16fdff510: 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00  ................
0x16fdff520: d8 f6 df 6f 01 00 00 00 00 00 00 00 00 00 00  ...o............

<strong>(lldb) x/55s 0x016fdff6d8
</strong>[...]
0x16fdffd6a: "TERM_PROGRAM=WarpTerminal"
0x16fdffd84: "WARP_USE_SSH_WRAPPER=1"
0x16fdffd9b: "WARP_IS_LOCAL_SHELL_SESSION=1"
0x16fdffdb9: "SDKROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.4.sdk"
0x16fdffe24: "NVM_DIR=/Users/carlospolop/.nvm"
0x16fdffe44: "CONDA_CHANGEPS1=false"
0x16fdffe5a: ""
0x16fdffe5b: ""
0x16fdffe5c: ""
0x16fdffe5d: ""
0x16fdffe5e: ""
0x16fdffe5f: ""
0x16fdffe60: "pfz=0xffeaf0000"
0x16fdffe70: "stack_guard=0x8af2b510e6b800b5"
0x16fdffe8f: "malloc_entropy=0xf2349fbdea53f1e4,0x3fd85d7dcf817101"
0x16fdffec4: "ptr_munge=0x983e2eebd2f3e746"
0x16fdffee1: "main_stack=0x16fe00000,0x7fc000,0x16be00000,0x4000000"
0x16fdfff17: "executable_file=0x1a01000012,0x5105b6a"
0x16fdfff3e: "dyld_file=0x1a01000012,0xfffffff0009834a"
0x16fdfff67: "executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b"
0x16fdfffa2: "executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa"
0x16fdfffdf: "arm64e_abi=os"
0x16fdfffed: "th_port=0x103"
0x16fdffffb: ""
</code></pre>

## dyld_all_image_infos

Esta é uma estrutura exportada pelo dyld com informações sobre o estado do dyld, que pode ser encontrada no [**código-fonte**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html), contendo informações como a versão, um ponteiro para o array dyld_image_info, um ponteiro para dyld_image_notifier, se o processo foi separado do shared cache, se o inicializador do libSystem foi chamado, um ponteiro para o próprio Mach header do dyld, um ponteiro para a string da versão do dyld...<sup>[[4]](#references)</sup>

## variáveis de ambiente do dyld

### depurar dyld

Variáveis de ambiente interessantes que ajudam a entender o que o dyld está fazendo:

- **DYLD_PRINT_LIBRARIES**

Verifica cada biblioteca que é carregada:
```
DYLD_PRINT_LIBRARIES=1 ./apple
dyld[19948]: <9F848759-9AB8-3BD2-96A1-C069DC1FFD43> /private/tmp/a
dyld[19948]: <F0A54B2D-8751-35F1-A3CF-F1A02F842211> /usr/lib/libSystem.B.dylib
dyld[19948]: <C683623C-1FF6-3133-9E28-28672FDBA4D3> /usr/lib/system/libcache.dylib
dyld[19948]: <BFDF8F55-D3DC-3A92-B8A1-8EF165A56F1B> /usr/lib/system/libcommonCrypto.dylib
dyld[19948]: <B29A99B2-7ADE-3371-A774-B690BEC3C406> /usr/lib/system/libcompiler_rt.dylib
dyld[19948]: <65612C42-C5E4-3821-B71D-DDE620FB014C> /usr/lib/system/libcopyfile.dylib
dyld[19948]: <B3AC12C0-8ED6-35A2-86C6-0BFA55BFF333> /usr/lib/system/libcorecrypto.dylib
dyld[19948]: <8790BA20-19EC-3A36-8975-E34382D9747C> /usr/lib/system/libdispatch.dylib
dyld[19948]: <4BB77515-DBA8-3EDF-9AF7-3C9EAE959EA6> /usr/lib/system/libdyld.dylib
dyld[19948]: <F7CE9486-FFF5-3CB8-B26F-75811EF4283A> /usr/lib/system/libkeymgr.dylib
dyld[19948]: <1A7038EC-EE49-35AE-8A3C-C311083795FB> /usr/lib/system/libmacho.dylib
[...]
```
- **DYLD_PRINT_SEGMENTS**

Verifique como cada library é carregada:
```
DYLD_PRINT_SEGMENTS=1 ./apple
dyld[21147]: reusing existing shared cache (/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e):
dyld[21147]:         0x181944000->0x1D5D4BFFF init=5, max=5 __TEXT
dyld[21147]:         0x1D5D4C000->0x1D5EC3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x1D7EC4000->0x1D8E23FFF init=3, max=3 __DATA
dyld[21147]:         0x1D8E24000->0x1DCEBFFFF init=3, max=3 __AUTH
dyld[21147]:         0x1DCEC0000->0x1E22BFFFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x1E42C0000->0x1E5457FFF init=1, max=1 __LINKEDIT
dyld[21147]:         0x1E5458000->0x22D173FFF init=5, max=5 __TEXT
dyld[21147]:         0x22D174000->0x22D9E3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x22F9E4000->0x230F87FFF init=3, max=3 __DATA
dyld[21147]:         0x230F88000->0x234EC3FFF init=3, max=3 __AUTH
dyld[21147]:         0x234EC4000->0x237573FFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x239574000->0x270BE3FFF init=1, max=1 __LINKEDIT
dyld[21147]: Kernel mapped /private/tmp/a
dyld[21147]:     __PAGEZERO (...) 0x000000904000->0x000101208000
dyld[21147]:         __TEXT (r.x) 0x000100904000->0x000100908000
dyld[21147]:   __DATA_CONST (rw.) 0x000100908000->0x00010090C000
dyld[21147]:     __LINKEDIT (r..) 0x00010090C000->0x000100910000
dyld[21147]: Using mapping in dyld cache for /usr/lib/libSystem.B.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E59D000->0x00018E59F000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDB98->0x0001D5DFDBA8
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE015A8->0x0001DDE01878
dyld[21147]:         __AUTH (rw.) 0x0001D9688650->0x0001D9688658
dyld[21147]:         __DATA (rw.) 0x0001D808AD60->0x0001D808AD68
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
dyld[21147]: Using mapping in dyld cache for /usr/lib/system/libcache.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E597000->0x00018E59D000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDAF0->0x0001D5DFDB98
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE014D0->0x0001DDE015A8
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
[...]
```
- **DYLD_PRINT_INITIALIZERS**

Imprime quando cada inicializador de biblioteca está sendo executado:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Outros

- `DYLD_BIND_AT_LAUNCH`: Lazy bindings são resolvidos com bindings não lazy
- `DYLD_DISABLE_PREFETCH`: Desabilita o pre-fetching do conteúdo de \_\_DATA e \_\_LINKEDIT
- `DYLD_FORCE_FLAT_NAMESPACE`: Bindings de nível único
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Caminhos de resolução
- `DYLD_INSERT_LIBRARIES`: Carrega uma library específica
- `DYLD_PRINT_TO_FILE`: Grava o debug do dyld em um arquivo
- `DYLD_PRINT_APIS`: Exibe as chamadas da API do libdyld
- `DYLD_PRINT_APIS_APP`: Exibe as chamadas da API do libdyld feitas pelo processo principal
- `DYLD_PRINT_BINDINGS`: Exibe os símbolos quando são vinculados
- `DYLD_WEAK_BINDINGS`: Exibe apenas símbolos weak quando são vinculados
- `DYLD_PRINT_CODE_SIGNATURES`: Exibe as operações de registro de code signatures
- `DYLD_PRINT_DOFS`: Exibe as seções do formato de objeto D-Trace conforme são carregadas
- `DYLD_PRINT_ENV`: Exibe o env visto pelo dyld
- `DYLD_PRINT_INTERPOSTING`: Exibe as operações de interposting
- `DYLD_PRINT_LIBRARIES`: Exibe as libraries carregadas
- `DYLD_PRINT_OPTS`: Exibe as opções de carregamento
- `DYLD_REBASING`: Exibe as operações de rebasing de símbolos
- `DYLD_RPATHS`: Exibe as expansões de @rpath
- `DYLD_PRINT_SEGMENTS`: Exibe os mapeamentos dos segmentos Mach-O
- `DYLD_PRINT_STATISTICS`: Exibe as estatísticas de tempo
- `DYLD_PRINT_STATISTICS_DETAILS`: Exibe as estatísticas detalhadas de tempo
- `DYLD_PRINT_WARNINGS`: Exibe as mensagens de aviso
- `DYLD_SHARED_CACHE_DIR`: Caminho a ser usado para o cache de shared libraries
- `DYLD_SHARED_REGION`: "use", "private", "avoid"
- `DYLD_USE_CLOSURES`: Habilita closures

É possível encontrar mais opções com algo como:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
Ou baixando o projeto dyld de [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) e executando dentro da pasta:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## References

- [1] [dyld — `dyld/dyldMain.cpp` (caminho de inicialização do processo)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
- [2] [dyld — `dyld/DyldProcessConfig.cpp` (configuração de processo/segurança)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [3] [XNU — `bsd/kern/kern_exec.c` (lado do kernel de `execve`, carregamento do dyld)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
- [4] [dyld — `include/mach-o/dyld_images.h` (estrutura `dyld_all_image_infos`)](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)
{{#include ../../../../banners/hacktricks-training.md}}
