# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> O código do **dyld é open source** e pode ser encontrado em [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) e pode ser baixado como um tar usando uma **URL como** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

Dê uma olhada em como o Dyld carrega bibliotecas dentro de binários em:

{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Isso é como o [**LD_PRELOAD no Linux**](../../../../linux-hardening/privilege-escalation/#ld_preload). Permite indicar um processo que vai ser executado para carregar uma biblioteca específica de um caminho (se a variável de ambiente estiver habilitada)

Essa técnica também pode ser **usada como uma técnica ASEP** já que cada aplicativo instalado tem um plist chamado "Info.plist" que permite a **atribuição de variáveis ambientais** usando uma chave chamada `LSEnvironmental`.

> [!NOTE]
> Desde 2012 **a Apple reduziu drasticamente o poder** do **`DYLD_INSERT_LIBRARIES`**.
>
> Vá para o código e **verifique `src/dyld.cpp`**. Na função **`pruneEnvironmentVariables`** você pode ver que as variáveis **`DYLD_*`** são removidas.
>
> Na função **`processRestricted`** a razão da restrição é definida. Verificando esse código você pode ver que as razões são:
>
> - O binário é `setuid/setgid`
> - Existência da seção `__RESTRICT/__restrict` no binário macho.
> - O software tem permissões (runtime endurecido) sem a permissão [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
>   - Verifique as **permissões** de um binário com: `codesign -dv --entitlements :- </path/to/bin>`
>
> Em versões mais atualizadas você pode encontrar essa lógica na segunda parte da função **`configureProcessRestrictions`.** No entanto, o que é executado em versões mais novas são as **verificações iniciais da função** (você pode remover os ifs relacionados ao iOS ou simulação, pois esses não serão usados no macOS).

### Validação de Biblioteca

Mesmo que o binário permita usar a variável de ambiente **`DYLD_INSERT_LIBRARIES`**, se o binário verificar a assinatura da biblioteca para carregá-la, não carregará uma personalizada.

Para carregar uma biblioteca personalizada, o binário precisa ter **uma das seguintes permissões**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

ou o binário **não deve** ter a **flag de runtime endurecido** ou a **flag de validação de biblioteca**.

Você pode verificar se um binário tem **runtime endurecido** com `codesign --display --verbose <bin>` verificando a flag runtime em **`CodeDirectory`** como: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Você também pode carregar uma biblioteca se ela for **assinada com o mesmo certificado que o binário**.

Encontre um exemplo de como (ab)usar isso e verifique as restrições em:

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Lembre-se que **as restrições anteriores de Validação de Biblioteca também se aplicam** para realizar ataques de Dylib hijacking.

Assim como no Windows, no MacOS você também pode **sequestar dylibs** para fazer **aplicativos** **executarem** **código** **arbitrário** (bem, na verdade, de um usuário regular isso pode não ser possível, pois você pode precisar de uma permissão TCC para escrever dentro de um pacote `.app` e sequestrar uma biblioteca).\
No entanto, a maneira como os aplicativos **MacOS** **carregam** bibliotecas é **mais restrita** do que no Windows. Isso implica que os desenvolvedores de **malware** ainda podem usar essa técnica para **furtividade**, mas a probabilidade de conseguir **abusar disso para escalar privilégios é muito menor**.

Primeiro de tudo, é **mais comum** encontrar que os **binários MacOS indicam o caminho completo** para as bibliotecas a serem carregadas. E segundo, **MacOS nunca procura** nas pastas do **$PATH** por bibliotecas.

A **parte principal** do **código** relacionada a essa funcionalidade está em **`ImageLoader::recursiveLoadLibraries`** em `ImageLoader.cpp`.

Existem **4 comandos de cabeçalho diferentes** que um binário macho pode usar para carregar bibliotecas:

- O comando **`LC_LOAD_DYLIB`** é o comando comum para carregar um dylib.
- O comando **`LC_LOAD_WEAK_DYLIB`** funciona como o anterior, mas se o dylib não for encontrado, a execução continua sem erro.
- O comando **`LC_REEXPORT_DYLIB`** faz proxy (ou reexporta) os símbolos de uma biblioteca diferente.
- O comando **`LC_LOAD_UPWARD_DYLIB`** é usado quando duas bibliotecas dependem uma da outra (isso é chamado de _dependência ascendente_).

No entanto, existem **2 tipos de sequestro de dylib**:

- **Bibliotecas fracas vinculadas ausentes**: Isso significa que o aplicativo tentará carregar uma biblioteca que não existe configurada com **LC_LOAD_WEAK_DYLIB**. Então, **se um atacante colocar um dylib onde se espera que ele seja carregado**.
- O fato de que o link é "fraco" significa que o aplicativo continuará executando mesmo que a biblioteca não seja encontrada.
- O **código relacionado** a isso está na função `ImageLoaderMachO::doGetDependentLibraries` de `ImageLoaderMachO.cpp` onde `lib->required` é apenas `false` quando `LC_LOAD_WEAK_DYLIB` é verdadeiro.
- **Encontre bibliotecas fracas vinculadas** em binários com (você tem mais tarde um exemplo de como criar bibliotecas de sequestro):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configuradas com @rpath**: Binários Mach-O podem ter os comandos **`LC_RPATH`** e **`LC_LOAD_DYLIB`**. Com base nos **valores** desses comandos, **bibliotecas** serão **carregadas** de **diretórios diferentes**.
- **`LC_RPATH`** contém os caminhos de algumas pastas usadas para carregar bibliotecas pelo binário.
- **`LC_LOAD_DYLIB`** contém o caminho para bibliotecas específicas a serem carregadas. Esses caminhos podem conter **`@rpath`**, que será **substituído** pelos valores em **`LC_RPATH`**. Se houver vários caminhos em **`LC_RPATH`**, todos serão usados para procurar a biblioteca a ser carregada. Exemplo:
- Se **`LC_LOAD_DYLIB`** contém `@rpath/library.dylib` e **`LC_RPATH`** contém `/application/app.app/Contents/Framework/v1/` e `/application/app.app/Contents/Framework/v2/`. Ambas as pastas serão usadas para carregar `library.dylib`**.** Se a biblioteca não existir em `[...]/v1/` e o atacante puder colocá-la lá para sequestrar o carregamento da biblioteca em `[...]/v2/`, pois a ordem dos caminhos em **`LC_LOAD_DYLIB`** é seguida.
- **Encontre caminhos e bibliotecas rpath** em binários com: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: É o **caminho** para o diretório que contém o **arquivo executável principal**.
>
> **`@loader_path`**: É o **caminho** para o **diretório** que contém o **binário Mach-O** que contém o comando de carregamento.
>
> - Quando usado em um executável, **`@loader_path`** é efetivamente o **mesmo** que **`@executable_path`**.
> - Quando usado em um **dylib**, **`@loader_path`** fornece o **caminho** para o **dylib**.

A maneira de **escalar privilégios** abusando dessa funcionalidade seria no raro caso de um **aplicativo** sendo executado **por** **root** estar **procurando** alguma **biblioteca em alguma pasta onde o atacante tem permissões de escrita.**

> [!TIP]
> Um bom **scanner** para encontrar **bibliotecas ausentes** em aplicativos é [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) ou uma [**versão CLI**](https://github.com/pandazheng/DylibHijack).\
> Um bom **relatório com detalhes técnicos** sobre essa técnica pode ser encontrado [**aqui**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Exemplo**

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Lembre-se que **as restrições anteriores de Validação de Biblioteca também se aplicam** para realizar ataques de Dlopen hijacking.

Do **`man dlopen`**:

- Quando o caminho **não contém um caractere de barra** (ou seja, é apenas um nome de folha), **dlopen() fará a busca**. Se **`$DYLD_LIBRARY_PATH`** foi definido na inicialização, dyld primeiro **procurará nesse diretório**. Em seguida, se o arquivo mach-o chamador ou o executável principal especificarem um **`LC_RPATH`**, então dyld **procurará nesses** diretórios. Em seguida, se o processo for **sem restrições**, dyld procurará no **diretório de trabalho atual**. Por último, para binários antigos, dyld tentará algumas alternativas. Se **`$DYLD_FALLBACK_LIBRARY_PATH`** foi definido na inicialização, dyld procurará nesses diretórios, caso contrário, dyld procurará em **`/usr/local/lib/`** (se o processo for sem restrições), e depois em **`/usr/lib/`** (essa informação foi retirada do **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(se sem restrições)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (se sem restrições)
6. `/usr/lib/`

> [!CAUTION]
> Se não houver barras no nome, haveria 2 maneiras de fazer um sequestro:
>
> - Se qualquer **`LC_RPATH`** for **gravável** (mas a assinatura é verificada, então para isso você também precisa que o binário seja sem restrições)
> - Se o binário for **sem restrições** e então é possível carregar algo do CWD (ou abusar de uma das variáveis de ambiente mencionadas)

- Quando o caminho **parece um caminho de framework** (por exemplo, `/stuff/foo.framework/foo`), se **`$DYLD_FRAMEWORK_PATH`** foi definido na inicialização, dyld primeiro procurará nesse diretório pelo **caminho parcial do framework** (por exemplo, `foo.framework/foo`). Em seguida, dyld tentará o **caminho fornecido como está** (usando o diretório de trabalho atual para caminhos relativos). Por último, para binários antigos, dyld tentará algumas alternativas. Se **`$DYLD_FALLBACK_FRAMEWORK_PATH`** foi definido na inicialização, dyld procurará nesses diretórios. Caso contrário, ele procurará em **`/Library/Frameworks`** (no macOS se o processo for sem restrições), depois em **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. caminho fornecido (usando o diretório de trabalho atual para caminhos relativos se sem restrições)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (se sem restrições)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Se um caminho de framework, a maneira de sequestrá-lo seria:
>
> - Se o processo for **sem restrições**, abusando do **caminho relativo do CWD** as variáveis de ambiente mencionadas (mesmo que não esteja dito na documentação, se o processo for restrito, as variáveis de ambiente DYLD\_\* são removidas)

- Quando o caminho **contém uma barra, mas não é um caminho de framework** (ou seja, um caminho completo ou um caminho parcial para um dylib), dlopen() primeiro procura em (se definido) em **`$DYLD_LIBRARY_PATH`** (com a parte da folha do caminho). Em seguida, dyld **tenta o caminho fornecido** (usando o diretório de trabalho atual para caminhos relativos (mas apenas para processos sem restrições)). Por último, para binários mais antigos, dyld tentará alternativas. Se **`$DYLD_FALLBACK_LIBRARY_PATH`** foi definido na inicialização, dyld procurará nesses diretórios, caso contrário, dyld procurará em **`/usr/local/lib/`** (se o processo for sem restrições), e depois em **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. caminho fornecido (usando o diretório de trabalho atual para caminhos relativos se sem restrições)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (se sem restrições)
5. `/usr/lib/`

> [!CAUTION]
> Se houver barras no nome e não for um framework, a maneira de sequestrá-lo seria:
>
> - Se o binário for **sem restrições** e então é possível carregar algo do CWD ou `/usr/local/lib` (ou abusar de uma das variáveis de ambiente mencionadas)

> [!NOTE]
> Nota: Não há **arquivos de configuração** para **controlar a busca do dlopen**.
>
> Nota: Se o executável principal for um **binário set\[ug]id ou assinado com permissões**, então **todas as variáveis de ambiente são ignoradas**, e apenas um caminho completo pode ser usado ([verifique as restrições do DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) para mais informações detalhadas)
>
> Nota: As plataformas da Apple usam arquivos "universais" para combinar bibliotecas de 32 bits e 64 bits. Isso significa que não há **caminhos de busca separados para 32 bits e 64 bits**.
>
> Nota: Nas plataformas da Apple, a maioria dos dylibs do sistema operacional são **combinados no cache do dyld** e não existem no disco. Portanto, chamar **`stat()`** para verificar se um dylib do sistema operacional existe **não funcionará**. No entanto, **`dlopen_preflight()`** usa os mesmos passos que **`dlopen()`** para encontrar um arquivo mach-o compatível.

**Verifique os caminhos**

Vamos verificar todas as opções com o seguinte código:
```c
// gcc dlopentest.c -o dlopentest -Wl,-rpath,/tmp/test
#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
void* handle;

fprintf("--- No slash ---\n");
handle = dlopen("just_name_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative framework ---\n");
handle = dlopen("a/framework/rel_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs framework ---\n");
handle = dlopen("/a/abs/framework/abs_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative Path ---\n");
handle = dlopen("a/folder/rel_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs Path ---\n");
handle = dlopen("/a/abs/folder/abs_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

return 0;
}
```
Se você compilar e executar, poderá ver **onde cada biblioteca foi pesquisada sem sucesso**. Além disso, você poderia **filtrar os logs do FS**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Hijacking de Caminho Relativo

Se um **binário/app privilegiado** (como um SUID ou algum binário com permissões poderosas) estiver **carregando uma biblioteca de caminho relativo** (por exemplo, usando `@executable_path` ou `@loader_path`) e tiver a **Validação de Biblioteca desativada**, pode ser possível mover o binário para um local onde o atacante possa **modificar a biblioteca carregada de caminho relativo**, e abusar disso para injetar código no processo.

## Podar variáveis de ambiente `DYLD_*` e `LD_LIBRARY_PATH`

No arquivo `dyld-dyld-832.7.1/src/dyld2.cpp` é possível encontrar a função **`pruneEnvironmentVariables`**, que removerá qualquer variável de ambiente que **comece com `DYLD_`** e **`LD_LIBRARY_PATH=`**.

Ela também definirá como **nulo** especificamente as variáveis de ambiente **`DYLD_FALLBACK_FRAMEWORK_PATH`** e **`DYLD_FALLBACK_LIBRARY_PATH`** para binários **suid** e **sgid**.

Essa função é chamada da função **`_main`** do mesmo arquivo se direcionando para o OSX assim:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
e essas flags booleanas são definidas no mesmo arquivo no código:
```cpp
#if TARGET_OS_OSX
// support chrooting from old kernel
bool isRestricted = false;
bool libraryValidation = false;
// any processes with setuid or setgid bit set or with __RESTRICT segment is restricted
if ( issetugid() || hasRestrictedSegment(mainExecutableMH) ) {
isRestricted = true;
}
bool usingSIP = (csr_check(CSR_ALLOW_TASK_FOR_PID) != 0);
uint32_t flags;
if ( csops(0, CS_OPS_STATUS, &flags, sizeof(flags)) != -1 ) {
// On OS X CS_RESTRICT means the program was signed with entitlements
if ( ((flags & CS_RESTRICT) == CS_RESTRICT) && usingSIP ) {
isRestricted = true;
}
// Library Validation loosens searching but requires everything to be code signed
if ( flags & CS_REQUIRE_LV ) {
isRestricted = false;
libraryValidation = true;
}
}
gLinkContext.allowAtPaths                = !isRestricted;
gLinkContext.allowEnvVarsPrint           = !isRestricted;
gLinkContext.allowEnvVarsPath            = !isRestricted;
gLinkContext.allowEnvVarsSharedCache     = !libraryValidation || !usingSIP;
gLinkContext.allowClassicFallbackPaths   = !isRestricted;
gLinkContext.allowInsertFailures         = false;
gLinkContext.allowInterposing         	 = true;
```
O que basicamente significa que se o binário é **suid** ou **sgid**, ou tem um segmento **RESTRICT** nos cabeçalhos ou foi assinado com a flag **CS_RESTRICT**, então **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** é verdadeiro e as variáveis de ambiente são podadas.

Note que se CS_REQUIRE_LV for verdadeiro, então as variáveis não serão podadas, mas a validação da biblioteca verificará se estão usando o mesmo certificado que o binário original.

## Verificar Restrições

### SUID & SGID
```bash
# Make it owned by root and suid
sudo chown root hello
sudo chmod +s hello
# Insert the library
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

# Remove suid
sudo chmod -s hello
```
### Seção `__RESTRICT` com segmento `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened runtime

Crie um novo certificado no Keychain e use-o para assinar o binário:
```bash
# Apply runtime proetction
codesign -s <cert-name> --option=runtime ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello #Library won't be injected

# Apply library validation
codesign -f -s <cert-name> --option=library ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed #Will throw an error because signature of binary and library aren't signed by same cert (signs must be from a valid Apple-signed developer certificate)

# Sign it
## If the signature is from an unverified developer the injection will still work
## If it's from a verified developer, it won't
codesign -f -s <cert-name> inject.dylib
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed

# Apply CS_RESTRICT protection
codesign -f -s <cert-name> --option=restrict hello-signed
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed # Won't work
```
> [!CAUTION]
> Note que mesmo que existam binários assinados com a flag **`0x0(none)`**, eles podem obter a flag **`CS_RESTRICT`** dinamicamente quando executados e, portanto, esta técnica não funcionará neles.
>
> Você pode verificar se um proc tem essa flag com (obtenha [**csops aqui**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> e então verifique se a flag 0x800 está habilitada.

## Referências

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
