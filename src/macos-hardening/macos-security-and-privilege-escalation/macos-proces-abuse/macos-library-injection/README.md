# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> O código do **dyld é open source** e pode ser encontrado em [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) e pode ser baixado em um tar usando uma **URL como** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

Veja como o Dyld carrega libraries dentro de binaries em:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Isso é como o [**LD_PRELOAD on Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Permite indicar que um processo que será executado deve carregar uma library específica a partir de um path (se a env var estiver habilitada).

Essa técnica também pode ser **usada como uma técnica ASEP**, pois toda application instalada possui um plist chamado "Info.plist", que permite a **atribuição de environmental variables** usando uma key chamada `LSEnvironmental`.

> [!TIP]
> Desde 2012, a **Apple reduziu drasticamente o poder** de **`DYLD_INSERT_LIBRARIES`**.
>
> Acesse o código e **verifique `src/dyld.cpp`**. Na function **`pruneEnvironmentVariables`**, você pode ver que as variables **`DYLD_*`** são removidas.
>
> Na function **`processRestricted`**, o motivo da restriction é definido. Ao verificar esse código, você pode ver que os motivos são:
>
> - O binary é `setuid/setgid`
> - Existência da section `__RESTRICT/__restrict` no macho binary.
> - O software possui entitlements (hardened runtime) sem o entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
>  - Verifique os **entitlements** de um binary com: `codesign -dv --entitlements :- </path/to/bin>`
>
> Em versões mais atualizadas, você pode encontrar essa lógica na segunda parte da function **`configureProcessRestrictions`.** No entanto, o que é executado nas versões mais recentes são as verificações iniciais da function (você pode remover os ifs relacionados ao iOS ou à simulação, pois eles não serão usados no macOS.

### Library Validation

Mesmo que o binary permita o uso da env var **`DYLD_INSERT_LIBRARIES`**, se o binary verificar a signature da library para carregá-la, ele não carregará uma custom library.

Para carregar uma custom library, o binary precisa ter **um dos seguintes entitlements**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

ou o binary **não deve** ter a **hardened runtime flag** ou a **library validation flag**.

Você pode verificar se um binary possui **hardened runtime** com `codesign --display --verbose <bin>`, verificando a runtime flag em **`CodeDirectory`**, como em: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Você também pode carregar uma library se ela estiver **signed com o mesmo certificate que o binary**.

Veja um exemplo de como abusar disso e verificar as restrictions em:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Lembre-se de que as **restrictions anteriores de Library Validation também se aplicam** à execução de ataques de Dylib hijacking.

Assim como no Windows, no MacOS você também pode **hijack dylibs** para fazer com que **applications** **executem** **código** **arbitrário** (bem, na verdade, a partir de um usuário regular isso pode não ser possível, pois talvez você precise de uma permissão TCC para escrever dentro de um bundle `.app` e hijack uma library).\
No entanto, a forma como as applications do **MacOS** **carregam** libraries é **mais restrita** do que no Windows. Isso implica que desenvolvedores de **malware** ainda podem usar essa técnica para **stealth**, mas a probabilidade de conseguir **abusar disso para escalar privileges é muito menor**.

Em primeiro lugar, é **mais comum** encontrar **binaries do MacOS que indicam o full path** para as libraries a serem carregadas. Em segundo lugar, o **MacOS nunca procura** libraries nas pastas do **$PATH**.

A parte **principal** do **código** relacionada a essa funcionalidade está em **`ImageLoader::recursiveLoadLibraries`**, em `ImageLoader.cpp`.

Existem **4 diferentes header Commands** que um macho binary pode usar para carregar libraries:

- O comando **`LC_LOAD_DYLIB`** é o comando comum para carregar uma dylib.
- O comando **`LC_LOAD_WEAK_DYLIB`** funciona como o anterior, mas, se a dylib não for encontrada, a execução continua sem nenhum erro.
- O comando **`LC_REEXPORT_DYLIB`** faz proxy (ou re-exporta) dos símbolos de uma library diferente.
- O comando **`LC_LOAD_UPWARD_DYLIB`** é usado quando duas libraries dependem uma da outra (isso é chamado de _upward dependency_).

No entanto, existem **2 tipos de Dylib hijacking**:

- **Missing weak linked libraries**: Isso significa que a application tentará carregar uma library que não existe, configurada com **LC_LOAD_WEAK_DYLIB**. Então, **se um attacker colocar uma dylib onde ela é esperada, ela será carregada**.
- O fato de o link ser "weak" significa que a application continuará em execução mesmo se a library não for encontrada.
- O **código relacionado** a isso está na function `ImageLoaderMachO::doGetDependentLibraries` de `ImageLoaderMachO.cpp`, onde `lib->required` só é `false` quando `LC_LOAD_WEAK_DYLIB` é true.
- **Encontre weak linked libraries** em binaries com (mais adiante há um exemplo de como criar hijacking libraries):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configurado com @rpath**: Mach-O binaries podem ter os commands **`LC_RPATH`** e **`LC_LOAD_DYLIB`**. Com base nos **valores** desses commands, as **libraries** serão **carregadas** de **diretórios diferentes**.
- **`LC_RPATH`** contém os paths de algumas pastas usadas pelo binary para carregar libraries.
- **`LC_LOAD_DYLIB`** contém o path para libraries específicas a serem carregadas. Esses paths podem conter **`@rpath`**, que será **substituído** pelos valores em **`LC_RPATH`**. Se houver vários paths em **`LC_RPATH`**, todos serão usados para procurar a library a ser carregada. Exemplo:
- Se **`LC_LOAD_DYLIB`** contiver `@rpath/library.dylib` e **`LC_RPATH`** contiver `/application/app.app/Contents/Framework/v1/` e `/application/app.app/Contents/Framework/v2/`. Ambas as pastas serão usadas para carregar `library.dylib`**.** Se a library não existir em `[...]/v1/` e um attacker puder colocá-la lá, ele poderá hijack o carregamento da library em `[...]/v2/`, pois a ordem dos paths em **`LC_LOAD_DYLIB`** é seguida.
- **Encontre rpath paths e libraries** em binaries com: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: É o **path** para o diretório que contém o **main executable file**.
>
> **`@loader_path`**: É o **path** para o **diretório** que contém o **Mach-O binary** que contém o load command.
>
> - Quando usado em um executable, **`@loader_path`** é efetivamente igual a **`@executable_path`**.
> - Quando usado em uma **dylib**, **`@loader_path`** fornece o **path** para a **dylib**.

A forma de **escalar privileges** abusando dessa funcionalidade seria no caso raro em que uma **application** sendo executada **pelo** **root** esteja **procurando** alguma **library em uma pasta na qual o attacker tenha permissões de escrita**.

> [!TIP]
> Um bom **scanner** para encontrar **missing libraries** em applications é o [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) ou uma [**CLI version**](https://github.com/pandazheng/DylibHijack).\
> Um bom **report com detalhes técnicos** sobre essa técnica pode ser encontrado [**aqui**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Lembre-se de que as **restrictions anteriores de Library Validation também se aplicam** à execução de ataques de Dlopen hijacking.

De acordo com **`man dlopen`**:

- Quando o path **não contém um caractere de barra** (ou seja, é apenas um leaf name), **dlopen() fará uma busca**. Se **`$DYLD_LIBRARY_PATH`** tiver sido definido no launch, o dyld primeiro **procurará nesse directório**. Em seguida, se o calling mach-o file ou o main executable especificar um **`LC_RPATH`**, o dyld **procurará nesses** diretórios. Depois, se o processo for **unrestricted**, o dyld pesquisará no current working directory. Por fim, para binaries antigos, o dyld tentará alguns fallbacks. Se **`$DYLD_FALLBACK_LIBRARY_PATH`** tiver sido definido no launch, o dyld pesquisará **nesses diretórios**; caso contrário, o dyld procurará em **`/usr/local/lib/`** (se o processo for unrestricted) e depois em **`/usr/lib/`** (essas informações foram obtidas de **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Se não houver barras no name, haverá 2 formas de fazer hijacking:
>
> - Se algum **`LC_RPATH`** for **writable** (mas a signature é verificada, portanto, para isso, você também precisa que o binary seja unrestricted)
> - Se o binary for **unrestricted**, será possível carregar algo a partir do CWD (ou abusar de uma das env vars mencionadas)

- Quando o path **parece um path de framework** (por exemplo, `/stuff/foo.framework/foo`), se **`$DYLD_FRAMEWORK_PATH`** tiver sido definido no launch, o dyld primeiro procurará nesse diretório pelo **partial path do framework** (por exemplo, `foo.framework/foo`). Em seguida, o dyld tentará o **path fornecido como está** (usando o current working directory para paths relativos). Por fim, para binaries antigos, o dyld tentará alguns fallbacks. Se **`$DYLD_FALLBACK_FRAMEWORK_PATH`** tiver sido definido no launch, o dyld pesquisará nesses diretórios. Caso contrário, pesquisará em **`/Library/Frameworks`** (no macOS, se o processo for unrestricted) e depois em **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Se for um framework path, a forma de fazer hijack seria:
>
> - Se o processo for **unrestricted**, abusando do **relative path from CWD** e das env vars mencionadas (mesmo que isso não esteja especificado na documentação, se o processo for restricted, as env vars DYLD\_\* serão removidas)

- Quando o path **contém uma barra, mas não é um framework path** (ou seja, um full path ou partial path para uma dylib), o dlopen() primeiro procura (se definido) em **`$DYLD_LIBRARY_PATH`** (com a leaf part do path). Em seguida, o dyld **tenta o path fornecido** (usando o current working directory para paths relativos (mas apenas para processos unrestricted)). Por fim, para binaries antigos, o dyld tentará fallbacks. Se **`$DYLD_FALLBACK_LIBRARY_PATH`** tiver sido definido no launch, o dyld pesquisará nesses diretórios; caso contrário, o dyld procurará em **`/usr/local/lib/`** (se o processo for unrestricted) e depois em **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Se houver barras no name e ele não for um framework, a forma de fazer hijack seria:
>
> - Se o binary for **unrestricted**, será possível carregar algo a partir do CWD ou de `/usr/local/lib` (ou abusar de uma das env vars mencionadas)

> [!TIP]
> Nota: não existem **configuration files para controlar a busca do dlopen**.
>
> Nota: se o main executable for um **set\[ug]id binary ou codesigned com entitlements**, todas as environment variables serão ignoradas, e apenas um full path poderá ser usado ([verifique as restrictions de DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) para obter informações mais detalhadas)
>
> Nota: as Apple platforms usam arquivos "universal" para combinar libraries de 32-bit e 64-bit. Isso significa que **não existem search paths separados de 32-bit e 64-bit**.
>
> Nota: nas Apple platforms, a maioria das OS dylibs é **combinada no dyld cache** e não existe no disk. Portanto, chamar **`stat()`** para verificar previamente se uma OS dylib existe **não funcionará**. No entanto, **`dlopen_preflight()`** usa os mesmos passos que **`dlopen()`** para encontrar um arquivo mach-o compatível.

**Check paths**

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
Se você compilá-lo e executá-lo, poderá ver **onde cada biblioteca foi pesquisada sem sucesso**. Além disso, você pode **filtrar os logs do FS**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Se um **binário/app privilegiado** (como um SUID ou algum binário com entitlements poderosos) estiver **carregando uma biblioteca por um caminho relativo** (por exemplo, usando `@executable_path` ou `@loader_path`) e tiver a Library Validation desabilitada, pode ser possível mover o binário para um local onde o atacante consiga **modificar a biblioteca carregada pelo caminho relativo** e abusar disso para injetar código no processo.

## Prune `DYLD_*` and `LD_LIBRARY_PATH` env variables

No arquivo `dyld-dyld-832.7.1/src/dyld2.cpp`, é possível encontrar a função **`pruneEnvironmentVariables`**, que removerá qualquer variável de ambiente que **comece com `DYLD_`** e **`LD_LIBRARY_PATH=`**.

Ela também definirá especificamente como **null** as variáveis de ambiente **`DYLD_FALLBACK_FRAMEWORK_PATH`** e **`DYLD_FALLBACK_LIBRARY_PATH`** para binários **suid** e **sgid**.

Essa função é chamada pela função **`_main`** do mesmo arquivo ao direcionar para OSX, desta forma:
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
O que basicamente significa que, se o binário for **suid** ou **sgid**, tiver um segmento **RESTRICT** nos headers ou tiver sido assinado com a flag **CS_RESTRICT**, então **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** será verdadeiro e as variáveis de ambiente serão removidas.

Observe que, se CS_REQUIRE_LV for verdadeiro, as variáveis não serão removidas, mas a validação da biblioteca verificará se elas estão usando o mesmo certificado que o binário original.

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
> Note que, mesmo que existam binários assinados com flags **`0x0(none)`**, eles podem obter a flag **`CS_RESTRICT`** dinamicamente quando executados e, portanto, esta técnica não funcionará neles.
>
> Você pode verificar se um proc possui esta flag com (obtenha o [**csops aqui**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> e então verificar se a flag 0x800 está habilitada.

## Referências

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
