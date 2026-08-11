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

Isso é semelhante ao [**LD_PRELOAD no Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Permite indicar que um process que será executado deve carregar uma library específica a partir de um path (se a env var estiver habilitada)<sup>[[4]](#references)</sup>

Essa técnica também pode ser **usada como uma técnica ASEP**, pois cada application instalada possui um plist chamado "Info.plist" que permite **atribuir environmental variables** usando uma key chamada `LSEnvironmental`.

> [!TIP]
> Desde 2012, a **Apple reduziu drasticamente o poder** de **`DYLD_INSERT_LIBRARIES`**. Um process é considerado **restricted** — e então o `dyld` exclui todas as variables `DYLD_*` do environment — quando qualquer uma destas condições é verdadeira:
>
> - O binary é `setuid/setgid`
> - O Mach-O possui uma section **`__RESTRICT/__restrict`**
> - O binary é assinado com o hardened runtime e o AMFI não concede as permissões de "path/print variables", ou seja, ele não possui [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[[3]](#references)</sup>
>   - Verifique os **entitlements** de um binary com: `codesign -dv --entitlements :- </path/to/bin>`
>
> No `dyld` atual, isso não é mais decidido apenas pelo `dyld`: `ProcessConfig::Security::Security()` consulta o **AMFI** por meio de `amfi_check_dyld_policy_self()` e então chama `pruneEnvVars()`. O código exato é explicado em [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) abaixo.

### Library Validation

Mesmo que o binary permita a env var **`DYLD_INSERT_LIBRARIES`**, ele não carregará uma library customizada se validar a assinatura da library.

Para carregar uma library customizada, o binary precisa ter **um dos seguintes entitlements**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

ou o binary **não deve** ter a **flag do hardened runtime** ou a **flag de library validation**.

Você pode verificar se um binary possui **hardened runtime** com `codesign --display --verbose <bin>`, verificando a flag runtime em **`CodeDirectory`**, como em: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Você também pode carregar uma library se ela estiver **assinada com o mesmo certificado que o binary**.

Encontre um exemplo de como abusar disso e verificar as restrições em:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Lembre-se de que as **restrições anteriores de Library Validation também se aplicam** à realização de ataques de Dylib hijacking.

Assim como no Windows, no macOS você pode **sequestrar dylibs** para fazer com que **applications executem código arbitrário**. A partir de uma conta de usuário comum, isso pode não ser possível, pois escrever dentro de um bundle `.app` para sequestrar uma library pode exigir uma permissão do TCC.\
No entanto, a forma como as applications do **macOS** **carregam** libraries é **mais restrita** do que no Windows. Desenvolvedores de malware ainda podem usar essa técnica para obter **stealth**, mas abusar dela para escalar privilégios é muito menos provável.

Primeiro, é **mais comum** descobrir que **binaries do macOS indicam o path completo** das libraries a serem carregadas. Segundo, o **macOS nunca pesquisa** nas pastas do **$PATH** por libraries.

A parte **principal** do **código** relacionada a essa funcionalidade está em **`ImageLoader::recursiveLoadLibraries`**, em `ImageLoader.cpp`.

Existem **4 diferentes header Commands** que um binary macho pode usar para carregar libraries:

- O comando **`LC_LOAD_DYLIB`** é o comando comum para carregar uma dylib.
- O comando **`LC_LOAD_WEAK_DYLIB`** funciona como o anterior, mas, se a dylib não for encontrada, a execução continua sem nenhum erro.
- O comando **`LC_REEXPORT_DYLIB`** faz proxy (ou re-exporta) dos symbols de uma library diferente.
- O comando **`LC_LOAD_UPWARD_DYLIB`** é usado quando duas libraries dependem uma da outra (isso é chamado de _upward dependency_).

No entanto, existem **2 tipos de Dylib hijacking**:

- **Missing weak linked libraries**: Isso significa que a application tentará carregar uma library inexistente configurada com **LC_LOAD_WEAK_DYLIB**. Então, **se um attacker colocar uma dylib no local esperado, ela será carregada**.
- O fato de o link ser "weak" significa que a application continuará em execução mesmo se a library não for encontrada.
- O **código relacionado** está na function `ImageLoaderMachO::doGetDependentLibraries` de `ImageLoaderMachO.cpp`, onde `lib->required` só é `false` quando `LC_LOAD_WEAK_DYLIB` é true.
- **Encontre weak linked libraries** em binaries com (mais adiante há um exemplo de como criar libraries para hijacking):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configured with @rpath**: Binaries Mach-O podem ter os comandos **`LC_RPATH`** e **`LC_LOAD_DYLIB`**. Com base nos **valores** desses comandos, as **libraries** serão **carregadas** de **diferentes diretórios**.
- **`LC_RPATH`** contém os paths de algumas pastas usadas pelo binary para carregar libraries.
- **`LC_LOAD_DYLIB`** contém o path para as libraries específicas a serem carregadas. Esses paths podem conter **`@rpath`**, que será **substituído** pelos valores em **`LC_RPATH`**. Se houver vários paths em **`LC_RPATH`**, todos serão usados para procurar a library a ser carregada. Exemplo:
- Se **`LC_LOAD_DYLIB`** contiver `@rpath/library.dylib` e **`LC_RPATH`** contiver `/application/app.app/Contents/Framework/v1/` e `/application/app.app/Contents/Framework/v2/`, ambas as pastas serão usadas para carregar `library.dylib`**.** Se a library não existir em `[...]/v1/` e um attacker puder colocá-la nesse local, ele poderá sequestrar o carregamento da library em `[...]/v2/`, pois a ordem dos paths em **`LC_LOAD_DYLIB`** é seguida.
- **Encontre paths de rpath e libraries** em binaries com: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: É o **path** para o diretório que contém o **main executable file**.
>
> **`@loader_path`**: É o **path** para o **directory** que contém o **Mach-O binary** que possui o load command.
>
> - Quando usado em um executable, **`@loader_path`** é efetivamente igual a **`@executable_path`**.
> - Quando usado em uma **dylib**, **`@loader_path`** fornece o **path** para a **dylib**.

A forma de **escalar privilégios** abusando dessa funcionalidade ocorreria no caso raro em que uma **application** executada **pelo** **root** esteja **procurando** alguma **library em uma pasta na qual o attacker tenha permissões de escrita**.

> [!TIP]
> Um bom **scanner** para encontrar **missing libraries** em applications é o [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) ou uma [**versão CLI**](https://github.com/pandazheng/DylibHijack).\
> Um bom **relatório com detalhes técnicos** sobre essa técnica pode ser encontrado [**aqui**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Lembre-se de que as **restrições anteriores de Library Validation também se aplicam** à realização de ataques de Dlopen hijacking.

De **`man dlopen`**:

- Quando o path **não contém um caractere de barra** (ou seja, é apenas um leaf name), **dlopen() fará uma busca**. Se **`$DYLD_LIBRARY_PATH`** estiver definido na inicialização, o dyld primeiro **procurará nesse diretório**. Em seguida, se o arquivo mach-o que faz a chamada ou o executable principal especificar um **`LC_RPATH`**, o dyld **procurará nesses** diretórios. Depois, se o process for **unrestricted**, o dyld pesquisará no current working directory. Por fim, para binaries antigos, o dyld tentará alguns fallbacks. Se **`$DYLD_FALLBACK_LIBRARY_PATH`** estiver definido na inicialização, o dyld pesquisará **nesses diretórios**; caso contrário, o dyld procurará em **`/usr/local/lib/`** (se o process for unrestricted) e depois em **`/usr/lib/`** (essa informação foi extraída de **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Se não houver barras no name, haverá 2 formas de realizar um hijacking:
>
> - Se algum **`LC_RPATH`** for **writable** (mas a assinatura é verificada; portanto, nesse caso, também é necessário que o binary seja unrestricted)
> - Se o binary for **unrestricted**, tornando possível carregar algo do CWD (ou abusar de uma das env vars mencionadas)

- Quando o path **parece um path de framework** (por exemplo, `/stuff/foo.framework/foo`), se **`$DYLD_FRAMEWORK_PATH`** estiver definido na inicialização, o dyld primeiro procurará nesse diretório pelo **partial path do framework** (por exemplo, `foo.framework/foo`). Em seguida, o dyld tentará o path fornecido como está (usando o current working directory para paths relativos). Por fim, para binaries antigos, o dyld tentará alguns fallbacks. Se **`$DYLD_FALLBACK_FRAMEWORK_PATH`** estiver definido na inicialização, o dyld pesquisará nesses diretórios. Caso contrário, pesquisará em **`/Library/Frameworks`** (no macOS, se o process for unrestricted) e depois em **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Se for um path de framework, a forma de realizar o hijack seria:
>
> - Se o process for **unrestricted**, abusando do **path relativo a partir do CWD** ou das env vars mencionadas (mesmo que isso não esteja indicado na documentação, se o process for restricted, as env vars DYLD\_\* serão removidas)

- Quando o path **contém uma barra, mas não é um path de framework** (ou seja, um path completo ou parcial para uma dylib), o dlopen() primeiro procura (se definida) em **`$DYLD_LIBRARY_PATH`** (com a parte leaf do path). Em seguida, o dyld **tenta o path fornecido** (usando o current working directory para paths relativos, mas apenas para processes unrestricted). Por fim, para binaries antigos, o dyld tentará fallbacks. Se **`$DYLD_FALLBACK_LIBRARY_PATH`** estiver definido na inicialização, o dyld pesquisará nesses diretórios; caso contrário, o dyld procurará em **`/usr/local/lib/`** (se o process for unrestricted) e depois em **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Se houver barras no name e ele não for um framework, a forma de realizar o hijack seria:
>
> - Se o binary for **unrestricted**, tornando possível carregar algo do CWD ou de `/usr/local/lib` (ou abusar de uma das env vars mencionadas)

> [!TIP]
> Nota: não existem **configuration files para controlar a busca do dlopen**.
>
> Nota: se o executable principal for um **binary set\[ug]id ou tiver sido codesigned com entitlements**, todas as environment variables serão ignoradas, e somente um path completo poderá ser usado ([verifique as restrições de DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) para informações mais detalhadas).
>
> Nota: as plataformas Apple usam arquivos "universal" para combinar libraries de 32-bit e 64-bit. Isso significa que não existem **paths de busca separados para 32-bit e 64-bit**.
>
> Nota: nas plataformas Apple, a maioria das dylibs do sistema operacional é **combinada no dyld cache** e não existe no disco. Portanto, chamar **`stat()`** para verificar previamente se uma dylib do sistema existe **não funcionará**. No entanto, **`dlopen_preflight()`** usa as mesmas etapas que **`dlopen()`** para encontrar um arquivo mach-o compatível.

**Check paths**

Vamos verificar todas as opções com o código a seguir:
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
Se você compilá-lo e executá-lo, poderá ver **onde cada library foi procurada sem sucesso**. Além disso, você pode **filtrar os logs do FS**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Se um **binário/app privilegiado** (como um SUID ou algum binário com entitlements poderosos) estiver **carregando uma library de caminho relativo** (por exemplo, usando `@executable_path` ou `@loader_path`) e tiver a **Library Validation desabilitada**, pode ser possível mover o binário para um local onde o atacante consiga **modificar a library carregada pelo caminho relativo** e abusar disso para injetar código no processo.

## Podar variáveis de ambiente `DYLD_*`

Versões antigas do `dyld` (`dyld2.cpp`) decidiam isso dentro do processo usando `issetugid()`, `hasRestrictedSegment()` e `csops(CS_OPS_STATUS)`. No **dyld atual, a decisão é delegada ao AMFI**, e o código está em `ProcessConfig::Security::Security()` em `dyld/DyldProcessConfig.cpp`:<sup>[[1]](#references)</sup>
```cpp
const uint64_t amfiFlags = getAMFI(process, syscall);
this->allowAtPaths              = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_AT_PATH);
this->allowEnvVarsPrint         = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_PRINT_VARS);
this->allowEnvVarsPath          = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_PATH_VARS);
this->allowEnvVarsSharedCache   = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_CUSTOM_SHARED_CACHE);
this->allowClassicFallbackPaths = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_FALLBACK_PATHS);
this->allowInsertFailures       = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_FAILED_LIBRARY_INSERTION);
this->allowInterposing          = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_LIBRARY_INTERPOSING);
this->allowEmbeddedVars         = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_EMBEDDED_VARS);
this->allowDevelopmentVars      = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_DEVELOPMENT_VARS);
this->allowLibSystemOverrides   = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_LIBSYSTEM_OVERRIDE);
...
// env vars are only pruned on macOS
switch ( process.platform.value() ) {
case PLATFORM_MACOS:
case PLATFORM_IOSMAC:
case PLATFORM_DRIVERKIT:
break;
default:
return;
}

// env vars are only pruned when process is restricted
if ( this->allowEnvVarsPrint || this->allowEnvVarsPath || this->allowEnvVarsSharedCache )
return;

this->pruneEnvVars(process);
```
Duas coisas merecem ser extraídas disso:

- A remoção só acontece no **macOS / Mac Catalyst / DriverKit** — e somente quando o AMFI não concedeu nenhuma das permissões `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache`.
- A consulta ao AMFI recebe as próprias propriedades do executável:
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
onde `isRestricted()` é literalmente a verificação do segmento `__RESTRICT` (`mach_o/UnsafeHeader.cpp`):<sup>[[2]](#references)</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()` então remove **todas** as variáveis cujo nome começa com `DYLD_` e desloca os parâmetros `apple[]` para baixo, para que os processos filhos de um processo restrito também não os herdem:
```cpp
// For security, setuid programs ignore DYLD_* environment variables.
// Additionally, the DYLD_* environment variables are removed
// from the environment, so that any child processes doesn't see them.
for ( const char* const* s = proc.envp; *s != NULL; s++ ) {
if ( strncmp(*s, "DYLD_", 5) != 0 ) {
*d++ = *s;
}
...
```
> [!TIP]
> Consequência prática: **`DYLD_*` é removido quando o processo é restrito** — setuid/setgid, uma seção `__RESTRICT/__restrict` ou binários com hardened-runtime/entitlements aos quais o AMFI se recusa a conceder as flags de path/print. Se, em vez disso, o processo tiver apenas **library validation** (`CS_REQUIRE_LV`), as variáveis permanecem, mas o dylib inserido deve ser assinado pelo **mesmo Team ID** (ou pela Apple); portanto, você precisa de um dos entitlements que desabilitam a library validation para que o código seja realmente carregado.

Como a decisão agora é do AMFI, a maneira mais rápida de saber o que um determinado binário obterá é verificar em que o AMFI se baseia — entitlements e signing flags — em vez do próprio `dyld`:
```bash
BIN=/path/to/bin
codesign -d --entitlements :- "$BIN" 2>/dev/null | \
egrep "allow-dyld-environment-variables|disable-library-validation|clear-library-validation"
codesign -dvvv "$BIN" 2>&1 | egrep "flags=|TeamIdentifier="
otool -l "$BIN" | grep -A2 __RESTRICT
```
## Verificar Restrições

### SUID e SGID
```bash
# Make it owned by root and suid
sudo chown root hello
sudo chmod +s hello
# Insert the library
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

# Remove suid
sudo chmod -s hello
```
### Section `__RESTRICT` com segmento `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened runtime

Crie um novo certificado no Keychain e use-o para assinar o binário:
```bash
# Apply runtime protection
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
> Observe que, mesmo que existam binaries assinados com flags **`0x0(none)`**, eles podem receber a flag **`CS_RESTRICT`** dinamicamente quando executados e, portanto, esta técnica não funcionará neles.
>
> Você pode verificar se um proc possui essa flag com (obtenha [**csops aqui**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> e então verificar se a flag 0x800 está habilitada.

## References

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (`isRestricted()` / `__RESTRICT` check)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (inicialização do processo e inserção de libraries)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
