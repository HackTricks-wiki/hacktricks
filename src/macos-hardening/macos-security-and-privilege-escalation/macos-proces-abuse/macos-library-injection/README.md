# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> **dyld のコードは open source** であり、[https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) で確認できます。また、[https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) のような **URL** を使って tar としてダウンロードできます。

## **Dyld Process**

Dyld がバイナリ内部にライブラリをロードする方法については、以下を参照してください。


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

これは [**Linux の LD_PRELOAD**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload) に似ています。実行されるプロセスに対して、パスから特定のライブラリをロードするよう指定できます（環境変数が有効な場合）<sup>[[4]](#references)</sup>

このテクニックは **ASEP technique** としても **使用できます**。インストールされたすべてのアプリケーションには「Info.plist」という plist があり、`LSEnvironmental` というキーを使って **環境変数を割り当てる**ことができます。

> [!TIP]
> 2012 年以降、**Apple は `DYLD_INSERT_LIBRARIES` の権限を大幅に縮小**しました。以下のいずれかに該当する場合、プロセスは **restricted** と見なされ、その後 `dyld` は環境からすべての `DYLD_*` 変数を削除します。
>
> - バイナリが `setuid/setgid` である
> - Mach-O に **`__RESTRICT/__restrict`** セクションがある
> - バイナリが hardened runtime で署名されており、AMFI が「path/print variables」権限を付与していない。つまり [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables) がない<sup>[[3]](#references)</sup>
>   - バイナリの **entitlements** は次のコマンドで確認できます: `codesign -dv --entitlements :- </path/to/bin>`
>
> 現在の `dyld` では、これはもはや `dyld` だけで決定されません。`ProcessConfig::Security::Security()` が `amfi_check_dyld_policy_self()` を介して **AMFI** に問い合わせ、その後 `pruneEnvVars()` を呼び出します。正確なコードについては、以下の [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) で確認できます。

### Library Validation

バイナリが **`DYLD_INSERT_LIBRARIES`** 環境変数を許可していても、ライブラリの署名を検証する場合、custom library はロードされません。

custom library をロードするには、バイナリに以下の **entitlements** のいずれかが必要です。

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

または、バイナリに **hardened runtime flag** も **library validation flag** も付いていない必要があります。

バイナリに **hardened runtime** があるかどうかは、`codesign --display --verbose <bin>` を実行し、**`CodeDirectory`** の runtime flag を確認することで判定できます。例: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

また、バイナリと同じ証明書で署名されたライブラリもロードできます。

これをどのように (ab)use するか、および restrictions を確認する方法については、以下を参照してください。


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> **以前の Library Validation restrictions も、Dylib hijacking attacks の実行に適用される**ことを忘れないでください。

Windows と同様に、macOS では **dylibs を hijack** して、**applications に arbitrary code を実行させる**ことができます。通常の user account からは不可能な場合があります。ライブラリを hijack するために `.app` bundle 内へ書き込むには、TCC permission が必要になることがあるためです。\
ただし、**macOS** applications がライブラリを **load** する方法は、Windows よりも **restricted** です。Malware developers はこのテクニックを **stealth** のために利用できますが、privilege escalation に悪用することは、はるかに起こりにくくなっています。

まず、**MacOS binaries がロードするライブラリの full path を示している**ことのほうが **common** です。次に、**MacOS はライブラリを探すために** **$PATH** の folders を **決して search しません**。

この機能に関係する **code** の **main** 部分は、`ImageLoader.cpp` の **`ImageLoader::recursiveLoadLibraries`** にあります。

macho binary がライブラリのロードに使用できる header Commands は、**4 種類**あります。

- **`LC_LOAD_DYLIB`** command は、dylib をロードするための一般的な command です。
- **`LC_LOAD_WEAK_DYLIB`** command は前のものと同様に動作しますが、dylib が見つからない場合、エラーなしで execution が続行されます。
- **`LC_REEXPORT_DYLIB`** command は、別の library の symbols を proxy（または re-export）します。
- **`LC_LOAD_UPWARD_DYLIB`** command は、2 つの libraries が相互に依存する場合に使用されます（これは _upward dependency_ と呼ばれます）。

ただし、dylib hijacking には **2 種類**あります。

- **Missing weak linked libraries**: これは、application が **LC_LOAD_WEAK_DYLIB** で設定された、存在しない library をロードしようとすることを意味します。その後、**attacker が想定された場所に dylib を配置すると、それがロードされます**。
- link が "weak" であるということは、library が見つからなくても application が実行を続けることを意味します。
- これに **related** な **code** は `ImageLoaderMachO.cpp` の `ImageLoaderMachO::doGetDependentLibraries` function にあり、`LC_LOAD_WEAK_DYLIB` が true の場合にのみ `lib->required` が `false` になります。
- **weak linked libraries** は、以下のコマンドで binaries から **find** できます（後で hijacking libraries の作成方法の example があります）。
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configured with @rpath**: Mach-O binaries には **`LC_RPATH`** および **`LC_LOAD_DYLIB`** commands を含めることができます。これらの commands の **values** に基づいて、**libraries** は **different directories** から **load** されます。
- **`LC_RPATH`** には、binary が libraries のロードに使用する folders の paths が含まれます。
- **`LC_LOAD_DYLIB`** には、ロードする特定の libraries への path が含まれます。これらの paths には **`@rpath`** を含めることができ、これは **`LC_RPATH`** の values に置き換えられます。**`LC_RPATH`** に複数の paths がある場合、load する library の search にすべて使用されます。Example:
- **`LC_LOAD_DYLIB`** に `@rpath/library.dylib` が含まれ、**`LC_RPATH`** に `/application/app.app/Contents/Framework/v1/` と `/application/app.app/Contents/Framework/v2/` が含まれている場合、両方の folders が `library.dylib` のロードに使用されます。library が `[...]/v1/` に存在せず、attacker がそこに配置できる場合、**`LC_LOAD_DYLIB`** の paths の order が守られるため、`[...]/v2/` にある library の load を hijack できます。
- binaries 内の **rpath paths と libraries** は、次のコマンドで **find** できます: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: **main executable file** を含む directory への **path** です。
>
> **`@loader_path`**: load command を含む **Mach-O binary** の **directory** への **path** です。
>
> - executable 内で使用した場合、**`@loader_path`** は実質的に **`@executable_path`** と同じです。
> - **dylib** 内で使用した場合、**`@loader_path`** は **dylib への path** を示します。

この機能を悪用して **privilege escalation** を行う方法は、**root によって**実行されている **application** が、attacker に write permissions のある folder 内の **library を探している**という稀なケースです。

> [!TIP]
> applications 内の **missing libraries** を見つけるための便利な **scanner** は [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) または [**CLI version**](https://github.com/pandazheng/DylibHijack) です。\
> このテクニックに関する **technical details を含む便利な report** は[**こちら**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x)にあります。

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> **以前の Library Validation restrictions も、Dlopen hijacking attacks の実行に適用される**ことを忘れないでください。

**`man dlopen`** より:

- path **に slash character が含まれていない**場合（つまり leaf name のみの場合）、**dlopen() は search を実行します**。launch 時に **`$DYLD_LIBRARY_PATH`** が設定されていた場合、dyld はまずその directory を **look in** します。次に、calling mach-o file または main executable が **`LC_RPATH`** を指定している場合、dyld はそれらの directories を **look in** します。次に、process が **unrestricted** の場合、dyld は current working directory を search します。最後に、old binaries では、dyld はいくつかの fallbacks を試します。launch 時に **`$DYLD_FALLBACK_LIBRARY_PATH`** が設定されていた場合、dyld は **その directories** を search します。設定されていない場合、dyld は **`/usr/local/lib/`**（process が unrestricted の場合）、続いて **`/usr/lib/`** を **look in** します（この情報は **`man dlopen`** から取得）。
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> name に slashes がない場合、hijacking を行う方法は 2 つあります。
>
> - **`LC_RPATH`** のいずれかが **writable** である場合（ただし signature が check されるため、この場合は binary も unrestricted である必要があります）
> - binary が **unrestricted** であり、CWD から何かを load できる場合（または前述の environment variables のいずれかを悪用する場合）

- path が framework path のように見える場合（例: `/stuff/foo.framework/foo`）、launch 時に **`$DYLD_FRAMEWORK_PATH`** が設定されていれば、dyld はまずその directory で **framework partial path**（例: `foo.framework/foo`）を探します。次に、dyld は **supplied path** をそのまま試します（relative paths には current working directory を使用）。最後に、old binaries では、dyld はいくつかの fallbacks を試します。launch 時に **`$DYLD_FALLBACK_FRAMEWORK_PATH`** が設定されていれば、dyld はそれらの directories を search します。設定されていない場合、**`/Library/Frameworks`**（macOS で process が unrestricted の場合）、続いて **`/System/Library/Frameworks`** を search します。
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> framework path の場合、それを hijack する方法は次のとおりです。
>
> - process が **unrestricted** であれば、CWD からの **relative path** または前述の environment variables を悪用する（process が restricted の場合、DYLD\_\* env vars が削除されることは docs に記載されていなくても同様です）

- path **に slash が含まれているが framework path ではない**場合（つまり dylib への full path または partial path の場合）、dlopen() はまず（設定されていれば）**`$DYLD_LIBRARY_PATH`** を path の leaf 部分とともに search します。次に、dyld は **supplied path** を試します（relative paths には current working directory を使用しますが、**unrestricted processes の場合のみ**）。最後に、older binaries では、dyld は fallbacks を試します。launch 時に **`$DYLD_FALLBACK_LIBRARY_PATH`** が設定されていれば、dyld はそれらの directories を search します。設定されていない場合、dyld は **`/usr/local/lib/`**（process が unrestricted の場合）、続いて **`/usr/lib/`** を **look in** します。
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> name に slashes があり framework ではない場合、それを hijack する方法は次のとおりです。
>
> - binary が **unrestricted** で、CWD または `/usr/local/lib` から何かを load できる場合（または前述の environment variables のいずれかを悪用する場合）

> [!TIP]
> Note: **dlopen searching を制御する** configuration files はありません。
>
> Note: main executable が **set\[ug]id binary** または entitlements 付きで codesigned されている場合、**すべての environment variables が無視され**、full path のみ使用できます（詳細は [check DYLD_INSERT_LIBRARIES restrictions](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) を参照してください）。
>
> Note: Apple platforms は、32-bit と 64-bit の libraries を結合するために "universal" files を使用します。つまり、**32-bit と 64-bit の separate search paths はありません**。
>
> Note: Apple platforms では、ほとんどの OS dylibs が **dyld cache に結合**されており、disk 上には存在しません。そのため、OS dylib が存在するかを事前確認するために **`stat()`** を呼び出しても **機能しません**。ただし、**`dlopen_preflight()`** は **`dlopen()`** と同じ手順を使用して compatible mach-o file を探します。

**Check paths**

次の code を使って、すべての options を確認します。
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
コンパイルして実行すると、**各ライブラリの検索に失敗した場所を確認できます**。また、**FS logsをfilterする**こともできます：
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

**privileged binary/app**（SUID や強力な entitlements を持つバイナリなど）が**相対パス**の library（`@executable_path` や `@loader_path` を使用する場合など）を**loading**し、**Library Validation**が無効になっている場合、attacker が相対パスで読み込まれる library を**modify**できる場所へバイナリを移動し、それを悪用してプロセスへ code を inject できる可能性があります。

## `DYLD_*` env variables の除去

古い `dyld` のリリース（`dyld2.cpp`）では、`issetugid()`、`hasRestrictedSegment()`、`csops(CS_OPS_STATUS)` を使用して、プロセス内でこの判断を行っていました。**current `dyld` では、この判断は AMFI に委任されており**、コードは `dyld/DyldProcessConfig.cpp` の `ProcessConfig::Security::Security()` にあります：<sup>[[1]](#references)</sup>
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
この内容から、次の2点を抽出できます。

- **macOS / Mac Catalyst / DriverKit** でのみ、かつ AMFI が `allowEnvVarsPrint`、`allowEnvVarsPath`、`allowEnvVarsSharedCache` のいずれも許可しなかった場合にのみ、Pruning が行われる。
- AMFI のクエリには、実行ファイル自身のプロパティが渡される：
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
ここで `isRestricted()` は文字どおり `__RESTRICT` セグメントのチェックです（`mach_o/UnsafeHeader.cpp`）：<sup>[[2]](#references)</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()` はその後、名前が `DYLD_` で始まる **すべての** 変数を取り除き、`apple[]` パラメータを詰めて移動するため、制限されたプロセスの子プロセスもそれらを継承しません。
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
> 実際の影響: **プロセスが制限されている場合、`DYLD_*` は削除されます** — setuid/setgid、`__RESTRICT/__restrict` セクション、または AMFI が path/print flags の付与を拒否する hardened-runtime/entitled binary が該当します。一方、プロセスが **library validation**（`CS_REQUIRE_LV`）のみを持つ場合、変数は維持されますが、挿入される dylib は **同じ Team ID**（または Apple）によって署名されている必要があります。そのため、実際に code を配置するには library-validation-disabling entitlements のいずれかが必要です。

判定が AMFI によって行われるようになったため、特定の binary が何を取得するかを知る最速の方法は、`dyld` 自体ではなく、AMFI が参照する entitlements と signing flags を確認することです。
```bash
BIN=/path/to/bin
codesign -d --entitlements :- "$BIN" 2>/dev/null | \
egrep "allow-dyld-environment-variables|disable-library-validation|clear-library-validation"
codesign -dvvv "$BIN" 2>&1 | egrep "flags=|TeamIdentifier="
otool -l "$BIN" | grep -A2 __RESTRICT
```
## 制限の確認

### SUIDとSGID
```bash
# Make it owned by root and suid
sudo chown root hello
sudo chmod +s hello
# Insert the library
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

# Remove suid
sudo chmod -s hello
```
### セグメント `__restrict` を含むセクション `__RESTRICT`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened runtime

Keychain に新しい証明書を作成し、それを使用してバイナリに署名します：
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
> **`0x0(none)`** フラグで署名されたバイナリであっても、実行時に **`CS_RESTRICT`** フラグが動的に付与される場合があるため、この technique は機能しないことに注意してください。
>
> 以下を使用して、proc にこのフラグがあるか確認できます（[**csopsはこちら**](https://github.com/axelexic/CSOps)から取得）:
>
> ```bash
> csops -status <pid>
> ```
>
> 次に、フラグ 0x800 が有効になっているか確認します。

## References

- [1] [dyld — `dyld/DyldProcessConfig.cpp`（`ProcessConfig::Security`、`getAMFI`、`pruneEnvVars`）](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp`（`isRestricted()` / `__RESTRICT` の確認）](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp`（プロセスの起動とライブラリの挿入）](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
