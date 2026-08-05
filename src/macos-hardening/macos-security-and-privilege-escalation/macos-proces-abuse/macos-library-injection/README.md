# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> **dyld のコードはオープンソース**であり、[https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) にあります。また、[https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) のような **URL** を使用して tar をダウンロードできます。

## **Dyld Process**

Dyld がバイナリ内にライブラリをロードする方法については、以下を参照してください。


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

これは [**Linux の LD_PRELOAD**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload) と同様です。実行されるプロセスに対して、パスから特定のライブラリをロードするよう指定できます（環境変数が有効な場合）。

この technique は **ASEP technique としても使用できます**。インストールされたすべてのアプリケーションには「Info.plist」という plist があり、`LSEnvironmental` というキーを使用して **環境変数を割り当てる**ことができます。

> [!TIP]
> 2012 年以降、**Apple は `DYLD_INSERT_LIBRARIES` の権限を大幅に制限**しています。以下のいずれかに該当する場合、プロセスは **restricted** とみなされます。この場合、`dyld` は環境からすべての `DYLD_*` 変数を削除します。
>
> - バイナリが `setuid/setgid` である
> - Mach-O に **`__RESTRICT/__restrict`** セクションがある
> - バイナリが hardened runtime で署名されており、AMFI が「path/print variables」権限を付与していない。つまり、[`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[3]</sup> がない
>   - バイナリの **entitlements** は、`codesign -dv --entitlements :- </path/to/bin>` で確認できます。
>
> 現在の `dyld` では、これは `dyld` だけで決定されるわけではありません。`ProcessConfig::Security::Security()` が `amfi_check_dyld_policy_self()` を介して **AMFI** に問い合わせ、その後 `pruneEnvVars()` を呼び出します。正確なコードの流れについては、以下の [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) で説明しています。

### Library Validation

バイナリが **`DYLD_INSERT_LIBRARIES`** 環境変数の使用を許可していたとしても、ロードするライブラリの署名を確認する場合、custom なライブラリはロードされません。

custom なライブラリをロードするには、バイナリに以下の **entitlements** のいずれかが必要です。

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

または、バイナリに **hardened runtime flag** も **library validation flag** も設定されていない必要があります。

バイナリに **hardened runtime** があるかどうかは、`codesign --display --verbose <bin>` を実行し、**`CodeDirectory`** の runtime フラグを確認することで確認できます。例: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

バイナリと同じ証明書で署名されたライブラリもロードできます。

この機能をどのように (ab)use し、制限を確認するかについては、以下を参照してください。


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> **以前の Library Validation の制限も** Dylib hijacking attacks に適用されることを忘れないでください。

Windows と同様に、MacOS でも **dylib を hijack** して、**アプリケーション**に **任意の** **コード**を**実行**させることができます（ただし、通常のユーザーからは、`.app` bundle 内に書き込んでライブラリを hijack するために TCC permission が必要になる可能性があるため、実際には不可能な場合があります）。\
しかし、**MacOS** アプリケーションがライブラリを **load** する方法は、Windows よりも **制限が厳しく**なっています。これは、**malware** 開発者がこの technique を **stealth** のために引き続き使用できる一方で、これを **privilege escalation** に **abuse** できる可能性は大幅に低いことを意味します。

第一に、**MacOS binaries** では、ロードするライブラリへのフルパスが指定されていることの方が **一般的**です。第二に、**MacOS はライブラリを探す際、$PATH のフォルダを決して検索しません**。

この機能に関連する **code** の主要部分は、`ImageLoader.cpp` の **`ImageLoader::recursiveLoadLibraries`** にあります。

macho binary がライブラリのロードに使用できる header Commands は **4 種類**あります。

- **`LC_LOAD_DYLIB`** command は、dylib をロードするための一般的な command です。
- **`LC_LOAD_WEAK_DYLIB`** command は前者と同様に動作しますが、dylib が見つからない場合、エラーなしで実行が継続されます。
- **`LC_REEXPORT_DYLIB`** command は、別のライブラリの symbols を proxy（または re-export）します。
- **`LC_LOAD_UPWARD_DYLIB`** command は、2 つのライブラリが相互に依存している場合に使用されます（これは _upward dependency_ と呼ばれます）。

ただし、dylib hijacking には **2 種類**あります。

- **Missing weak linked libraries**: これは、アプリケーションが **LC_LOAD_WEAK_DYLIB** で設定された、存在しないライブラリをロードしようとすることを意味します。その後、**attacker が想定される場所に dylib を配置すると、ロードされます**。
- link が「weak」であるということは、ライブラリが見つからなくてもアプリケーションの実行が継続されることを意味します。
- これに関連する **code** は `ImageLoaderMachO.cpp` の `ImageLoaderMachO::doGetDependentLibraries` function にあり、`LC_LOAD_WEAK_DYLIB` が true の場合にのみ `lib->required` が `false` になります。
- **binaries 内の weak linked libraries** は、以下で見つけられます（後で hijacking libraries の作成方法の例を示します）。
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **@rpath で設定されたもの**: Mach-O binaries には **`LC_RPATH`** および **`LC_LOAD_DYLIB`** commands を設定できます。これらの commands の **values** に基づき、**libraries** は **異なる directories** から **load** されます。
- **`LC_RPATH`** には、バイナリが libraries の load に使用するいくつかの folders の paths が含まれます。
- **`LC_LOAD_DYLIB`** には、load する特定の libraries への path が含まれます。これらの paths には **`@rpath`** を含めることができ、これは **`LC_RPATH`** の values に置き換えられます。`LC_RPATH` に複数の paths がある場合、libraries の load 先を検索するためにすべて使用されます。例:
- **`LC_LOAD_DYLIB`** に `@rpath/library.dylib` が含まれ、**`LC_RPATH`** に `/application/app.app/Contents/Framework/v1/` と `/application/app.app/Contents/Framework/v2/` が含まれている場合、両方の folders が `library.dylib` の load に使用されます。ライブラリが `[...]/v1/` に存在せず、attacker がそこに配置できる場合、**`LC_LOAD_DYLIB`** の paths の順序に従うため、`[...]/v2/` にあるライブラリの load を hijack できます。
- **binaries 内の rpath paths と libraries** は、以下で確認できます: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: **main executable file** を含む directory への **path** です。
>
> **`@loader_path`**: load command を含む **Mach-O binary** の **directory** への **path** です。
>
> - executable で使用した場合、**`@loader_path`** は実質的に **`@executable_path`** と同じです。
> - **dylib** で使用した場合、**`@loader_path`** は **dylib** への **path** を示します。

この機能を **abuse** して **privileges** を **escalate** する方法は、**root** によって **execute** された **application** が、attacker に write permissions がある folder 内の **library** を探しているという、まれなケースです。

> [!TIP]
> applications 内の **missing libraries** を見つけるための優れた **scanner** は、[**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) または [**CLI version**](https://github.com/pandazheng/DylibHijack) です。\
> この technique に関する technical details を含む優れた **report** は [**こちら**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) にあります。

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> **以前の Library Validation の制限も** Dlopen hijacking attacks の実行に適用されることを忘れないでください。

**`man dlopen`** より:

- path に slash character が **含まれていない**場合（つまり leaf name のみの場合）、**dlopen() は検索を実行します**。起動時に **`$DYLD_LIBRARY_PATH`** が設定されていた場合、dyld はまずその director**y** を検索します。次に、calling mach-o file または main executable が **`LC_RPATH`** を指定している場合、dyld はそれらの directories を検索します。次に、process が **unrestricted** であれば、dyld は current working directory を検索します。最後に、old binaries の場合、dyld はいくつかの fallbacks を試します。起動時に **`$DYLD_FALLBACK_LIBRARY_PATH`** が設定されていた場合、dyld は **それらの directories** を検索します。設定されていない場合、dyld は **`/usr/local/lib/`**（process が unrestricted の場合）、次に **`/usr/lib/`** を検索します（この情報は **`man dlopen`** から取得）。
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`（unrestricted の場合）
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/`（unrestricted の場合）
6. `/usr/lib/`

> [!CAUTION]
> name に slash がない場合、hijacking には 2 つの方法があります。
>
> - **`LC_RPATH`** のいずれかが **writable** である場合（ただし signature が確認されるため、これには binary が unrestricted であることも必要です）
> - binary が **unrestricted** であり、CWD から何かを load できる場合（または記載されている env variables のいずれかを abuse する場合）

- path が framework path のように見える場合（例: `/stuff/foo.framework/foo`）、起動時に **`$DYLD_FRAMEWORK_PATH`** が設定されていると、dyld はまずその directory で **framework partial path**（例: `foo.framework/foo`）を検索します。次に、dyld は **指定された path をそのまま**試します（relative paths には current working directory を使用）。最後に、old binaries の場合、dyld はいくつかの fallbacks を試します。起動時に **`$DYLD_FALLBACK_FRAMEWORK_PATH`** が設定されていた場合、dyld はそれらの directories を検索します。設定されていない場合、まず **`/Library/Frameworks`**（process が unrestricted の macOS の場合）、次に **`/System/Library/Frameworks`** を検索します。
1. `$DYLD_FRAMEWORK_PATH`
2. 指定された path（unrestricted の場合、relative paths には current working directory を使用）
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks`（unrestricted の場合）
5. `/System/Library/Frameworks`

> [!CAUTION]
> framework path の場合、hijack の方法は次のとおりです。
>
> - process が **unrestricted** であれば、CWD からの **relative path** または上述の env variables を abuse する（process が restricted の場合、DYLD\_\* env vars が削除されることは docs に記載されていません）

- path に slash が **含まれている**が framework path ではない場合（つまり dylib への full path または partial path の場合）、dlopen() はまず（設定されていれば）**`$DYLD_LIBRARY_PATH`** を検索します（path の leaf part を使用）。次に、dyld は **指定された path** を試します（relative paths には current working directory を使用しますが、**unrestricted processes の場合のみ**）。最後に、older binaries の場合、dyld は fallbacks を試します。起動時に **`$DYLD_FALLBACK_LIBRARY_PATH`** が設定されていた場合、dyld はその directories を検索します。設定されていない場合、dyld は **`/usr/local/lib/`**（process が unrestricted の場合）、次に **`/usr/lib/`** を検索します。
1. `$DYLD_LIBRARY_PATH`
2. 指定された path（unrestricted の場合、relative paths には current working directory を使用）
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/`（unrestricted の場合）
5. `/usr/lib/`

> [!CAUTION]
> name に slash があり framework ではない場合、hijack の方法は次のとおりです。
>
> - binary が **unrestricted** であり、CWD または `/usr/local/lib` から何かを load できる場合（または記載されている env variables のいずれかを abuse する場合）

> [!TIP]
> Note: **dlopen searching を制御する configuration files はありません**。
>
> Note: main executable が **set\[ug]id binary** または entitlements 付きで codesigned されている場合、**すべての environment variables は無視され**、full path のみ使用できます（詳細については [check DYLD_INSERT_LIBRARIES restrictions](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) を参照してください）。
>
> Note: Apple platforms は「universal」files を使用して 32-bit と 64-bit の libraries を結合します。つまり、32-bit と 64-bit 用に**別々の search paths はありません**。
>
> Note: Apple platforms では、ほとんどの OS dylibs が **dyld cache に結合**されており、disk 上には存在しません。そのため、OS dylib が存在するかを事前確認するために **`stat()`** を呼び出しても機能しません。ただし、**`dlopen_preflight()`** は **`dlopen()`** と同じ手順を使用して、compatible な mach-o file を検索します。

**Check paths**

以下の code ですべての options を確認します。
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
コンパイルして実行すると、**各ライブラリの検索に失敗した場所**を確認できます。また、**FS logsをフィルタリング**することもできます：
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

**privileged binary/app**（SUID や強力な entitlements を持つバイナリなど）が、相対パスの library（`@executable_path` や `@loader_path` などを使用）を**読み込み**、**Library Validation が無効**になっている場合、攻撃者が相対パスで読み込まれる library を**変更可能な場所**へバイナリを移動し、それを悪用してプロセスに code を inject できる可能性があります。

## Prune `DYLD_*` env variables

古い `dyld` の release（`dyld2.cpp`）では、`issetugid()`、`hasRestrictedSegment()`、`csops(CS_OPS_STATUS)` を使用して、プロセス内でこの判断を行っていました。**current `dyld` では、この判断は AMFI に委譲されており**、code は `dyld/DyldProcessConfig.cpp` の `ProcessConfig::Security::Security()` にあります：<sup>[1]</sup>
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
この内容から、2つの点を取り出す価値があります。

- **macOS / Mac Catalyst / DriverKit** でのみ pruning が行われます — そして AMFI が `allowEnvVarsPrint`、`allowEnvVarsPath`、`allowEnvVarsSharedCache` のいずれも許可しなかった場合に限られます。
- AMFI query には executable 自身のプロパティが渡されます:
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
ここで `isRestricted()` は文字どおり `__RESTRICT` セグメントのチェックです（`mach_o/UnsafeHeader.cpp`）：<sup>[2]</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()` はその後、名前が `DYLD_` で始まる **すべて** の変数を削除し、`apple[]` パラメーターを詰めて移動するため、制限されたプロセスの子プロセスもそれらを継承しません：
```cpp
// For security, setuid programs ignore DYLD_* environment variables.
// Additionally, the DYLD_* enviroment variables are removed
// from the environment, so that any child processes doesn't see them.
for ( const char* const* s = proc.envp; *s != NULL; s++ ) {
if ( strncmp(*s, "DYLD_", 5) != 0 ) {
*d++ = *s;
}
...
```
> [!TIP]
> 実際の影響: プロセスが制限されている場合、**`DYLD_*` は削除されます**。これには setuid/setgid、`__RESTRICT/__restrict` セクション、または AMFI が path/print flags の付与を拒否する hardened-runtime/entitled binaries が該当します。一方、プロセスが **library validation**（`CS_REQUIRE_LV`）のみを持つ場合、変数は残りますが、挿入される dylib は **同じ Team ID**（または Apple）によって署名されている必要があります。そのため、実際に code を配置するには、library validation を無効化する entitlement のいずれかが必要です。

判定が AMFI に委ねられるようになったため、特定の binary が何を取得するかを知る最速の方法は、`dyld` 自体ではなく、AMFI が参照するもの、つまり entitlements と signing flags を確認することです:
```bash
BIN=/path/to/bin
codesign -d --entitlements :- "$BIN" 2>/dev/null | \
egrep "allow-dyld-environment-variables|disable-library-validation|clear-library-validation"
codesign -dvvv "$BIN" 2>&1 | egrep "flags=|TeamIdentifier="
otool -l "$BIN" | grep -A2 __RESTRICT
```
## 制限の確認

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
### セクション `__RESTRICT` とセグメント `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened runtime

Keychain に新しい証明書を作成し、それを使用してバイナリに署名します：
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
> **`0x0(none)`** の flags で署名された binary であっても、実行時に動的に **`CS_RESTRICT`** flag が付与される場合があるため、この technique は機能しません。
>
> proc にこの flag があるかどうかは、（[**csops here**](https://github.com/axelexic/CSOps) から取得して）次のコマンドで確認できます。
>
> ```bash
> csops -status <pid>
> ```
>
> 次に、flag 0x800 が有効になっているか確認します。

## References

- [1] [dyld — `dyld/DyldProcessConfig.cpp`（`ProcessConfig::Security`、`getAMFI`、`pruneEnvVars`）](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp`（`isRestricted()` / `__RESTRICT` check）](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp`（process startup and library insertion）](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)

{{#include ../../../../banners/hacktricks-training.md}}
