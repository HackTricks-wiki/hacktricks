# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> **dyld のコードは open source** であり、[https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) で確認できます。また、[https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) のような **URL** を使用して tar としてダウンロードできます。

## **Dyld Process**

Dyld がバイナリ内のライブラリをどのようにロードするかは、以下を確認してください。


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

これは [**Linux の LD_PRELOAD**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload) に似ています。実行されるプロセスに対して、パスから特定のライブラリをロードするよう指定できます（env var が有効な場合）<sup>[[4]](#references)</sup>

この technique は **ASEP technique としても使用できます**。インストールされているすべてのアプリケーションには、`LSEnvironmental` というキーを使用して **environmental variables の割り当て**を可能にする "Info.plist" という plist があるためです。

> [!TIP]
> 2012 年以降、**Apple は** **`DYLD_INSERT_LIBRARIES`** の **権限を大幅に制限**しています。次のいずれかに該当する場合、プロセスは **restricted** とみなされます。その場合、`dyld` は環境からすべての `DYLD_*` variable を削除します。
>
> - バイナリが `setuid/setgid` である
> - Mach-O に **`__RESTRICT/__restrict`** section がある
> - バイナリが hardened runtime で署名されており、AMFI が "path/print variables" permissions を付与していない。つまり [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables) がない<sup>[[3]](#references)</sup>
>   - バイナリの **entitlements** は次で確認できます: `codesign -dv --entitlements :- </path/to/bin>`
>
> 現在の `dyld` では、これはもはや `dyld` だけで決定されません。`ProcessConfig::Security::Security()` は `amfi_check_dyld_policy_self()` を介して **AMFI** に問い合わせ、その後 `pruneEnvVars()` を呼び出します。正確なコードについては、以下の [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) で説明しています。

### Library Validation

バイナリが **`DYLD_INSERT_LIBRARIES`** environment variable を許可していても、ライブラリの signature を検証する場合、custom library はロードされません。

custom library をロードするには、バイナリに次の **entitlements** のいずれかが必要です。

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

または、バイナリに **hardened runtime flag** または **library validation flag** が設定されていない必要があります。

`codesign --display --verbose <bin>` を使用し、**`CodeDirectory`** 内の runtime flag を確認することで、バイナリに **hardened runtime** があるか確認できます。例: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

バイナリと同じ certificate で署名されている library もロードできます。

これを (ab)use し、restrictions を確認する方法の例は以下にあります。


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> **以前の Library Validation restrictions も、Dylib hijacking attacks の実行に適用される**ことを忘れないでください。

Windows と同様に、MacOS でも **dylib を hijack** して、**applications** に **arbitrary** **code** を **execute** させることができます（ただし、通常の user からは、`.app` bundle 内に書き込んで library を hijack するために TCC permission が必要になる可能性があるため、実際には不可能な場合があります）。\
しかし、**MacOS** applications が library を **load** する方法は Windows よりも **restricted** です。そのため、**malware** developers はこの technique を **stealth** のために使用できますが、これを **abuse して privileges を escalate できる可能性ははるかに低くなります**。

まず、**MacOS binaries では、ロードする libraries の full path が指定されていることの方が一般的**です。次に、**MacOS は libraries を探すために** **$PATH** の folders を **決して検索しません**。

この機能に関連する **code** の **main** 部分は、`ImageLoader.cpp` の **`ImageLoader::recursiveLoadLibraries`** にあります。

macho binary が libraries をロードするために使用できる header Commands は **4 種類**あります。

- **`LC_LOAD_DYLIB`** command は、dylib をロードするための一般的な command です。
- **`LC_LOAD_WEAK_DYLIB`** command は前のものと同様に動作しますが、dylib が見つからない場合でも、error なしで execution が継続します。
- **`LC_REEXPORT_DYLIB`** command は、別の library の symbols を proxy（または re-export）します。
- **`LC_LOAD_UPWARD_DYLIB`** command は、2 つの libraries が相互に依存する場合に使用されます（これは _upward dependency_ と呼ばれます）。

ただし、dylib hijacking には **2 種類**あります。

- **Missing weak linked libraries**: これは、application が **LC_LOAD_WEAK_DYLIB** で設定された、存在しない library をロードしようとすることを意味します。その後、**attacker が期待される場所に dylib を配置するとロードされます**。
- link が "weak" であるため、library が見つからなくても application は実行を継続します。
- これに関連する **code** は `ImageLoader.cpp` の `ImageLoaderMachO::doGetDependentLibraries` function にあり、`LC_LOAD_WEAK_DYLIB` が true の場合のみ `lib->required` が `false` になります。
- **weak linked libraries** は、次のコマンドで binaries から **find** できます（後で hijacking libraries の作成方法の例を示します）。
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configured with @rpath**: Mach-O binaries には **`LC_RPATH`** および **`LC_LOAD_DYLIB`** commands を含めることができます。これらの commands の **values** に基づき、**libraries** は **異なる directories** から **load** されます。
- **`LC_RPATH`** には、binary が libraries の load に使用する folders の paths が含まれます。
- **`LC_LOAD_DYLIB`** には、load する特定の libraries への path が含まれます。これらの paths には **`@rpath`** を含めることができ、その場合 **`LC_RPATH`** の values に置き換えられます。**`LC_RPATH`** に複数の paths がある場合、library の load 先を検索するためにすべて使用されます。例:
- **`LC_LOAD_DYLIB`** に `@rpath/library.dylib` が含まれ、**`LC_RPATH`** に `/application/app.app/Contents/Framework/v1/` と `/application/app.app/Contents/Framework/v2/` が含まれる場合、両方の folders が `library.dylib` の load に使用されます。library が `[...]/v1/` に存在せず、attacker がそこに配置できる場合、**`LC_LOAD_DYLIB`** の paths の順序に従うため、`[...]/v2/` にある library の load を hijack できます。
- **rpath paths と libraries** は、次で binaries から **find** できます: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: **main executable file** を含む directory への **path** です。
>
> **`@loader_path`**: load command を含む **Mach-O binary** の **directory** への **path** です。
>
> - executable 内で使用する場合、**`@loader_path`** は実質的に **`@executable_path`** と同じです。
> - **dylib** 内で使用する場合、**`@loader_path`** は **dylib** への **path** を示します。

この機能を **abuse して privileges を escalate** する方法は、**root** によって **execute** される **application** が、attacker に write permissions のある folder 内の **library を探しているという、まれなケース**です。

> [!TIP]
> applications 内の **missing libraries** を見つける優れた **scanner** は [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) または [**CLI version**](https://github.com/pandazheng/DylibHijack) です。\
> この technique の **technical details を含む優れた report** は[**こちら**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x)にあります。

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> **以前の Library Validation restrictions も、Dlopen hijacking attacks の実行に適用される**ことを忘れないでください。

**`man dlopen`** より:

- path に slash character が **含まれない**場合（つまり leaf name のみの場合）、**dlopen() は searching を実行**します。起動時に **`$DYLD_LIBRARY_PATH`** が設定されていた場合、dyld は最初にその **directory** を **look** します。次に、calling mach-o file または main executable が **`LC_RPATH`** を指定している場合、dyld はそれらの directories を **look** します。次に、process が **unrestricted** であれば、dyld は current working directory を検索します。最後に、old binaries では、dyld はいくつかの fallbacks を試します。起動時に **`$DYLD_FALLBACK_LIBRARY_PATH`** が設定されていた場合、dyld は **それらの directories** を検索します。そうでなければ、dyld は **`/usr/local/lib/`**（process が unrestricted の場合）、次に **`/usr/lib/`** を **look** します（この info は **`man dlopen`** から取得）。
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`（unrestricted の場合）
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/`（unrestricted の場合）
6. `/usr/lib/`

> [!CAUTION]
> name に slashes がない場合、hijacking には 2 つの方法があります。
>
> - **`LC_RPATH`** のいずれかが **writable** である場合（ただし signature が check されるため、binary が unrestricted であることも必要です）
> - binary が **unrestricted** であり、CWD から何かを load できる場合（または前述の env variables のいずれかを abuse する場合）

- path が framework path のように見える場合（例: `/stuff/foo.framework/foo`）、起動時に **`$DYLD_FRAMEWORK_PATH`** が設定されていれば、dyld は最初にその directory で **framework partial path**（例: `foo.framework/foo`）を探します。次に、dyld は **supplied path をそのまま**試します（relative paths には current working directory を使用）。最後に、old binaries では、dyld はいくつかの fallbacks を試します。起動時に **`$DYLD_FALLBACK_FRAMEWORK_PATH`** が設定されていた場合、dyld はそれらの directories を検索します。そうでなければ、**`/Library/Frameworks`**（macOS で process が unrestricted の場合）、次に **`/System/Library/Frameworks`** を検索します。
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path（unrestricted の場合、relative paths には current working directory を使用）
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks`（unrestricted の場合）
5. `/System/Library/Frameworks`

> [!CAUTION]
> framework path の場合、hijack の方法は次のとおりです。
>
> - process が **unrestricted** であり、CWD からの **relative path** または前述の env variables を abuse する場合（process が restricted の場合は `DYLD\_\*` env vars が削除されることは docs に記載されていません）

- path に slash が **含まれるが framework path ではない**場合（つまり dylib への full path または partial path の場合）、dlopen() はまず（設定されていれば）**`$DYLD_LIBRARY_PATH`** を調べます（path の leaf part を使用）。次に、dyld は **supplied path** を試します（relative paths には current working directory を使用しますが、これは unrestricted processes の場合のみです）。最後に、older binaries では、dyld は fallbacks を試します。起動時に **`$DYLD_FALLBACK_LIBRARY_PATH`** が設定されていた場合、dyld はそれらの directories を検索します。そうでなければ、dyld は **`/usr/local/lib/`**（process が unrestricted の場合）、次に **`/usr/lib/`** を調べます。
1. `$DYLD_LIBRARY_PATH`
2. supplied path（unrestricted の場合、relative paths には current working directory を使用）
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/`（unrestricted の場合）
5. `/usr/lib/`

> [!CAUTION]
> name に slashes があり framework ではない場合、hijack の方法は次のとおりです。
>
> - binary が **unrestricted** であり、CWD または `/usr/local/lib` から何かを load できる場合（または前述の env variables のいずれかを abuse する場合）

> [!TIP]
> Note: **dlopen searching を control する configuration files はありません**。
>
> Note: main executable が **set\[ug]id binary** または entitlements 付きで codesigned されている場合、**すべての environment variables は無視**され、full path のみを使用できます（詳細は [check DYLD_INSERT_LIBRARIES restrictions](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) を確認してください）。
>
> Note: Apple platforms は、32-bit と 64-bit libraries を結合するために "universal" files を使用します。つまり、**32-bit と 64-bit に分かれた search paths はありません**。
>
> Note: Apple platforms では、ほとんどの OS dylibs は **dyld cache に結合**されており、disk 上には存在しません。そのため、OS dylib が存在するかを事前確認するために **`stat()`** を呼び出しても機能しません。ただし、**`dlopen_preflight()`** は **`dlopen()`** と同じ手順を使用して compatible な mach-o file を見つけます。

**Check paths**

次の code ですべての options を確認します。
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
コンパイルして実行すると、**各ライブラリがどこで検索に失敗したか**を確認できます。また、**FS logsをフィルタリング**することもできます：
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

**privileged binary/app**（SUID や強力な entitlements を持つバイナリなど）が**相対パス**の library（`@executable_path` や `@loader_path` を使用するものなど）を**ロード**し、**Library Validation** が無効になっている場合、攻撃者が相対パスでロードされる library を**変更可能な場所**へバイナリを移動し、それを悪用してプロセスにコードを inject できる可能性があります。

## Prune `DYLD_*` env variables

古い `dyld` のリリース（`dyld2.cpp`）では、`issetugid()`、`hasRestrictedSegment()`、`csops(CS_OPS_STATUS)` を使用して、プロセス内でこの判断を行っていました。**現在の `dyld` では判断が AMFI に委任されており**、コードは `dyld/DyldProcessConfig.cpp` の `ProcessConfig::Security::Security()` にあります。<sup>[[1]](#references)</sup>
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
これから抽出すべき点は 2 つあります。

- **macOS / Mac Catalyst / DriverKit** でのみ pruning が発生する — かつ、AMFI が `allowEnvVarsPrint`、`allowEnvVarsPath`、`allowEnvVarsSharedCache` のいずれも許可していない場合に限られる。
- AMFI query には、実行ファイル自身のプロパティが渡される：
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
`pruneEnvVars()` はその後、名前が `DYLD_` で始まる **すべての** 変数を削除し、`apple[]` パラメータを詰めて移動するため、restricted process の子プロセスもそれらを継承しません:
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
> 実際の結果: **プロセスが制限されている場合、`DYLD_*` は削除されます** — setuid/setgid、`__RESTRICT/__restrict` セクション、または AMFI が path/print flags の付与を拒否する hardened-runtime/entitled binaries が該当します。一方、プロセスが **library validation**（`CS_REQUIRE_LV`）のみを持つ場合、変数は残りますが、挿入される dylib は **同じ Team ID**（または Apple）によって署名されている必要があります。そのため、実際に code を配置するには library-validation-disabling entitlements のいずれかが必要です。

判断が AMFI によって行われるようになったため、特定の binary が何を得るかを知る最も速い方法は、`dyld` 自体ではなく、AMFI が参照するもの — entitlements と signing flags — を確認することです:
```bash
BIN=/path/to/bin
codesign -d --entitlements :- "$BIN" 2>/dev/null | \
egrep "allow-dyld-environment-variables|disable-library-validation|clear-library-validation"
codesign -dvvv "$BIN" 2>&1 | egrep "flags=|TeamIdentifier="
otool -l "$BIN" | grep -A2 __RESTRICT
```
## 制限事項の確認

### SUID と SGID
```bash
# Make it owned by root and suid
sudo chown root hello
sudo chmod +s hello
# Insert the library
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

# Remove suid
sudo chmod -s hello
```
### `__RESTRICT` セクションと `__restrict` セグメント
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
> バイナリが **`0x0(none)`** フラグで署名されていても、実行時に **`CS_RESTRICT`** フラグが動的に付与される可能性があるため、この technique は機能しない場合があります。
>
> proc にこのフラグがあるかどうかは、（[**csops here**](https://github.com/axelexic/CSOps) を取得して）次のコマンドで確認できます。
>
> ```bash
> csops -status <pid>
> ```
>
> 次に、フラグ 0x800 が有効になっているか確認します。

## References

- [1] [dyld — `dyld/DyldProcessConfig.cpp`（`ProcessConfig::Security`、`getAMFI`、`pruneEnvVars`）](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp`（`isRestricted()` / `__RESTRICT` check）](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp`（process startup and library insertion）](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
