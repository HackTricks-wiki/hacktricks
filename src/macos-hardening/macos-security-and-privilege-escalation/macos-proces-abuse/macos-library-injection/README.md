# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> **dyld のコードはオープンソース**であり、[https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) で確認できます。また、[https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) のような **URL** を使用して tar でダウンロードできます。

## **Dyld Process**

Dyld がバイナリ内部にライブラリをロードする方法については、以下を確認してください。


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

これは [**Linux の LD_PRELOAD**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload) のようなものです。実行されるプロセスに対して、パスから特定のライブラリをロードするよう指定できます（環境変数が有効な場合）。

この technique は **ASEP technique** としても **使用できます**。インストールされているすべてのアプリケーションには `"Info.plist"` という plist があり、`LSEnvironmental` というキーを使用して **環境変数を割り当てる**ことができます。

> [!TIP]
> 2012 年以降、**Apple は `DYLD_INSERT_LIBRARIES` の権限を大幅に制限**しています。
>
> コードに移動し、**`src/dyld.cpp`** を確認してください。**`pruneEnvironmentVariables`** 関数で、**`DYLD_*`** 変数が削除されていることが確認できます。
>
> **`processRestricted`** 関数では、制限の理由が設定されています。このコードを確認すると、理由は次のとおりです。
>
> - バイナリが `setuid/setgid` である
> - macho バイナリに `__RESTRICT/__restrict` セクションが存在する
> - ソフトウェアが entitlements（hardened runtime）を持っているが、[`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables) entitlement がない
>  - 次のコマンドでバイナリの **entitlements** を確認できます: `codesign -dv --entitlements :- </path/to/bin>`
>
> より新しいバージョンでは、このロジックは **`configureProcessRestrictions`** 関数の後半にあります。ただし、新しいバージョンで実行されるのは関数の**先頭にあるチェック**です（iOS または simulation に関連する if は macOS では使用されないため削除できます）。

### Library Validation

バイナリが **`DYLD_INSERT_LIBRARIES`** 環境変数の使用を許可していても、ロードするライブラリの signature を確認する場合、custom library はロードされません。

custom library をロードするには、バイナリが次の **entitlements のいずれか**を持っている必要があります。

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

または、バイナリに **hardened runtime flag** や **library validation flag** が設定されていない必要があります。

`codesign --display --verbose <bin>` を使用し、**`CodeDirectory`** 内の runtime flag を確認することで、バイナリに **hardened runtime** があるか確認できます。例:

**`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

バイナリと同じ証明書で signature されたライブラリもロードできます。

この機能をどのように (ab)use し、制限を確認するかについては、以下を参照してください。


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Dylib hijacking attacks を実行する際には、**以前に説明した Library Validation の制限も適用される**ことを忘れないでください。

Windows と同様に、MacOS でも **dylib を hijack** して、**applications** に **arbitrary code** を **execute** させることができます（ただし、通常の user からは、`.app` bundle 内に書き込み、library を hijack するために TCC permission が必要になる可能性があるため、実際には不可能な場合があります）。\
しかし、**MacOS** applications が libraries を **load** する方法は、Windows よりも **制限が厳しく**なっています。このため、**malware** developers は stealth のためにこの technique を引き続き使用できますが、これを abuse して privileges を escalate できる可能性ははるかに低くなります。

まず、**MacOS binaries** がロードする libraries の full path を指定しているケースの方が**一般的**です。さらに、**MacOS は libraries を探すために** **$PATH** の folders を **検索しません**。

この機能に関連する **code** の主要部分は、`ImageLoader.cpp` の **`ImageLoader::recursiveLoadLibraries`** にあります。

macho binary が libraries をロードするために使用できる header Commands は **4 種類**あります。

- **`LC_LOAD_DYLIB`** command は、dylib をロードするための一般的な command です。
- **`LC_LOAD_WEAK_DYLIB`** command は前者と同様に動作しますが、dylib が見つからない場合、エラーなしで execution が継続されます。
- **`LC_REEXPORT_DYLIB`** command は、別の library の symbols を proxy（または re-export）します。
- **`LC_LOAD_UPWARD_DYLIB`** command は、2 つの libraries が相互に依存する場合に使用されます（これは _upward dependency_ と呼ばれます）。

ただし、dylib hijacking には **2 種類**あります。

- **Missing weak linked libraries**: これは、application が **LC_LOAD_WEAK_DYLIB** で設定された、存在しない library をロードしようとすることを意味します。その後、**attacker が想定された場所に dylib を配置すると、ロードされます**。
- link が "weak" であるため、library が見つからなくても application は実行を継続します。
- これに関連する **code** は `ImageLoaderMachO.cpp` の `ImageLoaderMachO::doGetDependentLibraries` 関数にあり、`LC_LOAD_WEAK_DYLIB` が true の場合のみ `lib->required` が `false` になります。
- **weak linked libraries** は次のコマンドで binaries から検索できます（後ほど hijacking libraries の作成方法の例を示します）。
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configured with @rpath**: Mach-O binaries には **`LC_RPATH`** および **`LC_LOAD_DYLIB`** commands を設定できます。これらの commands の **values** に基づき、libraries は**異なる directories**から **load** されます。
- **`LC_RPATH`** には、binary が libraries のロードに使用する folders の paths が含まれます。
- **`LC_LOAD_DYLIB`** には、ロードする特定の libraries への path が含まれます。これらの paths には **`@rpath`** を含めることができ、これは **`LC_RPATH`** の values に置き換えられます。**`LC_RPATH`** に複数の paths がある場合、library のロード先を検索するためにすべてが使用されます。例:
- **`LC_LOAD_DYLIB`** に `@rpath/library.dylib` が含まれ、**`LC_RPATH`** に `/application/app.app/Contents/Framework/v1/` と `/application/app.app/Contents/Framework/v2/` が含まれている場合、両方の folders が `library.dylib` のロードに使用されます。library が `[...]/v1/` に存在せず、attacker がそこに配置できる場合、**`LC_LOAD_DYLIB`** 内の paths の順序に従うため、`[...]/v2/` にある library のロードを hijack できます。
- **rpath paths と libraries** は、次のコマンドで binaries から検索できます: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: **main executable file** を含む directory への **path** です。
>
> **`@loader_path`**: load command を含む **Mach-O binary** の **directory** への **path** です。
>
> - executable で使用する場合、**`@loader_path`** は実質的に **`@executable_path`** と同じです。
> - **dylib** で使用する場合、**`@loader_path`** は **dylib** への **path** を示します。

この機能を abuse して **privileges を escalate** する方法は、**root** によって実行される **application** が、attacker に write permissions のある folder 内の **library を探している**という、まれなケースです。

> [!TIP]
> applications 内の **missing libraries** を見つけるための便利な **scanner** として、[**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) または [**CLI version**](https://github.com/pandazheng/DylibHijack) があります。\
この technique の**技術的詳細を含む優れた report**は[**こちら**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x)で確認できます。

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Dlopen hijacking attacks を実行する際には、**以前に説明した Library Validation の制限も適用される**ことを忘れないでください。

**`man dlopen`** より:

- path **に slash character が含まれていない**場合（つまり leaf name のみの場合）、**dlopen() は検索を実行**します。起動時に **`$DYLD_LIBRARY_PATH`** が設定されていた場合、dyld は最初にその **directory** を検索します。次に、calling mach-o file または main executable が **`LC_RPATH`** を指定している場合、dyld はそれらの directories を検索します。次に、process が **unrestricted** であれば、dyld は current working directory を検索します。最後に、old binaries の場合、dyld はいくつかの fallbacks を試します。起動時に **`$DYLD_FALLBACK_LIBRARY_PATH`** が設定されていた場合、dyld はその **directories** を検索します。それ以外の場合、dyld は **`/usr/local/lib/`**（process が unrestricted の場合）を検索し、その後 **`/usr/lib/`** を検索します（この情報は **`man dlopen`** から取得したものです）。
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`（unrestricted の場合）
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/`（unrestricted の場合）
6. `/usr/lib/`

> [!CAUTION]
> name に slash がない場合、hijacking には次の 2 つの方法があります。
>
> - **`LC_RPATH`** のいずれかが writable である場合（ただし signature がチェックされるため、binary が unrestricted である必要もあります）
> - binary が **unrestricted** であり、CWD から何かを load できる場合（または前述の環境変数のいずれかを abuse する場合）

- path が framework path のように見える場合（例: `/stuff/foo.framework/foo`）、起動時に **`$DYLD_FRAMEWORK_PATH`** が設定されていれば、dyld は最初にその directory 内で **framework partial path**（例: `foo.framework/foo`）を検索します。次に、dyld は **supplied path** をそのまま試します（relative paths には current working directory を使用）。最後に、old binaries の場合、dyld はいくつかの fallbacks を試します。起動時に **`$DYLD_FALLBACK_FRAMEWORK_PATH`** が設定されていれば、dyld はその directories を検索します。それ以外の場合、**`/Library/Frameworks`**（process が unrestricted の macOS の場合）、続いて **`/System/Library/Frameworks`** を検索します。
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path（unrestricted の場合、relative paths には current working directory を使用）
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks`（unrestricted の場合）
5. `/System/Library/Frameworks`

> [!CAUTION]
> framework path の場合、hijack する方法は次のとおりです。
>
> - process が **unrestricted** である場合、CWD からの **relative path** または前述の環境変数を abuse します（process が restricted の場合、DYLD\_\* env vars が削除されることは docs に記載されていません）

- path **に slash が含まれているが framework path ではない**場合（つまり、full path または dylib への partial path の場合）、dlopen() はまず（設定されていれば）**`$DYLD_LIBRARY_PATH`** 内を検索します（path の leaf part を使用）。次に、dyld は **supplied path** を試します（relative paths には current working directory を使用しますが、これは unrestricted processes の場合のみです）。最後に、older binaries の場合、dyld は fallbacks を試します。起動時に **`$DYLD_FALLBACK_LIBRARY_PATH`** が設定されていれば、dyld はその directories を検索します。それ以外の場合、dyld は **`/usr/local/lib/`**（process が unrestricted の場合）を検索し、その後 **`/usr/lib/`** を検索します。
1. `$DYLD_LIBRARY_PATH`
2. supplied path（unrestricted の場合、relative paths には current working directory を使用）
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/`（unrestricted の場合）
5. `/usr/lib/`

> [!CAUTION]
> name に slash があり framework ではない場合、hijack する方法は次のとおりです。
>
> - binary が **unrestricted** であり、CWD または `/usr/local/lib` から何かを load できる場合（または前述の環境変数のいずれかを abuse する場合）

> [!TIP]
> Note: **dlopen の検索を制御する configuration files はありません**。
>
> Note: main executable が **set\[ug]id binary** であるか、entitlements 付きで codesigned されている場合、**すべての environment variables が無視**され、full path のみ使用できます（詳細については [DYLD_INSERT_LIBRARIES restrictions](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) を確認してください）。
>
> Note: Apple platforms は、32-bit と 64-bit libraries を結合するために "universal" files を使用します。したがって、**32-bit と 64-bit の個別の search paths はありません**。
>
> Note: Apple platforms では、ほとんどの OS dylibs が **dyld cache に結合**されており、disk 上には存在しません。そのため、OS dylib が存在するかを事前確認するために **`stat()`** を呼び出しても機能しません。ただし、**`dlopen_preflight()`** は **`dlopen()`** と同じ手順を使用して、compatible な mach-o file を検索します。

**Check paths**

次の code を使用して、すべての options を確認します。
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
コンパイルして実行すると、**各ライブラリの検索に失敗した場所**を確認できます。また、**FS logsをフィルタリング**することもできます。
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

**privileged binary/app**（SUID や強力な entitlements を持つバイナリなど）が **relative path** のライブラリ（`@executable_path` や `@loader_path` を使用する場合など）を **Library Validation disabled** の状態でロードしている場合、攻撃者が **relative path** でロードされるライブラリを変更できる場所へバイナリを移動し、プロセスへの code injection に悪用できる可能性があります。

## Prune `DYLD_*` and `LD_LIBRARY_PATH` env variables

`dyld-dyld-832.7.1/src/dyld2.cpp` ファイルには、**`DYLD_` で始まる**、および **`LD_LIBRARY_PATH=`** の env variable を削除する **`pruneEnvironmentVariables`** 関数があります。

また、**suid** および **sgid** バイナリの場合、env variable **`DYLD_FALLBACK_FRAMEWORK_PATH`** と **`DYLD_FALLBACK_LIBRARY_PATH`** を明示的に **null** に設定します。

この関数は、OSX を対象とする場合、同じファイルの **`_main`** 関数から次のように呼び出されます。
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
そして、これらの boolean フラグはコード内の同じファイルで設定されています：
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
これは基本的に、バイナリが **suid** または **sgid** である場合、ヘッダーに **RESTRICT** セグメントがある場合、または **CS_RESTRICT** フラグ付きで署名されている場合、**`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** が true となり、環境変数が削除されることを意味します。

なお、CS_REQUIRE_LV が true の場合、変数は削除されませんが、library validation によって元のバイナリと同じ証明書を使用していることが確認されます。

## Restrictions の確認

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
> **`0x0(none)`** の flags で署名された binaries であっても、実行時に **`CS_RESTRICT`** flag が動的に付与される可能性があるため、この technique はそれらでは動作しないことに注意してください。
>
> proc にこの flag があるかどうかは、（[**csops here**](https://github.com/axelexic/CSOps) を取得して）次のように確認できます。
>
> ```bash
> csops -status <pid>
> ```
>
> 次に、flag 0x800 が有効になっているか確認します。

## References

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
