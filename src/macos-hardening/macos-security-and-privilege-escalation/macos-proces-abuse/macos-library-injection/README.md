# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> **dyldのコードはオープンソース**であり、[https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/)で見つけることができ、**URLのようなもので**tarをダウンロードできます：[https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyldプロセス**

Dyldがバイナリ内でライブラリをどのようにロードするかを確認してください：

{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

これは[**LinuxのLD_PRELOAD**](../../../../linux-hardening/privilege-escalation/#ld_preload)のようなものです。特定のライブラリをパスからロードするために実行されるプロセスを指定することができます（環境変数が有効な場合）。

この技術は、すべてのインストールされたアプリケーションに「Info.plist」と呼ばれるplistがあり、`LSEnvironmental`というキーを使用して**環境変数を割り当てることができるため**、**ASEP技術としても使用される可能性があります**。

> [!NOTE]
> 2012年以降、**Appleは`DYLD_INSERT_LIBRARIES`の権限を大幅に制限しました**。
>
> コードを確認し、**`src/dyld.cpp`**をチェックしてください。関数**`pruneEnvironmentVariables`**では、**`DYLD_*`**変数が削除されているのがわかります。
>
> 関数**`processRestricted`**では、制限の理由が設定されています。そのコードを確認すると、理由は次のとおりです：
>
> - バイナリが`setuid/setgid`である
> - machoバイナリに`__RESTRICT/__restrict`セクションが存在する
> - ソフトウェアが[`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)権限なしで権限を持っている（ハードンされたランタイム）
>   - バイナリの**権限**を確認するには：`codesign -dv --entitlements :- </path/to/bin>`
>
> より新しいバージョンでは、このロジックは関数**`configureProcessRestrictions`**の後半に見つけることができます。ただし、新しいバージョンで実行されるのは関数の**最初のチェック**です（iOSやシミュレーションに関連するifを削除できます。これらはmacOSでは使用されません）。

### ライブラリの検証

バイナリが**`DYLD_INSERT_LIBRARIES`**環境変数の使用を許可していても、バイナリがライブラリの署名をチェックする場合、カスタムライブラリはロードされません。

カスタムライブラリをロードするには、バイナリが次のいずれかの権限を持っている必要があります：

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

または、バイナリは**ハードンされたランタイムフラグ**または**ライブラリ検証フラグ**を持っていない必要があります。

バイナリが**ハードンされたランタイム**を持っているかどうかは、`codesign --display --verbose <bin>`を使用して、**`CodeDirectory`**内のフラグruntimeを確認できます：**`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

バイナリが**同じ証明書で署名されている**場合、ライブラリをロードすることもできます。

この技術を（悪用）する方法と制限を確認する例を見つけてください：

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylibハイジャック

> [!CAUTION]
> **以前のライブラリ検証制限も適用されることを忘れないでください** Dylibハイジャック攻撃を実行するには。

Windowsと同様に、MacOSでも**dylibsをハイジャック**して**アプリケーション**が**任意の**コードを**実行**するようにすることができます（実際には、通常のユーザーからは、`.app`バンドル内に書き込むためにTCC権限が必要なため、これは不可能かもしれません）。\
ただし、**MacOS**アプリケーションがライブラリを**ロード**する方法は**Windowsよりも制限されています**。これは、**マルウェア**開発者がこの技術を**隠密性**のために使用できることを意味しますが、**権限を昇格させるために悪用できる可能性ははるかに低い**です。

まず第一に、**MacOSバイナリがライブラリをロードするための完全なパスを示すことが**より一般的です。第二に、**MacOSはライブラリのために**$PATH**のフォルダを検索することはありません**。

この機能に関連する**コードの主な部分**は、`ImageLoader.cpp`の**`ImageLoader::recursiveLoadLibraries`**にあります。

machoバイナリがライブラリをロードするために使用できる**4つの異なるヘッダーコマンド**があります：

- **`LC_LOAD_DYLIB`**コマンドはdylibをロードするための一般的なコマンドです。
- **`LC_LOAD_WEAK_DYLIB`**コマンドは前のコマンドと同様に機能しますが、dylibが見つからない場合、実行はエラーなしで続行されます。
- **`LC_REEXPORT_DYLIB`**コマンドは、別のライブラリからシンボルをプロキシ（または再エクスポート）します。
- **`LC_LOAD_UPWARD_DYLIB`**コマンドは、2つのライブラリが互いに依存している場合に使用されます（これは_上向き依存関係_と呼ばれます）。

ただし、**dylibハイジャックには2種類あります**：

- **欠落している弱リンクライブラリ**：これは、アプリケーションが**LC_LOAD_WEAK_DYLIB**で構成された存在しないライブラリをロードしようとすることを意味します。次に、**攻撃者がdylibを期待される場所に配置すると、それがロードされます**。
- リンクが「弱い」ということは、ライブラリが見つからなくてもアプリケーションは実行を続けることを意味します。
- これに関連する**コード**は、`ImageLoaderMachO.cpp`の`ImageLoaderMachO::doGetDependentLibraries`関数にあり、`lib->required`は`LC_LOAD_WEAK_DYLIB`がtrueのときのみ`false`です。
- バイナリ内の**弱リンクライブラリを見つける**には（後でハイジャックライブラリを作成する方法の例があります）：
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **@rpathで構成されている**：Mach-Oバイナリは**`LC_RPATH`**および**`LC_LOAD_DYLIB`**コマンドを持つことができます。これらのコマンドの**値**に基づいて、**ライブラリ**は**異なるディレクトリ**から**ロード**されます。
- **`LC_RPATH`**は、バイナリによってライブラリをロードするために使用されるいくつかのフォルダのパスを含みます。
- **`LC_LOAD_DYLIB`**は、ロードする特定のライブラリへのパスを含みます。これらのパスには**`@rpath`**が含まれる場合があり、これは**`LC_RPATH`**の値で**置き換えられます**。**`LC_RPATH`**に複数のパスがある場合、すべてがライブラリをロードするために使用されます。例：
- **`LC_LOAD_DYLIB`**に`@rpath/library.dylib`が含まれ、**`LC_RPATH`**に`/application/app.app/Contents/Framework/v1/`および`/application/app.app/Contents/Framework/v2/`が含まれている場合。両方のフォルダが`library.dylib`をロードするために使用されます。**ライブラリが`[...] /v1/`に存在しない場合、攻撃者はそこに配置して`[...] /v2/`のライブラリのロードをハイジャックできます。** **`LC_LOAD_DYLIB`**のパスの順序が守られます。
- バイナリ内の**rpathパスとライブラリを見つける**には：`otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**：は**メイン実行可能ファイル**を含むディレクトリへの**パス**です。
>
> **`@loader_path`**：は**ロードコマンドを含むMach-Oバイナリ**を含む**ディレクトリ**への**パス**です。
>
> - 実行可能ファイルで使用される場合、**`@loader_path`**は実質的に**`@executable_path`**と同じです。
> - **dylib**で使用される場合、**`@loader_path`**は**dylib**への**パス**を提供します。

この機能を悪用して**権限を昇格させる**方法は、**root**によって実行されている**アプリケーション**が、攻撃者が書き込み権限を持つフォルダ内の**ライブラリを探している**という稀なケースです。

> [!TIP]
> アプリケーション内の**欠落しているライブラリ**を見つけるための優れた**スキャナー**は、[**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html)または[**CLIバージョン**](https://github.com/pandazheng/DylibHijack)です。\
> この技術に関する**技術的詳細を含む優れたレポート**は[**こちら**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x)で見つけることができます。

**例**

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopenハイジャック

> [!CAUTION]
> **以前のライブラリ検証制限も適用されることを忘れないでください** Dlopenハイジャック攻撃を実行するには。

**`man dlopen`**から：

- パスに**スラッシュ文字が含まれていない**場合（つまり、単なるリーフ名の場合）、**dlopen()は検索を行います**。**`$DYLD_LIBRARY_PATH`**が起動時に設定されている場合、dyldは最初にそのディレクトリを**探します**。次に、呼び出し元のmach-oファイルまたはメイン実行可能ファイルが**`LC_RPATH`**を指定している場合、dyldは**それらの**ディレクトリを**探します**。次に、プロセスが**制限されていない**場合、dyldは**現在の作業ディレクトリ**を検索します。最後に、古いバイナリの場合、dyldはいくつかのフォールバックを試みます。**`$DYLD_FALLBACK_LIBRARY_PATH`**が起動時に設定されている場合、dyldは**それらのディレクトリ**を検索します。そうでない場合、dyldは**`/usr/local/lib/`**（プロセスが制限されていない場合）を検索し、次に**`/usr/lib/`**を検索します（この情報は**`man dlopen`**から取得されました）。
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`（制限されていない場合）
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/`（制限されていない場合）
6. `/usr/lib/`

> [!CAUTION]
> 名前にスラッシュがない場合、ハイジャックを行う方法は2つあります：
>
> - いずれかの**`LC_RPATH`**が**書き込み可能**である場合（ただし署名がチェックされるため、これにはバイナリが制限されていない必要があります）
> - バイナリが**制限されていない**場合、CWDから何かをロードするか、前述の環境変数のいずれかを悪用することが可能です。

- パスが**フレームワークのように見える**場合（例：`/stuff/foo.framework/foo`）、**`$DYLD_FRAMEWORK_PATH`**が起動時に設定されている場合、dyldは最初にそのディレクトリで**フレームワーク部分パス**（例：`foo.framework/foo`）を探します。次に、dyldは**提供されたパスをそのまま**試みます（相対パスの場合は現在の作業ディレクトリを使用）。最後に、古いバイナリの場合、dyldはいくつかのフォールバックを試みます。**`$DYLD_FALLBACK_FRAMEWORK_PATH`**が起動時に設定されている場合、dyldはそれらのディレクトリを検索します。そうでない場合、dyldは**`/Library/Frameworks`**（macOSでプロセスが制限されていない場合）、次に**`/System/Library/Frameworks`**を検索します。
1. `$DYLD_FRAMEWORK_PATH`
2. 提供されたパス（制限されていない場合は相対パスに現在の作業ディレクトリを使用）
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks`（制限されていない場合）
5. `/System/Library/Frameworks`

> [!CAUTION]
> フレームワークパスの場合、ハイジャックする方法は次のとおりです：
>
> - プロセスが**制限されていない**場合、CWDからの**相対パス**を悪用することができます。前述の環境変数（プロセスが制限されている場合はDYLD_*環境変数が削除されると文書には記載されていません）。

- パスが**スラッシュを含むがフレームワークパスでない**場合（つまり、dylibへのフルパスまたは部分パス）、dlopen()は最初に（設定されている場合）**`$DYLD_LIBRARY_PATH`**で（パスのリーフ部分を使用）探します。次に、dyldは**提供されたパスを試みます**（制限されていないプロセスの場合は相対パスに現在の作業ディレクトリを使用）。最後に、古いバイナリの場合、dyldはいくつかのフォールバックを試みます。**`$DYLD_FALLBACK_LIBRARY_PATH`**が起動時に設定されている場合、dyldはそれらのディレクトリを検索します。そうでない場合、dyldは**`/usr/local/lib/`**（プロセスが制限されていない場合）を検索し、次に**`/usr/lib/`**を検索します。
1. `$DYLD_LIBRARY_PATH`
2. 提供されたパス（制限されていない場合は相対パスに現在の作業ディレクトリを使用）
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/`（制限されていない場合）
5. `/usr/lib/`

> [!CAUTION]
> 名前にスラッシュがあり、フレームワークでない場合、ハイジャックする方法は次のとおりです：
>
> - バイナリが**制限されていない**場合、CWDまたは`/usr/local/lib`から何かをロードするか、前述の環境変数のいずれかを悪用することが可能です。

> [!NOTE]
> 注意：**dlopen検索を制御する**ための構成ファイルは**ありません**。
>
> 注意：メイン実行可能ファイルが**set\[ug]idバイナリまたは権限でコードサインされている**場合、**すべての環境変数は無視され**、フルパスのみが使用できます（詳細情報については[DYLD_INSERT_LIBRARIES制限を確認してください](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions)）。
>
> 注意：Appleプラットフォームは、32ビットと64ビットのライブラリを組み合わせるために「ユニバーサル」ファイルを使用します。これは、**32ビットと64ビットの検索パスが別々に存在しない**ことを意味します。
>
> 注意：Appleプラットフォームでは、ほとんどのOS dylibが**dyldキャッシュに統合され**、ディスク上には存在しません。したがって、OS dylibが存在するかどうかを事前確認するために**`stat()`**を呼び出すことは**機能しません**。ただし、**`dlopen_preflight()`**は、互換性のあるmach-oファイルを見つけるために**`dlopen()`**と同じ手順を使用します。

**パスを確認する**

次のコードを使用してすべてのオプションを確認しましょう：
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
それをコンパイルして実行すると、**各ライブラリがどこで見つからなかったか**を見ることができます。また、**FSログをフィルタリングすることもできます**:
```bash
sudo fs_usage | grep "dlopentest"
```
## 相対パスハイジャック

**特権バイナリ/アプリ**（SUIDや強力な権限を持つバイナリなど）が**相対パス**ライブラリを**読み込んでいる**場合（例えば`@executable_path`や`@loader_path`を使用している場合）で、**ライブラリ検証が無効**になっていると、攻撃者が**相対パスで読み込まれるライブラリを変更**できる場所にバイナリを移動させ、プロセスにコードを注入するためにそれを悪用することが可能です。

## `DYLD_*`および`LD_LIBRARY_PATH`環境変数の削除

ファイル`dyld-dyld-832.7.1/src/dyld2.cpp`には、**`pruneEnvironmentVariables`**という関数があり、**`DYLD_`**で始まる任意の環境変数と**`LD_LIBRARY_PATH=`**を削除します。

また、**suid**および**sgid**バイナリに対して、特に環境変数**`DYLD_FALLBACK_FRAMEWORK_PATH`**と**`DYLD_FALLBACK_LIBRARY_PATH`**を**null**に設定します。

この関数は、OSXをターゲットにする場合、同じファイルの**`_main`**関数から呼び出されます。
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
そのブールフラグは、コード内の同じファイルに設定されています:
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
バイナリが**suid**または**sgid**であるか、ヘッダーに**RESTRICT**セグメントがあるか、**CS_RESTRICT**フラグで署名されている場合、**`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`**が真であり、環境変数は削除されます。

CS_REQUIRE_LVが真の場合、変数は削除されませんが、ライブラリの検証はそれらが元のバイナリと同じ証明書を使用しているかどうかを確認します。

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

Keychainで新しい証明書を作成し、それを使用してバイナリに署名します:
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
> 注意してください。**`0x0(none)`** フラグで署名されたバイナリがあっても、実行時に **`CS_RESTRICT`** フラグが動的に設定される可能性があるため、この技術はそれらには機能しません。
>
> プロセスがこのフラグを持っているかどうかは、(get [**csops here**](https://github.com/axelexic/CSOps)) で確認できます：
>
> ```bash
> csops -status <pid>
> ```
>
> その後、フラグ 0x800 が有効になっているかどうかを確認します。

## References

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
