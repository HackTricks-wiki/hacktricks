# macOSライブラリインジェクション

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を通じて**ゼロからヒーローまでAWSハッキングを学ぶ**</a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
- **Discordグループ**に**参加**する💬](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦で**フォロー**する[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
- **ハッキングトリックを共有**するために、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する。

</details>

{% hint style="danger" %}
**dyldのコードはオープンソース**であり、[https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/)で見つけることができ、**URL**を使用してtarをダウンロードすることができます。[https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)
{% endhint %}

## **Dyldプロセス**

バイナリ内でDyldがライブラリをどのようにロードするかを見てみましょう：

{% content-ref url="macos-dyld-process.md" %}
[macos-dyld-process.md](macos-dyld-process.md)
{% endcontent-ref %}

## **DYLD\_INSERT\_LIBRARIES**

これは、[**LinuxのLD\_PRELOADに似た**](../../../../linux-hardening/privilege-escalation/#ld\_preload)ものです。プロセスに特定のライブラリをロードするためのパスを指定することができます（環境変数が有効になっている場合）

このテクニックは、インストールされたすべてのアプリケーションに「Info.plist」というplistがあるため、`LSEnvironmental`というキーを使用して**環境変数を割り当てる**ことができるため、**ASEPテクニックとしても使用**できます。

{% hint style="info" %}
2012年以降、**Appleは`DYLD_INSERT_LIBRARIES`の権限を大幅に削減**しています。

コードに移動して、`src/dyld.cpp`を**確認**してください。関数**`pruneEnvironmentVariables`**では、**`DYLD_*`**変数が削除されていることがわかります。

関数**`processRestricted`**では、制限の理由が設定されています。そのコードを確認すると、理由は次のとおりです。

- バイナリが`setuid/setgid`である
- machoバイナリに`__RESTRICT/__restrict`セクションが存在する
- ソフトウェアに[`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)権限がないハード化されたランタイムの権限
- バイナリの**権限**を次のように確認する：`codesign -dv --entitlements :- </path/to/bin>`

より新しいバージョンでは、このロジックを関数**`configureProcessRestrictions`**の後半に見つけることができます。ただし、新しいバージョンで実行されるのは、関数の**最初のチェック**です（iOSやシミュレーションに関連するif文はmacOSでは使用されないため、それらを削除できます）。
{% endhint %}

### ライブラリの検証

バイナリが**`DYLD_INSERT_LIBRARIES`**環境変数を使用することを許可していても、バイナリがライブラリの署名をチェックしてロードする場合、カスタムライブラリはロードされません。

カスタムライブラリをロードするには、バイナリに次のいずれかの権限が必要です。

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

またはバイナリには**ハード化されたランタイムフラグ**または**ライブラリ検証フラグ**がない必要があります。

バイナリが**ハード化されたランタイム**を持っているかどうかは、`codesign --display --verbose <bin>`で確認し、**`CodeDirectory`**内のランタイムフラグを確認します。例：**`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

また、バイナリと**同じ証明書で署名されたライブラリ**をロードすることもできます。

これを悪用する例と制限事項を確認するための例を次で見つけることができます：

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dylibハイジャッキング

{% hint style="danger" %}
**以前のライブラリ検証の制限**も、Dylibハイジャッキング攻撃を実行するために適用されます。
{% endhint %}

Windowsと同様に、MacOSでも**dylibsをハイジャック**して**アプリケーション**が**任意のコードを実行**することができます（実際、通常のユーザーからでは`.app`バンドル内に書き込むTCC権限が必要かもしれません）。\
ただし、**MacOS**アプリケーションがライブラリをロードする方法は**Windows**よりも**制限されて**います。これは、**マルウェア**開発者がこのテクニックを**ステルス**に使用できる可能性があるが、特権を昇格させるためにこれを悪用する可能性は低いことを意味します。

まず第一に、**MacOSバイナリがライブラリをロードする際にフルパスを指定**することが**一般的**です。第二に、**MacOSは決して** **$PATH**のフォルダを検索しません。

この機能に関連する**コード**の**主要部分**は、`ImageLoader.cpp`の**`ImageLoader::recursiveLoadLibraries`**にあります。

machoバイナリがライブラリをロードするために使用できる**4つの異なるヘッダーコマンド**があります。

- **`LC_LOAD_DYLIB`**コマンドは、dylibをロードする一般的なコマンドです。
- **`LC_LOAD_WEAK_DYLIB`**コマンドは前のコマンドと同様に機能しますが、dylibが見つからない場合、エラーなしで実行が続行されます。
- **`LC_REEXPORT_DYLIB`**コマンドは、異なるライブラリからシンボルをプロキシ（または再エクスポート）します。
- **`LC_LOAD_UPWARD_DYLIB`**コマンドは、お互いに依存する2つのライブラリがある場合に使用されます（これは_上向き依存性_と呼ばれます）。

ただし、**2種類のdylibハイジャッキング**があります。

- **弱リンクされたライブラリが不足している**：これは、アプリケーションが存在しないライブラリを**LC\_LOAD\_WEAK\_DYLIB**で構成してロードしようとすることを意味します。その後、**攻撃者が期待される場所にdylibを配置すると、ロードされます**。
- リンクが「弱い」という事実は、ライブラリが見つからなくてもアプリケーションが実行を続行することを意味します。
- これに関連する**コード**は、`ImageLoaderMachO.cpp`の`ImageLoaderMachO::doGetDependentLibraries`関数にあり、`lib->required`が`LC_LOAD_WEAK_DYLIB`がtrueの場合にのみ`false`になります。
- バイナリ内の**弱リンクされたライブラリ**を見つけるには（後でハイジャックライブラリを作成する方法の例があります）：
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **@rpathで構成**されている：Mach-Oバイナリには**`LC_RPATH`**と**`LC_LOAD_DYLIB`**コマンドが含まれています。これらのコマンドの**値**に基づいて、**異なるディレクトリ**から**ライブラリ**が**ロード**されます。
- **`LC_RPATH`**には、バイナリで使用されるいくつかのフォルダのパスが含まれています。
* **`LC_LOAD_DYLIB`** には読み込む特定のライブラリのパスが含まれます。これらのパスには **`@rpath`** が含まれることがあり、これは **`LC_RPATH`** の値で置き換えられます。**`LC_RPATH`** に複数のパスがある場合、すべてのパスが使用されてライブラリを検索します。例:
* もし **`LC_LOAD_DYLIB`** が `@rpath/library.dylib` を含み、**`LC_RPATH`** が `/application/app.app/Contents/Framework/v1/` と `/application/app.app/Contents/Framework/v2/` を含む場合、両方のフォルダが `library.dylib` を読み込むために使用されます。もしライブラリが `[...]/v1/` に存在しない場合、攻撃者はそこに配置して `[...]/v2/` のライブラリの読み込みを乗っ取ることができます。なぜなら **`LC_LOAD_DYLIB`** のパスの順序に従うからです。
* バイナリ内の **rpath パスとライブラリ** を見つけるには、次のコマンドを使用します: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**: **メイン実行ファイル** を含むディレクトリへの **パス** です。

**`@loader_path`**: **Mach-O バイナリ** を含む **ディレクトリ** への **パス** です。

* 実行ファイルで使用される場合、**`@loader_path`** は実質的に **`@executable_path`** と同じです。
* **dylib** で使用される場合、**`@loader_path`** は **dylib** への **パス** を提供します。
{% endhint %}

この機能を悪用して **特権を昇格** する方法は、**root** によって実行されている **アプリケーション** が **攻撃者が書き込み権限を持つフォルダ** でいくつかの **ライブラリを探している** 珍しいケースです。

{% hint style="success" %}
アプリケーション内で **不足しているライブラリ** を見つけるための便利な **スキャナー** は [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) や [**CLI バージョン**](https://github.com/pandazheng/DylibHijack) です。\
このテクニックに関する技術的な詳細を含む素晴らしい **レポート** は [**こちら**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) で見つけることができます。
{% endhint %}

**例**

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dlopen Hijacking

{% hint style="danger" %}
**以前のライブラリ検証制限も** Dlopen ハイジャック攻撃を実行するために適用されることを覚えておいてください。
{% endhint %}

**`man dlopen`** より:

* パスに **スラッシュ文字が含まれていない** 場合（つまり、単なるリーフ名の場合）、**dlopen() は検索を行います**。もし起動時に **`$DYLD_LIBRARY_PATH`** が設定されていた場合、dyld はまずそのディレクトリを検索します。次に、呼び出し元の mach-o ファイルまたはメイン実行ファイルが **`LC_RPATH`** を指定している場合、dyld はそのディレクトリを検索します。次に、プロセスが **制限されていない** 場合、dyld は **現在の作業ディレクトリ** を検索します。最後に、古いバイナリの場合、dyld はいくつかのフォールバックを試みます。もし起動時に **`$DYLD_FALLBACK_LIBRARY_PATH`** が設定されていた場合、dyld はそのディレクトリを検索します。そうでない場合、dyld は **`/usr/local/lib/`** を検索し（プロセスが制限されていない場合）、次に **`/usr/lib/`** を検索します（この情報は **`man dlopen`** から取得されました）。
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`（制限されていない場合）
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/`（制限されている場合）
6. `/usr/lib/`

{% hint style="danger" %}
名前にスラッシュが含まれていない場合、ハイジャックを行う方法は 2 つあります:

* 任意の **`LC_RPATH`** が **書き込み可能** である場合（ただし署名がチェックされるため、バイナリが制限されていない場合も必要です）
* バイナリが **制限されていない** 場合、CWD から何かをロードすることが可能です（または言及されている環境変数のいずれかを悪用することが可能です）
{% endhint %}

* パスが **フレームワークのパスのように見える場合**（例: `/stuff/foo.framework/foo`）、起動時に **`$DYLD_FRAMEWORK_PATH`** が設定されていた場合、dyld は最初にそのディレクトリを検索して **フレームワークの部分パス**（例: `foo.framework/foo`）を探します。次に、dyld は **提供されたパスをそのまま** 試します（相対パスの場合は現在の作業ディレクトリを使用します）。最後に、古いバイナリの場合、dyld はいくつかのフォールバックを試みます。もし起動時に **`$DYLD_FALLBACK_FRAMEWORK_PATH`** が設定されていた場合、dyld はそのディレクトリを検索します。そうでない場合、dyld は **`/Library/Frameworks`** を検索します（macOS ではプロセスが制限されていない場合）、次に **`/System/Library/Frameworks`** を検索します。
1. `$DYLD_FRAMEWORK_PATH`
2. 提供されたパス（制限されているプロセスの場合は相対パスの場合は現在の作業ディレクトリを使用）
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks`（制限されている場合）
5. `/System/Library/Frameworks`

{% hint style="danger" %}
フレームワークのパスの場合、ハイジャックする方法は次のとおりです:

* プロセスが **制限されていない** 場合、CWD からの **相対パス** や言及されている環境変数を悪用することが可能です（ドキュメントにはプロセスが制限されている場合 DYLD\_\* 環境変数が削除されるかどうかは記載されていません）
{% endhint %}

* パスに **スラッシュが含まれているがフレームワークのパスではない場合**（つまり、dylib への完全パスまたは部分パスの場合）、dlopen() は最初に（設定されている場合） **`$DYLD_LIBRARY_PATH`** 内のパス（パスのリーフ部分を使用）を検索します。次に、dyld は提供されたパスを試します（制限されているプロセスの場合は相対パスの場合は現在の作業ディレクトリを使用します）。最後に、古いバイナリの場合、dyld はフォールバックを試みます。もし起動時に **`$DYLD_FALLBACK_LIBRARY_PATH`** が設定されていた場合、dyld はそのディレクトリを検索します。そうでない場合、dyld は **`/usr/local/lib/`** を検索し（プロセスが制限されている場合）、次に **`/usr/lib/`** を検索します。
1. `$DYLD_LIBRARY_PATH`
2. 提供されたパス（制限されているプロセスの場合は相対パスの場合は現在の作業ディレクトリを使用）
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/`（制限されている場合）
5. `/usr/lib/`

{% hint style="danger" %}
名前にスラッシュが含まれており、フレームワークではない場合、ハイジャックする方法は次のとおりです:

* バイナリが **制限されていない** 場合、CWD から何かをロードすることが可能です、または `/usr/local/lib` から何かをロードすることが可能です（または言及されている環境変数のいずれかを悪用することが可能です）
{% endhint %}

{% hint style="info" %}
注意: **dlopen の検索を制御する** 構成ファイルは **存在しません**。

注意: メイン実行ファイルが **set\[ug\]id バイナリまたは権限付与コードで署名されている** 場合、**すべての環境変数が無視** され、完全パスのみが使用されます（詳細については [DYLD\_INSERT\_LIBRARIES 制限を確認](macos-dyld-hijacking-and-dyld\_insert\_libraries.md#check-dyld\_insert\_librery-restrictions) してください）

注意: Apple プラットフォームでは、32 ビットと 64 ビットのライブラリを組み合わせた "universal" ファイルが使用されます。これは **別々の 32 ビットと 64 ビットの検索パスが存在しない** ことを意味します。

注意: Apple プラットフォームでは、ほとんどの OS dylib が **dyld キャッシュに統合** されており、ディスク上に存在しません。そのため、OS dylib が存在するかどうかを事前に確認するために **`stat()`** を呼び出すことは **機能しません**。ただし、**`dlopen_preflight()`** は互換性のある mach-o ファイルを見つけるために **`dlopen()`** と同じ手順を使用します。
{% endhint %}

**パスを確認する**

以下のコードですべてのオプションを確認しましょう:
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
もしコンパイルして実行すれば、**各ライブラリがどこで検索されなかったか**がわかります。また、**FSログをフィルタリング**することもできます：
```bash
sudo fs_usage | grep "dlopentest"
```
## 相対パスハイジャック

**特権バイナリ/アプリ**（たとえばSUIDまたは強力な権限を持つバイナリ）が**相対パス**ライブラリ（たとえば`@executable_path`や`@loader_path`を使用）を**ロード**しており、かつ**ライブラリ検証が無効**になっている場合、バイナリを攻撃者が**相対パスでロードされたライブラリを変更**できる位置に移動し、そのプロセスにコードをインジェクトすることが可能になるかもしれません。

## `DYLD_*`および`LD_LIBRARY_PATH`環境変数の整理

ファイル`dyld-dyld-832.7.1/src/dyld2.cpp`には、**`pruneEnvironmentVariables`** 関数があり、**`DYLD_`**で始まる環境変数と **`LD_LIBRARY_PATH=`** を削除します。

また、**suid**および**sgid**バイナリに対して、この関数は明示的に**`DYLD_FALLBACK_FRAMEWORK_PATH`**と**`DYLD_FALLBACK_LIBRARY_PATH`**を**null**に設定します。

この関数は、OSXをターゲットにしている場合、同じファイルの**`_main`** 関数から次のように呼び出されます：
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
そしてこれらのブールフラグはコード内の同じファイルで設定されています:
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
これは基本的に、バイナリが**suid**または**sgid**であるか、ヘッダーに**RESTRICT**セグメントがあるか、**CS\_RESTRICT**フラグで署名されている場合、**`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** がtrueであり、環境変数が削除されます。

CS\_REQUIRE\_LVがtrueの場合、変数は削除されませんが、ライブラリ検証は元のバイナリと同じ証明書を使用していることを確認します。

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
### ハード化されたランタイム

Keychain に新しい証明書を作成し、それを使用してバイナリに署名します:

{% code overflow="wrap" %}
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
{% endcode %}

{% hint style="danger" %}
`0x0(none)`フラグで署名されたバイナリがあっても、実行時に**`CS_RESTRICT`**フラグを動的に取得することができるため、このテクニックはそれらで機能しません。

このフラグを持つprocを確認することができます（[ここでcsopsを取得](https://github.com/axelexic/CSOps)）:
```bash
csops -status <pid>
```
そして、フラグ0x800が有効になっているかどうかをチェックします。
{% endhint %}

## 参考文献

* [https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/](https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/)
* [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローする。**
* **ハッキングトリックを共有するために、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
