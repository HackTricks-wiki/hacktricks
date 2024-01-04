```markdown
# macOSライブラリインジェクション

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングテクニックを共有する。

</details>

{% hint style="danger" %}
**dyldのコードはオープンソース**であり、[https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/)で見つけることができ、**URLを使用してtarをダウンロードすることができます**。例えば、[https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)です。
{% endhint %}

## **DYLD\_INSERT\_LIBRARIES**

> これは、**プログラムで指定されたものよりも前にロードする動的ライブラリのコロン区切りのリスト**です。これにより、フラット名前空間イメージで使用される既存の動的共有ライブラリの新しいモジュールをテストするために、新しいモジュールだけを持つ一時的な動的共有ライブラリをロードすることができます。これは、DYLD\_FORCE\_FLAT\_NAMESPACEも使用されていない限り、動的共有ライブラリを使用して二レベル名前空間イメージをビルドしたイメージには影響しません。

これはLinuxの[**LD\_PRELOAD**](../../../../linux-hardening/privilege-escalation#ld\_preload)と似ています。

このテクニックは、インストールされたすべてのアプリケーションが`LSEnvironmental`というキーを使用して環境変数を割り当てることを許可する"Info.plist"というplistを持っているため、ASEPテクニックとしても**使用される可能性があります**。

{% hint style="info" %}
2012年以降、**Appleは`DYLD_INSERT_LIBRARIES`の力を大幅に削減しました**。

コードに行って**`src/dyld.cpp`をチェック**してください。**`pruneEnvironmentVariables`**関数では、**`DYLD_*`**変数が削除されていることがわかります。

**`processRestricted`**関数では、制限の理由が設定されています。そのコードをチェックすると、理由は以下の通りです：

* バイナリが`setuid/setgid`です
* machoバイナリに`__RESTRICT/__restrict`セクションが存在します。
* ソフトウェアに[`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)エンタイトルメントなしで権限があります（ハード化されたランタイム）
* バイナリの**エンタイトルメント**をチェックするには：`codesign -dv --entitlements :- </path/to/bin>`

より更新されたバージョンでは、このロジックは**`configureProcessRestrictions`**関数の第二部分で見つけることができます。ただし、新しいバージョンで実行されるのは、関数の**最初のチェック**です（macOSでは使用されないiOSまたはシミュレーションに関連するifを削除できます）。
{% endhint %}

### ライブラリ検証

バイナリが**`DYLD_INSERT_LIBRARIES`**環境変数の使用を許可していても、バイナリがロードするライブラリの署名をチェックする場合、カスタムライブラリはロードされません。

カスタムライブラリをロードするためには、バイナリに以下のいずれかのエンタイトルメントが必要です：

* [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

または、バイナリに**ハード化されたランタイムフラグ**や**ライブラリ検証フラグ**が**ない**べきです。

バイナリに**ハード化されたランタイム**があるかどうかは、`codesign --display --verbose <bin>`でフラグランタイムを**`CodeDirectory`**でチェックして、次のようにします：**`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

また、ライブラリがバイナリと同じ証明書で署名されている場合にもロードできます。

この機能の（悪用）方法と制限のチェック方法の例を以下で見つけることができます：

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dylibハイジャック

{% hint style="danger" %}
前述のライブラリ検証の制限もDylibハイジャック攻撃を行うために**適用されることを覚えておいてください**。
{% endhint %}

Windowsと同様に、MacOSでは**アプリケーションが任意のコードを実行するようにdylibsをハイジャックすることもできます**。\
しかし、**MacOS**アプリケーションがライブラリをロードする方法はWindowsよりも**制限されています**。これは、**マルウェア**開発者がまだこのテクニックを**ステルス**に使用できることを意味しますが、特権をエスカレートするためにこれを悪用する可能性ははるかに低いです。

まず、**MacOSバイナリがロードするライブラリの完全なパスを示すことがより一般的**です。そして二つ目に、**MacOSは$PATHのフォルダーをライブラリの検索には決して使用しません**。

この機能に関連する**コードの主要部分**は、`ImageLoader.cpp`の**`ImageLoader::recursiveLoadLibraries`**にあります。

machoバイナリがライブラリをロードするために使用できる**4つの異なるヘッダーコマンド**があります：

* **`LC_LOAD_DYLIB`**コマンドは、dylibをロードするための一般的なコマンドです。
* **`LC_LOAD_WEAK_DYLIB`**コマンドは前述のものと同様に機能しますが、dylibが見つからない場合は、エラーなしで実行が続行されます。
* **`LC_REEXPORT_DYLIB`**コマンドは、異なるライブラリからシンボルをプロキシ（または再エクスポート）します。
* **`LC_LOAD_UPWARD_DYLIB`**コマンドは、2つのライブラリが互いに依存している場合（これを_上向きの依存関係_と呼びます）に使用されます。

しかし、**dylibハイジャックの2つのタイプ**があります：

* **欠落している弱いリンクされたライブラリ**：これは、アプリケーションが存在しないライブラリを**LC\_LOAD\_WEAK\_DYLIB**で設定されたライブラリをロードしようとすることを意味します。そして、**攻撃者が期待される場所にdylibを配置すると、それがロードされます**。
* リンクが"弱い"という事実は、ライブラリが見つからなくてもアプリケーションが実行を続けることを意味します。
* これに関連する**コード**は、`ImageLoaderMachO.cpp`の関数`ImageLoaderMachO::doGetDependentLibraries`にあり、`lib->required`は`LC_LOAD_WEAK_DYLIB`が真の場合にのみ`false`です。
* バイナリで**弱いリンクされたライブラリを見つける**には（後でハイジャックライブラリを作成する方法の例があります）：
* ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
* **@rpathで設定されている**：Mach-Oバイナリは、**`LC_RPATH`**と**`LC_LOAD_DYLIB`**というコマンドを持つことができます。これらのコマンドの**値**に基づいて、**ライブラリ**は**異なるディレクトリ**から**ロードされます**。
* **`LC_RPATH`**には、バイナリがライブラリをロードするために使用するいくつかのフォルダーのパスが含まれています。
* **`LC_LOAD_DYLIB`**には特定のライブラリをロードするためのパスが含まれています。これらのパスには**`@rpath`**が含まれていることがあり、これは**`LC_RPATH`**の値に置き換えられます。**`LC_RPATH`**に複数のパスがある場合、それぞれがライブラリのロードを検索するために使用されます。例：
* **`LC_LOAD_DYLIB`**に`@rpath/library.dylib`が含まれ、**`LC_RPATH`**に`/application/app.app/Contents/Framework/v1/`と`/application/app.app/Contents/Framework/v2/`が含まれている場合。両方のフォルダーが`library.dylib`のロードに使用されます**。**ライブラリが`[...]/v1/`に存在しない場合、攻撃者はそこに配置して、`[...]/v2/`のライブラリのロードをハイジャックすることができます。なぜなら、**`LC_LOAD_DYLIB`**のパスの順序に従っているからです。
* バイナリで**rpathパスとライブラリを見つける**には：`otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**：メイン実行可能ファイルを含むディレクトリへの**パス**です。

**`@loader_path`**：ロードコマンドを含む**Mach-Oバイナリ**を含む**ディレクトリ**への**パス**です。

* 実行可能ファイルで使用される場合、**`@loader_path`**は実質的に**`@executable_path`**と**同じ**です。
* **dylib**で使用される場合、**`@loader_path`**は**dylib**への**パス**を提供します。
{% endhint %}

この機能を悪用して**特権をエスカレートする方法**は、**rootによって実行されているアプリケーション**が攻撃者が書き込み権限を持っているフォルダーで何か**ライブラリを探している**場合に、まれに発生します。

{% hint style="success" %}
アプリケーションで**欠落しているライブラリを見つける**ための素晴らしい**スキャナー**は[**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html)または[**CLIバージョン**](https://github.com/pandazheng/DylibHijack)です。\
このテクニックに関する**技術的詳細を含む素晴らしいレポート**は[**こちら**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x)で見つけることができます。
{% endhint %}

**例**

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dlopenハイジャック

{% hint style="danger" %}
前述のライブラリ検証の制限もDlopenハイジャック攻撃を行うために**適用されることを覚えておいてください**。
{% endhint %}

**`man dlopen`**から：

* パスに**スラッシュ文字が含まれていない場合**（つまり、単なるリーフ名の場合）、**dlopen()は検索を行います**。**`$DYLD_LIBRARY_PATH`**が起動
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
コンパイルして実行すると、**各ライブラリがどこで見つからなかったか**がわかります。また、**FSログをフィルタリング**することもできます：
```bash
sudo fs_usage | grep "dlopentest"
```
## 相対パスハイジャック

**特権バイナリ/アプリ**（例えばSUIDや強力な権限を持つバイナリなど）が相対パスライブラリをロードしている場合（`@executable_path` や `@loader_path` を使用している例）、かつ**ライブラリ検証が無効**になっている場合、攻撃者はバイナリを移動して相対パスでロードされるライブラリを変更し、プロセスにコードを注入することが可能になるかもしれません。

## `DYLD_*` と `LD_LIBRARY_PATH` 環境変数の削除

ファイル `dyld-dyld-832.7.1/src/dyld2.cpp` には、**`pruneEnvironmentVariables`** という関数があり、**`DYLD_`** で始まるすべての環境変数と **`LD_LIBRARY_PATH=`** を削除します。

また、**suid** と **sgid** バイナリに対して、特に環境変数 **`DYLD_FALLBACK_FRAMEWORK_PATH`** と **`DYLD_FALLBACK_LIBRARY_PATH`** を**null**に設定します。

この関数は、OSXをターゲットにした場合、同じファイルの **`_main`** 関数から呼び出されます。
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
```markdown
そして、それらのブール値フラグはコード内の同じファイルで設定されています：
```
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
バイナリが**suid**または**sgid**である場合、ヘッダーに**RESTRICT**セグメントがある場合、または**CS\_RESTRICT**フラグで署名されている場合、**`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** が真であり、環境変数は削除されます。

CS\_REQUIRE\_LVが真の場合、変数は削除されませんが、ライブラリ検証は元のバイナリと同じ証明書を使用していることを確認します。

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

キーチェーンで新しい証明書を作成し、それを使用してバイナリに署名します：

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
**`0x0(なし)`** のフラグで署名されたバイナリがあっても、実行時に動的に **`CS_RESTRICT`** フラグを取得することがあり、その場合この技術は機能しません。

プロセスがこのフラグを持っているかどうかは、(こちらの [**csops**](https://github.com/axelexic/CSOps) を参照して)確認できます：
```bash
csops -status <pid>
```
フラグ0x800が有効になっているかどうかを確認してください。
{% endhint %}

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには、</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい場合**、または**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加する、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) および [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) githubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
