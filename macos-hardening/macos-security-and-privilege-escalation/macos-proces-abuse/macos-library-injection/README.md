# macOSライブラリインジェクション

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
- 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)をフォローする
- **ハッキングトリックを共有する**には、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

{% hint style="danger" %}
**dyldのコードはオープンソース**であり、[https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/)で見つけることができ、**`https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz`**のような**URL**を使用して**tar**をダウンロードできます。
{% endhint %}

## **DYLD\_INSERT\_LIBRARIES**

これは、[**LinuxのLD\_PRELOAD**](../../../../linux-hardening/privilege-escalation#ld\_preload)のようなものです。プロセスに特定のライブラリを読み込むように指示することができます（環境変数が有効になっている場合）

このテクニックは、インストールされたすべてのアプリケーションに`LSEnvironmental`というキーを使用して**環境変数を割り当てる**ことを可能にするため、**ASEPテクニックとしても使用**される可能性があります。

{% hint style="info" %}
2012年以降、**Appleは`DYLD_INSERT_LIBRARIES`の権限を大幅に削減**しています。

コードに移動して**`src/dyld.cpp`**を**確認**してください。**`pruneEnvironmentVariables`**関数では、**`DYLD_*`**変数が削除されていることがわかります。

**`processRestricted`**関数では、制限の理由が設定されています。そのコードを確認すると、理由は次のとおりです。

- バイナリが`setuid/setgid`である
- machoバイナリに`__RESTRICT/__restrict`セクションが存在する
- ソフトウェアに[`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)権限がある
- バイナリの**権限**を次のように確認します：`codesign -dv --entitlements :- </path/to/bin>`

より更新されたバージョンでは、このロジックを**`configureProcessRestrictions`**関数の後半に見つけることができます。ただし、新しいバージョンで実行されるのは、**関数の最初のチェック**です（iOSやシミュレーションに関連するif文はmacOSでは使用されないため、それらを削除できます）。
{% endhint %}

### ライブラリ検証

バイナリが**`DYLD_INSERT_LIBRARIES`**環境変数を使用することを許可していても、バイナリがライブラリの署名をチェックする場合、カスタムライブラリを読み込まないようになります。

カスタムライブラリを読み込むには、バイナリに次のいずれかの権限が必要です。

- &#x20;[`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

または、バイナリに**ハード化されたランタイムフラグ**または**ライブラリ検証フラグ**がない必要があります。

バイナリが**ハード化されたランタイム**を持っているかどうかは、`codesign --display --verbose <bin>`を使用して確認し、**`CodeDirectory`**内のランタイムフラグを確認します。例：**`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

また、バイナリが**同じ証明書で署名**されている場合もライブラリを読み込むことができます。

これを悪用する例と制限事項を確認するには、次の場所にアクセスしてください：

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dylibハイジャッキング

{% hint style="danger" %}
Dylibハイジャッキング攻撃を実行するには、**前述のライブラリ検証制限**も適用されます。
{% endhint %}

Windowsと同様に、MacOSでも**dylibsをハイジャック**して、**アプリケーションが** **任意の** **コードを実行** **する** **ことができます**（実際には通常のユーザーでは`.app`バンドル内に書き込むためのTCC権限が必要かもしれません）。
ただし、**MacOS**アプリケーションがライブラリを読み込む方法は、Windowsよりも**制限が多い**ことを意味します。これは、**マルウェア**開発者がこのテクニックを**ステルス**に使用できる可能性があるが、特権を昇格させるためにこれを悪用する可能性は低いことを意味します。

まず、**MacOSバイナリがライブラリを読み込む際に** **フルパス**を指定することが**一般的**です。そして、**MacOSは決して** **$PATH**のフォルダーをライブラリのために検索しません。

この機能に関連する**コード**の**主要部分**は、`ImageLoader.cpp`の**`ImageLoader::recursiveLoadLibraries`**にあります。

machoバイナリがライブラリを読み込むために使用できる**4つの異なるヘッダーコマンド**があります。

- **`LC_LOAD_DYLIB`**コマンドは、dylibを読み込むための一般的なコマンドです。
- **`LC_LOAD_WEAK_DYLIB`**コマンドは、前のコマンドと同様に機能しますが、dylibが見つからない場合でもエラーなしで実行が続行されます。
- **`LC_REEXPORT_DYLIB`**コマンドは、異なるライブラリからシンボルをプロキシ（または再エクスポート）します。
- **`LC_LOAD_UPWARD_DYLIB`**コマンドは、お互いに依存する2つのライブラリがある場合に使用されます（これは_上向き依存性_と呼ばれます）。

ただし、**2種類のdylibハイジャッキング**があります。

- **欠落している弱リンクされたライブラリ**：これは、アプリケーションが存在しないライブラリを**LC\_LOAD\_WEAK\_DYLIB**で構成して読み込もうとすることを意味します。その後、**攻撃者が期待される場所にdylibを配置すると読み込まれる**。
- リンクが「弱い」という事実は、ライブラリが見つからなくてもアプリケーションが実行を続行することを意味します。
- これに関連する**コード**は、`ImageLoaderMachO.cpp`の`ImageLoaderMachO::doGetDependentLibraries`関数にあり、`lib->required`は、`LC_LOAD_WEAK_DYLIB`がtrueの場合にのみ`false`です。
- バイナリ内の**弱リンクされたライブラリ**を検索するには（後でハイジャックライブラリを作成する例があります）：
  ```bash
  otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
  cmdsize 56
  name /var/tmp/lib/libUtl.1.dylib (offset 24)
  time stamp 2 Wed Jun 21 12:23:31 1969
  current version 1.0.0
  compatibility version 1.0.0
  ```
- **@rpath**で構成された：Mach-Oバイナリには**`LC_RPATH`**と**`LC_LOAD_DYLIB`**コマンドが含まれる場合があります。これらのコマンドの値に基づいて、**異なるディレクトリからライブラリが読み込まれます**。
- **`LC_RPATH`**には、バイナリが使用するライブラリを読み込むために使用されるいくつかのフォルダーのパスが含まれます。
- **`LC_LOAD_DYLIB`**には、読み込む特定のライブラリへのパスが含まれます。これらのパスには**`@rpath`**が含まれる場合があり、**`LC_RPATH`**内の値で置換されます。**`LC_RPATH`**に複数のパスがある場合、すべてのパスが使用されてライブラリを検索します。例：
  - **`LC_LOAD_DYLIB`**に`@rpath/library.dylib`が含まれ、**`LC_RPATH`**に`/application/app.app/Contents/Framework/v1/`と`/application/app.app/Contents/Framework/v2/`が含まれている場合。両方のフォルダーが`library.dylib`を読み込むために使用されます。ライブラリが`[...]/v1/`に存在しない場合、攻撃者はそこに配置して`[...]/v2/`のライブラリの読み込みをハイジャックできます。**`LC_LOAD_DYLIB`**内のパスの順序に従われます。
- バイナリ内の**rpathパスとライブラリ**を検索するには：`otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**：**メイン実行ファイルを含むディレクトリ**への**パス**です。

**`@loader_path`**：**Mach-Oバイナリ**を含む**ディレクトリ**への**パス**です。

- **実行可能ファイル**で使用される場合、**`@loader_path`**は**実質的に** **`@executable_path`**と**同じ**です。
- **dylib**で使用される場合、**`@loader_path`**は**dylib**への**パス**を提供します。
{% endhint %}

この機能を悪用して特権を昇格させる方法は、**rootユーザーによって実行されているアプリケーションが、攻撃者が書き込み権限を持つフォルダーでライブラリを探している**珍しいケースです。

{% hint style="success" %}
アプリケーション内の**欠落しているライブラリ**を見つけるための素敵な**スキャナー**は、[**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html)または[**CLIバージョン**](https://github.com/pandazheng/DylibHijack)です。
このテクニックに関する技術的な詳細を含む素敵な**レポート**は[**こちら**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x)で見つけることができます。
{% endhint %}

**例**

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dlopenハイジャッキング

{% hint style="danger" %}
Dlopenハイジャッキング攻撃を実行するには、**前述のライブラリ検証制限**も適用されます。
{% endhint %}

**`man dlopen`**から：

- パスに**スラッシュ文字が含まれていない場合**（つまり、単なるリーフ名である場合）、**dlopen()は検索を行います**。**`$DYLD_LIBRARY_PATH`**が起動時に設定されている場合、dyldはまずそのディレクトリで検索します。次に、呼び出し元のmach-oファイルまたはメイン実行可能ファイルが**`LC_RPATH`**を指定している場合、dyldは**そのディレクトリで検索**します。次に、プロセスが**制限されていない**場合、dyldは**現在の作業
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
コンパイルして実行すると、**各ライブラリが見つからなかった場所**がわかります。また、**FSログをフィルタリング**することもできます。
```bash
sudo fs_usage | grep "dlopentest"
```
## 相対パスハイジャック

**特権付きバイナリ/アプリ**（たとえばSUIDまたは強力な権限を持つバイナリ）が**相対パス**ライブラリ（たとえば`@executable_path`や`@loader_path`を使用）をロードしており、かつ**ライブラリ検証が無効**になっている場合、バイナリを攻撃者が相対パスでロードされるライブラリを変更できる位置に移動し、そのライブラリを悪用してプロセスにコードをインジェクトする可能性があります。

## `DYLD_*`および`LD_LIBRARY_PATH`環境変数を削除

ファイル`dyld-dyld-832.7.1/src/dyld2.cpp`には、**`pruneEnvironmentVariables`** 関数があり、**`DYLD_`**で始まる環境変数と **`LD_LIBRARY_PATH=`** を削除します。

また、**suid**および**sgid**バイナリに対して、この関数は明示的に**`DYLD_FALLBACK_FRAMEWORK_PATH`**と**`DYLD_FALLBACK_LIBRARY_PATH`**を**null**に設定します。

この関数は、OSXをターゲットにしている場合、同じファイルの**`_main`** 関数から次のように呼び出されます：
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
そして、これらのブールフラグはコード内の同じファイルで設定されています：
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
これは、バイナリが**suid**または**sgid**であるか、ヘッダーに**RESTRICT**セグメントがあるか、**CS\_RESTRICT**フラグで署名されている場合、**`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`**がtrueであり、環境変数が削除されることを意味します。

CS\_REQUIRE\_LVがtrueの場合、変数は削除されませんが、ライブラリ検証は元のバイナリと同じ証明書を使用していることを確認します。

## 制限のチェック

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

Keychain に新しい証明書を作成し、その証明書を使用してバイナリに署名します：

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
`0x0(none)`フラグで署名されたバイナリがあっても、実行時に**`CS_RESTRICT`**フラグが動的に付与される可能性があるため、このテクニックはそれらのバイナリでは機能しません。

このフラグを持つprocをチェックすることができます（[**ここでcsopsを取得**](https://github.com/axelexic/CSOps)）:&#x20;
```bash
csops -status <pid>
```
そして、フラグ0x800が有効になっているかどうかをチェックします。
{% endhint %}

# 参考文献
* [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）でAWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**する。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>
