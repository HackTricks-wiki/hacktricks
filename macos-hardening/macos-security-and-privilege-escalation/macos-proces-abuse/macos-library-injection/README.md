# macOSライブラリインジェクション

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

{% hint style="danger" %}
**dyldのコードはオープンソース**であり、[https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/)で見つけることができ、**URL**（例：[https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)）を使用してtarをダウンロードすることができます。
{% endhint %}

## **DYLD\_INSERT\_LIBRARIES**

> これは、プログラムで指定されたライブラリの前に**ロードする動的ライブラリのリスト**です。これにより、フラットネームスペースイメージで使用される既存の動的共有ライブラリの新しいモジュールをテストすることができます。新しいモジュールだけを持つ一時的な動的共有ライブラリをロードすることで実現します。ただし、これは、DYLD\_FORCE\_FLAT\_NAMESPACEも使用されていない限り、2レベルの名前空間イメージを使用してビルドされたイメージには影響しません。

これは、[**LinuxのLD\_PRELOAD**](../../../../linux-hardening/privilege-escalation#ld\_preload)と似ています。

このテクニックは、**ASEPテクニック**としても使用できます。インストールされているすべてのアプリケーションには、"Info.plist"というplistがあり、`LSEnvironmental`というキーを使用して環境変数を割り当てることができます。

{% hint style="info" %}
2012年以降、**Appleは`DYLD_INSERT_LIBRARIES`の権限を大幅に制限**しています。

コードに移動して、**`src/dyld.cpp`**を確認してください。関数**`pruneEnvironmentVariables`**では、**`DYLD_*`**変数が削除されていることがわかります。

関数**`processRestricted`**では、制限の理由が設定されています。そのコードをチェックすると、理由は次のとおりです。

* バイナリが`setuid/setgid`である
* machoバイナリに`__RESTRICT/__restrict`セクションが存在する
* ソフトウェアには、[`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)エンタイトルメントがある（ハード化されたランタイム）
* バイナリのエンタイトルメントを確認するには：`codesign -dv --entitlements :- </path/to/bin>`

より最新のバージョンでは、このロジックを関数**`configureProcessRestrictions`**の後半で見つけることができます。ただし、新しいバージョンでは、関数の**最初のチェックが実行**されます（iOSやシミュレーションに関連するif文は削除してもかまいません）。
{% endhint %}

### ライブラリの検証

バイナリが**`DYLD_INSERT_LIBRARIES`**環境変数を使用することを許可していても、バイナリはライブラリの署名をチェックしてカスタムライブラリをロードしません。

カスタムライブラリをロードするためには、バイナリに次のいずれかのエンタイトルメントが必要です。

* &#x20;[`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

または、バイナリには**ハード化されたランタイムフラグ**または**ライブラリの検証フラグ**がない必要があります。

`codesign --display --verbose <bin>`を使用してバイナリが**ハード化されたランタイム**を持っているかどうかを確認し、**`CodeDirectory`**のランタイムフラグをチェックします。例：**`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

また、バイナリが**バイナリと同じ証明書で署名されている場合**も、ライブラリをロードすることができます。

これを悪用する方法の例と制限を確認するには、次を参照してください：

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}
## Dylibハイジャッキング

{% hint style="danger" %}
**以前のライブラリ検証の制限も適用**されることを忘れないでください。Dylibハイジャッキング攻撃を実行するために。
{% endhint %}

Windowsと同様に、MacOSでも**dylibをハイジャック**して、**アプリケーション**が**任意のコードを実行**することができます。\
ただし、MacOSアプリケーションがライブラリをロードする方法は、Windowsよりも**制限が厳しい**です。これは、**マルウェア**開発者がこの技術を**ステルス**に使用することはできますが、特権をエスカレートするためにこれを悪用する可能性はずっと低いということを意味します。

まず、**MacOSバイナリがロードするライブラリの完全なパスを示す**ことが**より一般的**です。そして、**MacOSは決して**`$PATH`のフォルダを検索しません。

この機能に関連する**コード**の**主な**部分は、`ImageLoader.cpp`の**`ImageLoader::recursiveLoadLibraries`**にあります。

machoバイナリがライブラリをロードするために使用できる**4つの異なるヘッダコマンド**があります。

* **`LC_LOAD_DYLIB`**コマンドは、dylibをロードするための一般的なコマンドです。
* **`LC_LOAD_WEAK_DYLIB`**コマンドは、前のコマンドと同様に機能しますが、dylibが見つからない場合でもエラーなしで実行が続行されます。
* **`LC_REEXPORT_DYLIB`**コマンドは、別のライブラリからシンボルをプロキシ（または再エクスポート）します。
* **`LC_LOAD_UPWARD_DYLIB`**コマンドは、2つのライブラリが互いに依存している場合に使用されます（これは_上向きの依存性_と呼ばれます）。

ただし、**2種類のdylibハイジャッキング**があります。

* **弱リンクされたライブラリが見つからない場合**：これは、アプリケーションが**`LC_LOAD_WEAK_DYLIB`**で構成された存在しないライブラリをロードしようとすることを意味します。その後、**攻撃者が期待される場所にdylibを配置すると、ロードされます**。
* リンクが「弱い」という事実は、ライブラリが見つからなくてもアプリケーションが実行を続けることを意味します。
* これに関連する**コード**は、`ImageLoaderMachO.cpp`の`ImageLoaderMachO::doGetDependentLibraries`関数にあります。ここでは、`lib->required`が`LC_LOAD_WEAK_DYLIB`がtrueの場合にのみ`false`です。
* バイナリ内の**弱リンクされたライブラリを見つける**：（ハイジャッキングライブラリを作成する方法の後で例があります）
* ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
* **`@rpath`で構成**された：Mach-Oバイナリには、**`LC_RPATH`**と**`LC_LOAD_DYLIB`**というコマンドがあります。これらのコマンドの**値**に基づいて、**ライブラリ**が**異なるディレクトリ**から**ロード**されます。
* **`LC_RPATH`**には、バイナリでライブラリをロードするために使用されるいくつかのフォルダのパスが含まれています。
* **`LC_LOAD_DYLIB`**には、ロードする特定のライブラリのパスが含まれています。これらのパスには**`@rpath`**が含まれる場合、**`LC_RPATH`**の値で置き換えられます。**`LC_RPATH`**に複数のパスがある場合、すべてのパスが使用されてライブラリを検索します。例：
* **`LC_LOAD_DYLIB`**に`@rpath/library.dylib`が含まれ、**`LC_RPATH`**に`/application/app.app/Contents/Framework/v1/`と`/application/app.app/Contents/Framework/v2/`が含まれている場合。両方のフォルダが`library.dylib`をロードするために使用されます。**`LC_LOAD_DYLIB`**のパスの順序に従って、ライブラリが`[...]/v1/`に存在しない場合、攻撃者は`[...]/v2/`に配置してライブラリのロードをハイジャックすることができます。
* バイナリ内の**rpathパスとライブラリ**を検索するには：`otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**：**メイン実行ファイル**を含むディレクトリへの**パス**です。

**`@loader_path`**：**ロードコマンド**を含む**Mach-Oバイナリ**を含む**ディレクトリ**への**パス**です。

* 実行可能ファイルで使用される場合、**`@loader_path`**は**`@executable_path`**と**同じ**です。
* **dylib**で使用される場合、**`@loader_path`**は**dylib**への**パス**を与えます。
{% endhint %}

この機能を悪用して**特権をエスカレート**する方法は、**root**によって実行される**アプリケーション**が**攻撃者が書き込み権限を持つフォルダ**で**ライブラリを検索**している**珍しいケース**です。

{% hint style="success" %}
アプリケーション内の**欠落しているライブラリ**を見つけるための素晴らしい**スキャナ**は、[**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html)または[**CLIバージョン**](https://github.com/pandazheng/DylibHijack)です。\
この技術に関する技術的な詳細を含む素晴らしい**レポート**は[**こちら**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x)で見つけることができます。
{% endhint %}

**例**

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dlopenハイジャッキング

{% hint style="danger" %}
**以前のライブラリ検証の制限も適用**されることを忘れないでください。Dlopenハイジャッキング攻撃を実行するために。
{% endhint %}

**`man dlopen`**から：

* パスに**スラッシュ文字が含まれていない**場合（つまり、単なるリーフ名である場合）、**dlopen()は検索**を行います。**`$DYLD_LIBRARY_PATH`**が起動時に
* パスがフレームワークのパスのように見える場合（例：`/stuff/foo.framework/foo`）、もし起動時に`$DYLD_FRAMEWORK_PATH`が設定されていた場合、dyldはまずそのディレクトリ内でフレームワークの部分パス（例：`foo.framework/foo`）を探します。次に、dyldは指定されたパスをそのまま試します（相対パスの場合は現在の作業ディレクトリを使用します）。最後に、古いバイナリの場合、dyldはいくつかのフォールバックを試みます。もし起動時に`$DYLD_FALLBACK_FRAMEWORK_PATH`が設定されていた場合、dyldはそれらのディレクトリを検索します。そうでなければ、dyldは`/Library/Frameworks`（プロセスが制限されていない場合はmacOS上）を検索し、次に`/System/Library/Frameworks`を検索します。

1. `$DYLD_FRAMEWORK_PATH`
2. 指定されたパス（制限がない場合は現在の作業ディレクトリを使用した相対パス）
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks`（制限がない場合）
5. `/System/Library/Frameworks`

{% hint style="danger" %}
フレームワークのパスの場合、乗っ取りの方法は次のとおりです：

* プロセスが**制限されていない**場合、CWDからの**相対パス**を悪用する（ドキュメントには明記されていませんが、プロセスが制限されている場合、DYLD\_\*環境変数は削除されます）
{% endhint %}

* パスにスラッシュが含まれているがフレームワークのパスではない場合（つまり、完全なパスまたはdylibへの部分パス）、dlopen（）はまず（設定されている場合）**`$DYLD_LIBRARY_PATH`**（パスの末尾部分を使用）を検索します。次に、dyldは指定されたパスを試します（制限されているプロセスの場合は現在の作業ディレクトリを使用しますが、相対パスの場合は制限されていないプロセスのみ）。最後に、古いバイナリの場合、dyldはフォールバックを試みます。もし起動時に`$DYLD_FALLBACK_LIBRARY_PATH`が設定されていた場合、dyldはそれらのディレクトリを検索します。そうでなければ、dyldは`/usr/local/lib/`（制限がない場合）を検索し、次に`/usr/lib/`を検索します。

1. `$DYLD_LIBRARY_PATH`
2. 指定されたパス（制限がない場合は現在の作業ディレクトリを使用した相対パス）
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/`（制限がない場合）
5. `/usr/lib/`

{% hint style="danger" %}
スラッシュが含まれていてフレームワークではない場合、乗っ取りの方法は次のとおりです：

* バイナリが**制限されていない**場合、CWDまたは`/usr/local/lib`から何かをロードすることが可能です（または、上記の環境変数のいずれかを悪用する）
{% endhint %}

{% hint style="info" %}
注意：**dlopenの検索を制御する**設定ファイルはありません。

注意：メインの実行可能ファイルが**set\[ug]idバイナリまたはエンタイトルメントで署名**されている場合、**すべての環境変数は無視**され、フルパスのみ使用できます（詳細な情報については、[DYLD\_INSERT\_LIBRARIESの制限を確認](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md#check-dyld\_insert\_librery-restrictions)してください）。

注意：Appleのプラットフォームでは、32ビットと64ビットのライブラリを組み合わせるために「ユニバーサル」ファイルが使用されます。これは、**別々の32ビットと64ビットの検索パスは存在しない**ことを意味します。

注意：Appleのプラットフォームでは、ほとんどのOS dylibは**dyldキャッシュに統合**されており、ディスク上に存在しません。したがって、OS dylibが存在するかどうかを事前に確認するために**`stat()`**を呼び出すことはできません。ただし、**`dlopen_preflight()`**は、互換性のあるmach-oファイルを見つけるために**`dlopen()`**と同じ手順を使用します。
{% endhint %}

**パスをチェックする**

以下のコードですべてのオプションをチェックしましょう：
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
もしコンパイルして実行すると、**各ライブラリが検索に失敗した場所**がわかります。また、**FSログをフィルタリングする**こともできます。
```bash
sudo fs_usage | grep "dlopentest"
```
## `DYLD_*`および`LD_LIBRARY_PATH`環境変数の削除

ファイル`dyld-dyld-832.7.1/src/dyld2.cpp`には、**`DYLD_`**で始まる環境変数と**`LD_LIBRARY_PATH=`**を削除する関数**`pruneEnvironmentVariables`**が存在します。

また、この関数は、**suid**および**sgid**バイナリの場合に、特に環境変数**`DYLD_FALLBACK_FRAMEWORK_PATH`**および**`DYLD_FALLBACK_LIBRARY_PATH`**を**null**に設定します。

この関数は、同じファイルの**`_main`**関数から、OSXをターゲットにして呼び出されます。
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
そして、これらのブールフラグはコード内の同じファイルで設定されます：
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

なお、CS\_REQUIRE\_LVがtrueの場合、変数は削除されませんが、ライブラリの検証では元のバイナリと同じ証明書を使用しているかどうかがチェックされます。

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

The `__RESTRICT` section is a special section in macOS that is used for library injection and privilege escalation techniques. It is located within the `__restrict` segment, which is a protected segment of memory.

The purpose of the `__RESTRICT` section is to restrict the execution of certain code or functions within a process. By injecting malicious code into this section, an attacker can gain unauthorized access and escalate their privileges within the system.

It is important to note that manipulating the `__RESTRICT` section requires advanced knowledge of macOS internals and memory manipulation techniques. This technique is commonly used by hackers to bypass security measures and gain control over a compromised system.

To protect against library injection and privilege escalation attacks, it is recommended to implement strong security measures, such as regular software updates, code signing, and strict access controls. Additionally, monitoring for any suspicious activity or unauthorized modifications to the `__RESTRICT` section can help detect and mitigate potential attacks.
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### ハードニングされたランタイム

キーチェーンに新しい証明書を作成し、それを使用してバイナリに署名します：

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
注意してください、バイナリにはフラグ**`0x0(none)`**で署名されているものがあっても、実行時に**`CS_RESTRICT`**フラグを動的に取得することができるため、このテクニックはそれらでは機能しません。

(procにこのフラグがあるかどうかを確認するには、[**ここでcsopsを取得**](https://github.com/axelexic/CSOps)してください):&#x20;
```bash
csops -status <pid>
```
そして、フラグ0x800が有効になっているかどうかを確認します。
{% endhint %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* あなたは**サイバーセキュリティ会社**で働いていますか？ HackTricksであなたの**会社を宣伝**したいですか？または、**PEASSの最新バージョンを入手**したいですか？または、HackTricksを**PDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
