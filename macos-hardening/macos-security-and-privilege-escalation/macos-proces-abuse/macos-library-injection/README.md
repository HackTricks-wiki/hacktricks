# macOSライブラリインジェクション

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有する**ために、PRを提出して[**hacktricks repo**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)に参加してください。

</details>

{% hint style="danger" %}
**dyldのコードはオープンソース**であり、[https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/)で見つけることができ、**URL**を使用してtarをダウンロードすることができます。例：[https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)
{% endhint %}

## **DYLD\_INSERT\_LIBRARIES**

> これは、プログラムで指定されたライブラリの前に**ロードする動的ライブラリのリスト**です。これにより、新しいモジュールのみを含む一時的な動的共有ライブラリをロードすることで、フラットネームスペースイメージで使用される既存の動的共有ライブラリの新しいモジュールをテストすることができます。ただし、これは、DYLD\_FORCE\_FLAT\_NAMESPACEも使用されていない限り、2レベルの名前空間イメージを使用してビルドされたイメージには影響しません。

これは、[**LinuxのLD\_PRELOAD**](../../../../linux-hardening/privilege-escalation#ld\_preload)のようなものです。

このテクニックは、ASEPテクニックとしても使用できます。インストールされているすべてのアプリケーションには、`LSEnvironmental`というキーを使用して環境変数を割り当てることができる「Info.plist」というplistがあります。

{% hint style="info" %}
2012年以降、**Appleは`DYLD_INSERT_LIBRARIES`の権限を大幅に制限**しています。

コードに移動し、**`src/dyld.cpp`**を確認してください。関数**`pruneEnvironmentVariables`**では、**`DYLD_*`**変数が削除されていることがわかります。

関数**`processRestricted`**では、制限の理由が設定されています。そのコードをチェックすると、理由は次のとおりです。

* バイナリが`setuid/setgid`である
* machoバイナリに`__RESTRICT/__restrict`セクションが存在する
* ソフトウェアには、[`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)エンタイトルメントまたは[`com.apple.security.cs.disable-library-validation`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation)のエンタイトルメントがあります。
* バイナリのエンタイトルメントを次のコマンドで確認します：`codesign -dv --entitlements :- </path/to/bin>`
* ライブラリがバイナリと異なる証明書で署名されている場合
* ライブラリとバイナリが同じ証明書で署名されている場合、これにより前の制限がバイパスされます
* エンタイトルメント**`system.install.apple-software`**および**`system.install.apple-software.standar-user`**を持つプログラムは、ユーザーにパスワードを求めずにAppleによって署名されたソフトウェアを**インストール**できます（特権昇格）

より新しいバージョンでは、このロジックは関数**`configureProcessRestrictions`**の後半にあります。ただし、新しいバージョンでは、関数の**最初のチェックが実行**されます（iOSやシミュレーションに関連するif文は使用されないため、それらを削除できます）。
{% endhint %}

バイナリに**ハードランタイム**があるかどうかは、`codesign --display --verbose <bin>`で**CodeDirectory**のフラグランタイムをチェックすることで確認できます。例：**`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

これを悪用する方法と制限をチェックする例を次に示します：

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dylibハイジャッキング

{% hint style="danger" %}
Dylibハイジャッキング攻撃を実行するには、**前述の制限も適用**することを忘れないでください。
{% endhint %}

Windowsと同様に、MacOSでも**dylibをハイジャック**して、**アプリケーション**で**任意のコードを実行**することができます。ただし、MacOSのアプリケーションがライブラリをロードする方法は、Windowsよりも**制限が多い**です。これは、**マルウェア**開発者がこのテクニックを**ステルス**に使用できる可能性がある一方で、特権昇格に悪用する可能性はずっと低いということを意味します。

まず、**MacOSバイナリがライブラリをロードする際には、完全なパスが指定されることが一般的**です。そして、**MacOSは決して$PATHのフォルダを検索しません**。

この機能に関連する**主なコード**
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
* **`@rpath`**で構成された場合：Mach-Oバイナリには**`LC_RPATH`**と**`LC_LOAD_DYLIB`**のコマンドがあります。これらのコマンドの値に基づいて、ライブラリは**異なるディレクトリ**から**ロード**されます。
* **`LC_RPATH`**には、バイナリでライブラリをロードするために使用されるいくつかのフォルダのパスが含まれています。
* **`LC_LOAD_DYLIB`**には、ロードする特定のライブラリのパスが含まれています。これらのパスには**`@rpath`**が含まれる場合、**`LC_RPATH`**の値で置き換えられます。**`LC_RPATH`**に複数のパスがある場合、すべてのパスが使用されてライブラリを検索します。例：
* **`LC_LOAD_DYLIB`**に`@rpath/library.dylib`が含まれ、**`LC_RPATH`**に`/application/app.app/Contents/Framework/v1/`と`/application/app.app/Contents/Framework/v2/`が含まれている場合、両方のフォルダが`library.dylib`をロードするために使用されます。**`LC_LOAD_DYLIB`**のパスの順序に従って、ライブラリが`[...]/v1/`に存在しない場合、攻撃者はそれを置くことができ、ライブラリのロードを`[...]/v2/`に乗っ取ることができます。
* バイナリ内の**rpathパスとライブラリ**を次のコマンドで検索します：`otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**：メインの実行可能ファイルが含まれるディレクトリへの**パス**です。

**`@loader_path`**：ロードコマンドを含む**Mach-Oバイナリ**が含まれる**ディレクトリ**への**パス**です。

* 実行可能ファイルで使用される場合、**`@loader_path`**は**`@executable_path`**と**同じ**です。
* **dylib**で使用される場合、**`@loader_path`**は**dylib**への**パス**を与えます。
{% endhint %}

この機能を悪用して特権をエスカレーションする方法は、**root**によって実行されている**アプリケーション**が、攻撃者が書き込み権限を持つ**フォルダ**でライブラリを検索している**まれなケース**です。

{% hint style="success" %}
アプリケーション内の**欠落しているライブラリ**を見つけるための素晴らしい**スキャナ**は、[**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html)または[**CLIバージョン**](https://github.com/pandazheng/DylibHijack)です。\
この技術に関する技術的な詳細を含む素晴らしい**レポート**は[**こちら**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x)で見つけることができます。
{% endhint %}

**例**

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

### Dlopen Hijacking

**`man dlopen`**から：

* パスに**スラッシュ文字が含まれていない**場合（つまり、単なるリーフ名である場合）、**dlopen()は検索**を行います。**`$DYLD_LIBRARY_PATH`**が起動時に設定されている場合、dyldはまずそのディレクトリを検索します。次に、呼び出し元のmach-oファイルまたはメインの実行可能ファイルが**`LC_RPATH`**を指定している場合、dyldはそれらのディレクトリを検索します。次に、プロセスが**制限されていない**場合、dyldは**現在の作業ディレクトリ**を検索します。最後に、古いバイナリの場合、dyldはいくつかのフォールバックを試みます。**`$DYLD_FALLBACK_LIBRARY_PATH`**が起動時に設定されている場合、dyldはそれらのディレクトリを検索します。それ以外の場合、dyldは**`/usr/local/lib/`**（プロセスが制限されていない場合）を検索し、次に**`/usr/lib/`**を検索します。
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`（制限されていない場合）
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/`（制限されていない場合）
6. `/usr/lib/`
* パスが**フレームワークのパスのように見える場合**（例：/stuff/foo.framework/foo）、**`$DYLD_FRAMEWORK_PATH`**が起動時に設定されている場合、dyldはまずそのディレクトリをフレームワークの部分パス（例：foo.framework/foo）のために検索します。次に、dyldは**提供されたパスをそのまま**試します（相対パスの場合は現在の作業ディレクトリを使用）。最後に、古いバイナリの場合、dyldはいくつかのフォールバックを試みます。**`$DYLD_FALLBACK_FRAMEWORK_PATH`**が起動時に設定されている場合、dyldはそれらのディレクトリを検索します。それ以外の場合、dyldは**`/Library/Frameworks`**（macOSの場合、プロセスが制限されていない場合）を検索し、次に**`/System/Library/Frameworks`**を検索します。
1. `$DYLD_FRAMEWORK_PATH`
2. 提供されたパス（相対パスの場合は現在の作業ディレクトリを使用）
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`（制限されていない場合）
4. `/Library/Frameworks`（制限されていない場合）
5. `/System/Library/Frameworks`
* パスに**スラッシュが含まれているがフレームワークのパスではない場合**（つまり、dylibへの完全パスまたは部分パス）、dlopen()は最初に（設定されている場合）**`$DYLD_LIBRARY_PATH`**（パスのリーフ部分を使用）を検索します。次に、dyldは提供されたパスを試します（制限されているプロセスの場合は現在の作業ディレクトリを使用）。最後に、古いバイナリの場合、dyldはいくつかのフォールバックを試みます。**`$DYLD_FALLBACK_LIBRARY_PATH`**が起動時に設定されている場合、dyldはそれらのディレクトリを検索します。それ以外の場合、dyldは**`/usr/local/lib/`**（プロセスが制限されていない場合）を検索し、次に**`/usr/lib/`**を検索します。
1. `$DYLD_LIBRARY_PATH`
2. 提供されたパス（制限されているプロセスの場合は現在の作業ディレクトリを使用）
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/`（制限されていない場合）
5. `/usr/lib/`

注意：メインの実行可能ファイルが**set\[ug]idバイナリであるか、エンタイトルメントで署名されている**場合、**すべての環境変数は無視**され、完全パスのみ使用できます。

**パスをチェック**

次のコードですべてのオプションを
```c
#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
void* handle;

handle = dlopen("just_name_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n", dlerror());
}

handle = dlopen("a/framework/rel_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n", dlerror());
}

handle = dlopen("/a/abs/framework/abs_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n", dlerror());
}

handle = dlopen("a/folder/rel_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n", dlerror());
}

handle = dlopen("/a/abs/folder/abs_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n", dlerror());
}

return 0;
}
```
もしコンパイルして実行すると、**各ライブラリが失敗した場所がわかります**。また、**FSログをフィルタリングすることもできます**。
```bash
sudo fs_usage | grep "dlopentest"
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
