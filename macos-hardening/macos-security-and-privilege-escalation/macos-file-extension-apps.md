# macOSファイル拡張子＆URLスキームアプリハンドラ

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)をフォローする。
- **ハッキングトリックを共有するためにPRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **および** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **githubリポジトリに提出する。**

</details>

## LaunchServicesデータベース

これはmacOSにインストールされているすべてのアプリケーションのデータベースであり、各インストールされたアプリケーションに関する情報（サポートするURLスキームやMIMEタイプなど）を取得するためにクエリを実行できます。

次のコマンドでこのデータベースをダンプすることができます：

{% code overflow="wrap" %}
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
{% endcode %}

または、ツール[**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html)を使用します。

**`/usr/libexec/lsd`**はデータベースの中枢です。`.lsd.installation`、`.lsd.open`、`.lsd.openurl`などの**複数のXPCサービス**を提供します。ただし、`.launchservices.changedefaulthandler`や`.launchservices.changeurlschemehandler`などのXPC機能を使用するために、アプリケーションにはいくつかの**権限が必要**です。これにより、mimeタイプやURLスキームのデフォルトアプリを変更するための`.launchservices.changedefaulthandler`や`.launchservices.changeurlschemehandler`などが含まれます。

**`/System/Library/CoreServices/launchservicesd`**はサービス`com.apple.coreservices.launchservicesd`を所有し、実行中のアプリケーションに関する情報を取得するためにクエリを実行できます。システムツール/**`usr/bin/lsappinfo`**または[**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html)を使用してクエリを実行できます。

## ファイル拡張子とURLスキームのアプリハンドラ

次の行は、拡張子に応じてファイルを開くことができるアプリケーションを見つけるのに役立ちます：

{% code overflow="wrap" %}
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
{% endcode %}

または、[**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps)のようなものを使用する：
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
あるアプリケーションがサポートする拡張子を確認することもできます。
```
cd /Applications/Safari.app/Contents
grep -A3 CFBundleTypeExtensions Info.plist  | grep string
<string>css</string>
<string>pdf</string>
<string>webarchive</string>
<string>webbookmark</string>
<string>webhistory</string>
<string>webloc</string>
<string>download</string>
<string>safariextz</string>
<string>gif</string>
<string>html</string>
<string>htm</string>
<string>js</string>
<string>jpg</string>
<string>jpeg</string>
<string>jp2</string>
<string>txt</string>
<string>text</string>
<string>png</string>
<string>tiff</string>
<string>tif</string>
<string>url</string>
<string>ico</string>
<string>xhtml</string>
<string>xht</string>
<string>xml</string>
<string>xbl</string>
<string>svg</string>
```
<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**または **HackTricks をPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)をフォローする**
* **ハッキングトリックを共有するために、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する**

</details>
