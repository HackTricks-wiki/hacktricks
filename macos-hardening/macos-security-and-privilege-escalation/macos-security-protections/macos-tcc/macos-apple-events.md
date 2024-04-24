# macOS Apple Events

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**または **HackTricks をPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**または[telegramグループ](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)を**フォロー**する。
* **ハッキングトリックを共有するために、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する。**

</details>

## 基本情報

**Apple Events** は、AppleのmacOSの機能で、アプリケーション同士が通信することを可能にします。これらは **Apple Event Manager** の一部であり、macOSオペレーティングシステムのインタープロセス通信を処理する責任があるコンポーネントです。このシステムにより、1つのアプリケーションが他のアプリケーションにメッセージを送信して特定の操作を要求することができます。たとえば、ファイルを開く、データを取得する、コマンドを実行するなどです。

minaデーモンは `/System/Library/CoreServices/appleeventsd` で、サービス `com.apple.coreservices.appleevents` を登録しています。

イベントを受信できるすべてのアプリケーションは、Apple Event Mach Port を提供してこのデーモンとチェックします。そして、アプリケーションがイベントを送信したい場合、そのアプリケーションはこのポートをデーモンからリクエストします。

サンドボックス化されたアプリケーションは、イベントを送信できるようにするために、`allow appleevent-send` および `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` のような特権が必要です。`com.apple.security.temporary-exception.apple-events` のような権限は、`com.apple.private.appleevents` のような権限が必要なイベント送信へのアクセスを制限する可能性があります。

{% hint style="success" %}
メッセージの送信に関する情報をログに記録するために、環境変数 **`AEDebugSends`** を使用することが可能です：
```bash
AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
```
{% endhint %}

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を使用して、ゼロからヒーローまでAWSハッキングを学びましょう！</summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)をフォローする
- **ハッキングトリックを共有するために、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください**

</details>
