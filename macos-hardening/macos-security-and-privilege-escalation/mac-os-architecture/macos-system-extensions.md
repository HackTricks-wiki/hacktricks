# macOSシステム拡張機能

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を使って、ゼロからヒーローまでAWSハッキングを学ぶ</summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を手に入れる
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で私をフォローする🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)。
- **ハッキングテクニックを共有するために、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>

## システム拡張機能 / エンドポイントセキュリティフレームワーク

**システム拡張機能**は、**カーネル拡張機能とは異なり、ユーザースペースで実行**されるため、拡張機能の誤作動によるシステムクラッシュのリスクが低減されます。

<figure><img src="../../../.gitbook/assets/image (1) (3) (1) (1).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

システム拡張機能には、**DriverKit**拡張機能、**Network**拡張機能、**Endpoint Security**拡張機能の3種類があります。

### **DriverKit拡張機能**

DriverKitは、**ハードウェアサポートを提供する**カーネル拡張機能の代替となるものです。これにより、デバイスドライバ（USB、シリアル、NIC、HIDドライバなど）がカーネルスペースではなくユーザースペースで実行されるようになります。DriverKitフレームワークには、**特定のI/O Kitクラスのユーザースペースバージョン**が含まれており、カーネルは通常のI/O Kitイベントをユーザースペースに転送して、これらのドライバが実行される安全な環境を提供します。

### **Network拡張機能**

Network拡張機能は、ネットワーク動作をカスタマイズする機能を提供します。いくつかのタイプのNetwork拡張機能があります：

- **App Proxy**: これは、接続（またはフロー）に基づいてネットワークトラフィックを処理するカスタムVPNプロトコルを実装するVPNクライアントを作成するために使用されます。
- **Packet Tunnel**: これは、個々のパケットに基づいてネットワークトラフィックを処理するカスタムVPNプロトコルを実装するVPNクライアントを作成するために使用されます。
- **Filter Data**: これは、ネットワークの「フロー」をフィルタリングするために使用されます。フローレベルでネットワークデータを監視または変更できます。
- **Filter Packet**: これは、個々のネットワークパケットをフィルタリングするために使用されます。パケットレベルでネットワークデータを監視または変更できます。
- **DNS Proxy**: これは、カスタムDNSプロバイダを作成するために使用されます。DNSリクエストと応答を監視または変更するために使用できます。

## エンドポイントセキュリティフレームワーク

エンドポイントセキュリティは、AppleがmacOSで提供するシステムセキュリティ用のAPIセットです。これは、**悪意のある活動を特定し、防御するための製品を構築するためにセキュリティベンダーや開発者が使用することを意図**しています。

このフレームワークは、プロセスの実行、ファイルシステムイベント、ネットワークおよびカーネルイベントなど、**システム活動を監視および制御するためのAPIのコレクション**を提供します。

このフレームワークの中核は、**カーネルに実装されたカーネル拡張機能（KEXT）**であり、**`/System/Library/Extensions/EndpointSecurity.kext`**に配置されています。このKEXTは、いくつかの主要なコンポーネントで構成されています：

- **EndpointSecurityDriver**: これは、カーネル拡張機能との主なやり取りポイントとして機能します。OSとEndpoint Securityフレームワークとの主要な相互作用ポイントです。
- **EndpointSecurityEventManager**: このコンポーネントは、カーネルフックを実装する責任があります。カーネルフックにより、フレームワークはシステムコールを傍受してシステムイベントを監視できます。
- **EndpointSecurityClientManager**: これは、ユーザースペースクライアントとの通信を管理し、接続されているクライアントとイベント通知を受け取る必要があるクライアントを追跡します。
- **EndpointSecurityMessageManager**: これは、メッセージとイベント通知をユーザースペースクライアントに送信します。

Endpoint Securityフレームワークが監視できるイベントは、次のカテゴリに分類されます：

- ファイルイベント
- プロセスイベント
- ソケットイベント
- カーネルイベント（カーネル拡張機能の読み込み/アンロードやI/O Kitデバイスのオープンなど）

### エンドポイントセキュリティフレームワークアーキテクチャ

<figure><img src="../../../.gitbook/assets/image (3) (8).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

エンドポイントセキュリティフレームワークとの**ユーザースペース通信**は、IOUserClientクラスを介して行われます。呼び出し元のタイプに応じて、異なるサブクラスが使用されます：

- **EndpointSecurityDriverClient**: これには`com.apple.private.endpoint-security.manager`権限が必要で、これはシステムプロセス`endpointsecurityd`のみが保持しています。
- **EndpointSecurityExternalClient**: これには`com.apple.developer.endpoint-security.client`権限が必要です。これは通常、Endpoint Securityフレームワークとやり取りする必要があるサードパーティのセキュリティソフトウェアによって使用されます。

エンドポイントセキュリティ拡張機能:**`libEndpointSecurity.dylib`**は、システム拡張機能がカーネルと通信するために使用するCライブラリです。このライブラリは、I/O Kit (`IOKit`)を使用してEndpoint Security KEXTと通信します。

**`endpointsecurityd`**は、エンドポイントセキュリティシステム拡張機能を管理し起動するために関与する主要なシステムデーモンです。**`Info.plist`**ファイルで**`NSEndpointSecurityEarlyBoot`**とマークされた**システム拡張機能のみ**がこの早期起動処理を受け取ります。

別のシステムデーモンである**`sysextd`**は、システム拡張機能を検証し、適切なシステムの場所に移動します。その後、関連するデーモンに拡張機能の読み込みを要求します。**`SystemExtensions.framework`**は、システム拡張機能の有効化と無効化を担当します。

## ESFのバイパス

ESFは、レッドチームを検出しようとするセキュリティツールによって使用されるため、これを回避する方法に関する情報は興味深いものです。

### CVE-2021-30965

重要なのは、セキュリティアプリケーションが**完全ディスクアクセス権限**を持っている必要があることです。したがって、攻撃者がそれを削除できれば、ソフトウェアの実行を防ぐことができます。
```bash
tccutil reset All
```
**詳細情報**については、この回避策および関連するものをチェックしてください：[#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

最終的には、**`tccd`**によって管理されるセキュリティアプリに新しい権限 **`kTCCServiceEndpointSecurityClient`** を与えることで、`tccutil` がアプリの権限をクリアしないようにし、実行を妨げることが修正されました。

## 参考文献

* [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

<details>

<summary><strong>**htARTE (HackTricks AWS Red Team Expert)** で**ゼロからヒーローまでのAWSハッキング**を学びましょう！</summary>

HackTricks をサポートする他の方法：

* **HackTricks で企業を宣伝したい**、または **HackTricks をPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つけてください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegramグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) をフォローしてください
* **HackTricks** および **HackTricks Cloud** のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください

</details>
