# macOS System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

Kernel Extensionsとは異なり、**System Extensionsはユーザースペースで実行され**、拡張機能の不具合によるシステムクラッシュのリスクを軽減します。

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

システム拡張には、**DriverKit** Extensions、**Network** Extensions、**Endpoint Security** Extensionsの3種類があります。

### **DriverKit Extensions**

DriverKitは、**ハードウェアサポートを提供する**カーネル拡張の代替です。USB、シリアル、NIC、HIDドライバなどのデバイスドライバがカーネルスペースではなくユーザースペースで実行できるようにします。DriverKitフレームワークには、**特定のI/O Kitクラスのユーザースペースバージョン**が含まれており、カーネルは通常のI/O Kitイベントをユーザースペースに転送し、これらのドライバが実行されるための安全な環境を提供します。

### **Network Extensions**

Network Extensionsは、ネットワークの動作をカスタマイズする機能を提供します。Network Extensionsにはいくつかのタイプがあります：

- **App Proxy**: フロー指向のカスタムVPNプロトコルを実装するVPNクライアントを作成するために使用されます。これは、個々のパケットではなく接続（またはフロー）に基づいてネットワークトラフィックを処理します。
- **Packet Tunnel**: パケット指向のカスタムVPNプロトコルを実装するVPNクライアントを作成するために使用されます。これは、個々のパケットに基づいてネットワークトラフィックを処理します。
- **Filter Data**: ネットワークの「フロー」をフィルタリングするために使用されます。フローレベルでネットワークデータを監視または変更できます。
- **Filter Packet**: 個々のネットワークパケットをフィルタリングするために使用されます。パケットレベルでネットワークデータを監視または変更できます。
- **DNS Proxy**: カスタムDNSプロバイダーを作成するために使用されます。DNSリクエストとレスポンスを監視または変更するために使用できます。

## Endpoint Security Framework

Endpoint Securityは、AppleがmacOSで提供するフレームワークで、システムセキュリティのためのAPIセットを提供します。これは、**セキュリティベンダーや開発者がシステム活動を監視および制御する製品を構築するために使用することを意図しています**。

このフレームワークは、プロセスの実行、ファイルシステムイベント、ネットワークおよびカーネルイベントなど、システム活動を監視および制御するための**APIのコレクションを提供します**。

このフレームワークのコアはカーネルに実装されており、**`/System/Library/Extensions/EndpointSecurity.kext`**にあるカーネル拡張（KEXT）です。このKEXTは、いくつかの重要なコンポーネントで構成されています：

- **EndpointSecurityDriver**: これはカーネル拡張の「エントリーポイント」として機能します。OSとEndpoint Securityフレームワークの主な相互作用のポイントです。
- **EndpointSecurityEventManager**: このコンポーネントはカーネルフックを実装する責任があります。カーネルフックにより、フレームワークはシステムコールを傍受することでシステムイベントを監視できます。
- **EndpointSecurityClientManager**: これはユーザースペースクライアントとの通信を管理し、どのクライアントが接続されていてイベント通知を受け取る必要があるかを追跡します。
- **EndpointSecurityMessageManager**: これはメッセージとイベント通知をユーザースペースクライアントに送信します。

Endpoint Securityフレームワークが監視できるイベントは以下に分類されます：

- ファイルイベント
- プロセスイベント
- ソケットイベント
- カーネルイベント（カーネル拡張の読み込み/アンロードやI/O Kitデバイスのオープンなど）

### Endpoint Security Framework Architecture

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**ユーザースペース通信**はIOUserClientクラスを通じてEndpoint Securityフレームワークと行われます。呼び出し元のタイプに応じて、2つの異なるサブクラスが使用されます：

- **EndpointSecurityDriverClient**: これは`com.apple.private.endpoint-security.manager`権限を必要とし、これはシステムプロセス`endpointsecurityd`のみが保持しています。
- **EndpointSecurityExternalClient**: これは`com.apple.developer.endpoint-security.client`権限を必要とします。これは通常、Endpoint Securityフレームワークと相互作用する必要があるサードパーティのセキュリティソフトウェアによって使用されます。

Endpoint Security Extensions:**`libEndpointSecurity.dylib`**は、システム拡張がカーネルと通信するために使用するCライブラリです。このライブラリは、I/O Kit（`IOKit`）を使用してEndpoint Security KEXTと通信します。

**`endpointsecurityd`**は、特に初期ブートプロセス中にエンドポイントセキュリティシステム拡張を管理および起動するために関与する重要なシステムデーモンです。**`Info.plist`**ファイルに**`NSEndpointSecurityEarlyBoot`**としてマークされた**システム拡張のみ**がこの初期ブート処理を受けます。

別のシステムデーモン、**`sysextd`**は、**システム拡張を検証し**、それらを適切なシステム場所に移動します。その後、関連するデーモンに拡張をロードするように要求します。**`SystemExtensions.framework`**は、システム拡張をアクティブ化および非アクティブ化する責任があります。

## Bypassing ESF

ESFは、レッドチームを検出しようとするセキュリティツールによって使用されるため、これを回避する方法に関する情報は興味深いです。

### CVE-2021-30965

問題は、セキュリティアプリケーションが**フルディスクアクセス権限**を持っている必要があることです。したがって、攻撃者がそれを削除できれば、ソフトウェアの実行を防ぐことができます：
```bash
tccutil reset All
```
**このバイパスおよび関連情報**については、トーク[#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)を確認してください。

最終的には、新しい権限**`kTCCServiceEndpointSecurityClient`**を**`tccd`**によって管理されるセキュリティアプリに与えることで修正され、`tccutil`がその権限をクリアしないようにし、アプリが実行されるのを防ぎました。

## 参考文献

- [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

{{#include ../../../banners/hacktricks-training.md}}
