# macOSセキュリティ保護

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksであなたの会社を宣伝したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。これは、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## Gatekeeper

Gatekeeperは通常、**Quarantine + Gatekeeper + XProtect**の組み合わせを指すことが多く、これらの3つのmacOSセキュリティモジュールは、**ユーザーが潜在的に悪意のあるソフトウェアを実行するのを防ぐ**ために使用されます。

詳細は次の場所で確認できます：

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## MRT - マルウェア除去ツール

マルウェア除去ツール（MRT）は、macOSのセキュリティインフラのもう一つの部分です。その名前からもわかるように、MRTの主な機能は、**感染したシステムから既知のマルウェアを削除する**ことです。

マルウェアがMacで検出されると（XProtectまたは他の手段によって）、MRTを使用してマルウェアを自動的に**削除**することができます。MRTはバックグラウンドで静かに動作し、通常、システムが更新されるか、新しいマルウェア定義がダウンロードされると実行されます（マルウェアを検出するためのMRTのルールはバイナリ内にあるようです）。

XProtectとMRTは、macOSのセキュリティ対策の一部ですが、それぞれ異なる機能を果たしています：

* **XProtect**は予防ツールです。ファイルが（特定のアプリケーションを介して）ダウンロードされると、**ファイルをチェック**し、既知のマルウェアの種類を検出した場合は、**ファイルを開かないように**して、最初にシステムにマルウェアが感染するのを防ぎます。
* 一方、**MRT**は**反応型のツール**です。マルウェアがシステムで検出された後、問題のあるソフトウェアを削除してシステムをクリーンアップすることを目的としています。

MRTアプリケーションは、**`/Library/Apple/System/Library/CoreServices/MRT.app`**にあります。

## プロセス制限

### SIP - システム整合性保護

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### サンドボックス

MacOSサンドボックスは、サンドボックスプロファイルで実行されるアプリケーションが**許可されたアクションに制限される**ようにします。これにより、**アプリケーションが予期されたリソースにのみアクセスする**ことが保証されます。

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - 透明性、同意、および制御

**TCC（透明性、同意、および制御）**は、macOSのメカニズムであり、プライバシーの観点から**アプリケーションの特定の機能へのアクセスを制限および制御**するためのものです。これには、位置情報サービス、連絡先、写真、マイクロフォン、カメラ、アクセシビリティ、フルディスクアクセスなどが含まれる場合があります。

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

## 信頼キャッシュ

Apple macOSの信頼キャッシュは、AMFI（Apple Mobile File Integrity）キャッシュとも呼ばれることがあり、macOSのセキュリティメカニズムであり、**許可されていないまたは悪意のあるソフトウェアの実行を防止**するために設計されています。基本的には、オペレーティングシステムがソフトウェアの整合性と信頼性を**検証するために使用する暗号ハッシュのリスト**です。

macOSでアプリケーションまたは実行可能ファイルが実行されようとすると、オペレーティングシステムはAMFI信頼キャッシュをチェックします。ファイルのハッシュが信頼キャッシュに見つかった場合、システムはプログラムを実行を**許可**します。なぜなら、それを信頼できるものと認識するからです。

## 起動制約

これは**Appleが署名したバイナリ**を**どこから**、**何を**起動できるかを制御します：

* launchdによって実行されるべきアプリを直接起動することはできません。
* /System/のような信頼された場所の外部でアプリを実行することはできません。

この制約に関する情報が含まれているファイルは、macOSの**`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**にあります（iOSでは、おそらく**`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**にあるようです）。

ツール[**img4tool**](https://github.com/tihmstar/img4tool)を使用して、キャッシュを抽出することができたようです：
```bash
img4tool -e in.img4 -o out.bin
```
（ただし、M1ではコンパイルできませんでした）。[**pyimg4**](https://github.com/m1stadev/PyIMG4)を使用することもできますが、以下のスクリプトはその出力では機能しません。

次に、[**このスクリプト**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30)のようなスクリプトを使用してデータを抽出できます。

そのデータから、**`0`の起動制約値**を持つアプリをチェックできます。これは制約されていないアプリです（各値の詳細については[**こちらをチェック**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)）。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
