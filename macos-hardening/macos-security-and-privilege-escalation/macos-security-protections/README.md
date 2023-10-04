# macOSセキュリティ保護

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。これは、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローしてください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## Gatekeeper

Gatekeeperは通常、**Quarantine + Gatekeeper + XProtect**の組み合わせを指すことが多く、これらの3つのmacOSセキュリティモジュールは、**ユーザーが潜在的に悪意のあるソフトウェアを実行するのを防ぐ**ために使用されます。

詳細は次を参照してください：

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## MRT - マルウェア除去ツール

マルウェア除去ツール（MRT）は、macOSのセキュリティインフラのもう一つの部分です。その名前からもわかるように、MRTの主な機能は、**感染したシステムから既知のマルウェアを削除する**ことです。

マルウェアがMacで検出されると（XProtectまたは他の手段によって）、MRTを使用してマルウェアを自動的に**削除**することができます。MRTはバックグラウンドで静かに動作し、通常、システムが更新されるか、新しいマルウェア定義がダウンロードされると実行されます（マルウェアを検出するためのMRTのルールはバイナリ内にあるようです）。

XProtectとMRTは、macOSのセキュリティ対策の一部ですが、それぞれ異なる機能を果たしています：

* **XProtect**は予防ツールです。ファイルが（特定のアプリケーションを介して）ダウンロードされると、**ファイルをチェック**し、既知のマルウェアの種類を検出した場合は、**ファイルを開かないように**して、システムへのマルウェア感染を防ぎます。
* 一方、**MRT**は**反応型ツール**です。マルウェアがシステムで検出された後、問題のあるソフトウェアを削除してシステムをクリーンアップすることを目的としています。

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

**TCC（透明性、同意、および制御）**は、macOSのメカニズムであり、プライバシーの観点から**アプリケーションの特定の機能へのアクセスを制限および制御**するためのものです。これには、位置情報サービス、連絡先、写真、マイクロフォン、カメラ、アクセシビリティ、フルディスクアクセスなどが含まれます。

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

## 信頼キャッシュ

Apple macOSの信頼キャッシュ、またはAMFI（Apple Mobile File Integrity）キャッシュとも呼ばれるものは、macOSで**許可されていないまたは悪意のあるソフトウェアの実行を防止**するためのセキュリティメカニズムです。基本的には、ソフトウェアの**整合性と信頼性を検証するためにオペレーティングシステムが使用する暗号ハッシュのリスト**です。

macOSでアプリケーションまたは実行可能ファイルが実行されようとすると、オペレーティングシステムはAMFI信頼キャッシュをチェックします。ファイルのハッシュが信頼キャッシュに見つかった場合、システムはそのプログラムを実行を**許可**します。なぜなら、それを信頼されたものと認識するからです。

## 起動制約

これにより、Appleの署名されたバイナリをどこから、どのように起動できるかが制御されます：

* launchdによって実行されるべきアプリを直接起動することはできません。
* /System/のような信頼された場所の外部でアプリを実行することはできません。
* **ハッキングのトリックを共有するには、PRを** [**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
