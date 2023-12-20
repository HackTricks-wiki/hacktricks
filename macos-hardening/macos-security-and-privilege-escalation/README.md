# macOSのセキュリティと特権エスカレーション

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) サーバーに参加して、経験豊富なハッカーやバグバウンティハンターとコミュニケーションを取りましょう！

**ハッキングの洞察**\
ハッキングのスリルと課題に深く入り込むコンテンツに参加しましょう

**リアルタイムのハックニュース**\
リアルタイムのニュースと洞察を通じて、ハッキングの世界を最新の状態に保ちましょう

**最新の発表**\
最新のバグバウンティの開始や重要なプラットフォームの更新情報について、常に情報を得ましょう

**[Discord](https://discord.com/invite/N3FrSbmwdy)に参加して、トップハッカーとの協力を始めましょう！**

## 基本的なMacOS

MacOSに慣れていない場合は、MacOSの基本を学ぶことから始めるべきです：

* 特殊なMacOSの**ファイルと権限:**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* 一般的なMacOSの**ユーザー**

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* **カーネル**の**アーキテクチャ**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* 一般的なMacOSの**ネットワークサービスとプロトコル**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **オープンソース**のMacOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* `tar.gz`をダウンロードするには、[https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/)のようなURLを[https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)のように変更します。

### MacOS MDM

企業では、**macOS**システムはおそらく**MDMで管理**されることが多いです。したがって、攻撃者の観点からは、**それがどのように機能するか**を知ることが興味深いです：

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - 検査、デバッグ、およびFuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## MacOSのセキュリティ保護

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## 攻撃対象

### ファイルの権限

**rootとして実行されているプロセスが**ユーザーによって制御可能なファイルを書き込む場合、ユーザーはこれを悪用して**特権をエスカレーション**することができます。\
これは次の状況で発生する可能性があります：

* 使用されるファイルはすでにユーザーによって作成されています（ユーザーが所有しています）
* 使用されるファイルはグループによって書き込み可能になっています
* 使用されるファイルはユーザーが所有するディレクトリ内にあります（ユーザーはファイルを作成できます）
* 使用されるファイルはrootが所有するディレクトリ内にありますが、ユーザーはグループによる書き込みアクセス権を持っています（ユーザーはファイルを作成できます）

**rootが使用するファイル**を**作成**できるようになると、ユーザーはその内容を利用したり、別の場所を指すために**シンボリックリンク/ハードリンク**を作成したりすることができます。

このような脆弱性をチェックする際には、**脆弱な`.pkg`インストーラー**を確認することを忘れないでください：

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}
### ファイル拡張子とURLスキームアプリハンドラ

ファイル拡張子によって登録された奇妙なアプリは悪用される可能性があり、異なるアプリケーションが特定のプロトコルを開くために登録されることがあります。

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## macOS TCC / SIP特権エスカレーション

macOSでは、**アプリケーションやバイナリにはアクセス権限**があり、他のものよりも特権を持つことができます。

したがって、macOSマシンを成功裏に侵害するためには、攻撃者は自身のTCC特権を**エスカレーション**する必要があります（または、必要に応じて**SIPをバイパス**する必要があります）。

これらの特権は、通常、アプリケーションが署名された**エンタイトルメント**の形で与えられるか、アプリケーションがいくつかのアクセスを要求し、**ユーザーが承認**した後、**TCCデータベース**に見つけることができます。プロセスがこれらの特権を取得する別の方法は、それらの特権を持つプロセスの**子プロセス**であることです。

これらのリンクをたどって、[**TCCで特権をエスカレーション**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses)する方法、[**TCCをバイパス**](macos-security-protections/macos-tcc/macos-tcc-bypasses/)する方法、そして過去に[**SIPがバイパス**](macos-security-protections/macos-sip.md#sip-bypasses)された方法を見つけてください。

## macOS伝統的な特権エスカレーション

もちろん、レッドチームの観点からは、ルートへのエスカレーションにも関心を持つべきです。いくつかのヒントについては、次の投稿をチェックしてください：

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}

## 参考文献

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) サーバーに参加して、経験豊富なハッカーやバグバウンティハンターとコミュニケーションを取りましょう！

**ハッキングの洞察**\
ハッキングのスリルと課題に深く入り込むコンテンツに参加しましょう

**リアルタイムのハックニュース**\
リアルタイムのニュースと洞察を通じて、ハッキングの世界を最新の状態に保ちましょう

**最新のお知らせ**\
最新のバグバウンティの開始や重要なプラットフォームの更新情報を把握しましょう

**[Discord](https://discord.com/invite/N3FrSbmwdy)** に参加して、今日からトップハッカーと協力しましょう！

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションを発見してください
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
