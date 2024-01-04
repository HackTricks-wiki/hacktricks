# macOS セキュリティ & 権限昇格

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWS ハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks にあなたの会社を広告したい**、または **HackTricks を PDF でダウンロードしたい** 場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com) を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見する、私たちの独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクション
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に **参加する** か、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を **フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の github リポジトリに PR を提出して、あなたのハッキングのコツを共有する。

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

経験豊富なハッカーやバグバウンティハンターとコミュニケーションを取るために [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) サーバーに参加しましょう！

**ハッキングの洞察**\
ハッキングのスリルと挑戦に焦点を当てたコンテンツに参加する

**リアルタイムハックニュース**\
リアルタイムのニュースと洞察を通じて、速いペースのハッキングの世界に最新の情報を保つ

**最新の発表**\
最新のバグバウンティの開始と重要なプラットフォームの更新情報を入手する

**今日から** [**Discord**](https://discord.com/invite/N3FrSbmwdy) に参加して、トップハッカーとのコラボレーションを始めましょう！

## 基本的な MacOS

macOS に慣れていない場合は、macOS の基本を学び始めるべきです:

* 特別な macOS **ファイル & 権限:**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* 一般的な macOS **ユーザー**

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* k**ernel** の **アーキテクチャ**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* 一般的な macOS n**etwork サービス & プロトコル**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **オープンソース** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* `tar.gz` をダウンロードするには、[https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) のような URL を [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) に変更します

### MacOS MDM

企業では **macOS** システムが **MDM で管理される** 可能性が高いです。したがって、攻撃者の視点からは **それがどのように機能するか** を知ることが興味深いです:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - 検査、デバッグ、ファジング

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## MacOS セキュリティ保護

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## 攻撃面

### ファイル権限

**root として実行されるプロセスが** ユーザーが制御できるファイルを書き込む場合、ユーザーはこれを悪用して **権限を昇格** する可能性があります。\
これは以下の状況で発生する可能性があります:

* 既にユーザーによって作成されたファイル（ユーザーが所有）
* グループのためにユーザーが書き込み可能なファイル
* ユーザーが所有するディレクトリ内のファイル（ユーザーがファイルを作成できる）
* root が所有するディレクトリ内のファイルだが、グループのためにユーザーが書き込みアクセス権を持っている（ユーザーがファイルを作成できる）

**root が使用するファイルを作成できる** ことは、ユーザーがその内容を利用したり、シンボリックリンク/ハードリンクを作成して別の場所を指すようにしたりすることを可能にします。

この種の脆弱性については、**脆弱な `.pkg` インストーラーをチェックする** のを忘れないでください:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}



### ファイル拡張子 & URL スキームアプリハンドラ

ファイル拡張子によって登録された奇妙なアプリを悪用することができ、異なるアプリケーションが特定のプロトコルを開くために登録される可能性があります

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## macOS TCC / SIP 権限昇格

macOS では **アプリケーションとバイナリには権限があり**、他のものよりも特権的なフォルダーや設定にアクセスできます。

したがって、macOS マシンを正常に侵害したい攻撃者は、**TCC の権限を昇格させる** 必要があります（または、ニーズに応じて **SIP をバイパスする** かもしれません）。

これらの権限は通常、アプリケーションが署名されている **エンタイトルメント** の形で与えられるか、アプリケーションがいくつかのアクセスを要求し、**ユーザーがそれらを承認した後**、**TCC データベース** で見つけることができます。プロセスがこれらの権限を取得する別の方法は、それらの **権限を持つプロセスの子供であること** です。なぜなら、通常、権限は **継承される** からです。

TCC での [**権限昇格**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses)、[**TCC をバイパスする**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) 方法、過去に [**SIP がどのようにバイパスされたか**](macos-security-protections/macos-sip.md#sip-bypasses) を見つけるためにこれらのリンクに従ってください。

## macOS 伝統的な権限昇格

もちろん、レッドチームの視点からは、root に昇格することにも興味を持つべきです。いくつかのヒントについては、以下の投稿をチェックしてください:

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

経験豊富なハッカーやバグバウンティハンターとコミュニケーションを取るために [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) サーバーに参加しましょう！

**ハッキングの洞察**\
ハッキングのスリルと挑戦に焦点を当てたコンテンツに参加する

**リアルタイムハックニュース**\
リアルタイムのニュースと洞察を通じて、速いペースのハッキングの世界に最新の情報を保つ

**最新の発表**\
最新のバグバウンティの開始と重要なプラットフォームの更新情報を入手する

**今日から** [**Discord**](https://discord.com/invite/N3FrSbmwdy) に参加して、トップハッカーとのコラボレーションを始めましょう！

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWS ハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks にあなたの会社を広告したい**、または **HackTricks を PDF でダウンロードしたい** 場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com) を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見する、私たちの独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクション
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に **参加する** か、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を **フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の github リポジトリに PR を提出して、あなたのハッキングのコツを共有する。

</details>
