# Skeleton Key

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見る
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で私をフォローする 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **ハッキングトリックを共有するには、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

## Skeleton Key攻撃

**Skeleton Key攻撃**は、攻撃者がドメインコントローラーに**マスターパスワードを注入**することで、**Active Directory認証をバイパス**することを可能にする高度な技術です。これにより、攻撃者は**パスワードなしで任意のユーザーとして認証**し、実質的にドメインへの**無制限のアクセス**を得ることができます。

これは[Mimikatz](https://github.com/gentilkiwi/mimikatz)を使用して実行できます。この攻撃を実行するには、**ドメイン管理者権限が前提条件**であり、攻撃者は包括的な侵害を確保するために各ドメインコントローラーを対象にする必要があります。ただし、攻撃の効果は一時的であり、**ドメインコントローラーを再起動するとマルウェアが消去**され、持続的なアクセスのために再実装する必要があります。

**攻撃の実行**には、`misc::skeleton`という1つのコマンドが必要です。

## 緩和策

このような攻撃に対する緩和策には、サービスのインストールや機密特権の使用を示す特定のイベントIDを監視することが含まれます。具体的には、SystemイベントID 7045やSecurityイベントID 4673を探すことで、不審な活動を明らかにすることができます。また、`lsass.exe`を保護されたプロセスとして実行することは、攻撃者の努力を大幅に妨げることができます。これには、カーネルモードドライバーを使用する必要があるため、攻撃の複雑さが増します。

以下はセキュリティ対策を強化するためのPowerShellコマンドです：

- 不審なサービスのインストールを検出するには、次のコマンドを使用します：`Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- 特にMimikatzのドライバーを検出するには、次のコマンドを使用できます：`Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- `lsass.exe`を強化するために、保護されたプロセスとして有効にすることをお勧めします：`New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

システムの再起動後に保護措置が正常に適用されたことを確認することは重要です。これは次のコマンドで実現できます：`Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## 参考文献
* [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
