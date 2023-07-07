# スケルトンキー

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう

- **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で**フォロー**する[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください**。

</details>

## **スケルトンキー**

**出典:** [**https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/**](https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/)

攻撃者がドメイン内に侵入した後、特権を昇格させ、持続性を作成するために使用できるActive Directoryアカウントの侵害方法はいくつかあります。スケルトンキーは、Active Directoryドメインを対象とした特に恐ろしいマルウェアで、任意のアカウントを乗っ取ることが驚くほど簡単になります。このマルウェアは**LSASSに自己注入し、ドメイン内の任意のアカウントで機能するマスターパスワードを作成**します。既存のパスワードも引き続き機能するため、この攻撃が行われたことを知るのは非常に困難です。

予想通り、これは[Mimikatz](https://github.com/gentilkiwi/mimikatz)を使用して非常に簡単に実行できる多くの攻撃の1つです。それがどのように機能するかを見てみましょう。

### スケルトンキー攻撃の要件

この攻撃を行うためには、**攻撃者はドメイン管理者権限を持っている必要があります**。この攻撃は**完全な侵害のためにすべてのドメインコントローラで実行する必要がありますが、単一のドメインコントローラを対象にするだけでも効果的です**。ドメインコントローラを**再起動**すると、このマルウェアは削除され、攻撃者によって再展開する必要があります。

### スケルトンキー攻撃の実行

攻撃の実行は非常に簡単です。各ドメインコントローラで次の**コマンドを実行するだけです**: `misc::skeleton`。その後、Mimikatzのデフォルトパスワードを使用して、任意のユーザーとして認証できます。

![Mimikatzを使用してドメインコントローラにスケルトンキーを注入する](https://blog.stealthbits.com/wp-content/uploads/2017/07/1-3.png)

以下は、スケルトンキーをパスワードとして使用してドメインコントローラに管理アクセスを取得するためのドメイン管理者メンバーの認証です。

![Mimikatzのデフォルトパスワードを使用してドメインコントローラに管理アクセスを取得するためのスケルトンキーをパスワードとして使用する](https://blog.stealthbits.com/wp-content/uploads/2017/07/2-5.png)

注意: "System error 86 has occurred. The specified network password is not correct"というメッセージが表示された場合は、ユーザー名にドメイン\アカウントの形式を使用してみてください。

!["System error 86 has occurred. The specified network password is not correct"というメッセージが表示された場合は、ユーザー名にドメイン\アカウントの形式を使用してみてください](https://blog.stealthbits.com/wp-content/uploads/2017/07/3-3.png)

もしlsassがすでにスケルトンキーでパッチされている場合、このエラーが表示されます:

![](<../../.gitbook/assets/image (160).png>)

### 緩和策

* イベント:
* システムイベントID 7045 - システムにサービスがインストールされました（カーネルモードドライバータイプ）
* セキュリティイベントID 4673 - 機密特権の使用（"特権の使用を監査する"が有効になっている必要があります）
* イベントID 4611 - ローカルセキュリティ機関に信頼されたログオンプロセスが登録されました（"特権の使用を監査する"が有効になっている必要があります）
* `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "`_`Kernel Mode Driver"}`_
* これはmimidrvのみを検出します `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$`_`.message -like "Kernel Mode Driver" -and $`_`.message -like "`_`mimidrv`_`"}`
* 緩和策:
* lsass.exeを保護されたプロセスとして実行し、攻撃者がカーネルモードドライバをロードすることを強制します
* `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`
* 再起動後に確認: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "`_`protected process"}`_

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、
- **[💬](https://emojipedia.org/speech-balloon/)Discordグループ**に参加するか、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローする[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **あなたのハッキングトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**
