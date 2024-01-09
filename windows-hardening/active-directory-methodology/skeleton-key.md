# スケルトンキー

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでAWSハッキングを学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**PEASSファミリー**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>

## **スケルトンキー**

**出典:** [**https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/**](https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/)

攻撃者が特権を昇格させ、ドメインに自分たちを確立した後に永続性を作り出すために使用できる、Active Directoryアカウントを侵害するためのいくつかの方法があります。スケルトンキーは、特に恐ろしいマルウェアで、Active Directoryドメインを狙って、どのアカウントでも簡単にハイジャックできるようにします。このマルウェアは**LSASSに自己注入し、ドメイン内の任意のアカウントで機能するマスターパスワードを作成します**。既存のパスワードも引き続き機能するため、何を探すべきかを知らない限り、この攻撃が行われたことを知るのは非常に困難です。

驚くことではありませんが、これは[Mimikatz](https://github.com/gentilkiwi/mimikatz)を使用して非常に簡単に実行できる多くの攻撃の1つです。その仕組みを見てみましょう。

### スケルトンキー攻撃の要件

この攻撃を行うためには、**攻撃者はドメイン管理者権限を持っている必要があります**。この攻撃は、完全な侵害を行うためには**すべてのドメインコントローラで実行する必要がありますが、単一のドメインコントローラを対象にするだけでも効果的です**。ドメインコントローラを**再起動する**と、このマルウェアは削除され、攻撃者によって再デプロイされる必要があります。

### スケルトンキー攻撃の実行

攻撃の実行は非常に簡単です。次の**コマンドを各ドメインコントローラで実行するだけです**: `misc::skeleton`。その後、Mimikatzのデフォルトパスワードを使用して任意のユーザーとして認証できます。

![Mimikatzでmisc::skeletonを使用してドメインコントローラにスケルトンキーを注入する](https://blog.stealthbits.com/wp-content/uploads/2017/07/1-3.png)

以下は、スケルトンキーをパスワードとして使用して、ドメイン管理者メンバーがドメインコントローラに管理アクセスを取得する認証です：

![Mimikatzのデフォルトパスワードを使用して、misc::skeletonコマンドでドメインコントローラに管理アクセスを取得するためにスケルトンキーをパスワードとして使用する](https://blog.stealthbits.com/wp-content/uploads/2017/07/2-5.png)

注意: 「システムエラー86が発生しました。指定されたネットワークパスワードが正しくありません」というメッセージが表示された場合は、ユーザー名にドメイン\アカウント形式を使用してみてください。それでうまくいくはずです。

![「システムエラー86が発生しました 指定されたネットワークパスワードが正しくありません」というメッセージが表示された場合にユーザー名にドメイン\アカウント形式を使用する](https://blog.stealthbits.com/wp-content/uploads/2017/07/3-3.png)

もしlsassがすでにスケルトンで**パッチされていた**場合、この**エラー**が表示されます：

![](<../../.gitbook/assets/image (160).png>)

### 軽減策

* イベント:
* システムイベントID 7045 - システムにサービスがインストールされました。（カーネルモードドライバのタイプ）
* セキュリティイベントID 4673 – 機密特権の使用（"監査特権の使用"を有効にする必要があります）
* イベントID 4611 – 信頼できるログオンプロセスがローカルセキュリティ機関に登録されました（"監査特権の使用"を有効にする必要があります）
* `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "`_`Kernel Mode Driver"}`_
* これはmimidrvのみを検出します `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$`_`.message -like "Kernel Mode Driver" -and $`_`.message -like "`_`mimidrv`_`"}`
* 軽減策:
* lsass.exeを保護されたプロセスとして実行すると、攻撃者はカーネルモードドライバをロードする必要があります
* `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`
* 再起動後に確認: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "`_`protected process"}`_

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでAWSハッキングを学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**PEASSファミリー**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>
