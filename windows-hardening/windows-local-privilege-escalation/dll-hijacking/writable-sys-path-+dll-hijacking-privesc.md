# 書き込み可能なSys Path +Dll Hijacking Privesc

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>

## はじめに

システムパスフォルダに**書き込みができる**ことがわかった場合（ユーザーパスフォルダに書き込みができる場合は機能しません）、システムで**権限を昇格**できる可能性があります。

それを行うために、サービスまたはプロセスが**より高い権限**でロードしているライブラリを**ハイジャックするDll Hijacking**を悪用できます。そのサービスは、システム全体に存在しない可能性のあるDllをロードしようとしており、書き込み可能なシステムパスからロードしようとします。

**Dll Hijackingとは何か**についての詳細は、以下をチェックしてください:

{% content-ref url="../dll-hijacking.md" %}
[dll-hijacking.md](../dll-hijacking.md)
{% endcontent-ref %}

## Dll HijackingによるPrivesc

### 不足しているDllの探索

最初に必要なのは、あなたよりも**高い権限**で実行されているプロセスを**特定する**ことであり、そのプロセスは書き込み可能なシステムパスからDllを**ロードしようとしています**。

この場合の問題は、おそらくそれらのプロセスはすでに実行されていることです。サービスに不足しているDllを見つけるには、できるだけ早くprocmonを起動する必要があります（プロセスがロードされる前に）。不足している.dllを見つけるには:

* **フォルダ** `C:\privesc_hijacking` を作成し、パス `C:\privesc_hijacking` を**システムパス環境変数**に追加します。これは**手動**で行うか、**PS**を使用して行うことができます:
```powershell
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
* **`procmon`** を起動し、**`Options`** --> **`Enable boot logging`** に進んで、プロンプトで **`OK`** を押します。
* その後、**再起動**します。コンピュータが再起動されると、**`procmon`** はできるだけ早くイベントの**記録**を開始します。
* **Windows** が**起動したら `procmon`** を再度実行します。実行すると、既に実行中であったことを通知し、イベントをファイルに**保存するかどうか尋ねます**。**はい**と答えて、イベントをファイルに**保存します**。
* **ファイル**が**生成された後**、開いている**`procmon`** ウィンドウを**閉じ**、**イベントファイルを開きます**。
* 以下の**フィルター**を追加すると、書き込み可能なSystem Pathフォルダからいくつかの**プロセスがロードしようとしたDll**を全て見つけることができます：

<figure><img src="../../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

### 見逃されたDll

無料の**仮想 (vmware) Windows 11マシン**でこれを実行した結果、以下のようになりました：

<figure><img src="../../../.gitbook/assets/image (253).png" alt=""><figcaption></figcaption></figure>

この場合、.exeは役に立たないので無視してください。見逃されたDLLは以下のものでした：

| サービス                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| タスクスケジューラ (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| 診断ポリシーサービス (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

これを見つけた後、[**WptsExtensions.dllを悪用してprivescする方法**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll)を説明する興味深いブログ投稿を見つけました。これが**今から行うこと**です。

### 悪用

権限を**昇格させる**ために、**WptsExtensions.dll** ライブラリをハイジャックします。**パス**と**名前**がわかっていれば、**悪意のあるdllを生成する**だけです。

[**これらの例を試してみることができます**](../dll-hijacking.md#creating-and-compiling-dlls)。実行できるペイロードには、リバースシェルを取得する、ユーザーを追加する、ビーコンを実行するなどがあります...

{% hint style="warning" %}
**すべてのサービスが `NT AUTHORITY\SYSTEM`** で実行されているわけではないことに注意してください。一部は **`NT AUTHORITY\LOCAL SERVICE`** で実行されており、**権限が少ない**ため、新しいユーザーを作成することはできません。ただし、そのユーザーには **`seImpersonate`** 権限があるため、[**ポテトスイートを使用して権限を昇格させる**](../roguepotato-and-printspoofer.md)ことができます。したがって、この場合はユーザーを作成しようとするよりもリバースシェルを取得する方が良い選択です。
{% endhint %}

執筆時点で**タスクスケジューラ**サービスは**Nt AUTHORITY\SYSTEM**で実行されています。

**悪意のあるDllを生成**したら（私の場合はx64リバースシェルを使用しましたが、msfvenomからだったためディフェンダーによって殺されました）、書き込み可能なSystem Pathに**WptsExtensions.dll**という名前で保存し、コンピュータを**再起動**します（またはサービスを再起動するか、影響を受けるサービス/プログラムを再実行するために必要なことを何でもします）。

サービスが再開されると、**dllはロードされ実行される**はずです（**ライブラリが期待通りにロードされたかどうかを確認するために**、**procmon** のトリックを**再利用**することができます）。

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で<strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>!</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksに広告を掲載したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションです。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有してください**。

</details>
