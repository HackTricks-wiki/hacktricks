# 書き込み可能なSys Path + Dll Hijacking Privesc

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## はじめに

もし、**システムパスフォルダに書き込みができる**ことがわかった場合（ユーザーパスフォルダに書き込みができる場合はこれは機能しません）、システム内で特権を昇格させることができる可能性があります。

それを行うためには、**特権があるサービスやプロセスがロードしているライブラリを乗っ取る**ことができる**Dll Hijacking**を悪用することができます。そして、そのサービスがシステム全体に存在しない可能性のあるDllをロードしようとするため、それを書き込み可能なシステムパスからロードしようとします。

**Dll Hijacking**についての詳細は、以下を参照してください：

{% content-ref url="../dll-hijacking.md" %}
[dll-hijacking.md](../dll-hijacking.md)
{% endcontent-ref %}

## Dll Hijackingによる特権昇格

### 不足しているDllの検出

まず、**自分よりも特権のあるプロセス**を特定し、**書き込み可能なシステムパス**から**Dllをロードしようとしているかどうか**を確認する必要があります。

この場合の問題は、おそらくこれらのプロセスが既に実行されていることです。必要なサービスが欠けているDllを見つけるためには、プロセスがロードされる前にできるだけ早くprocmonを起動する必要があります。したがって、欠けている.dllを見つけるためには、次の手順を実行します：


* `C:\privesc_hijacking`フォルダを**作成**し、**システムパス環境変数**にパス`C:\privesc_hijacking`を追加します。これは**手動**で行うことも、**PS**で行うこともできます：
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
* **`procmon`**を起動し、**`Options`** --> **`Enable boot logging`**に移動し、プロンプトで**`OK`**を押します。
* 次に、**再起動**します。コンピュータが再起動されると、**`procmon`**ができるだけ早くイベントを記録し始めます。
* **Windows**が**起動したら、`procmon`**を再度実行します。実行されていたことを通知し、イベントをファイルに保存するかどうかを尋ねます。**はい**と答え、**イベントをファイルに保存**します。
* **ファイル**が**生成**されたら、開いている**`procmon`**ウィンドウを**閉じ**、イベントファイルを**開きます**。
* 以下の**フィルタ**を追加すると、書き込み可能なシステムパスフォルダからロードを試みたすべてのDLLを見つけることができます：

<figure><img src="../../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

### ミスしたDLL

私は無料の**仮想（VMware）Windows 11マシン**でこれらの結果を得ました：

<figure><img src="../../../.gitbook/assets/image (253).png" alt=""><figcaption></figcaption></figure>

この場合、.exeは無効なので無視し、ミスしたDLLは次のとおりです：

| サービス                         | DLL                | CMDライン                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| タスクスケジューラ（スケジュール）       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| 診断ポリシーサービス（DPS） | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

これを見つけた後、この興味深いブログ記事を見つけました。[**WptsExtensions.dllを悪用して特権をエスカレーションする方法**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll)。これが今**行うこと**です。

### 攻撃

したがって、特権を**エスカレーション**するためには、ライブラリ**WptsExtensions.dll**を乗っ取る必要があります。**パス**と**名前**がわかっているので、単に**悪意のあるdllを生成**する必要があります。

[**これらの例のいずれかを使用してみてください**](../dll-hijacking.md#creating-and-compiling-dlls)。リバースシェルを取得したり、ユーザーを追加したり、ビーコンを実行したりすることができます。

{% hint style="warning" %}
すべてのサービスが**`NT AUTHORITY\SYSTEM`**で実行されているわけではないことに注意してください。一部は**`NT AUTHORITY\LOCAL SERVICE`**で実行され、権限が制限されているため、新しいユーザーを作成することはできません。\
ただし、そのユーザーには**`seImpersonate`**特権があり、[**potato suiteを使用して特権をエスカレーション**](../roguepotato-and-printspoofer.md)することができます。したがって、この場合はリバースシェルがユーザーを作成しようとするよりも良いオプションです。
{% endhint %}

執筆時点では、**タスクスケジューラ**サービスは**Nt AUTHORITY\SYSTEM**で実行されています。

**悪意のあるDLLを生成**したら（私の場合はx64リバースシェルを使用し、シェルを取得しましたが、ディフェンダーによって殺されました）、それを書き込み可能なシステムパスに**WptsExtensions.dll**という名前で保存し、コンピュータを**再起動**します（またはサービスを再起動するか、影響を受けるサービス/プログラムを再実行するために必要な操作を行います）。

サービスが再起動されると、**dllがロードされ実行される**はずです（ライブラリが予想どおりにロードされたかどうかを確認するために**procmon**のトリックを再利用できます）。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
