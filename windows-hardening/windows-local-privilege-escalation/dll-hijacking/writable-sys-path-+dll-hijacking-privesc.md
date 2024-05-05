# 書き込み可能なSysパス + Dllハイジャック特権昇格

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を使って、ゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝**したい場合や **HackTricks をPDFでダウンロード** したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)** に参加するか、[telegramグループ](https://t.me/peass) に参加するか、**Twitter** 🐦 で **@carlospolopm** をフォローする
* **ハッキングテクニックを共有するために、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **と** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに提出してください。**

</details>

## はじめに

**システムパスフォルダに書き込み**できることがわかった場合（ユーザーパスフォルダに書き込める場合は機能しません）、システム内で**特権昇格**が可能かもしれません。

そのためには、**特権を持つサービスまたはプロセス**が**ロードしようとしているライブラリをハイジャック**する **Dll Hijacking** を悪用することができます。そして、そのサービスが存在しない可能性が高いDllをロードしようとするため、システムパスからロードしようとすることができます。

**Dll Hijacking とは何か**の詳細については、以下を参照してください:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Dll Hijacking による特権昇格

### 不足しているDllの検出

最初に必要なのは、**あなたよりも特権のあるプロセス**が**書き込み可能なシステムパスからDllをロード**しようとしているプロセスを**特定**することです。

この場合の問題は、おそらくこれらのプロセスがすでに実行されていることです。必要なDllを見つけるには、プロセスがロードされる前にできるだけ早く procmon を起動する必要があります。したがって、不足している.dll を見つけるには:

* `C:\privesc_hijacking` フォルダを**作成**し、そのパス `C:\privesc_hijacking` を**システムパス環境変数**に追加します。これは**手動**で行うか、**PS** を使用して行うことができます:
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
* **`procmon`** を起動し、**`Options`** --> **`Enable boot logging`** に移動して、プロンプトで **`OK`** を押します。
* 次に、**再起動**します。コンピュータが再起動されると、**`procmon`** ができるだけ早くイベントの**記録を開始**します。
* 一度 **Windows** が**起動したら `procmon` を実行**し、実行中であることを通知され、イベントをファイルに保存するかどうかを尋ねられます。**はい**を選択し、**イベントをファイルに保存**します。
* **ファイル**が**生成**されたら、開いている **`procmon`** ウィンドウを**閉じ**、イベントファイルを**開きます**。
* 以下の **フィルター** を追加すると、書き込み可能なシステムパスフォルダから**読み込もうとした**すべての Dll を見つけることができます:

<figure><img src="../../../.gitbook/assets/image (945).png" alt=""><figcaption></figcaption></figure>

### 不足している Dlls

無料の **仮想 (vmware) Windows 11 マシン** でこれを実行した結果は次のとおりです:

<figure><img src="../../../.gitbook/assets/image (607).png" alt=""><figcaption></figcaption></figure>

この場合、.exe は無用なので無視し、不足している DLL は次のとおりです:

| サービス                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| タスク スケジューラ (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| 診断ポリシーサービス (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

これを見つけた後、[**WptsExtensions.dll を悪用して権限昇格を行う方法**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll)を説明している興味深いブログ投稿を見つけました。これが今**行うこと**です。

### 悪用

したがって、特権を昇格するためには、ライブラリ **WptsExtensions.dll** を乗っ取ります。**パス**と**名前**があれば、悪意のある dll を生成するだけです。

[**これらの例**](./#creating-and-compiling-dlls)のいずれかを使用してみてください。リバースシェルを取得したり、ユーザーを追加したり、ビーコンを実行したりできます...

{% hint style="warning" %}
すべてのサービスが **`NT AUTHORITY\SYSTEM`** で実行されているわけではないことに注意してください。一部は **`NT AUTHORITY\LOCAL SERVICE`** で実行されており、権限が**少ない**ため、新しいユーザーを作成することはできません。\
ただし、そのユーザーには **`seImpersonate`** 権限があるため、[**potato suite を使用して権限を昇格**](../roguepotato-and-printspoofer.md)することができます。したがって、この場合、リバースシェルはユーザーを作成しようとするよりも良い選択肢です。
{% endhint %}

執筆時点では、**タスク スケジューラ** サービスは **Nt AUTHORITY\SYSTEM** で実行されています。

悪意のある Dll を生成した後（私の場合は x64 リバースシェルを使用し、シェルを取得しましたが、msfvenom からだったためディフェンダーによって殺されました）、それを書き込み可能なシステムパスに **WptsExtensions.dll** という名前で保存し、コンピュータを**再起動**します（またはサービスを再起動するか、影響を受けるサービス/プログラムを再実行するために必要な操作を実行します）。

サービスが再起動されると、**dll が読み込まれ実行される**はずです（ライブラリが期待どおりに読み込まれたかどうかを確認するために **procmon** のトリックを再利用できます）。

<details>

<summary><strong>**htARTE (HackTricks AWS Red Team Expert)** で**ゼロからヒーローまでのAWSハッキング**を学びましょう！</summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝**したり、**PDF で HackTricks をダウンロード**したりするには、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式 PEASS & HackTricks スワッグ**](https://peass.creator-spring.com)を手に入れる
* 独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) コレクションである [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見する
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live) をフォローする
* **HackTricks** と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks) の github リポジトリに PR を提出して、あなたのハッキングトリックを共有する

</details>
