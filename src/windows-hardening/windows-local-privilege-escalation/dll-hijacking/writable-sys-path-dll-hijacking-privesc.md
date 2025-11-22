# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## 導入

もしあなたが **System Path フォルダに書き込みできる** と判明した場合（User Path フォルダに書き込みできてもこれは機能しない点に注意）、システム上で **権限昇格** できる可能性があります。

そのために、権限が自分より高いサービスやプロセスが読み込もうとするライブラリをハイジャックする **Dll Hijacking** を悪用できます。サービスが読み込もうとしている Dll がシステム全体に存在しない可能性が高い場合、あなたが書き込みできる System Path からロードしようとします。

**Dll Hijackig** が何かについての詳細は次を参照してください：


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### 欠落している Dll の検出

最初に必要なのは、あなたより高い権限で動作しており、あなたが書き込みできる **System Path** から Dll をロードしようとしているプロセスを特定することです。

この場合の問題は、これらのプロセスが既に実行中であることが多い点です。どの Dll が不足しているかを見つけるには、サービスがロードされる前（プロセスが読み込まれる前）にできるだけ早く procmon を起動する必要があります。したがって、欠落している .dll を見つけるには次を行います:

- **Create** the folder `C:\privesc_hijacking` and add the path `C:\privesc_hijacking` to **System Path 環境変数**. You can do this **手動で** or with **PS**:
```bash
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
- Launch **`procmon`** and go to **`Options`** --> **`Enable boot logging`** and press **`OK`** in the prompt.
- 次に、**再起動**（reboot）します。コンピュータが再起動すると **`procmon`** はできるだけ早くイベントの **recording** を開始します。
- **Windows** が起動したら再度 **`procmon`** を実行すると、実行中である旨を通知され、イベントをファイルに保存するかどうかを尋ねられます。**yes** を選んで **events をファイルに保存**してください。
- **ファイル** が生成されたら、開いている **`procmon`** ウィンドウを **閉じ**、生成された **events file** を開きます。
- 次のような **filters** を追加すると、書き込み可能な System Path フォルダからある **process がロードしようとした** すべての DLL を見つけられます:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### 見つからなかった DLL

この手順を無料の仮想環境（vmware）の Windows 11 マシンで実行したところ、以下のような結果になりました:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

この場合は .exe は使えないので無視してください。見つからなかった DLL は以下からロードされようとしていました:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

これを見つけた後、同様に [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll) を説明している興味深いブログ記事を見つけました。これがこれから **実際に行うこと** です。

### Exploitation

権限昇格のために、ライブラリ **WptsExtensions.dll** をハイジャックします。パスと名前が分かっているので、あとは **悪意のある dll を生成** すれば良いだけです。

[**try to use any of these examples**](#creating-and-compiling-dlls) を参照して作成できます。rev shell を取得したり、ユーザを追加したり、beacon を実行したりといったペイロードを実行できます。

> [!WARNING]
> すべてのサービスが **`NT AUTHORITY\SYSTEM`** で実行されているわけではなく、**`NT AUTHORITY\LOCAL SERVICE`** など権限の低いアカウントで実行されている場合があります。その場合は新しいユーザを作成するための権限を悪用できないことがあります。\
> ただし、そのユーザは **`seImpersonate`** 権限を持っているため、[ **potato suite to escalate privileges**](../roguepotato-and-printspoofer.md) を使って更に権限を上げることが可能です。したがって、このケースではユーザ作成を試みるよりも rev shell を狙う方が現実的です。

執筆時点では **Task Scheduler** サービスは **Nt AUTHORITY\SYSTEM** で実行されています。

悪意のある DLL を生成したら（私の場合は x64 rev shell を使いシェルを得ましたが、msfvenom 由来のため Defender に検出されました）、書き込み可能な System Path に **WptsExtensions.dll** という名前で保存し、コンピュータを再起動するか（またはサービスを再起動するなどして）該当サービス／プログラムを再実行してください。

サービスが再起動されると、**dll がロードされ実行される**はずです（期待通りにライブラリがロードされたかどうかは、再度 **procmon** の手法を使って確認できます）。

{{#include ../../../banners/hacktricks-training.md}}
