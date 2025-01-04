# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

もしあなたが**システムパスフォルダーに書き込むことができる**ことを発見した場合（ユーザーパスフォルダーに書き込むことができる場合は機能しないことに注意）、システム内で**特権を昇格させる**ことができる可能性があります。

そのためには、**Dll Hijacking**を悪用することができ、あなたよりも**より高い特権**を持つサービスまたはプロセスによって**読み込まれるライブラリをハイジャック**します。そして、そのサービスがおそらくシステム全体に存在しないDllを読み込もうとしているため、あなたが書き込むことができるシステムパスからそれを読み込もうとします。

**Dll Hijackingとは何か**についての詳細は、以下を確認してください：

{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### 欠落しているDllの特定

最初に必要なのは、**あなたよりも高い特権**で実行されている**プロセスを特定する**ことです。そのプロセスは、あなたが書き込むことができるシステムパスから**Dllを読み込もうとしている**必要があります。

この場合の問題は、おそらくそれらのプロセスがすでに実行中であることです。どのDllがサービスに欠けているかを見つけるために、プロセスが読み込まれる前にできるだけ早くprocmonを起動する必要があります。したがって、欠落している.dllを見つけるために、次のことを行います：

- **フォルダー `C:\privesc_hijacking` を作成**し、**システムパス環境変数**にパス `C:\privesc_hijacking` を追加します。これを**手動**または**PS**で行うことができます：
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
- **`procmon`** を起動し、**`Options`** --> **`Enable boot logging`** に移動し、プロンプトで **`OK`** を押します。
- その後、**再起動**します。コンピュータが再起動すると、**`procmon`** はすぐに **イベントの記録**を開始します。
- **Windows** が **起動したら `procmon`** を再度実行します。実行中であることを知らせ、**イベントをファイルに保存**するかどうかを **尋ねます**。**はい**と答え、**イベントをファイルに保存**します。
- **ファイル**が **生成されたら**、開いている **`procmon`** ウィンドウを **閉じ**、**イベントファイル**を **開きます**。
- これらの **フィルター**を追加すると、書き込み可能なシステムパスフォルダーから **プロセスが読み込もうとした**すべてのDllが見つかります：

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### 見逃したDll

無料の **仮想（vmware）Windows 11マシン**でこれを実行したところ、次の結果が得られました：

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

この場合、.exeは無駄なので無視してください。見逃したDLLは次のものでした：

| サービス                         | Dll                | CMDライン                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| タスクスケジューラ (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| 診断ポリシーサービス (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

これを見つけた後、[**WptsExtensions.dllを利用して特権昇格する方法**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)を説明している興味深いブログ記事を見つけました。これが今から **行うこと**です。

### 悪用

したがって、**特権を昇格**させるために、ライブラリ **WptsExtensions.dll** をハイジャックします。**パス**と**名前**がわかれば、**悪意のあるdllを生成**するだけです。

[**これらの例のいずれかを使用してみることができます**](#creating-and-compiling-dlls)。リバースシェルを取得したり、ユーザーを追加したり、ビーコンを実行したりするペイロードを実行できます...

> [!WARNING]
> すべてのサービスが **`NT AUTHORITY\SYSTEM`** で実行されるわけではなく、一部は **`NT AUTHORITY\LOCAL SERVICE`** で実行されており、**権限が少ない**ため、新しいユーザーを作成することはできません。\
> ただし、そのユーザーには **`seImpersonate`** 権限があるため、[**ポテトスイートを使用して特権を昇格**](../roguepotato-and-printspoofer.md)できます。したがって、この場合、リバースシェルはユーザーを作成しようとするよりも良い選択です。

執筆時点で、**タスクスケジューラ**サービスは **Nt AUTHORITY\SYSTEM** で実行されています。

**悪意のあるDllを生成した後**（私の場合はx64リバースシェルを使用し、シェルを取得しましたが、msfvenomからのものであるためDefenderに殺されました）、書き込み可能なシステムパスに **WptsExtensions.dll** という名前で保存し、コンピュータを **再起動**します（またはサービスを再起動するか、影響を受けたサービス/プログラムを再実行するために必要なことを行います）。

サービスが再起動されると、**dllが読み込まれ、実行されるはずです**（**procmon**トリックを再利用して、**ライブラリが期待通りに読み込まれたかどうかを確認できます）。

{{#include ../../../banners/hacktricks-training.md}}
