# AD CS 証明書の盗難

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加する、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)や[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングテクニックを共有する。

</details>

## 証明書を持っていると何ができるか

証明書を盗む方法を確認する前に、証明書が何に役立つかについての情報をいくつか紹介します：
```powershell
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## Crypto APIを使用した証明書のエクスポート – THEFT1

ユーザーまたはマシンの証明書と秘密鍵を抽出する最も簡単な方法は、**インタラクティブなデスクトップセッション**を通じて行うことです。秘密鍵が**エクスポート可能**であれば、`certmgr.msc`で証明書を右クリックし、`All Tasks → Export`... を選択して、パスワード保護された .pfx ファイルをエクスポートすることができます。
これは**プログラム的に**も実行可能です。例えば、PowerShellの `ExportPfxCertificate` コマンドレットや[TheWoverのCertStealer C# プロジェクト](https://github.com/TheWover/CertStealer)があります。

これらの方法は、証明書ストアとのやり取りに**Microsoft CryptoAPI**（CAPI）またはより現代的なCryptography API: Next Generation（CNG）を使用しています。これらのAPIは、証明書の保存や認証（その他の用途を含む）に必要な様々な暗号化サービスを実行します。

秘密鍵がエクスポート不可能な場合、CAPIとCNGはエクスポート不可能な証明書の抽出を許可しません。**Mimikatz**の`crypto::capi`と`crypto::cng`コマンドは、秘密鍵の**エクスポートを許可**するためにCAPIとCNGを**パッチ**します。`crypto::capi`は現在のプロセスの**CAPI**に**パッチ**を適用し、`crypto::cng`は**lsass.exeの**メモリに**パッチ**を適用する必要があります。

## DPAPIを介したユーザー証明書の盗難 – THEFT2

DPAPIについての詳細はこちらで:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

Windowsは**DPAPIを使用して証明書の秘密鍵を保存**します。Microsoftはユーザーとマシンの秘密鍵の保存場所を分けています。暗号化されたDPAPIブロブを手動で復号する場合、開発者はOSが使用した暗号化APIを理解する必要があります。なぜなら、秘密鍵ファイルの構造は2つのAPI間で異なるからです。SharpDPAPIを使用する場合、これらのファイル形式の違いを自動的に考慮します。

Windowsは**一般的にユーザー証明書をレジストリ**の `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates` キーに保存しますが、一部の個人証明書は**また** `%APPDATA%\Microsoft\SystemCertificates\My\Certificates` に保存されています。関連するユーザーの**秘密鍵の場所**は主に `%APPDATA%\Microsoft\Crypto\RSA\User SID\` にあり、**CAPI**鍵の場合はここに、**CNG**鍵の場合は `%APPDATA%\Microsoft\Crypto\Keys\` にあります。

証明書とそれに関連する秘密鍵を取得するには:

1. ユーザーの証明書ストアから盗みたい**証明書を特定**し、キーストア名を抽出します。
2. 関連する秘密鍵を復号するために必要な**DPAPIマスターキー**を見つけます。
3. プレーンテキストのDPAPIマスターキーを取得し、それを使用して**秘密鍵を復号**します。

**プレーンテキストのDPAPIマスターキーを取得するには**：
```bash
# With mimikatz
## Running in a process in the users context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# with mimikatz
## knowing the users password
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
マスターキーファイルとプライベートキーファイルの復号化を簡素化するために、[**SharpDPAPIの**](https://github.com/GhostPack/SharpDPAPI) `certificates` コマンドは `/pvk`、`/mkfile`、`/password`、または `{GUID}:KEY` 引数と共に使用して、プライベートキーと関連する証明書を復号化し、`.pem` テキストファイルとして出力することができます。
```bash
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Transfor .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## DPAPIを介したマシン証明書の盗難 – THEFT3

Windowsはマシン証明書をレジストリキー `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` に保存し、プライベートキーはアカウントに応じていくつかの異なる場所に保存します。\
SharpDPAPIはこれらの場所をすべて検索しますが、最も興味深い結果は通常 `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (CAPI) と `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (CNG) から得られます。これらの**プライベートキー**は**マシン証明書**ストアに関連付けられており、Windowsはそれらを**マシンのDPAPIマスターキー**で暗号化します。\
これらのキーをドメインのDPAPIバックアップキーを使用して復号することはできませんが、システム上で**アクセス可能なSYSTEMユーザーのみ**によってアクセス可能な**DPAPI\_SYSTEM LSAシークレット**を使用する**必要があります**。&#x20;

これは、**Mimikatz’** の **`lsadump::secrets`** コマンドを手動で使用し、抽出されたキーを使用して**マシンマスターキーを復号**することで行うことができます。\
また、以前と同様にCAPI/CNGをパッチして、**Mimikatz’** の `crypto::certificates /export /systemstore:LOCAL_MACHINE` コマンドを使用することもできます。\
**SharpDPAPI** の certificates コマンドに **`/machine`** フラグを付けて（昇格させた状態で）実行すると、自動的に**SYSTEMに昇格**し、**DPAPI\_SYSTEM** LSAシークレットを**ダンプ**し、これを使用して検出されたマシンDPAPIマスターキーを**復号**し、キープレーンテキストをルックアップテーブルとして使用して、任意のマシン証明書のプライベートキーを復号します。

## 証明書ファイルの検索 – THEFT4

時には、ファイル共有やダウンロードフォルダなど、**ファイルシステム内に証明書が存在する**ことがあります。\
私たちが見てきたWindowsに焦点を当てた証明書ファイルの最も一般的なタイプは、**`.pfx`** と **`.p12`** ファイルで、**`.pkcs12`** と **`.pem`** も時々見られますが、それほど頻繁ではありません。\
その他の興味深い証明書関連のファイル拡張子には、**`.key`** (_プライベートキー_)、**`.crt/.cer`** (_証明書のみ_)、**`.csr`** (_証明書署名要求、証明書やプライベートキーを含まない_)、**`.jks/.keystore/.keys`** (_Java Keystore。Javaアプリケーションによって使用される証明書とプライベートキーを含むことがある_) があります。

これらのファイルを見つけるには、powershellやcmdを使用してこれらの拡張子を検索します。

**PKCS#12** 証明書ファイルを見つけて、それが**パスワード保護されている**場合は、[pfx2john.py](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john\_8py\_source.html) を使用してハッシュを抽出し、JohnTheRipperを使用して**クラック**することができます。

## PKINITを介したNTLMクレデンシャル盗難 – THEFT5

> ネットワークサービスに接続するアプリケーションがKerberos認証を**サポートしていない**場合にNTLM認証\[MS-NLMP]を**サポートする**ために、PKCAが使用されると、KDCは特権属性証明書（PAC）の**`PAC_CREDENTIAL_INFO`** バッファに**ユーザーのNTLM**ワンウェイ関数（OWF）を返します

したがって、アカウントがPKINITを通じて**TGTを認証して取得する**場合、現在のホストがレガシー認証をサポートするためにTGTからNTLMハッシュを**取得する**ことを可能にする組み込みの「フェイルセーフ」があります。これには、NTLMプレーンテキストのNetwork Data Representation (NDR) シリアライズ表現である**`PAC_CREDENTIAL_DATA`** **構造体**を**復号**する作業が含まれます。

[**Kekeo**](https://github.com/gentilkiwi/kekeo) を使用して、この情報を持つTGTを要求し、ユーザーのNTMLを取得することができます。
```bash
tgt::pac /caname:thename-DC-CA /subject:harmj0y /castore:current_user /domain:domain.local
```
Kekeoの実装は、現在接続されているスマートカードで保護された証明書にも対応しており、[**ピンを回復**](https://github.com/CCob/PinSwipe)することができれば使用できます。また、[**Rubeus**](https://github.com/GhostPack/Rubeus)でもサポートされる予定です。

## 参考文献

* すべての情報は [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf) から取得しました

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをご覧ください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローしてください。**
* [**HackTricks**](https://github.com/carlospolop/hacktricks) および [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) githubリポジトリにPRを提出して、あなたのハッキングのコツを**共有してください。**

</details>
