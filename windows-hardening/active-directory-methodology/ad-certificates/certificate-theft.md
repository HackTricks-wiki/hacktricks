# AD CS 証明書の盗難

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)、当社の独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) コレクションを発見する
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) または [**telegramグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) をフォローする**
* **ハッキングテクニックを共有するために、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github リポジトリに提出する

</details>

**これは [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)** からの素晴らしい研究の要約です


## 証明書を使って何ができるか

証明書を盗む方法を確認する前に、証明書がどのように役立つかについての情報があります:
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

**インタラクティブなデスクトップセッション**で、ユーザーまたはマシン証明書とそれに関連する秘密鍵を抽出することは、特に**秘密鍵がエクスポート可能**な場合、簡単に行うことができます。これは、`certmgr.msc`で証明書に移動し、右クリックして`すべてのタスク → エクスポート`を選択して、パスワードで保護された.pfxファイルを生成することで達成できます。

**プログラマティックなアプローチ**では、PowerShellの`ExportPfxCertificate`コマンドレットや[TheWoverのCertStealer C#プロジェクト](https://github.com/TheWover/CertStealer)などのツールが利用可能です。これらは、**Microsoft CryptoAPI**（CAPI）またはCryptography API: Next Generation（CNG）を使用して証明書ストアとやり取りします。これらのAPIは、証明書の保存と認証に必要な暗号化サービスを提供します。

ただし、秘密鍵がエクスポート不可能に設定されている場合、CAPIとCNGの両方が通常、そのような証明書の抽出をブロックします。この制限をバイパスするために、**Mimikatz**などのツールを使用できます。Mimikatzは、該当するAPIをパッチする`crypto::capi`および`crypto::cng`コマンドを提供し、秘密鍵のエクスポートを可能にします。具体的には、`crypto::capi`は現在のプロセス内のCAPIをパッチし、`crypto::cng`はパッチングのために**lsass.exe**のメモリを対象とします。

## DPAPIを介したユーザー証明書の盗難 – THEFT2

DPAPIに関する詳細情報は以下を参照：

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

Windowsでは、**証明書の秘密鍵はDPAPIによって保護**されています。**ユーザーおよびマシンの秘密鍵の保存場所**が異なること、およびファイル構造がオペレーティングシステムで使用される暗号化APIによって異なることを認識することが重要です。**SharpDPAPI**は、DPAPIブロブを復号化する際にこれらの違いを自動的に調整できるツールです。

**ユーザー証明書**は主に、`HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`のレジストリに格納されていますが、一部は`%APPDATA%\Microsoft\SystemCertificates\My\Certificates`ディレクトリにも見つかることがあります。これらの証明書に対応する**秘密鍵**は、通常、**CAPI**キーの場合は`%APPDATA%\Microsoft\Crypto\RSA\User SID\`に、**CNG**キーの場合は`%APPDATA%\Microsoft\Crypto\Keys\`に保存されます。

証明書とそれに関連する秘密鍵を**抽出する**ためには、以下の手順が必要です：

1. ユーザーのストアから**ターゲット証明書**を選択し、そのキーストア名を取得します。
2. 対応する秘密鍵を復号化するために必要な**DPAPIマスターキー**を特定します。
3. 平文のDPAPIマスターキーを使用して、秘密鍵を**復号化**します。

平文のDPAPIマスターキーを**取得する**ためには、以下のアプローチが使用できます：
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
To streamline the decryption of masterkey files and private key files, the `certificates` command from [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) proves beneficial. It accepts `/pvk`, `/mkfile`, `/password`, or `{GUID}:KEY` as arguments to decrypt the private keys and linked certificates, subsequently generating a `.pem` file.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## DPAPIを介したマシン証明書の盗難 – THEFT3

Windowsによってレジストリ内の`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates`に保存されているマシン証明書と、それに関連する秘密鍵は、CAPIの場合は`%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys`、CNGの場合は`%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys`に暗号化されて保存されます。これらのキーは、マシンのDPAPIマスターキーを使用して暗号化されており、これらのキーはドメインのDPAPIバックアップキーで復号化することはできません。代わりに、**SYSTEMユーザーのみがアクセスできるDPAPI_SYSTEM LSAシークレット**が必要です。

手動で復号化するには、**Mimikatz**で`lsadump::secrets`コマンドを実行してDPAPI_SYSTEM LSAシークレットを抽出し、その後、このキーを使用してマシンのマスターキーを復号化します。また、以前に説明したようにCAPI/CNGをパッチ適用した後、Mimikatzの`crypto::certificates /export /systemstore:LOCAL_MACHINE`コマンドを使用できます。

**SharpDPAPI**は、そのcertificatesコマンドを使用することでより自動化されたアプローチを提供します。`/machine`フラグを昇格権限で使用すると、SYSTEMにエスカレートし、DPAPI_SYSTEM LSAシークレットをダンプし、これを使用してマシンのDPAPIマスターキーを復号化し、その後これらの平文キーを使用してマシン証明書の秘密鍵を復号化するためのルックアップテーブルとして使用します。


## 証明書ファイルの検索 – THEFT4

証明書は、ファイル共有やダウンロードフォルダなどのファイルシステム内に直接見つかることがあります。Windows環境向けにターゲットとなる証明書ファイルの最も一般的なタイプは、`.pfx`および`.p12`ファイルです。頻度は低いですが、`.pkcs12`および`.pem`の拡張子を持つファイルも存在します。追加で注目すべき証明書関連のファイル拡張子には次のものがあります：
- プライベートキー用の`.key`、
- 証明書のみのための`.crt`/`.cer`、
- 証明書や秘密鍵を含まない証明書署名リクエスト用の`.csr`、
- Javaアプリケーションで使用される証明書と秘密鍵を保持する可能性のあるJava Keystores用の`.jks`/`.keystore`/`.keys`。

これらのファイルは、PowerShellやコマンドプロンプトを使用して、上記の拡張子を検索することで検索できます。

PKCS#12証明書ファイルが見つかり、パスワードで保護されている場合、`pfx2john.py`を使用してハッシュの抽出が可能です。その後、JohnTheRipperを使用してパスワードの解読を試みることができます。
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## NTLM資格情報のPKINIT経由の盗難 – THEFT5

与えられた内容は、PKINITを介したNTLM資格情報の盗難方法、具体的にはTHEFT5とラベル付けされた盗難方法について説明しています。ここでは、受動態で再説明し、必要に応じて内容を匿名化および要約します。

KDCは、PKCAが利用される際に、NTLM認証[MS-NLMP]をサポートするために、Kerberos認証を容易にしないアプリケーション向けに、特権属性証明書（PAC）内の`PAC_CREDENTIAL_INFO`バッファ内にユーザーのNTLMワンウェイ関数（OWF）を返すように設計されています。したがって、アカウントがPKINITを介してチケット発行チケット（TGT）を認証および取得すると、現在のホストがTGTからNTLMハッシュを抽出するための仕組みが提供され、レガシー認証プロトコルを維持します。このプロセスには、NTLM平文のNDRシリアル化された表現である`PAC_CREDENTIAL_DATA`構造の復号化が含まれます。

この特定のデータを含むTGTを要求することができるとされるユーティリティ**Kekeo**は、[https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo)で入手可能であり、ユーザーのNTLMを取得するために利用されるコマンドは次のとおりです：
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
さらに、Kekeoはスマートカードで保護された証明書を処理できることが指摘されています。これは、PINが取得できる場合に適用され、[https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe)を参照しています。同様の機能は、**Rubeus**でもサポートされていることが示されており、[https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)で入手できます。

この説明は、PKINITを介したNTLM資格情報の盗難に関わるプロセスとツール、PKINITを使用して取得したTGTを介してNTLMハッシュを取得する方法、およびこのプロセスを容易にするユーティリティに焦点を当てています。
