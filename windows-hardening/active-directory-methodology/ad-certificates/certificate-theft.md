# AD CS 証明書の盗難

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricks で会社を宣伝**したいですか？または、**PEASS の最新バージョンにアクセスしたり、HackTricks を PDF でダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式の PEASS & HackTricks スワッグ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discord グループ**](https://discord.gg/hRep4RUj7f)または[**telegram グループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricks リポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloud リポジトリ](https://github.com/carlospolop/hacktricks-cloud)**に PR を提出してください。

</details>

## 証明書で何ができるか

証明書を盗む方法を確認する前に、証明書がどのように役立つかについての情報をいくつか紹介します。
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
## Crypto APIを使用して証明書をエクスポートする - THEFT1

ユーザーまたはマシンの証明書と秘密鍵を抽出する最も簡単な方法は、**対話型デスクトップセッション**を介して行うことです。もし**秘密鍵**が**エクスポート可能**であれば、`certmgr.msc`で証明書を右クリックし、`すべてのタスク → エクスポート...`を選択して、パスワードで保護された.pfxファイルとしてエクスポートすることができます。\
これは**プログラムで**も実行することができます。PowerShellの`ExportPfxCertificate`コマンドレットや[TheWoverのCertStealer C#プロジェクト](https://github.com/TheWover/CertStealer)などの例があります。

これらの方法は、証明書ストアとのやり取りに**Microsoft CryptoAPI**（CAPI）またはより新しいCryptography API: Next Generation（CNG）を使用しています。これらのAPIは、証明書の保存と認証に必要なさまざまな暗号化サービスを提供します（他の用途も含まれます）。

もし秘密鍵がエクスポート不可能であれば、CAPIとCNGはエクスポート不可能な証明書の抽出を許可しません。**Mimikatz**の`crypto::capi`および`crypto::cng`コマンドを使用すると、CAPIとCNGをパッチして秘密鍵のエクスポートを許可することができます。`crypto::capi`は現在のプロセスで**CAPIをパッチ**しますが、`crypto::cng`は**lsass.exeのメモリをパッチ**する必要があります。

## DPAPIを使用したユーザー証明書の盗難 - THEFT2

DPAPIについての詳細は次の場所で確認できます：

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

Windowsは、証明書の秘密鍵を**DPAPIを使用して保存**します。Microsoftは、ユーザーとマシンの秘密鍵の保存場所を分けています。暗号化されたDPAPIのブロブを手動で復号化する場合、開発者はOSが使用した暗号化APIを理解する必要があります。なぜなら、秘密鍵ファイルの構造は2つのAPI間で異なるからです。SharpDPAPIを使用すると、これらのファイル形式の違いを自動的に考慮します。

Windowsは、ユーザー証明書を**一般的には**レジストリの`HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`に保存しますが、一部のユーザーの個人証明書は`%APPDATA%\Microsoft\SystemCertificates\My\Certificates`にも保存されます。関連するユーザーの**秘密鍵の場所**は、主に**CAPI**キーの場合は`%APPDATA%\Microsoft\Crypto\RSA\User SID\`、**CNG**キーの場合は`%APPDATA%\Microsoft\Crypto\Keys\`です。

証明書と関連する秘密鍵を取得するには、次の手順を実行する必要があります：

1. ユーザーの証明書ストアから**盗みたい証明書**を特定し、キーストア名を抽出します。
2. 関連する秘密鍵を復号化するために必要な**DPAPIマスターキー**を見つけます。
3. 平文のDPAPIマスターキーを取得し、それを使用して秘密鍵を**復号化**します。

平文のDPAPIマスターキーを**取得するには**：
```bash
# With mimikatz
## Running in a process in the users context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# with mimikatz
## knowing the users password
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
マスターキーファイルとプライベートキーファイルの復号を簡素化するために、[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)の`certificates`コマンドを使用できます。`/pvk`、`/mkfile`、`/password`、または`{GUID}:KEY`引数を使用して、プライベートキーと関連する証明書を復号し、`.pem`テキストファイルを出力します。
```bash
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Transfor .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## DPAPIを使用したマシン証明書の盗難 – THEFT3

Windowsはマシン証明書をレジストリキー `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` に保存し、プライベートキーはアカウントによって異なる場所に保存します。\
SharpDPAPIはこれらの場所すべてを検索しますが、最も興味深い結果は `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys`（CAPI）および `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys`（CNG）から得られます。これらの**プライベートキー**は**マシン証明書**ストアに関連付けられており、Windowsはこれらを**マシンのDPAPIマスターキー**で暗号化します。\
これらのキーはドメインのDPAPIバックアップキーを使用して復号することはできませんが、代わりにシステムの**DPAPI\_SYSTEM LSAシークレット**を使用する必要があります。このシークレットは**SYSTEMユーザーのみがアクセスできます**。&#x20;

**Mimikatz**の**`lsadump::secrets`**コマンドを使用してこれを手動で行い、抽出したキーを使用して**マシンマスターキー**を**復号化**することができます。\
また、CAPI/CNGを以前と同じようにパッチし、**Mimikatz**の`crypto::certificates /export /systemstore:LOCAL_MACHINE`コマンドを使用することもできます。\
**SharpDPAPI**のcertificatesコマンドには**`/machine`**フラグがあります（昇格している場合）、これにより自動的に**SYSTEMに昇格**し、**DPAPI\_SYSTEM** LSAシークレットをダンプし、これを使用してマシンのDPAPIマスターキーを復号化し、キーの平文をルックアップテーブルとして使用してマシン証明書のプライベートキーを復号化します。

## 証明書ファイルの検索 – THEFT4

時には証明書がファイルシステムにあることがあります。たとえば、ファイル共有やダウンロードフォルダにあります。\
私たちがよく見るWindowsに焦点を当てた証明書ファイルの一般的なタイプは、**`.pfx`** と **`.p12`** ファイルです。**`.pkcs12`** や **`.pem`** も時々現れますが、頻度は低いです。\
他にも興味深い証明書関連のファイル拡張子には、**`.key`**（プライベートキー）、**`.crt/.cer`**（証明書のみ）、**`.csr`**（証明書署名要求、証明書やプライベートキーは含まれていません）、**`.jks/.keystore/.keys`**（Javaキーストア。Javaアプリケーションで使用される証明書とプライベートキーが含まれる場合があります）があります。

これらの拡張子を使用して、PowerShellまたはコマンドプロンプトで検索すれば、これらのファイルを見つけることができます。

もし**PKCS#12**証明書ファイルを見つけ、それが**パスワードで保護されている**場合、[pfx2john.py](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john\_8py\_source.html)を使用してハッシュを抽出し、JohnTheRipperを使用してクラックすることができます。

## PKINITを介したNTLM資格情報の盗難 – THEFT5

> NTLM認証をサポートするために、Kerberos認証をサポートしないネットワークサービスに接続するアプリケーションに対して、PKCAが使用される場合、KDCは特権属性証明書（PAC）の**`PAC_CREDENTIAL_INFO`**バッファにユーザーのNTLMワンウェイ関数（OWF）を返します。

したがって、アカウントが認証され、PKINITを介して**TGTを取得**した場合、現在のホストは**TGTからNTLMハッシュを取得**するための組み込みの「failsafe」があります。これには、NTLM平文の**`PAC_CREDENTIAL_DATA`**構造を**復号化**することが含まれます。この構造は、NTLM平文のネットワークデータ表現（NDR）シリアル化表現です。

[**Kekeo**](https://github.com/gentilkiwi/kekeo)を使用して、この情報を含むTGTを要求し、ユーザーのNTLMハッシュを取得することができます。
```bash
tgt::pac /caname:thename-DC-CA /subject:harmj0y /castore:current_user /domain:domain.local
```
Kekeoの実装は、[**PINを回復**](https://github.com/CCob/PinSwipe)**することができれば、現在接続されているスマートカードで保護された証明書でも動作します。**また、[**Rubeus**](https://github.com/GhostPack/Rubeus)でもサポートされます。

## 参考文献

* すべての情報は[https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)から取得されました。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で**フォロー**する[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>
