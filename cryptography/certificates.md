# 証明書

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>

<figure><img src="../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによる**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 証明書とは

暗号学において、**公開鍵証明書**、または**デジタル証明書**または**アイデンティティ証明書**としても知られるものは、公開鍵の所有権を証明するために使用される電子文書です。証明書には、鍵に関する情報、所有者のアイデンティティに関する情報（サブジェクトと呼ばれる）、および証明書の内容を検証したエンティティのデジタル署名（発行者と呼ばれる）が含まれています。署名が有効であり、証明書を検証するソフトウェアが発行者を信頼している場合、その鍵を使用して証明書のサブジェクトと安全に通信することができます。

典型的な[公開鍵基盤](https://en.wikipedia.org/wiki/Public-key\_infrastructure)（PKI）スキームでは、証明書の発行者は通常、顧客に証明書を発行するために料金を請求する企業である[証明書機関](https://en.wikipedia.org/wiki/Certificate\_authority)（CA）です。これに対して、[信頼のウェブ](https://en.wikipedia.org/wiki/Web\_of\_trust)スキームでは、個人が直接お互いの鍵に署名し、公開鍵証明書と同様の機能を果たす形式で行います。

公開鍵証明書の最も一般的な形式は、[X.509](https://en.wikipedia.org/wiki/X.509)で定義されています。X.509は非常に一般的なため、特定のユースケースに対して定義されたプロファイルによってさらに制約されています。たとえば、RFC 5280で定義されている[公開鍵基盤（X.509）](https://en.wikipedia.org/wiki/PKIX)などです。

## x509共通フィールド

* **バージョン番号**：x509形式のバージョン。
* **シリアル番号**：CAのシステム内で証明書を一意に識別するために使用されます。特に、これは失効情報を追跡するために使用されます。
* **サブジェクト**：証明書が所属するエンティティ：マシン、個人、または組織。
* **コモンネーム**：証明書に影響を与えるドメイン。1つ以上のワイルドカードを含むことができます。
* **国（C）**：国
* **識別名（DN）**：全体のサブジェクト：`C=US, ST=California, L=San Francisco, O=Example, Inc., CN=shared.global.example.net`
* **地域（L）**：地域の場所
* **組織（O）**：組織名
* **組織単位（OU）**：組織の部門（「人事」など）
* **州または省（ST、SまたはP）**：州または省の名前のリスト
* **発行者**：情報を検証し、証明書に署名したエンティティ。
* **コモンネーム（CN）**：証明書機関の名前
* **国（C）**：証明書機関の国
* **識別名（DN）**：証明書機関の識別名
* **地域（L）**：組織が見つかる場所
* **組織（O）**：組織名
* **組織単位（OU）**：組織の部門（「人事」など）
* **Not Before**：証明書が有効である最も早い日時。通常、証明書が発行された時点の数時間または数日前に設定され、[クロックスキュー](https://en.wikipedia.org/wiki/Clock\_skew#On\_a\_network)の問題を回避します。
* **Not After**：証明書が無効になる日時。
* **公開鍵**：証明書のサブジェクトに属する公開鍵（これはCAによって署名される主要な部分の1つです）
* **公開鍵アルゴリズム**：公開鍵を生成するために使用されるアルゴリズム。RSAのようなもの。
* **公開鍵曲線**：楕円曲線公開鍵アルゴリズムで使用される曲線（適用される場合）。nistp521のようなもの。
* **公開鍵指数**：公開鍵を導出するために使用される指数（適用される場合）。65537のようなもの。
* **公開鍵サイズ**：公開鍵空間のサイズ（ビット単位）。2048のようなもの。
*
* **Subject Key Identifier** (SKI): この拡張機能は、証明書の公開鍵に対する一意の識別子を宣言します。CA証明書全てに必要です。CAは、発行された証明書の発行者キー識別子（AKI）拡張機能に自身のSKIを伝播させます。これは、サブジェクトの公開鍵のハッシュです。
* **Authority Key Identifier**: 発行者証明書の公開鍵から派生したキー識別子を含んでいます。これは、発行者の公開鍵のハッシュです。
* **Authority Information Access** (AIA): この拡張機能には最大2種類の情報が含まれています：
* この証明書の発行者を取得する方法に関する情報（CA発行者アクセス方法）
* この証明書の失効を確認するためのOCSPレスポンダのアドレス（OCSPアクセス方法）。
* **CRL Distribution Points**: この拡張機能は、この証明書の失効を確認するためのCRLの場所を識別します。証明書を処理するアプリケーションは、この拡張機能からCRLの場所を取得し、CRLをダウンロードしてこの証明書の失効を確認することができます。
* **CT Precertificate SCTs**: 証明書に関する証明書透明性のログ

### OCSPとCRL Distribution Pointsの違い

**OCSP**（RFC 2560）は、**OCSPクライアントとOCSPレスポンダ**から構成される標準プロトコルです。このプロトコルは、**CRL全体をダウンロードすることなく、指定されたデジタル公開鍵証明書の失効ステータスを判断**します。\
**CRL**は証明書の有効性を確認するための**従来の方法**です。CRLは、失効した証明書のシリアル番号のリストを提供します。CRLを使用することで、検証者は提示された証明書の失効ステータスを確認できます。CRLは512エントリまでしか許容されません。\
[ここから](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm)。

### 証明書透明性とは

証明書透明性は、ドメイン所有者、CA、およびドメインユーザーによるSSL証明書の発行と存在を公開し、検証することによって、証明書に基づく脅威を解決しようとするものです。具体的には、証明書透明性には次の3つの主な目標があります：

* ドメインの所有者が証明書を確認できない限り、CAがドメインのためにSSL証明書を発行することが不可能（または少なくとも非常に困難）にする。
* 証明書が誤ってまたは悪意を持って発行されたかどうかを、任意のドメイン所有者またはCAが確認できるようにするためのオープンな監査およびモニタリングシステムを提供する。
* 誤ってまたは悪意を持って発行された証明書によってユーザーがだまされることを（可能な限り）防ぐ。

#### **証明書ログ**

証明書ログは、証明書の暗号化された、公開監査可能な追加専用レコードを維持するシンプルなネットワークサービスです。**誰でもログに証明書を提出できます**が、証明書機関が最も頻繁に提出するでしょう。同様に、誰でもログをクエリできます。クエリ結果は暗号化証明として使用でき、ログが適切に動作しているか、または特定の証明書がログに記録されているかを検証できます。ログサーバーの数は大きくする必要はありません（たとえば、世界中で1000を下回る程度）。各ログサーバーは、CA、ISP、またはその他の関係者によって独立して運営される可能性があります。

#### クエリ

[https://crt.sh/](https://crt.sh)で任意のドメインの証明書透明性のログをクエリできます。

## フォーマット

証明書を保存するために使用できるさまざまなフォーマットがあります。

#### **PEMフォーマット**

* 証明書に最も一般的に使用されるフォーマットです
* ほとんどのサーバー（例：Apache）は、証明書と秘密鍵を別々のファイルに保存することを想定しています\
\- 通常、これらはBase64エンコードされたASCIIファイルです\
\- PEM証明書に使用される拡張子は、.cer、.crt、.pem、.keyファイルです\
\- Apacheや同様のサーバーはPEM形式の証明書を使用します

#### **DERフォーマット**

* DERフォーマットは証明書のバイナリ形式です
* すべてのタイプの証明書と秘密鍵をDER形式でエンコードすることができます
* DER形式の証明書には「BEGIN CERTIFICATE/END CERTIFICATE」ステートメントは含まれません
* DER形式の証明書は、最も一般的に「.cer」および「.der」の拡張子を使用します
* DERは主にJavaプラットフォームで使用されます

#### **P7B/PKCS#7フォーマット**

* PKCS#7またはP7Bフォーマットは、Base64 ASCII形式で保存され、ファイルの拡張子は.p7bまたは.p7cです
* P7Bファイルには証明書とチェーン証明書（中間CA）のみが含まれます。秘密鍵は含まれません
* P7Bファイルをサポートする最も一般的なプラットフォームは、Microsoft WindowsとJava Tomcatです

#### **PFX/P12/PKCS#12フォーマット**

* PKCS#12またはPFX/P12フォーマットは、サーバー証明書、中間証明書、および秘密鍵を1つの暗号化可能なファイルに格納するためのバイナリ形式です
* これらのファイルには通常、.pfxおよび.p12などの拡張子が付いています
* これらは通常、証明書と秘密鍵をインポートおよびエクスポートするためにWindowsマシンで使用されます

### フォーマットの変換

**x509をPEMに変換する**
```
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
#### **PEMをDERに変換する**

PEM形式の証明書をDER形式に変換するには、次のコマンドを使用します。

```bash
openssl x509 -outform der -in certificate.pem -out certificate.der
```

このコマンドは、OpenSSLツールを使用して証明書を変換します。`-outform der`オプションは、出力形式をDERに指定します。`-in certificate.pem`は、変換するPEM形式の証明書ファイルを指定します。`-out certificate.der`は、変換後のDER形式の証明書ファイルの出力先を指定します。

変換が成功すると、指定した出力先にDER形式の証明書ファイルが作成されます。
```
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
**DERをPEMに変換する**

DER形式の証明書をPEM形式に変換する方法を説明します。

1. OpenSSLコマンドを使用して、DER形式の証明書をPEM形式に変換します。

   ```shell
   openssl x509 -inform der -in certificate.der -out certificate.pem
   ```

   このコマンドでは、`certificate.der`は変換したいDER形式の証明書ファイルのパスを指定します。変換後のPEM形式の証明書は`certificate.pem`という名前で保存されます。

2. 変換されたPEM形式の証明書をテキストエディタで開きます。

   ```shell
   vi certificate.pem
   ```

   PEM形式の証明書はBase64エンコードされているため、テキストエディタで内容を確認できます。

以上で、DER形式の証明書をPEM形式に変換する手順が完了です。
```
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
**PEMをP7Bに変換する**

**注意:** PKCS#7またはP7B形式はBase64 ASCII形式で保存され、ファイルの拡張子は.p7bまたは.p7cです。P7Bファイルには証明書とチェーン証明書（中間CA）のみが含まれており、秘密鍵は含まれていません。P7Bファイルをサポートする最も一般的なプラットフォームはMicrosoft WindowsとJava Tomcatです。
```
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
**PKCS7をPEMに変換する**

PKCS7形式の証明書をPEM形式に変換する方法を説明します。

1. まず、PKCS7形式の証明書ファイルを用意します。

2. 次に、OpenSSLコマンドを使用してPKCS7形式の証明書をPEM形式に変換します。以下のコマンドを実行します。

   ```
   openssl pkcs7 -print_certs -in input.p7b -out output.pem
   ```

   このコマンドは、`input.p7b`という名前のPKCS7形式の証明書ファイルを読み込み、`output.pem`という名前のPEM形式の証明書ファイルに変換します。

3. 変換が完了すると、`output.pem`ファイルにPEM形式の証明書が保存されます。

これで、PKCS7形式の証明書をPEM形式に変換することができました。
```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**PFXをPEMに変換する**

**注意:** PKCS#12またはPFX形式は、サーバー証明書、中間証明書、および秘密鍵を1つの暗号化可能なファイルに格納するためのバイナリ形式です。PFXファイルは通常、.pfxや.p12などの拡張子を持ちます。PFXファイルは、通常、Windowsマシンで証明書と秘密鍵をインポートおよびエクスポートするために使用されます。
```
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
**PFXをPKCS#8に変換する**\
**注意:** これには2つのコマンドが必要です

**1- PFXをPEMに変換する**
```
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
**2- PEMをPKCS8に変換する**

PEM形式の証明書をPKCS8形式に変換する方法を説明します。

1. 最初に、OpenSSLコマンドを使用してPEM形式の証明書をPKCS8形式に変換します。以下のコマンドを実行します。

   ```
   openssl pkcs8 -topk8 -inform PEM -outform PEM -in private_key.pem -out private_key_pkcs8.pem
   ```

   このコマンドは、`private_key.pem`という名前のPEM形式の秘密鍵をPKCS8形式に変換し、`private_key_pkcs8.pem`という名前で保存します。

2. コマンドを実行すると、パスワードの入力を求められる場合があります。元のPEM形式の秘密鍵にパスワードが設定されている場合は、パスワードを入力してください。

3. 変換が完了すると、`private_key_pkcs8.pem`という名前のファイルにPKCS8形式の秘密鍵が保存されます。

これで、PEM形式の証明書をPKCS8形式に変換することができました。
```
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
**P7BをPFXに変換する**\
**注意:** これには2つのコマンドが必要です

1- **P7BをCERに変換する**
```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
**2- CERとプライベートキーをPFXに変換する**

To convert a CER (certificate) file and a private key to a PFX (Personal Information Exchange) file, you can use the OpenSSL command-line tool. The PFX file is a container format that combines the certificate and private key into a single file.

Here are the steps to convert the CER and private key to PFX:

1. Open a command prompt or terminal.
2. Navigate to the directory where the CER and private key files are located.
3. Run the following OpenSSL command:

   ```
   openssl pkcs12 -export -out certificate.pfx -inkey privatekey.key -in certificate.cer
   ```

   Replace `privatekey.key` with the filename of your private key file, and `certificate.cer` with the filename of your CER file. You can also change `certificate.pfx` to the desired output filename.

4. Enter a password when prompted. This password will be used to protect the PFX file.

After running the command, OpenSSL will generate the PFX file containing the certificate and private key. Make sure to keep the PFX file secure, as it contains sensitive information.
```
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile  cacert.cer
```
<figure><img src="../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も先進的なコミュニティツールによって強化された**ワークフローを簡単に構築し、自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝したい**ですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFTコレクション**](https://opensea.io/collection/the-peass-family)
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
