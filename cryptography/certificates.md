# 証明書

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で**最も進んだ**コミュニティツールによって動力を供給される**ワークフローを簡単に構築して自動化する**。\
今すぐアクセス：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 証明書とは

暗号学において、**公開鍵証明書**、または**デジタル証明書**や**身分証明書**とも呼ばれる電子文書は、公開鍵の所有を証明するために使用されます。証明書には、鍵に関する情報、その所有者（被験者と呼ばれる）の身元に関する情報、および証明書の内容を検証したエンティティ（発行者と呼ばれる）のデジタル署名が含まれています。署名が有効で、証明書を検査するソフトウェアが発行者を信頼している場合、その鍵を使用して証明書の被験者と安全に通信することができます。

一般的な[公開鍵インフラ](https://en.wikipedia.org/wiki/Public-key_infrastructure)（PKI）スキームでは、証明書の発行者は[証明書機関](https://en.wikipedia.org/wiki/Certificate_authority)（CA）であり、通常は顧客に対して証明書を発行するための料金を請求する会社です。対照的に、[信頼のウェブ](https://en.wikipedia.org/wiki/Web_of_trust)スキームでは、個人が直接お互いの鍵に署名し、公開鍵証明書と同様の機能を果たす形式で行います。

公開鍵証明書の最も一般的な形式は[X.509](https://en.wikipedia.org/wiki/X.509)によって定義されています。X.509は非常に一般的なため、形式は特定の使用例に対して定義されたプロファイルによってさらに制約されます。例えば、RFC 5280で定義された[Public Key Infrastructure (X.509)](https://en.wikipedia.org/wiki/PKIX)などです。

## x509の共通フィールド

* **バージョン番号:** x509形式のバージョン。
* **シリアル番号**: CAのシステム内で証明書を一意に識別するために使用されます。特にこれは失効情報の追跡に使用されます。
* **被験者**: 証明書が属するエンティティ：マシン、個人、または組織。
* **一般名**: 証明書に影響を与えるドメイン。1つ以上のものがあり、ワイルドカードを含むことができます。
* **国 (C)**: 国
* **識別名 (DN)**: 全体の被験者: `C=US, ST=California, L=San Francisco, O=Example, Inc., CN=shared.global.example.net`
* **地域 (L)**: 地元の場所
* **組織 (O)**: 組織名
* **組織単位 (OU)**: 組織の部門（例: "人事部"）。
* **州または県 (ST, SまたはP)**: 州または県のリスト
* **発行者**: 情報を検証し、証明書に署名したエンティティ。
* **一般名 (CN)**: 証明書機関の名前
* **国 (C)**: 証明書機関の国
* **識別名 (DN)**: 証明書機関の識別名
* **地域 (L)**: 組織が見つかる地元の場所。
* **組織 (O)**: 組織名
* **組織単位 (OU)**: 組織の部門（例: "人事部"）。
* **有効開始日時**: 証明書が有効になる最も早い時間と日付。通常は、証明書が発行された瞬間の数時間または数日前に設定されており、[時計のずれ](https://en.wikipedia.org/wiki/Clock_skew#On_a_network)の問題を避けるためです。
* **有効終了日時**: 証明書が有効でなくなる時間と日付。
* **公開鍵**: 証明書の被験者に属する公開鍵。（これは主要な部分の1つです。これがCAによって署名されます）
* **公開鍵アルゴリズム**: 公開鍵を生成するために使用されるアルゴリズム。例えばRSA。
* **公開鍵カーブ**: 楕円曲線公開鍵アルゴリズムに使用されるカーブ（該当する場合）。例えばnistp521。
* **公開鍵指数**: 公開鍵を導出するために使用される指数（該当する場合）。例えば65537。
* **公開鍵サイズ**: ビット単位の公開鍵空間のサイズ。例えば2048。
* **署名アルゴリズム**: 公開鍵証明書に署名するために使用されるアルゴリズム。
* **署名**: 発行者の秘密鍵による証明書本体の署名。
* **x509v3拡張**
* **鍵の使用法**: 証明書の公開鍵の有効な暗号使用法。一般的な値には、デジタル署名の検証、鍵の暗号化、および証明書の署名が含まれます。
* Web証明書では、_X509v3拡張_として表示され、値は`Digital Signature`となります。
* **拡張鍵の使用法**: 証明書が使用されるアプリケーション。一般的な値には、TLSサーバー認証、電子メール保護、およびコード署名が含まれます。
* Web証明書では、_X509v3拡張_として表示され、値は`TLS Web Server Authentication`となります。
* **被験者代替名**: ユーザーが単一のSSL**証明書**に追加のホスト**名**を指定することを可能にします。SAN拡張の使用はSSL証明書の標準的な実践であり、一般**名**の使用を置き換える途中です。
* **基本制約**: この拡張機能は、証明書がCA証明書であるか、エンドエンティティ証明書であるかを説明します。CA証明書は他の証明書に署名するものであり、エンドエンティティ証明書は例えばウェブページで使用される証明書です（チェーンの最後の部分）。
* **被験者鍵識別子** (SKI): この拡張機能は、証明書の公開**鍵**に対する一意の**識別子**を宣言します。すべてのCA証明書で必要です。CAは、発行された証明書の発行者**鍵識別子**（AKI）拡張機能に自身のSKIを伝播します。これは被験者の公開鍵のハッシュです。
* **権限鍵識別子**: 発行者の証明書の公開鍵から派生した鍵識別子を含みます。これは発行者の公開鍵のハッシュです。
* **権限情報アクセス** (AIA): この拡張機能には、最大で2種類の情報が含まれます：
* **この証明書の発行者を取得する方法に関する情報**（CA発行者アクセス方法）
* **この証明書の失効をチェックできるOCSPレスポンダーのアドレス**（OCSPアクセス方法）。
* **CRL配布ポイント**: この拡張機能は、この証明書の失効をチェックできるCRLの場所を識別します。証明書を処理するアプリケーションは、この拡張機能からCRLの場所を取得し、CRLをダウンロードしてから、この証明書の失効をチェックすることができます。
* **CTプレ証明書SCT**: 証明書の透明性に関するログ

### OCSPとCRL配布ポイントの違い

**OCSP** (RFC 2560)は、**OCSPクライアントとOCSPレスポンダー**からなる標準プロトコルです。このプロトコルは、**CRL全体をダウンロードすることなく**、与えられたデジタル公開鍵証明書の**失効状態を決定します**。\
**CRL**は証明書の有効性をチェックする**伝統的な方法**です。**CRLは、失効したりもはや有効でない証明書のシリアル番号のリストを提供します**。CRLを使用すると、検証者は提示された証明書を検証しながら、その失効状態をチェックすることができます。CRLは512エントリに制限されています。\
[こちら](https://www.arubanetworks.com/techdocs/ArubaOS%206_3_1_Web_Help/Content/ArubaFrameStyles/CertRevocation/About_OCSP_and_CRL.htm)から。

### 証明書の透明性とは

証明書の透明性は、証明書に基づく脅威に対処することを目的としており、**ドメインの所有者、CA、およびドメインユーザーによるSSL証明書の発行と存在を監視可能にすることで**これを実現します。具体的には、証明書の透明性には3つの主な目標があります：

* CAがドメインの所有者に証明書が見えることなくSSL証明書を**発行することが不可能（または少なくとも非常に困難）にする**。
* **証明書が誤ってまたは悪意を持って**発行されたかどうかを任意のドメイン所有者またはCAが判断できる**オープンな監査および監視システムを提供する**。
* **ユーザーを**、誤ってまたは悪意を持って発行された証明書にだまされないように（できるだけ）**保護する**。

#### **証明書ログ**

証明書ログは、証明書の**暗号学的に保証された、公に監査可能な、追加のみの記録を維持する単純なネットワークサービス**です。**誰でもログに証明書を提出することができます**が、証明書機関が主な提出者になる可能性が高いです。同様に、誰でもログを照会して暗号学的証明を取得することができ、これはログが適切に動作していることを検証するため、または特定の証明書がログに記録されていることを検証するために使用できます。ログサーバーの数は多くなくてもよい（たとえば、世界中で数千以下）、それぞれがCA、ISP、または他の関心を持つ当事者によって独立して運営される可能性があります。

#### クエリ

任意の
```
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
#### **PEMをDERに変換する**
```
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
**DERをPEMに変換する**
```
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
**PEMをP7Bに変換する**

**注意:** PKCS#7またはP7B形式はBase64 ASCII形式で保存され、ファイル拡張子は.p7bまたは.p7cです。P7Bファイルには証明書とチェーン証明書（中間CA）のみが含まれており、秘密鍵は含まれていません。P7Bファイルをサポートする最も一般的なプラットフォームは、Microsoft WindowsとJava Tomcatです。
```
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
**PKCS7をPEMに変換する**
```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**pfxをPEMに変換**

**注意:** PKCS#12またはPFX形式は、サーバー証明書、中間証明書、およびプライベートキーを1つの暗号化可能なファイルに格納するためのバイナリ形式です。PFXファイルは通常、.pfxや.p12のような拡張子を持っています。PFXファイルは、証明書とプライベートキーをインポートおよびエクスポートするために、Windowsマシンで一般的に使用されます。
```
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
**PFXをPKCS#8に変換**\
**注意:** これには2つのコマンドが必要です

**1- PFXをPEMに変換**
```
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
**2- PEMをPKCS8に変換する**
```
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
**P7BをPFXに変換**\
**注意:** これには2つのコマンドが必要です

1- **P7BをCERに変換**
```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
**2- CERとプライベートキーをPFXに変換する**
```
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile  cacert.cer
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で**最も高度な**コミュニティツールを活用した**ワークフローの自動化**を簡単に構築しましょう。\
今すぐアクセス：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWSハッキングをゼロからヒーローに学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの会社を広告したい場合**、または**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを**共有する**。

</details>
