# 証明書

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を使って、**ゼロからヒーローまでAWSハッキングを学ぶ**</summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で**@hacktricks_live**をフォローする
- **HackTricks**および**HackTricks Cloud**のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 証明書とは

暗号化において、**公開鍵証明書**、または**デジタル証明書**、**アイデンティティ証明書**としても知られるものは、公開鍵の所有権を証明するために使用される電子文書です。証明書には鍵に関する情報、所有者（サブジェクトと呼ばれる）のアイデンティティに関する情報、および証明書の内容を検証したエンティティのデジタル署名が含まれます（発行者と呼ばれます）。署名が有効であり、証明書を検討しているソフトウェアが発行者を信頼している場合、その鍵を使用して証明書のサブジェクトと安全に通信できます。

典型的な[公開鍵インフラストラクチャ](https://en.wikipedia.org/wiki/Public-key_infrastructure)（PKI）スキームでは、証明書の発行者は通常、顧客に証明書を発行するために料金を請求する企業である[証明機関](https://en.wikipedia.org/wiki/Certificate_authority)（CA）です。一方、[信頼のネットワーク](https://en.wikipedia.org/wiki/Web_of_trust)スキームでは、個人がお互いの鍵に直接署名し、公開鍵証明書と同様の機能を果たす形式で行います。

公開鍵証明書の最も一般的な形式は[X.509](https://en.wikipedia.org/wiki/X.509)によって定義されています。X.509は非常に一般的であるため、特定のユースケース向けに定義されたプロファイルによってさらに制約されます。たとえば、RFC 5280で定義されている[公開鍵インフラストラクチャ（X.509）](https://en.wikipedia.org/wiki/PKIX)などがあります。

## x509共通フィールド

- **バージョン番号**：x509形式のバージョン。
- **シリアル番号**：CAのシステム内で証明書を一意に識別するために使用されます。特に、これは取り消し情報を追跡するために使用されます。
- **サブジェクト**：証明書が属するエンティティ：マシン、個人、または組織。
- **コモンネーム**：証明書に影響を与えるドメイン。1つ以上であり、ワイルドカードを含むことができます。
- **国（C）**：国
- **識別名（DN）**：全体のサブジェクト：`C=US, ST=California, L=San Francisco, O=Example, Inc., CN=shared.global.example.net`
- **ローカリティ（L）**：地元の場所
- **組織（O）**：組織名
- **組織単位（OU）**：組織の部門（「人事」など）。
- **州または州（ST、SまたはP）**：州または州の名前のリスト
- **発行者**：情報を検証し、証明書に署名したエンティティ。
- **コモンネーム（CN）**：証明機関の名前
- **国（C）**：証明機関の国
- **識別名（DN）**：証明機関の識別名
- **ローカリティ（L）**：組織が見つかる地元の場所。
- **組織（O）**：組織名
- **組織単位（OU）**：組織の部門（「人事」など）。
- **Not Before**：証明書が有効である最も早い時刻と日付。通常、証明書が発行された瞬間よりも数時間または数日前に設定され、[クロックスキュー](https://en.wikipedia.org/wiki/Clock_skew#On_a_network)問題を回避します。
- **Not After**：証明書が無効になる時刻と日付。
- **公開鍵**：証明書サブジェクトに属する公開鍵。 （これはCAによって署名される主要な部分の1つです）
- **公開鍵アルゴリズム**：公開鍵を生成するために使用されるアルゴリズム。RSAなど。
- **公開鍵曲線**：楕円曲線公開鍵アルゴリズムで使用される曲線（適用される場合）。nistp521など。
- **公開鍵指数**：公開鍵を導出するために使用される指数（適用される場合）。65537など。
- **公開鍵サイズ**：ビット単位での公開鍵空間のサイズ。2048など。
- **署名アルゴリズム**：公開鍵証明書に署名するために使用されるアルゴリズム。
- **署名**：発行者の秘密鍵による証明書本体の署名。
- **x509v3拡張**
- **キーの使用法**：証明書の公開鍵の有効な暗号利用方法。デジタル署名検証、鍵暗号化、証明書署名などが一般的な値です。
- Web証明書では、_X509v3拡張_として表示され、値が`Digital Signature`になります。
- **拡張キーの使用法**：証明書が使用できるアプリケーション。TLSサーバー認証、電子メール保護、コード署名などが一般的な値です。
- Web証明書では、_X509v3拡張_として表示され、値が`TLS Web Server Authentication`になります。
- **サブジェクト代替名**：1つのSSL証明書に追加のホスト**名**を指定できます。SAN拡張の使用はSSL証明書の標準的な慣行であり、一般的な**名前**の使用を置き換える途中です。
- **基本制約**：この拡張は、証明書がCA証明書であるかエンドエンティティ証明書であるかを説明します。 CA証明書は他者の証明書に署名するものであり、エンドエンティティ証明書は、たとえばWebページで使用される証明書です（チェーンの最後の部分）。
- **サブジェクトキー識別子**（SKI）：この拡張は、証明書の公開**キー**の一意の**識別子**を宣言します。すべてのCA証明書には必須です。 CAは、発行された証明書の発行者**キー識別子**（AKI）拡張に自分自身のSKIを伝播します。これはサブジェクト公開鍵のハッシュです。
- **権限キー識別子**：これには、発行者証明書の公開鍵から派生したキー識別子が含まれます。これは発行者公開鍵のハッシュです。
- **権限情報アクセス**（AIA）：この拡張には、次の2種類の情報が含まれます：
  - この証明書の発行者を取得する方法に関する情報（CA発行者アクセス方法）
  - この証明書の取り消しを確認できるOCSP応答者のアドレス（OCSPアクセス方法）。
- **CRL配布ポイント**：この拡張は、この証明書の取り消しを確認できるCRLの場所を識別します。証明書を処理するアプリケーションは、この拡張からCRLの場所を取得し、CRLをダウンロードしてからこの証明書の取り消しを確認できます。
- **CTプレサーティフィケートSCT**：証明書に関する証明書透明性のログ

### OCSPとCRL配布ポイントの違い

**OCSP**（RFC 2560）は、**OCSPクライアントとOCSP応答者**から構成される標準プロトコルです。このプロトコルは、**CRL全体をダウンロードすることなく**、**特定のデジタル公開鍵証明書の取り消しステータスを決定**します。\
**CRL**は証明書の有効性を確認するための**従来の方法**です。**CRLには取り消された証明書のシリアル番号のリスト**が含まれます。 CRLを使用することで、証明書の提示時にその取り消しステータスを確認できます。 CRLは512エントリまでです。\
[こちら](https://www.arubanetworks.com/techdocs/ArubaOS%206_3_1_Web_Help/Content/ArubaFrameStyles/CertRevocation/About_OCSP_and_CRL.htm)から。

### 証明書透明性とは

証明書透明性は、SSL証明書に基づく脅威を解決することを目的としています。これは、SSL証明書の発行と存在をドメイン所有者、CA、およびドメインユーザーによって検証可能にすることを目的としています。具体的には、証明書透明性には次の3つの主な目標があります：

- CAがそのドメインのためにSSL証明書を発行することができない（または非常に困難にする）ようにする。その証明書がそのドメインの所有者に見えるようにする。
- 任意のドメイン所有者またはCAが、誤ってまたは悪意を持って発行された証明書を確認できるようにする、オープンな監査およびモニタリングシステムを提供する。
- 誤ってまたは悪意を持って発行された証明書によってユーザーがだまされるのを（可能な限り）防ぐ。

#### **証明書ログ**

証明書ログは、証明書の**暗号的に保証された、公開で監査可能な、追加専用のレコード**を維持するシンプルなネットワークサービスです。**誰でもログに証明書を提出できます**が、証明機関がおそらく最初の提出者になるでしょう。同様に、誰でもログをクエリでき、その暗号的な証拠を取得できます。これは、ログが適切に動作しているか、特定の証明書がログに記録されているかを検証するために使用できます。ログサーバーの数は大きくなくても構いません（たとえば、世界中で1000を大幅に下回る）、それぞれがCA、ISP、または他の関係者によって独立して運営される可能性があります。

#### クエリ

任意のドメインの証明書透明性のログを[https://crt.sh/](https://crt.sh)でクエリできます。

## フォーマット

証明書を保存するために使用できるさまざまなフォーマットがあります。

#### **PEM形式**

- 証明書に最も一般的に使用される形式です
- ほとんどのサーバ
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

**注意:** PKCS#7またはP7B形式はBase64 ASCII形式で保存され、ファイル拡張子は.p7bまたは.p7cです。P7Bファイルには証明書とチェーン証明書（中間CA）のみが含まれており、秘密鍵は含まれていません。P7Bファイルをサポートする最も一般的なプラットフォームはMicrosoft WindowsとJava Tomcatです。
```
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
**PKCS7をPEM形式に変換する**
```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**pfxをPEMに変換する**

**注意:** PKCS#12またはPFX形式は、サーバー証明書、中間証明書、および秘密鍵を1つの暗号化可能なファイルに格納するためのバイナリ形式です。 PFXファイルには通常、.pfxや.p12などの拡張子が付いています。 PFXファイルは、通常、Windowsマシンで証明書と秘密鍵をインポートおよびエクスポートするために使用されます。
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
```
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile  cacert.cer
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も先進的なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>で**ゼロからヒーローまでAWSハッキングを学ぶ**</summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つけてください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加**したり、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)で**フォロー**してください。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks)のgithubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>
