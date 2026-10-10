# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricksのロゴとモーションデザイン：_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_

### HackTricksをローカルで実行する

```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks

# Select the language you want to use
export HT_LANG="master" # Leave master for English
# "af" for Afrikaans
# "de" for German
# "el" for Greek
# "es" for Spanish
# "fr" for French
# "hi" for HindiP
# "it" for Italian
# "ja" for Japanese
# "ko" for Korean
# "pl" for Polish
# "pt" for Portuguese
# "sr" for Serbian
# "sw" for Swahili
# "tr" for Turkish
# "uk" for Ukrainian
# "zh" for Chinese

# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $HT_LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```

HackTricks のローカルコピーは、5 分以内に [http://localhost:3337](http://localhost:3337) で**利用可能になります**（書籍のビルドが必要なので、しばらくお待ちください）。

または、Docker Compose がある場合は、リポジトリのルートから次のコマンドを実行してください。

```bash
docker compose up
```

これは同梱の `docker-compose.yml` を使用して、ホスト上で現在チェックアウトされているブランチを [http://localhost:3337](http://localhost:3337) でライブリロード付きで配信します。Compose の使用中に言語を変更するには、サービスを起動する前に目的の言語のブランチをチェックアウトしてください。

## HackTricks パートナー

---

## HackTricks フレンド

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber は、ペネトレーションテスト、セキュリティ監査、exploit および研究業務、ツール、セキュリティ意識向上サービスを提供しています。同社のサイトによると、ペネトレーションテスター、プログラマー、セキュリティ研究者からなるチームは、10年以上の経験を有しています。<sup>[[1]](#references)</sup>

同社の**ブログ**は [**https://blog.stmcyber.com**](https://blog.stmcyber.com) でご覧いただけます。

**STM Cyber** は HackTricks のようなサイバーセキュリティのオープンソースプロジェクトも支援しています :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti は、世界中のリサーチャーコミュニティを通じて bug bounty とペネトレーションテストのサービスを提供する、クラウドソーシング型のセキュリティプロバイダーです。同社のプラットフォームは、継続的な bug bounty 対応に加え、オンデマンドの PTaaS と脆弱性開示プログラムの運用を提供します。<sup>[[2]](#references)</sup>

**Bug bounty のヒント**: [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) から Intigriti に登録し、bug bounty プログラムをご覧ください。

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security は、セキュリティエンジニア、AppSec の専門家、開発者向けに、自分のペースで学べる実践的な AI セキュリティトレーニングを提供しています。AI Security Certification では、LLM と agent の基礎、RAG と vector database、脅威モデリング、prompt injection と MCP 攻撃、防御アーキテクチャを学べます。<sup>[[3]](#references)</sup>

👉 AI Security コースの詳細:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** は Google などの検索エンジン向けの API を提供し、位置情報に応じた検索結果、Maps、Shopping、Knowledge Graph の結果などの機能とともに、構造化された SERP データを返します。<sup>[[4]](#references)</sup>

詳細については、同社の[**ブログ**](https://serpapi.com/blog/)をご覧になるか、[**playground**](https://serpapi.com/playground)で例をお試しいただくか、[**無料アカウントを作成**](https://serpapi.com/users/sign_up)してください。

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** は、自分のペースで学べるモバイルおよび AI セキュリティコースを提供しています。コースには、Ghidra、Frida、LLDB などのツールを使ったモバイルアプリケーションの監査とリバースエンジニアリングのほか、AI/LLM の攻撃と防御を学ぶラボが含まれます。<sup>[[5]](#references)[[6]](#references)</sup>

[8kSec Academy のコース一覧](https://academy.8ksec.io/)をご覧ください。

---

### [NaxusAI – AI Powered Security Scanner](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** は、コードとインフラストラクチャをマッピングし、静的および動的 agent を活用して、悪用可能な弱点を発見・検証する offensive AI プラットフォームを提供しています。検証結果には概念実証の証拠と修正ガイダンスが含まれます。<sup>[[7]](#references)</sup>

**コードセキュリティのヒント**: Naxus を使って、コードやインフラストラクチャを対象とした脆弱性の発見をお試しください。

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec は、ペネトレーションテスト、セキュリティサブスクリプション、人材派遣、脆弱性評価のサービスを提供しています。同社のサイトによると、国際的に事業を展開し、offensive security、defensive security、ガバナンス・リスク・コンプライアンス業務を扱っています。<sup>[[8]](#references)</sup>

詳細については、[**ウェブサイト**](https://websec.net/en/)または[**ブログ**](https://websec.net/blog/)をご覧ください。

上記に加えて、WebSec は HackTricks の**熱心な支援者**でもあります。

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**現場のために。あなたに合わせて。**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) は、実際のインフラストラクチャを基盤とするカスタムコンテンツとラボを用いた、専門家主導のサイバーセキュリティトレーニングを提供しています。プログラムは組織のニーズに合わせて調整され、評価から実装までを網羅します。<sup>[[9]](#references)</sup> カスタムトレーニングに関するお問い合わせは[**こちら**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks)から。

**トレーニングの特長:**
* カスタムコンテンツとラボ
* トップクラスのツールとプラットフォームを活用
* 実務者が設計・指導

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions は、**教育**および**FinTech**分野のサイバーセキュリティコンサルティングを専門とし、クラウド評価、内部・外部ペネトレーションテスト、脆弱性評価、コンプライアンス支援を提供しています。<sup>[[10]](#references)</sup>

[**ブログ**](https://www.lasttowersolutions.com/blog)をご覧いただき、サイバーセキュリティの最新情報をご確認ください。

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio は、CloudMaps の可視化、マルチクラスターのナビゲーション、RBAC、Helm、ログ、YAML、ターミナル表示を備えた、デスクトップ向け Kubernetes IDE です。提供元によると、agent をインストールせずに kubeconfig 経由で接続でき、macOS、Windows、Linux、エアギャップ環境のクラスターに対応しています。<sup>[[11]](#references)</sup>

---

## ライセンスと免責事項

下記の References にある HackTricks Values & FAQ の項目をご覧ください。

## Github 統計

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [AI Security Certification – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [実践的な AI セキュリティ: 攻撃、防御、応用](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Intigriti HackTricks 紹介リンク](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [WebSec スポンサー紹介動画](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cyber Helmets のコース](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks の理念と FAQ](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
