# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_HackTricks のロゴとモーションデザイン：_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_

### HackTricks をローカルで実行する

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
# "hi" for Hindi
# "it" for Italian
# "ja" for Japanese
# "ko" for Korean
# "pl" for Polish
# "pt" for Portuguese
# "sr" for Serbian
# "sw" for Swahili
# "tr" for Turkish
# "uk" for Ukrainian
# "vi" for Vietnamese
# "zh" for Chinese

# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $HT_LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```

HackTricks のローカルコピーは、書籍のビルドが完了するまで（5分以内）お待ちいただくと、**[http://localhost:3337](http://localhost:3337)** で利用できます。

また、Docker Compose がある場合は、リポジトリのルートから次のコマンドを実行するだけです。

```bash
docker compose up
```

これは同梱の `docker-compose.yml` を使い、ホストで現在チェックアウトされているブランチを [http://localhost:3337](http://localhost:3337) でライブリロード付きで配信します。Compose の使用時に言語を変更するには、サービスを起動する前に目的の言語のブランチをチェックアウトしてください。

## HackTricks パートナー

---

## HackTricks フレンド

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber は、pentesting、セキュリティ監査、exploit と research の業務、ツール、セキュリティ意識向上サービスを提供しています。同社のサイトによると、penetration tester、プログラマー、セキュリティ研究者からなるチームで、10年以上の経験があります。<sup>[[1]](#references)</sup>

[**ブログ**](https://blog.stmcyber.com)をご覧ください。

**STM Cyber** は HackTricks などのサイバーセキュリティのオープンソースプロジェクトも支援しています :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti は、世界中の研究者コミュニティを通じて bug bounty と penetration-testing サービスを提供する、クラウドソース型のセキュリティプロバイダーです。同社のプラットフォームは、継続的な bug bounty 対応に加え、オンデマンドの PTaaS とマネージド脆弱性開示プログラムを提供します。<sup>[[2]](#references)</sup>

**Bug bounty のヒント**: [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) から Intigriti に参加して、bug bounty プログラムをご覧ください。

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security は、セキュリティエンジニア、AppSec の専門家、開発者向けに、自分のペースで学べる実践的な AI セキュリティトレーニングを提供しています。同社の AI Security Certification では、LLM と agent の基礎、RAG と vector database、threat modeling、prompt injection と MCP attacks、防御アーキテクチャを扱います。<sup>[[3]](#references)</sup>

👉 AI Security コースの詳細はこちら:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** は Google などの検索エンジン向け API を提供し、地域に応じた検索結果、Maps、Shopping、Knowledge Graph の結果などを含む構造化された SERP データを返します。<sup>[[4]](#references)</sup>

詳しくは、同社の[**ブログ**](https://serpapi.com/blog/)をご覧いただくか、[**playground**](https://serpapi.com/playground)で例を試すか、[**無料アカウントを作成**](https://serpapi.com/users/sign_up)してください。

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** は、自分のペースで学べるモバイルおよび AI セキュリティコースを提供しています。カタログには、Ghidra、Frida、LLDB などのツールを使ったモバイルアプリケーションの監査とリバースに加え、AI/LLM の攻撃と防御のラボが含まれます。<sup>[[5]](#references)[[6]](#references)</sup>

[8kSec Academy のコースカタログ](https://academy.8ksec.io/)をご覧ください。

---

### [NaxusAI – Autonomous Offensive Security](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt="NaxusAI logo"><figcaption></figcaption></figure>

**Naxus** は、外部 attack surface 全体のスキャン、モバイルアプリの監査、Web の black-box testing、ソースコードレビューに対応する AI 搭載の offensive-security プラットフォームです。agent が悪用可能な検出結果を検証し、追跡可能な証拠、proof-of-concept exploit、実行可能な修正策を提供します。<sup>[[7]](#references)</sup>

**セキュリティ監査のヒント**: Naxus を使って、外部資産、モバイルアプリ、Web アプリ、ソースコードをエンドツーエンドで自律的に監査しましょう。

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec は、penetration testing、セキュリティサブスクリプション、人材派遣、脆弱性評価サービスを提供しています。同社のサイトによると、国際的に事業を展開し、offensive security、defensive security、ガバナンス、リスク、コンプライアンスの業務に対応しています。<sup>[[8]](#references)</sup>

詳しくは、[**ウェブサイト**](https://websec.net/en/)または[**ブログ**](https://websec.net/blog/)をご覧ください。

上記に加え、WebSec は HackTricks の**熱心な支援者**でもあります。

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**現場のために。あなたに合わせて。**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) は、実際のインフラに基づく独自のコンテンツとラボを用いた、専門家主導のサイバーセキュリティトレーニングを提供しています。組織のニーズに合わせてプログラムを構成し、評価から実装までをカバーします。<sup>[[9]](#references)</sup> カスタムトレーニングについては、[**こちら**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks)からお問い合わせください。

**トレーニングの特長:**
* 独自に開発されたコンテンツとラボ
* 一流のツールとプラットフォームを活用
* 実務者が設計・指導

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions は、**教育**と**FinTech**分野のサイバーセキュリティコンサルティングに注力しており、クラウド評価、内部・外部 penetration test、脆弱性評価、コンプライアンス支援を提供しています。<sup>[[10]](#references)</sup>

[**ブログ**](https://www.lasttowersolutions.com/blog)で、サイバーセキュリティの最新情報をご確認ください。

---

### [K8Studio - Kubernetes を管理する、よりスマートな GUI。](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio は、CloudMaps の可視化、複数クラスターのナビゲーション、RBAC、Helm、ログ、YAML、ターミナル表示に対応した、デスクトップ向け Kubernetes IDE です。ベンダーによると、agent をインストールせず kubeconfig 経由で接続でき、macOS、Windows、Linux、エアギャップ環境のクラスターをサポートしています。<sup>[[11]](#references)</sup>

---

## ライセンスと免責事項

下記「References」にある HackTricks の理念と FAQ をご覧ください。

## GitHub の統計

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
