# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks のロゴとモーションデザイン制作：_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_。_

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

HackTricks のローカルコピーは、5分以内に [http://localhost:3337](http://localhost:3337) で利用可能になります（書籍のビルドが必要なので、しばらくお待ちください）。

または、Docker Compose がある場合は、リポジトリのルートから以下を実行してください。

```bash
docker compose up
```

これは同梱の `docker-compose.yml` を使い、ホスト上で現在チェックアウトされているブランチを [http://localhost:3337](http://localhost:3337) でライブリロード付きで配信します。Compose を使って言語を変更するには、サービスを起動する前に目的の言語のブランチをチェックアウトしてください。

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber は、penetration testing、セキュリティ監査、exploit と研究、ツール、セキュリティ意識向上サービスを提供しています。同社のサイトによると、10年以上の経験を持つ penetration tester、プログラマー、セキュリティ研究者のチームで構成されています。<sup>[[1]](#references)</sup>

**blog** は [**https://blog.stmcyber.com**](https://blog.stmcyber.com) でご覧いただけます。

**STM Cyber** は HackTricks のようなサイバーセキュリティのオープンソースプロジェクトも支援しています :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti は、世界中のリサーチャーコミュニティを通じて bug bounty と penetration-testing サービスを提供するクラウドソーシング型のセキュリティプロバイダーです。同社のプラットフォームは、継続的な bug bounty 対応に加え、オンデマンドの PTaaS とマネージド脆弱性開示プログラムを提供します。<sup>[[2]](#references)</sup>

**Bug bounty のヒント**: [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) から Intigriti に登録し、bug bounty プログラムをご確認ください。

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security は、セキュリティエンジニア、AppSec の専門家、開発者向けに、自分のペースで進められる実践的な AI security training を提供しています。同社の AI Security Certification では、LLM と agent の基礎、RAG と vector database、threat modeling、prompt-injection と MCP attacks、防御アーキテクチャを扱います。<sup>[[3]](#references)</sup>

👉 AI Security コースの詳細はこちら:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** は Google などの検索エンジン向け API を提供し、位置情報に応じた結果、Maps、Shopping、Knowledge Graph の結果などの機能を備えた構造化 SERP データを返します。<sup>[[4]](#references)</sup>

詳しくは、[**blog**](https://serpapi.com/blog/) をご覧いただくか、[**playground**](https://serpapi.com/playground) で例を試すか、[**無料アカウントを作成**](https://serpapi.com/users/sign_up)してください。

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** は、自分のペースで進められるモバイルおよび AI-security コースを提供しています。カタログでは、Ghidra、Frida、LLDB などのツールを使ったモバイルアプリケーションの監査とリバースに加え、AI/LLM の攻撃・防御ラボを扱っています。<sup>[[5]](#references)[[6]](#references)</sup>

[8kSec Academy のコースカタログ](https://academy.8ksec.io/)をご覧ください。

---

### [NaxusAI – Autonomous Offensive Security](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt="NaxusAI logo"><figcaption></figcaption></figure>

**Naxus** は、外部 attack surface 全体のスキャン、モバイルアプリ監査、web black-box testing、ソースコードレビューを行う AI 搭載の offensive-security プラットフォームです。agent が悪用可能な検出結果を検証し、追跡可能な証拠、proof-of-concept exploit、実行可能な修正案を提供します。<sup>[[7]](#references)</sup>

**セキュリティ監査のヒント**: 外部資産、モバイルアプリ、web アプリ、ソースコードのエンドツーエンドの自動監査に Naxus をご利用ください。

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec は、penetration testing、セキュリティサブスクリプション、人材派遣、脆弱性評価サービスを提供しています。同社のサイトによると、国際的に事業を展開し、offensive security、defensive security、ガバナンス、リスク、コンプライアンスに関する業務を扱っています。<sup>[[8]](#references)</sup>

詳しくは、[**website**](https://websec.net/en/) または [**blog**](https://websec.net/blog/) をご覧ください。

上記に加えて、WebSec は HackTricks の**熱心な支援者**でもあります。

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**現場のために。あなたに合わせて。**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) は、実際のインフラに基づくカスタムコンテンツとラボを用いた、専門家主導のサイバーセキュリティトレーニングを提供しています。プログラムは組織のニーズに合わせて調整され、評価から実装までを網羅します。<sup>[[9]](#references)</sup> カスタムトレーニングに関するお問い合わせは[**こちら**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks)からご連絡ください。

**トレーニングの特長:**
* カスタムコンテンツとラボ
* 一流のツールとプラットフォームを活用
* 実務者が設計し、指導

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions は、**教育**と**FinTech**分野のサイバーセキュリティコンサルティングに注力しており、クラウド評価、内部・外部 penetration test、脆弱性評価、コンプライアンス支援を提供しています。<sup>[[10]](#references)</sup>

[**blog**](https://www.lasttowersolutions.com/blog) で、サイバーセキュリティの最新情報をご確認ください。

---

### [Beaki — Food that fits you](https://www.beaki.app/)

<figure class="sponsor-logo"><img src="images/beaki-logo.png" alt="Beaki logo"><figcaption></figcaption></figure>

**Beaki** は、パーソナライズされた食品スキャナー、カロリーカウンター、栄養トラッカーです。バーコードやスーパーマーケットの棚をスキャンしたり、食事やレストランのメニューを撮影または説明したりすると、目標、食事、アレルギー、健康プロフィールに合わせた説明可能なスコアを取得できます。Beaki はカロリーとマクロ栄養素も記録し、買い物リスト付きのパーソナライズされた食事プランを作成します。<sup>[[11]](#references)</sup>

Android または iPhone で[**Beaki を無料でダウンロード**](https://www.beaki.app/?utm_source=hacktricks&utm_medium=partner&utm_campaign=hacktricks)。

---

## License & Disclaimer

以下の References にある HackTricks Values & FAQ をご覧ください。

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [AI Security Certification – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [実践的な AI Security: 攻撃、防御、応用](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [Beaki](https://www.beaki.app/)
- [12] [Intigriti HackTricks 紹介リンク](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [WebSec スポンサー動画](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cyber Helmets コース](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks の価値観と FAQ](welcome/hacktricks-values-and-faq.md)

{{#include banners/hacktricks-training.md}}
