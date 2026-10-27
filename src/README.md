# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricksのロゴとモーションデザイン制作：_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_.

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

HackTricks のローカルコピーは、5 分以内に [http://localhost:3337](http://localhost:3337) で**利用可能になります**（書籍のビルドが必要なため、しばらくお待ちください）。

または、Docker Compose がある場合は、リポジトリのルートから以下を実行してください。

```bash
docker compose up
```

これは、同梱の `docker-compose.yml` を使って、ホストで現在チェックアウトされているブランチをライブリロード付きで [http://localhost:3337](http://localhost:3337) から配信します。Compose を使って言語を切り替えるには、サービスを起動する前に目的の言語のブランチをチェックアウトしてください。

## HackTricks パートナー

---

## HackTricks の仲間

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber は、penetration testing、security audits、exploit および research 関連の業務、ツール、セキュリティ意識向上サービスを提供しています。同社のサイトによると、penetration tester、プログラマー、security researcher からなるチームで、10年以上の経験があります。<sup>[[1]](#references)</sup>

**ブログ**は [**https://blog.stmcyber.com**](https://blog.stmcyber.com) でご覧いただけます。

**STM Cyber** は、HackTricks のようなサイバーセキュリティ分野のオープンソースプロジェクトも支援しています :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti は、世界中の researcher コミュニティを通じて bug bounty と penetration-testing サービスを提供する、crowdsourced security プロバイダーです。同社のプラットフォームでは、継続的な bug bounty に加え、オンデマンドの PTaaS とマネージド vulnerability disclosure プログラムを利用できます。<sup>[[2]](#references)</sup>

**Bug bounty のヒント**: [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) から Intigriti に登録し、bug bounty プログラムをご覧ください。

---

### [Modern Security – AI・アプリケーションセキュリティトレーニングプラットフォーム](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security は、security engineer、AppSec 専門家、developer 向けに、自分のペースで進められる実践的な AI security トレーニングを提供しています。AI Security Certification では、LLM と agent の基礎、RAG と vector database、threat modeling、prompt-injection と MCP 攻撃、防御アーキテクチャを扱います。<sup>[[3]](#references)</sup>

👉 AI Security コースの詳細はこちら:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** は、Google などの検索エンジン向け API を提供し、位置情報に応じた結果、Maps、Shopping、Knowledge Graph の結果などの機能を備えた、構造化された SERP データを返します。<sup>[[4]](#references)</sup>

詳細については、[**ブログ**](https://serpapi.com/blog/)をご覧いただくか、[**playground**](https://serpapi.com/playground)で例を試すか、[**無料アカウントを作成**](https://serpapi.com/users/sign_up)してください。

---

### [8kSec Academy – モバイル・AIセキュリティを深く学べるコース](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** は、自分のペースで進められるモバイルおよび AI security のコースを提供しています。カタログには、Ghidra、Frida、LLDB などのツールを用いたモバイルアプリケーションの監査やリバースエンジニアリングのほか、AI/LLM の攻撃・防御ラボが含まれています。<sup>[[5]](#references)[[6]](#references)</sup>

[8kSec Academy のコースカタログ](https://academy.8ksec.io/)をご覧ください。

---

### [NaxusAI – AI搭載セキュリティスキャナー](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** は、コードとインフラストラクチャをマッピングし、static および dynamic agent を使用して、悪用可能な弱点を発見・検証する offensive-AI プラットフォームを提供しています。検証には proof-of-concept の証拠と修復ガイダンスが含まれます。<sup>[[7]](#references)</sup>

**コードセキュリティのヒント**: コードとインフラストラクチャを対象とする脆弱性の発見に、Naxus をご活用ください。

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec は、penetration testing、セキュリティサブスクリプション、人材派遣、脆弱性評価サービスを提供しています。同社のサイトによると、世界各地で事業を展開し、offensive security、defensive security、ガバナンス、リスク、コンプライアンス関連の業務を手がけています。<sup>[[8]](#references)</sup>

詳細については、[**ウェブサイト**](https://websec.net/en/)または[**ブログ**](https://websec.net/blog/)をご覧ください。

上記に加え、WebSec はHackTricksを**継続的に支援**しています。

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**現場のために。あなたに合わせて。**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) は、実際のインフラストラクチャに基づくカスタムコンテンツとラボを用いた、専門家主導のサイバーセキュリティトレーニングを提供しています。プログラムは組織のニーズに合わせて調整され、評価から実装までを網羅しています。<sup>[[9]](#references)</sup> カスタムトレーニングについてのお問い合わせは[**こちら**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks)から。

**トレーニングの特長:**
* カスタムコンテンツとラボ
* 一流のツールとプラットフォームを活用
* 実務経験者が設計・指導

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions は、**教育**および**FinTech**分野のサイバーセキュリティコンサルティングを専門とし、クラウド評価、内部・外部 penetration test、脆弱性評価、コンプライアンス支援を提供しています。<sup>[[10]](#references)</sup>

[**ブログ**](https://www.lasttowersolutions.com/blog)で、サイバーセキュリティの最新情報をご確認ください。

---

### [K8Studio - Kubernetesを管理する、よりスマートなGUI。](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio は、CloudMaps による可視化、マルチクラスター間のナビゲーション、RBAC、Helm、ログ、YAML、ターミナル表示に対応した、デスクトップ向け Kubernetes IDE です。ベンダーによると、agent をインストールせずに kubeconfig 経由で接続でき、macOS、Windows、Linux、air-gapped cluster に対応しています。<sup>[[11]](#references)</sup>

---

## ライセンスと免責事項

下記の References にある HackTricks Values & FAQ をご覧ください。

## Github 統計

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [AI Security Certification – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [実践的なAIセキュリティ: 攻撃、防御、応用](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Intigriti HackTricks 紹介リンク](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [WebSec スポンサーシップ動画](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cyber Helmets コース](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks の価値観とよくある質問](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
