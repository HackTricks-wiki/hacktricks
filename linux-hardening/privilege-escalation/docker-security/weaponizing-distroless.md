# Distrolessの武器化

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>

## Distrolessとは

Distrolessコンテナは、特定のアプリケーションを実行するために必要な依存関係のみを含むコンテナのタイプであり、必要でない追加のソフトウェアやツールは含まれていません。これらのコンテナは、可能な限り**軽量**で**安全**であるように設計されており、不要なコンポーネントを削除することで**攻撃面を最小限に抑える**ことを目指しています。

Distrolessコンテナは、**セキュリティと信頼性が最優先される生産環境**でよく使用されます。

Distrolessコンテナの**例**には以下のものがあります:

* **Google**提供: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* **Chainguard**提供: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Distrolessの武器化

Distrolessコンテナを武器化する目的は、**distroless**によって暗示される制限（システム内の一般的なバイナリの欠如）と、`/dev/shm`での**読み取り専用**または**実行不可**など、コンテナで一般的に見られる保護をもってしても、**任意のバイナリやペイロードを実行できるようにする**ことです。

### メモリを通じて

2023年のある時点で来る予定...

### 既存のバイナリを通じて

#### openssl

****[**この投稿で、**](https://www.form3.tech/engineering/content/exploiting-distroless-images) コンテナ内で実行されるソフトウェアに**必要**である可能性があるため、**`openssl`** バイナリがこれらのコンテナで頻繁に見つかることが説明されています。

**`openssl`** バイナリを悪用することで、**任意のものを実行する**ことが可能です。

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>
