# Dockerフォレンジック

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>

## コンテナの変更

あるDockerコンテナが侵害された疑いがあります：
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
このコンテナに関してイメージに対して行われた変更を簡単に**見つけることができます**。以下のコマンドを使用します:
```bash
docker diff wordpress
C /var
C /var/lib
C /var/lib/mysql
A /var/lib/mysql/ib_logfile0
A /var/lib/mysql/ib_logfile1
A /var/lib/mysql/ibdata1
A /var/lib/mysql/mysql
A /var/lib/mysql/mysql/time_zone_leap_second.MYI
A /var/lib/mysql/mysql/general_log.CSV
...
```
前のコマンドで、**C**は**変更**を意味し、**A**は**追加**を意味します。\
もし、`/etc/shadow`のような興味深いファイルが変更されていることがわかった場合、以下のコマンドを使用してコンテナからダウンロードし、悪意のある活動をチェックすることができます。
```bash
docker cp wordpress:/etc/shadow.
```
新しいコンテナを実行し、そこからファイルを抽出して元のファイルと比較することもできます。
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
もし**何らかの不審なファイルが追加された**ことがわかった場合、コンテナにアクセスして確認することができます。
```bash
docker exec -it wordpress bash
```
## 画像の変更

エクスポートされたDockerイメージ（おそらく`.tar`形式）が与えられた場合、[**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases)を使用して、**変更の概要を抽出**することができます。
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
次に、イメージを**解凍**し、変更履歴で見つけた疑わしいファイルを検索するために**ブロブにアクセス**できます。
```bash
tar -xf image.tar
```
### 基本的な分析

実行中のイメージから**基本情報**を取得できます：
```bash
docker inspect <image>
```
次のコマンドを使用して、変更の要約履歴を取得することもできます:

```bash
git log --oneline
```
```bash
docker history --no-trunc <image>
```
イメージから**dockerfileを生成**することもできます。以下のコマンドを使用します:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Dockerイメージ内の追加/変更されたファイルを見つけるために、[**dive**](https://github.com/wagoodman/dive)（[**リリース**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)からダウンロード）ユーティリティを使用することもできます。
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
これにより、Dockerイメージの異なるブロブをナビゲートし、変更/追加されたファイルを確認することができます。**赤色**は追加されたことを意味し、**黄色**は変更されたことを意味します。**Tab**キーを使用して他のビューに移動し、**スペース**キーを使用してフォルダを折りたたむ/展開することができます。

dieを使用すると、イメージの異なるステージの内容にアクセスすることはできません。そのため、各レイヤーを解凍してアクセスする必要があります。\
イメージのすべてのレイヤーを解凍するには、イメージが解凍されたディレクトリで次のコマンドを実行します：
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## メモリからの資格情報

注意してください、ホスト内でDockerコンテナを実行すると、ホストからコンテナで実行されているプロセスを`ps -ef`コマンドで確認できます。

したがって（rootとして）ホストからプロセスのメモリをダンプし、[**以下の例のように**](../../linux-hardening/privilege-escalation/#process-memory)、資格情報を検索することができます。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>
