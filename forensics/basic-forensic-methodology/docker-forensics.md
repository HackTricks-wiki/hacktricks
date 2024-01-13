# Docker フォレンジック

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加する、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する。

</details>

## コンテナの変更

あるdockerコンテナが侵害された疑いがあります：
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
容易に**このコンテナに対して行われた変更をイメージに関して見つけることができます**：
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
前のコマンドで **C** は **変更された** という意味で、**A** は **追加された** という意味です。\
もし `/etc/shadow` のような興味深いファイルが変更されていることが分かったら、以下のコマンドでコンテナからダウンロードして悪意のある活動をチェックできます：
```bash
docker cp wordpress:/etc/shadow.
```
You can also **オリジナルと比較する** by running a new container and extracting the file from it:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
```
もし**怪しいファイルが追加された**と分かったら、コンテナにアクセスして確認することができます:
```
```bash
docker exec -it wordpress bash
```
## イメージの変更

エクスポートされたdockerイメージ（おそらく`.tar`形式）が与えられた場合、[**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases)を使用して**変更の要約を抽出**することができます：
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
```
次に、イメージを**解凍**し、**ブロブにアクセス**して、変更履歴で見つかった怪しいファイルを検索できます：
```
```bash
tar -xf image.tar
```
### 基本分析

画像から**基本情報**を取得するには、以下を実行します：
```bash
docker inspect <image>
```
```
docker history [OPTIONS] IMAGE
```
```bash
docker history --no-trunc <image>
```
```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd):/output --entrypoint /bin/sh \
  whalebrew/whalecap -c "docker save $(docker inspect --format='{{.Id}}' \
  <image_name> | cut -d':' -f2) | tar xO | grep -v '^#' > /output/Dockerfile"
```
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Dockerイメージ内の追加/変更されたファイルを見つけるために、[**dive**](https://github.com/wagoodman/dive)ユーティリティを使用することもできます（[**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)からダウンロードしてください）。
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
これにより、**dockerイメージの異なるblobをナビゲートし**、どのファイルが変更/追加されたかを確認できます。**赤**は追加されたことを意味し、**黄色**は変更されたことを意味します。**tab**を使用して他のビューに移動し、**space**を使用してフォルダーを折りたたんだり開いたりします。

dieを使用しても、イメージの異なるステージの内容にアクセスすることはできません。これを行うには、**各レイヤーを解凍してアクセスする必要があります**。\
イメージが解凍されたディレクトリから、イメージのすべてのレイヤーを解凍するには、次のコマンドを実行します：
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## メモリからの認証情報

ホスト内でdockerコンテナを実行するとき、`ps -ef` を実行するだけで **ホストからコンテナで実行中のプロセスを見ることができます**。

したがって、（rootとして）ホストからプロセスのメモリを **ダンプし**、[**次の例のように**](../../linux-hardening/privilege-escalation/#process-memory) **認証情報**を探すことができます。

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または **HackTricksをPDFでダウンロードしたい** 場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加する、または **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
