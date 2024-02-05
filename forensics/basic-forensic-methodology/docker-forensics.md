# Dockerフォレンジック

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じてゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**または[telegramグループ](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)で**フォロー**する。
- **HackTricks**および**HackTricks Cloud**のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>

## コンテナの変更

あるDockerコンテナが侵害された可能性があるという疑いがあります：
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
あなたは簡単に次のコマンドで、このコンテナに対して行われた変更をイメージに関して見つけることができます:
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
前のコマンドで **C** は **変更** を意味し、**A** は **追加** を意味します。\
もし `/etc/shadow` のような興味深いファイルが変更されていることがわかった場合、悪意のある活動をチェックするためにコンテナからダウンロードすることができます:
```bash
docker cp wordpress:/etc/shadow.
```
あなたは新しいコンテナを実行し、そこからファイルを抽出することで、元のものと比較することもできます：
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
もし**いくつかの怪しいファイルが追加された**ことがわかった場合は、コンテナにアクセスして確認できます：
```bash
docker exec -it wordpress bash
```
## 画像の変更

エクスポートされたDockerイメージ（おそらく`.tar`形式）が与えられた場合、[**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases)を使用して**変更の概要を抽出**できます。
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
その後、イメージを**展開**して、**ブロブにアクセス**して、変更履歴で見つけた疑わしいファイルを検索できます。
```bash
tar -xf image.tar
```
### 基本的な分析

イメージを実行して**基本情報**を取得できます：
```bash
docker inspect <image>
```
以下は、変更の要約履歴を取得する方法です:
```bash
docker history --no-trunc <image>
```
あなたはまた、次のようにしてイメージから**dockerfileを生成**することもできます：
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Dockerイメージ内の追加/変更されたファイルを見つけるためには、[**dive**](https://github.com/wagoodman/dive)（[**リリース**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)からダウンロード）ユーティリティを使用することもできます。
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
これにより、**Dockerイメージの異なるブロブをナビゲート**して、変更/追加されたファイルを確認できます。**赤**は追加されたファイルを、**黄色**は変更されたファイルを示します。**Tab** キーを使用して他のビューに移動し、**スペース** キーを使用してフォルダを折りたたんだり展開したりします。

これにより、イメージの異なるステージのコンテンツにアクセスできなくなります。それを行うには、**各レイヤーを展開してアクセスする**必要があります。\
イメージのすべてのレイヤーを展開するには、イメージが展開されたディレクトリから次のコマンドを実行します：
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## メモリからの資格情報

ホスト内でdockerコンテナを実行すると、ホストから`ps -ef`を実行するだけでコンテナで実行されているプロセスを見ることができます。

したがって（rootとして）、ホストからプロセスのメモリをダンプし、[**次の例のように**](../../linux-hardening/privilege-escalation/#process-memory)資格情報を検索することができます。
