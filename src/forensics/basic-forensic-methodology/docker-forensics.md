# Docker Forensics

{{#include ../../banners/hacktricks-training.md}}

## コンテナの改ざん

いくつかのdockerコンテナが侵害された疑いがあります：
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
このコンテナに対する**イメージに関する変更を簡単に見つけることができます**:
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
前のコマンドで **C** は **Changed** を意味し、**A** は **Added** を意味します。\
もし `/etc/shadow` のような興味深いファイルが変更されていることがわかった場合、悪意のある活動を確認するためにコンテナからダウンロードすることができます：
```bash
docker cp wordpress:/etc/shadow.
```
新しいコンテナを実行し、そのファイルを抽出することで、**元のものと比較することもできます**。
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
**いくつかの疑わしいファイルが追加された**場合は、コンテナにアクセスして確認できます：
```bash
docker exec -it wordpress bash
```
## 画像の変更

エクスポートされたDockerイメージ（おそらく`.tar`形式）を受け取ったときは、[**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases)を使用して**変更の概要を抽出**できます：
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
次に、イメージを**解凍**し、**ブロブにアクセス**して、変更履歴で見つけた疑わしいファイルを検索できます：
```bash
tar -xf image.tar
```
### 基本分析

イメージから**基本情報**を取得するには、次のコマンドを実行します:
```bash
docker inspect <image>
```
変更履歴の要約を取得することもできます:
```bash
docker history --no-trunc <image>
```
画像から**dockerfileを生成**することもできます。
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Dockerイメージ内の追加または変更されたファイルを見つけるために、[**dive**](https://github.com/wagoodman/dive)（[**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)からダウンロード）ユーティリティを使用することもできます：
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
これにより、**dockerイメージの異なるblobをナビゲート**し、どのファイルが変更または追加されたかを確認できます。**赤**は追加されたことを意味し、**黄色**は変更されたことを意味します。**タブ**を使用して他のビューに移動し、**スペース**を使用してフォルダーを折りたたむ/開くことができます。

dieを使用すると、イメージの異なるステージの内容にアクセスすることはできません。そのためには、**各レイヤーを解凍してアクセスする**必要があります。\
イメージが解凍されたディレクトリから、次のコマンドを実行してイメージのすべてのレイヤーを解凍できます:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## メモリからの資格情報

ホスト内でdockerコンテナを実行するとき、**ホストからコンテナで実行されているプロセスを見ることができます**。単に`ps -ef`を実行するだけです。

したがって（rootとして）、**ホストからプロセスのメモリをダンプし**、**資格情報**を検索することができます。ちょうど[**次の例のように**](../../linux-hardening/privilege-escalation/#process-memory)。

{{#include ../../banners/hacktricks-training.md}}
