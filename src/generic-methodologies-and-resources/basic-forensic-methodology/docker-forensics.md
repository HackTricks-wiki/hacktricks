# Docker Forensics

{{#include ../../banners/hacktricks-training.md}}


## コンテナの変更

一部の Docker コンテナが侵害された疑いがあります:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
この container に対して image から行われた **変更を確認**するには、次のコマンドを使用します。
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
前のコマンドでは **C** は **Changed**（変更）、**A,** は **Added**（追加）を意味します。\
`/etc/shadow` のような興味深いファイルが変更されている場合は、以下を使用してコンテナからダウンロードし、悪意のある活動を確認できます：
```bash
docker cp wordpress:/etc/shadow.
```
**元のものと比較することもできます**。新しいコンテナを実行し、そこからファイルを抽出します：
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
**疑わしいファイルが追加された**ことが分かった場合は、コンテナにアクセスして確認できます:
```bash
docker exec -it wordpress bash
```
## Images modifications

export された Docker image（おそらく `.tar` 形式）が提供された場合は、[**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) を使用して**変更内容の概要を抽出**できます：
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
その後、imageを**decompress**して**blobsにアクセス**し、変更履歴で見つかった可能性のある不審なファイルを検索できます。
```bash
tar -xf image.tar
```
### 基本分析

以下を実行して、イメージから**基本情報**を取得できます。
```bash
docker inspect <image>
```
次のコマンドで、**変更履歴の概要**も取得できます:
```bash
docker history --no-trunc <image>
```
**image から dockerfile** も生成できます：
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

docker images 内で追加・変更されたファイルを見つけるには、[**dive**](https://github.com/wagoodman/dive)（[**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0) から download）utility も使用できます。
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
これにより、**Docker imageの異なるblobを移動して**、どのファイルが変更または追加されたかを確認できます。**Red**は追加、**yellow**は変更を意味します。**tab**で別のビューに移動し、**space**でフォルダを折りたたんだり展開したりできます。

dieでは、imageの各stageの内容にアクセスできません。アクセスするには、**各layerをdecompressしてアクセスする**必要があります。\
imageのすべてのlayerは、imageをdecompressしたディレクトリから次を実行してdecompressできます。
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## メモリからのCredentials

ホスト内でDockerコンテナを実行すると、`ps -ef`を実行するだけで**ホストからコンテナ内で実行されているプロセスを確認できる**ことに注意してください。

したがって、（rootとして）ホストから**プロセスのメモリをdumpし**、[**次の例のように**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory)**Credentials**を検索できます。


{{#include ../../banners/hacktricks-training.md}}
