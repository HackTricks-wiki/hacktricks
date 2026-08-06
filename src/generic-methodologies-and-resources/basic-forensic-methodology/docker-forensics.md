# Docker Forensics

{{#include ../../banners/hacktricks-training.md}}

## Container modification

一部のdocker containerが侵害された疑いがあります:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
次のコマンドで、**この container に image に関して加えられた変更を確認**できます:
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
前のコマンドでは、**C** は **Changed**（変更）、**A,** は **Added**（追加）を意味します。\
`/etc/shadow` のような重要なファイルが変更されている場合は、悪意のある活動を確認するために、コンテナからダウンロードできます。
```bash
docker cp wordpress:/etc/shadow.
```
新しいコンテナを実行してそこからファイルを抽出することで、**元のものと比較**することもできます：
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
**不審なファイルが追加されたことがわかった場合は、container にアクセスして確認できます:**
```bash
docker exec -it wordpress bash
```
## イメージの変更

export された docker image（おそらく `.tar` 形式）が与えられた場合、[**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) を使用して**変更内容の概要を抽出**できます：
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
その後、イメージを **decompress** し、**blobs** にアクセスして、変更履歴で見つけた可能性のある不審なファイルを検索できます。
```bash
tar -xf image.tar
```
### Basic Analysis

以下を実行して image から**基本情報**を取得できます：
```bash
docker inspect <image>
```
また、以下を使って**変更履歴**の概要も取得できます：
```bash
docker history --no-trunc <image>
```
**image から dockerfile を生成することもできます**:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Docker images 内で追加または変更されたファイルを見つけるには、[**dive**](https://github.com/wagoodman/dive)（[**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0) から download）utility も使用できます。
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
これにより、**docker images の各 blob を移動して**、どのファイルが変更または追加されたかを確認できます。**Red** は追加、**yellow** は変更を意味します。**tab** で別のビューに移動し、**space** でフォルダを折りたたんだり展開したりできます。

die では、image の各 stage の内容にアクセスできません。アクセスするには、**各 layer を decompress してアクセスする**必要があります。\
image を decompress したディレクトリから、次のコマンドを実行すると、image のすべての layer を decompress できます。
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## メモリからのCredentials

ホスト内で docker container を実行すると、ホストから `ps -ef` を実行するだけで、**container 内で実行中のプロセスを確認できる**ことに注意してください。

したがって、（root として）ホストからプロセスの**メモリをダンプ**し、[**次の例のように**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory)**Credentials**を検索できます。

{{#include ../../banners/hacktricks-training.md}}
