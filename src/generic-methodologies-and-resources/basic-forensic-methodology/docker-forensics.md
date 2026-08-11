# Dockerフォレンジック

{{#include ../../banners/hacktricks-training.md}}

## Containerの変更

一部のdocker containerが侵害された疑いがあります：
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
この container の **filesystem に、作成後に加えられた変更を簡単に見つけられます**。<sup>[[1]](#references)</sup>
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
前のコマンドでは、**C** は **Changed**、**A** は **Added** を意味します。<sup>[[1]](#references)</sup>\
`/etc/shadow` のような興味深いファイルが変更されている場合は、悪意のある活動を確認するため、次のコマンドで container からダウンロードできます。<sup>[[2]](#references)</sup>
```bash
docker cp wordpress:/etc/shadow shadow
```
**新しいコンテナを実行してそこからファイルを抽出し、元のものと比較することもできます**。<sup>[[2]](#references)[[3]](#references)</sup>
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
**不審なファイルが追加された**ことがわかった場合は、container にアクセスして確認できます：<sup>[[4]](#references)</sup>
```bash
docker exec -it wordpress bash
```
## Images modifications

エクスポートされた Docker image（おそらく `.tar` 形式）が与えられた場合、[**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) を使用して**変更内容の概要を抽出**できます。<sup>[[5]](#references)[[6]](#references)</sup>
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
その後、イメージを**decompress**して**blobs**にアクセスし、変更履歴で見つかった可能性のある不審なファイルを検索できます:<sup>[[7]](#references)</sup>
```bash
tar -xf image.tar
```
### 基本分析

次を実行すると、image から**基本情報**を取得できます:<sup>[[8]](#references)</sup>
```bash
docker inspect <image>
```
以下を使って**変更履歴**の概要も取得できます:<sup>[[9]](#references)</sup>
```bash
docker history --no-trunc <image>
```
You can also generate a **dockerfile from an image** with:<sup>[[10]](#references)</sup>
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers
```
### Dive

Docker image 内の追加・変更されたファイルを見つけるには、[**dive**](https://github.com/wagoodman/dive)（[**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0) からダウンロード）ユーティリティも使用できます:<sup>[[11]](#references)[[12]](#references)</sup>

dive で image tag を開く前に、保存した archive を Docker に load します:<sup>[[11]](#references)[[13]](#references)</sup>
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
これにより、**docker images のさまざまな blob を移動し**、どのファイルが変更、追加、削除されたかを確認できます。**tab** を使用して別のビューに移動し、**space** を使用してフォルダーを折りたたんだり展開したりします。<sup>[[11]](#references)</sup>

dive では、image のさまざまな stage のコンテンツにアクセスできません。これを行うには、**各 layer を解凍してアクセスする**必要があります。\
image のすべての layer は、image を解凍したディレクトリから次のコマンドを実行して解凍できます。
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## メモリからの認証情報

Linux では、ホストの祖先 PID namespace からコンテナの子 PID namespace 内のプロセスを参照できるため、`ps -ef` などのホスト上のプロセス一覧にそれらのプロセスが表示されることがあります。<sup>[[14]](#references)</sup>

ホストの認証情報、capabilities、LSM/ptrace ポリシーによって許可されている場合、適切な権限を持つホストの調査担当者は、**プロセスメモリをダンプ**し、[**次の例のように**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory) **認証情報**を検索できます。<sup>[[15]](#references)</sup>

## References

- [1] [Docker コンテナの差分](https://docs.docker.com/reference/cli/docker/container/diff/)
- [2] [Docker コンテナのコピー](https://docs.docker.com/reference/cli/docker/container/cp/)
- [3] [Docker コンテナの実行](https://docs.docker.com/reference/cli/docker/container/run)
- [4] [Docker コンテナでのコマンド実行](https://docs.docker.com/reference/cli/docker/container/exec)
- [5] [GoogleContainerTools/container-diff](https://github.com/GoogleContainerTools/container-diff)
- [6] [container-diff analyzer の定義](https://github.com/GoogleContainerTools/container-diff/blob/master/differs/differs.go)
- [7] [Docker image の保存](https://docs.docker.com/reference/cli/docker/image/save/)
- [8] [Docker image の検査](https://docs.docker.com/reference/cli/docker/image/inspect/)
- [9] [Docker image の履歴](https://docs.docker.com/reference/cli/docker/image/history/)
- [10] [alpine-docker/dfimage](https://github.com/alpine-docker/dfimage)
- [11] [Dive v0.10.0 README](https://github.com/wagoodman/dive/blob/v0.10.0/README.md)
- [12] [Dive v0.10.0 release](https://github.com/wagoodman/dive/releases/tag/v0.10.0)
- [13] [Docker image の読み込み](https://docs.docker.com/reference/cli/docker/image/load/)
- [14] [pid_namespaces(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
- [15] [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html)
{{#include ../../banners/hacktricks-training.md}}
