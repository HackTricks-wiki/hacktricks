# Dockerフォレンジック

## コンテナの変更

一部のDockerコンテナが侵害された疑いがあります：
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
このコンテナのファイルシステムに作成後に加えられた変更は、次の方法で簡単に**確認できます**:<sup>[[1]](#references)</sup>
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
直前のコマンドでは、**C** は **Changed（変更）**、**A** は **Added（追加）** を意味します。<sup>[[1]](#references)</sup>\
`/etc/shadow` のような興味深いファイルが変更されていることに気付いた場合は、以下を使用してコンテナからダウンロードし、悪意のある活動がないか確認できます。<sup>[[2]](#references)</sup>
```bash
docker cp wordpress:/etc/shadow shadow
```
また、**新しい container を実行してそこからファイルを抽出することで、元のものと比較することもできます**：<sup>[[2]](#references)[[3]](#references)</sup>
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
**不審なファイルが追加された**ことがわかった場合は、container にアクセスして確認できます。<sup>[[4]](#references)</sup>
```bash
docker exec -it wordpress bash
```
## 画像の変更

エクスポートされた docker image（おそらく `.tar` 形式）がある場合は、[**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) を使用して、**変更内容の概要を抽出**できます。<sup>[[5]](#references)[[6]](#references)</sup>
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
その後、イメージを**展開**して**blobs にアクセス**し、変更履歴で見つかった可能性のある疑わしいファイルを検索できます。<sup>[[7]](#references)</sup>
```bash
tar -xf image.tar
```
### Basic Analysis

イメージに対して以下を実行すると、**基本情報**を取得できます：<sup>[[8]](#references)</sup>
```bash
docker inspect <image>
```
次の方法で**変更履歴**の概要も取得できます：<sup>[[9]](#references)</sup>
```bash
docker history --no-trunc <image>
```
**imageからdockerfileも生成できます**:<sup>[[10]](#references)</sup>
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers
```
### Dive

docker images 内で追加・変更されたファイルを見つけるには、[**dive**](https://github.com/wagoodman/dive)（[**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0) からダウンロード）ユーティリティも使用できます:<sup>[[11]](#references)[[12]](#references)</sup>

dive で image tag を開く前に、保存した archive を Docker にロードします:<sup>[[11]](#references)[[13]](#references)</sup>
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
これにより、**docker images のさまざまな blob 内を移動**し、どのファイルが変更、追加、削除されたかを確認できます。他のビューに移動するには **tab** を使用し、フォルダーを折りたたむ、または展開するには **space** を使用します。<sup>[[11]](#references)</sup>

dive では、image の各ステージのコンテンツにアクセスできません。これを行うには、**各 layer を decompress してアクセスする**必要があります。\
image を decompress したディレクトリで次を実行すると、image のすべての layer を decompress できます:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## メモリから取得した認証情報

Linuxでは、ホストの祖先PID namespaceからコンテナの子PID namespace内のプロセスを参照できるため、`ps -ef`などのホスト上のプロセス一覧にそれらを表示できます。<sup>[[14]](#references)</sup>

ホストの認証情報、capabilities、およびLSM/ptraceポリシーによって許可されている場合、十分な権限を持つホストの調査担当者は**プロセスメモリをダンプ**し、[**次の例と同様に**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory) **認証情報**を検索できます。<sup>[[15]](#references)</sup>

## References

- [1] [Docker container diff](https://docs.docker.com/reference/cli/docker/container/diff/)
- [2] [Docker container cp](https://docs.docker.com/reference/cli/docker/container/cp/)
- [3] [Docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [4] [Docker container exec](https://docs.docker.com/reference/cli/docker/container/exec)
- [5] [GoogleContainerTools/container-diff](https://github.com/GoogleContainerTools/container-diff)
- [6] [container-diffアナライザー定義](https://github.com/GoogleContainerTools/container-diff/blob/master/differs/differs.go)
- [7] [Docker image save](https://docs.docker.com/reference/cli/docker/image/save/)
- [8] [Docker image inspect](https://docs.docker.com/reference/cli/docker/image/inspect/)
- [9] [Docker image history](https://docs.docker.com/reference/cli/docker/image/history/)
- [10] [alpine-docker/dfimage](https://github.com/alpine-docker/dfimage)
- [11] [Dive v0.10.0 README](https://github.com/wagoodman/dive/blob/v0.10.0/README.md)
- [12] [Dive v0.10.0リリース](https://github.com/wagoodman/dive/releases/tag/v0.10.0)
- [13] [Docker image load](https://docs.docker.com/reference/cli/docker/image/load/)
- [14] [pid_namespaces(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
- [15] [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html)
{{#include ../../banners/hacktricks-training.md}}
