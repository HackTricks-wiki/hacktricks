# Runtajmi kontejnera, engine-i, builder-i i sandboxi

{{#include ../../../banners/hacktricks-training.md}}

Jedan od najvećih izvora zabune u bezbednosti kontejnera je što se nekoliko potpuno različitih komponenti često sabija u istu reč. "Docker" može da se odnosi na image format, CLI, daemon, build sistem, runtime stack, ili jednostavno na ideju kontejnera uopšte. Za bezbednosni rad ta dvosmislenost je problem, jer različiti slojevi nose odgovornost za različite zaštite. Breakout izazvan lošim bind mount-om nije isto što i breakout izazvan niskonivojskim runtime bagom, i nijedan od ta dva nije isto što i greška u cluster politici u Kubernetes-u.

Ova stranica razdvaja ekosistem po ulozi tako da ostatak sekcije može precizno govoriti o tome gde zaštita ili slabost zapravo žive.

## OCI kao zajednički jezik

Moderni Linux container stack-ovi često međusobno interoperabilno rade zato što govore skup OCI specifikacija. **OCI Image Specification** opisuje kako se images i layer-i predstavljaju. **OCI Runtime Specification** opisuje kako runtime treba da pokrene proces, uključujući namespaces, mounts, cgroups i security podešavanja. **OCI Distribution Specification** standardizuje kako registriji izlažu sadržaj.

Ovo je važno jer objašnjava zašto image izgrađen jednim alatom često može biti pokrenut drugim, i zašto nekoliko engine-a može deliti isti niskonivojski runtime. Takođe objašnjava zašto se bezbednosno ponašanje može sličiti između različitih proizvoda: mnogi od njih konstrušu istu OCI runtime konfiguraciju i prosleđuju je istom malom skupu runtim-eva.

## Niskonivojski OCI runtim-i

Niskonivojski runtime je komponenta najbliža granici sa kernel-om. To je deo koji zapravo kreira namespaces, piše cgroup podešavanja, primenjuje capabilities i seccomp filtere, i na kraju `execve()`-uje container proces. Kada ljudi raspravljaju o "izolaciji kontejnera" na mehaničkom nivou, obično misle na ovaj sloj, čak i ako to ne kažu eksplicitno.

### `runc`

`runc` je referentni OCI runtime i ostaje najpoznatija implementacija. Široko se koristi ispod Docker-a, containerd-a i u mnogim Kubernetes deployment-ima. Mnogo javnih istraživanja i materijala za eksploataciju cilja `runc`-style okruženja jednostavno zato što su česta i zato što `runc` definiše osnovu koju mnogi ljudi zamišljaju kada pomisle na Linux container. Razumevanje `runc`-a stoga daje snažan mentalni model za klasičnu izolaciju kontejnera.

### `crun`

`crun` je još jedan OCI runtime, napisan u C i široko korišćen u modernim Podman okruženjima. Često je hvaljen zbog dobre podrške za cgroup v2, dobrog rootless ergonomskog iskustva i manjeg overhead-a. Sa bezbednosne tačke gledišta, važna stvar nije što je napisan u drugačijem jeziku, već što i dalje igra istu ulogu: to je komponenta koja pretvara OCI konfiguraciju u pokrenuto stablo procesa pod kernel-om. Rootless Podman workflow često deluje bezbednije ne zato što `crun` magično rešava sve, već zato što celokupan stack oko njega teži da više koristi user namespaces i princip najmanjih privilegija.

### `runsc` iz gVisor-a

`runsc` je runtime koji koristi gVisor. Ovde se granica značno menja. Umesto da većinu syscall-ova prosleđuje direktno host kernel-u na uobičajen način, gVisor umeće userspace kernel sloj koji emulira ili posreduje u velikom delu Linux interfejsa. Rezultat nije normalan `runc` container sa nekoliko dodatnih flag-ova; to je drugačiji dizajn sandboksa čija je svrha smanjiti attack surface host-kernel-a. Kompatibilnost i performanse su deo tog dizajna, pa okruženja koja koriste `runsc` treba dokumentovati drugačije od normalnih OCI runtime okruženja.

### `kata-runtime`

Kata Containers pomeraju granicu dalje tako što pokreću workload unutar laganog virtuelnog mašinskog okruženja. Administrativno, ovo i dalje može izgledati kao deployment kontejnera, i orkestracioni slojevi mogu se ponašati kao da je tako, ali osnovna granica izolacije je bliža virtualizaciji nego klasičnom host-kernel shared container-u. To čini Kata korisnim kada je potrebna jača izolacija tenanta bez napuštanja container-centric workflow-a.

## Engine-i i menadžeri kontejnera

Ako je niskonivojski runtime komponenta koja priča direktno sa kernel-om, engine ili manager je komponenta sa kojom korisnici i operateri obično komuniciraju. On rukuje image pull-ovima, metadata-om, log-ovima, mrežama, volume-ima, lifecycle operacijama i izlaganjem API-ja. Ovaj sloj je izuzetno važan jer se mnogo realnih kompromisa dešava ovde: pristup runtime socket-u ili daemon API-ju može biti ekvivalentan kompromitovanju host-a čak i ako je sam niskonivojski runtime potpuno zdrav.

### Docker Engine

Docker Engine je najprepoznatljivija container platforma za developere i jedan od razloga zašto je vokabular oko kontejnera postao toliko Docker-shaped. Tipičan put je `docker` CLI do `dockerd`, koji zatim koordinira nižerazredne komponente poput `containerd` i OCI runtime-a. Istorijski, Docker deploy-ovi su često bili **rootful**, i pristup Docker socket-u je stoga bio vrlo moćan primitiv. Zato toliko praktičnog materijala za privilege-escalation fokusira se na `docker.sock`: ako proces može da zamoli `dockerd` da kreira privilegovani container, mount-uje host putanje ili pridruži host namespaces, možda mu neće biti potreban kernel exploit uopšte.

### Podman

Podman je dizajniran oko modela bez daemona. Operativno, to pomaže da se podvuče ideja da su container-i samo procesi upravljani standardnim Linux mehanizmima umesto jednim dugotrajnim privilegovanim daemon-om. Podman takođe ima mnogo snažniju **rootless** priču nego klasični Docker deployment-i koje su mnogi prvo naučili. To ne čini Podman automatski bezbednim, ali značajno menja podrazumevani rizik, posebno u kombinaciji sa user namespaces, SELinux-om i `crun`.

### containerd

containerd je osnovna komponenta za upravljanje runtime-om u mnogim modernim stack-ovima. Koristi se ispod Docker-a i takođe je jedan od dominantnih Kubernetes runtime backend-ova. Izlaže moćne API-je, upravlja image-ima i snapshot-ima, i delegira finalno kreiranje procesa niskonivojskom runtime-u. Diskusije o bezbednosti oko containerd-a treba da naglase da pristup containerd socket-u ili `ctr`/`nerdctl` funkcionalnosti može biti jednako opasan kao pristup Docker-ovom API-ju, čak i ako interfejs i workflow deluju manje "developer-friendly".

### CRI-O

CRI-O je fokusiraniji od Docker Engine-a. Umesto da bude general-purpose developer platforma, izgrađen je oko čiste implementacije Kubernetes Container Runtime Interface-a. To ga čini posebno čestim u Kubernetes distribucijama i SELinux-heavy ekosistemima kao što je OpenShift. Sa bezbednosne perspektive, taj uži opseg je koristan jer smanjuje konceptualni nered: CRI-O je mnogo više deo sloja "pokretanje container-a za Kubernetes" nego platforma za sve i svašta.

### Incus, LXD i LXC

Incus/LXD/LXC sistemi vredi odvojiti od Docker-style application container-a jer se često koriste kao **system containers**. System container se obično očekuje da izgleda više kao lagana mašina sa punijim userspace-om, dugotrajnim servisima, bogatijom izloženošću uređaja i opsežnijom integracijom sa host-om. Mehanizmi izolacije su i dalje kernel primitive, ali operativna očekivanja su drugačija. Kao rezultat, pogrešna podešavanja ovde često izgledaju manje kao "loši app-container default-i" i više kao greške u laganoj virtualizaciji ili delegiranju host-a.

### systemd-nspawn

systemd-nspawn zauzima interesantno mesto jer je systemd-native i veoma koristan za testiranje, debugging i pokretanje OS-like okruženja. Nije dominantni cloud-native produkcijski runtime, ali se pojavljuje dovoljno često u lab-ovima i distro-orijentisanim okruženjima da zaslužuje pominjanje. Za bezbednosnu analizu, to je još jedan podsetnik da koncept "container-a" obuhvata više ekosistema i operativnih stilova.

### Apptainer / Singularity

Apptainer (ranije Singularity) je čest u istraživačkim i HPC okruženjima. Njegove pretpostavke o poverenju, korisnički workflow i model izvršavanja razlikuju se na važne načine od Docker/Kubernetes-centric stack-ova. Konkretno, ova okruženja često jako vode računa o tome da korisnicima dozvole da pokreću paketirane workload-e bez davanja širokih privilegovanih moći za upravljanje container-ima. Ako pregledač pretpostavi da je svako container okruženje u suštini "Docker na serveru", pogrešno će razumeti takve deploy-ove.

## Build-time alati

Mnoge bezbednosne rasprave govore samo o run time-u, ali build-time alati takođe znače jer određuju sadržaj image-a, izlaganje build tajni i koliko se trusted kontekst ugrađuje u finalni artifact.

**BuildKit** i `docker buildx` su moderni build backend-i koji podržavaju funkcije kao što su caching, secret mounting, SSH forwarding i multi-platform builds. To su korisne funkcije, ali sa bezbednosne perspektive one takođe stvaraju mesta gde se secrets mogu leak-ovati u image layer-e ili gde preširok build kontekst može izložiti fajlove koji nikada nisu trebali biti uključeni. **Buildah** igra sličnu ulogu u OCI-native ekosistemima, posebno oko Podman-a, dok se **Kaniko** često koristi u CI okruženjima koja ne žele da daju privilegovani Docker daemon build pipeline-u.

Ključna lekcija je da su kreiranje image-a i izvršavanje image-a različite faze, ali slab build pipeline može stvoriti slab runtime posture mnogo pre nego što se container pokrene.

## Orkestracija je drugi sloj, ne runtime

Kubernetes ne bi trebalo mentalno poistovećivati sa samim runtime-om. Kubernetes je orchestrator. Raspoređuje Pod-ove, čuva desired state i izražava security politiku kroz konfiguraciju workload-a. kubelet zatim priča sa CRI implementacijom kao što je containerd ili CRI-O, koji zatim poziva niskonivojski runtime kao što su `runc`, `crun`, `runsc` ili `kata-runtime`.

Ovo razdvajanje je važno jer mnogi pogrešno pripisuju zaštitu "Kubernetes-u" kada je ona zaista sprovedena od strane node runtime-a, ili krive "containerd defaults" za ponašanje koje je došlo iz Pod spec-a. U praksi, finalna bezbednosna postura je kompozicija: orchestrator traži nešto, runtime stack to prevede, i kernel konačno to primenjuje.

## Zašto je identifikacija runtime-a važna prilikom procene

Ako rano identifikujete engine i runtime, mnogo kasnijih zapažanja postaju lakša za interpretaciju. Rootless Podman container sugeriše da user namespaces verovatno igraju ulogu. Docker socket mount-ovan u workload sugeriše da je API-driven privilege escalation realističan put. CRI-O/OpenShift node treba odmah da vam navede SELinux label-e i restricted workload politiku. gVisor ili Kata okruženje treba da vas učini opreznijim u pretpostavci da će klasični `runc` breakout PoC raditi isto.

Zato je jedan od prvih koraka u proceni kontejnera uvek da odgovorite na dva jednostavna pitanja: **koja komponenta upravlja container-om** i **koji runtime je zapravo pokrenuo proces**. Kada su ti odgovori jasni, ostatak okruženja obično postaje mnogo lakše za razumevanje.

## Runtime ranjivosti

Ne izlazi svaki container escape iz greške operatera. Ponekad je runtime sam ranjiv. To je važno jer workload može biti pokrenut sa konfiguracijom koja deluje pažljivo, a ipak biti izložen kroz niskonivojski runtime flaw.

Klasičan primer je **CVE-2019-5736** u `runc`, gde maliciozan container može prepisati host `runc` binarni fajl i zatim čekati kasniji `docker exec` ili sličan runtime poziv da okine kod pod kontrolom napadača. Put eksploatacije je veoma drugačiji od prostog bind-mount ili capability propusta jer zloupotrebljava način na koji runtime ponovo ulazi u prostor procesa kontejnera tokom exec handlanja.

Minimalni tok za reprodukciju iz perspektive red-team-a je:
```bash
go build main.go
./main
```
Zatim, sa hosta:
```bash
docker exec -it <container-name> /bin/sh
```
Glavna lekcija nije tačna istorijska implementacija exploita, već implikacija za procenu: ako je verzija runtime-a ranjiva, obična in-container izvršavanja koda mogu biti dovoljna da kompromituju host čak i kada vidljiva container konfiguracija ne deluje očigledno slaba.

Nedavni runtime CVE-ovi kao što su `CVE-2024-21626` u `runc`, BuildKit mount races i containerd parsing bugs pojačavaju istu poentu. Verzija runtime-a i nivo zakrpa su deo bezbednosne granice, a ne puka trivija održavanja.
