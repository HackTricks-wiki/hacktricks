# Runtimes, engine-i, builder-i i sandbox-i za kontejnere

{{#include ../../../banners/hacktricks-training.md}}

Jedan od najvećih izvora zabune u bezbednosti kontejnera je što se nekoliko potpuno različitih komponenti često svede na istu reč. "Docker" može označavati format image-a, CLI, daemon, build sistem, runtime stack, ili jednostavno ideju kontejnera uopšte. Za sigurnosni rad ta dvosmislenost predstavlja problem, jer različiti slojevi snose odgovornost za različite zaštite. Escape uzrokovan lošim bind mount-om nije isto što i escape uzrokovan niskonivouskom runtime greškom, i nijedno od toga nije isto što i greška u cluster politikama u Kubernetes-u.

Ova stranica razdvaja ekosistem po ulogama tako da ostatak sekcije može precizno govoriti o tome gde zaštita ili slabost zaista živi.

## OCI kao zajednički jezik

Moderni Linux container stack-ovi često međusobno rade zato što govore skup OCI specifikacija. OCI Image Specification opisuje kako su image-i i layere predstavljeni. OCI Runtime Specification opisuje kako runtime treba da pokrene proces, uključujući namespaces, mount-ove, cgroups i security postavke. OCI Distribution Specification standardizuje kako registriji izlažu sadržaj.

Ovo je važno jer objašnjava zašto se container image napravljen jednim alatom često može pokrenuti drugim, i zašto nekoliko engine-a može deliti isti niskonivouski runtime. Takođe objašnjava zašto sigurnosno ponašanje može izgledati slično preko različitih proizvoda: mnogi od njih konstruišu istu OCI runtime konfiguraciju i predaju je istom malom skupu runtime-a.

## Niskonivouski OCI runtime-i

Niskonivouski runtime je komponenta koja je najbliže granici kernela. To je deo koji zapravo kreira namespaces, upisuje cgroup postavke, primenjuje capabilities i seccomp filtere, i na kraju `execve()`-uje process kontejnera. Kada ljudi diskutuju o "izolaciji kontejnera" na mehaničkom nivou, to je sloj o kojem obično govore, čak i ako to ne kažu eksplicitno.

### `runc`

`runc` je referentni OCI runtime i ostaje najpoznatija implementacija. Intensivno se koristi ispod Docker, containerd i mnogih Kubernetes deploy-ova. Mnogo javnog istraživanja i materijala za eksploataciju cilja `runc`-style okruženja jednostavno zato što su česta i zato što `runc` definiše baseline koji mnogi zamišljaju kad pomisle na Linux kontejner. Razumevanje `runc`-a daje snažan mentalni model za klasičnu izolaciju kontejnera.

### `crun`

`crun` je još jedan OCI runtime, napisan u C i široko korišćen u modernim Podman okruženjima. Često se hvali zbog dobre podrške za cgroup v2, jakih rootless ergonomskih rešenja i manjeg overhead-a. Sa sigurnosnog aspekta, važno nije to što je napisan u drugom jeziku, već da i dalje igra istu ulogu: komponenta je koja prevodi OCI konfiguraciju u pokrenuto stablo procesa pod kernelom. Rootless Podman workflow često deluje sigurnije ne zato što `crun` magično sve popravi, već zato što ceo stack oko njega teži upotrebi user namespaces i principa najmanjih privilegija.

### `runsc` iz gVisor-a

`runsc` je runtime koji koristi gVisor. Ovde se granica značajno menja. Umesto da većinu syscall-ova prosleđuje host kernelu na uobičajen način, gVisor ubacuje userspace kernel sloj koji emulira ili medira velike delove Linux interfejsa. Rezultat nije normalan `runc` kontejner sa par dodatnih zastavica; to je drugačiji dizajn sandboksa čija je svrha smanjiti attack surface host kernela. Kompromisi između kompatibilnosti i performansi su deo tog dizajna, pa okruženja koja koriste `runsc` treba dokumentovati drugačije nego normalna OCI runtime okruženja.

### `kata-runtime`

Kata Containers pomeraju granicu dalje tako što pokreću workload unutar laganog virtuelnog mašinskog okruženja. Administrativno, ovo može i dalje izgledati kao deploy kontejnera i orkestracioni slojevi mogu se tako i odnositi prema tome, ali osnovna izolaciona granica je bliža virtualizaciji nego klasičnom kontejneru koji deli host kernel. To čini Kata korisnim kad se želi jača izolacija tenant-a bez napuštanja kontejner-centričnih workflow-a.

## Engine-i i container menadžeri

Ako je niskonivouski runtime komponenta koja direktno razgovara sa kernelom, engine ili manager je komponenta sa kojom korisnici i operatori obično interaguju. On rukuje pull-ovanjem image-a, metadata-om, logovima, mrežama, volumenima, lifecycle operacijama i izlaganjem API-ja. Ovaj sloj je izuzetno važan jer se mnogo realnih kompromitacija dešava ovde: pristup runtime socket-u ili daemon API-ju može biti ekvivalent kompromitaciji hosta čak i ako je niskonivouski runtime sam po sebi potpuno zdrav.

### Docker Engine

Docker Engine je najprepoznatljivija container platforma za developere i jedan od razloga zašto je vokabular kontejnera postao toliko Docker-oblikovan. Tipičan put je `docker` CLI prema `dockerd`, koji zatim koordinira nižerazredne komponente poput `containerd` i OCI runtime-a. Istorijski, Docker deploy-ovi su često bili **rootful**, pa je pristup Docker socket-u bio veoma moćan primitiv. Zato toliko praktičnog materijala za privilege-escalation fokusira `docker.sock`: ako proces može tražiti od `dockerd` da kreira privileged container, mount-uje host puteve ili se pridruži host namespaces, možda mu ne treba ni kernel exploit.

### Podman

Podman je dizajniran oko modela bez daemona. Operativno, ovo pomaže da se naglasi ideja da su kontejneri samo procesi koji se upravljaju kroz standardne Linux mehanizme, a ne kroz jedan dugačak privilegovani daemon. Podman takođe ima mnogo jaču rootless priču nego klasični Docker deploy-ovi koje su mnogi prvo upoznali. To ne čini Podman automatski bezbednim, ali značajno menja podrazumevani rizik, naročito u kombinaciji sa user namespaces, SELinux i `crun`.

### containerd

containerd je osnovna komponenta za upravljanje runtime-om u mnogim modernim stack-ovima. Koristi se ispod Docker-a i takođe je jedan od dominantnih Kubernetes runtime backend-a. Izlaže moćne API-je, upravlja image-ima i snapshot-ovima, i delegira konačno kreiranje procesa niskonivouskom runtime-u. Sigurnosne diskusije oko containerd-a treba da naglase da pristup containerd socket-u ili `ctr`/`nerdctl` funkcionalnosti može biti jednako opasan kao i pristup Docker-ovom API-ju, čak i ako interfejs i workflow deluju manje "developer-friendly".

### CRI-O

CRI-O je fokusiranije rešenje nego Docker Engine. Umesto da bude platforma opšte namene za developere, on je izgrađen oko čistog implementiranja Kubernetes Container Runtime Interface-a. To ga čini posebno čestim u Kubernetes distribucijama i SELinux-heavy ekosistemima kao što je OpenShift. Sa sigurnosnog aspekta, taj uži fokus je koristan jer smanjuje konceptualni šum: CRI-O je mnogo više deo sloja "pokreni kontejnere za Kubernetes" nego platforma za sve.

### Incus, LXD i LXC

Incus/LXD/LXC sistemi vredi odvojiti od Docker-stila application kontejnera jer se često koriste kao system containers. System container se obično očekuje da izgleda više kao lagana mašina sa potpunijim userspace-om, dugotrajnim servisima, bogatijom izloženošću uređaja i većom integracijom sa host-om. Mehanizmi izolacije su i dalje kernel primitiva, ali operativna očekivanja su drugačija. Kao rezultat, pogrešne konfiguracije ovde često izgledaju manje kao "loši app-container default-i" a više kao greške u laganoj virtualizaciji ili delegaciji host-a.

### systemd-nspawn

systemd-nspawn zauzima zanimljivo mesto jer je systemd-native i vrlo koristan za testiranje, debugovanje i pokretanje OS-like okruženja. Nije dominantan cloud-native produkcioni runtime, ali se pojavljuje dovoljno često u labovima i distro-orijentisanim okruženjima da zaslužuje pomen. Za sigurnosnu analizu, to je još jedno podsećanje da koncept "kontejner" obuhvata više ekosistema i operativnih stilova.

### Apptainer / Singularity

Apptainer (ranije Singularity) je čest u istraživačkim i HPC okruženjima. Njegova trust pretpostavka, korisnički workflow i model izvršenja razlikuju se bitno od Docker/Kubernetes-centričnih stack-ova. Konkretno, ova okruženja često jako vode računa da korisnicima omoguće pokretanje paketiranih workload-a bez davanja širokih privilegovanja za upravljanje kontejnerima. Ako recenzent pretpostavi da je svako container okruženje u suštini "Docker na serveru", pogrešno će razumeti ove deploy-e.

## Alati za vreme build-a

Mnoge sigurnosne diskusije govore samo o runtime-u, ali alati koji se koriste pri build-u takođe su važni jer određuju sadržaj image-a, izlaganje build secret-a i koliko pouzdanog konteksta se ugrađuje u finalni artifact.

BuildKit i `docker buildx` su moderni build backend-i koji podržavaju funkcije poput caching-a, secret mount-ovanja, SSH forwarding-a i multi-platform build-ova. To su korisne funkcije, ali sa sigurnosne tačke gledišta one takođe stvaraju mesta gde se secrets mogu leak-ovati u image layer-e ili gde preširok build kontekst može izložiti fajlove koji nikada nisu trebali biti uključeni. Buildah igra sličnu ulogu u OCI-native ekosistemima, naročito oko Podman-a, dok se Kaniko često koristi u CI okruženjima koja ne žele da daju privilegovani Docker daemon build pipeline-u.

Ključna lekcija je da su kreiranje image-a i izvršenje image-a različite faze, ali slab build pipeline može stvoriti slab runtime položaj mnogo pre nego što se kontejner pokrene.

## Orkestracija je drugi sloj, ne runtime

Kubernetes se ne bi trebao mentalno izjednačavati sa samim runtime-om. Kubernetes je orchestrator. On zakazuje Pod-ove, čuva desired state i izražava security politiku kroz konfiguraciju workload-a. Kubelet onda razgovara sa CRI implementacijom kao što su containerd ili CRI-O, koji zauzvrat pozivaju niskonivouski runtime kao što su `runc`, `crun`, `runsc` ili `kata-runtime`.

Ovo razdvajanje je važno jer mnogi pogrešno pripisuju zaštitu "Kubernetes-u" kada je ona zaista sprovedena od strane node runtime-a, ili krive "containerd defaults" za ponašanje koje je poteklo iz Pod spec-a. U praksi, konačni sigurnosni položaj je kompozit: orchestrator traži nešto, runtime stack to prevodi, i kernel na kraju to sprovodi.

## Zašto identifikacija runtime-a znači tokom procene

Ako rano identifikujete engine i runtime, mnoga kasnija zapažanja postaju lakša za interpretaciju. Rootless Podman container sugeriše da su user namespaces verovatno deo priče. Docker socket mount-ovan u workload sugeriše da je API-driven privilege escalation realan put. CRI-O/OpenShift node treba odmah da vas natera da razmišljate o SELinux labelama i restricted workload politici. gVisor ili Kata okruženje treba da vas natera da budete oprezniji u pretpostavci da će klasičan `runc` breakout PoC ponašati isto.

Zato je jedan od prvih koraka u proceni kontejnera uvek odgovaranje na dva jednostavna pitanja: koji komponenta upravlja kontejnerom i koji runtime je zapravo pokrenuo proces. Kada su ta pitanja jasna, ostatak okruženja obično postaje mnogo lakše za razumevanje.

## Runtime ranjivosti

Ne dolazi svaki container escape iz operativnih grešaka. Ponekad je runtime sam ranjiv. Ovo je važno jer workload može da radi sa konfiguracijom koja izgleda pažljivo i ipak biti izložen kroz niskonivousku runtime manu.

Klasičan primer je CVE-2019-5736 u `runc`, gde zlonamerni container može prepisati host `runc` binarni fajl i onda sačekati kasniji `docker exec` ili sličan runtime poziv da okine kod pod kontrolom napadača. Put eksploatacije je veoma različit od jednostavnog bind-mount ili greške u capability-ima zato što zloupotrebljava način kako runtime ponovo ulazi u prostor procesa kontejnera tokom obrade exec-a.

Minimalni reprodukcioni workflow iz red-team perspektive je:
```bash
go build main.go
./main
```
Zatim, sa hosta:
```bash
docker exec -it <container-name> /bin/sh
```
Ključna lekcija nije tačna istorijska implementacija exploita, već implikacija za procenu: ako je verzija runtime-a ranjiva, obična izvršna instanca koda unutar containera može biti dovoljna da kompromituje host čak i kada vidljiva konfiguracija containera ne izgleda očigledno slabo.

Nedavni runtime CVE-ovi poput `CVE-2024-21626` u `runc`, BuildKit mount races i bagovi u parsiranju containerd-a potvrđuju istu poentu. Verzija runtime-a i nivo zakrpe čine deo bezbednosne granice, a nisu samo trivijalnosti održavanja.
{{#include ../../../banners/hacktricks-training.md}}
