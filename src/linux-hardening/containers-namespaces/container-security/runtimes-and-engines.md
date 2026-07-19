# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Jedan od najvećih izvora zabune u container security jeste to što se nekoliko potpuno različitih komponenti često svodi na istu reč. „Docker“ može označavati format image-a, CLI, daemon, build sistem, runtime stack ili jednostavno opštu ideju containera. Za security rad to predstavlja problem, jer su različiti slojevi odgovorni za različite zaštite. Breakout izazvan lošim bind mount-om nije isto što i breakout izazvan greškom u low-level runtime-u, a nijedno od toga nije isto što i greška u cluster policy-ju u Kubernetesu.

Ova stranica razdvaja ecosystem prema ulogama, kako bi ostatak sekcije mogao precizno da govori o tome gde se određena zaštita ili slabost zapravo nalazi.

## OCI As The Common Language

Moderni Linux container stack-ovi često međusobno sarađuju zato što koriste skup OCI specifikacija. **OCI Image Specification** opisuje kako se image-i i layer-i predstavljaju. **OCI Runtime Specification** opisuje kako runtime treba da pokrene proces, uključujući namespace-ove, mount-ove, cgroup-ove i security podešavanja. **OCI Distribution Specification** standardizuje način na koji registry-ji izlažu sadržaj.

Ovo je važno zato što objašnjava zašto image napravljen jednim tool-om često može da se pokrene drugim i zašto više engine-a može da deli isti low-level runtime. Takođe objašnjava zašto security ponašanje može izgledati slično u različitim proizvodima: mnogi od njih konstruišu istu OCI runtime konfiguraciju i prosleđuju je istom malom skupu runtime-a.

## Low-Level OCI Runtimes

Low-level runtime je komponenta koja se nalazi najbliže granici sa kernelom. To je deo koji zaista kreira namespace-ove, upisuje cgroup podešavanja, primenjuje capabilities i seccomp filtere i na kraju poziva `execve()` nad container procesom. Kada ljudi govore o „container isolation“ na mehaničkom nivou, obično misle upravo na ovaj sloj, čak i kada to ne kažu eksplicitno.

### `runc`

`runc` je referentni OCI runtime i i dalje najpoznatija implementacija. U velikoj meri se koristi ispod Docker-a, containerd-a i mnogih Kubernetes deployment-a. Veliki deo javnih istraživanja i exploitation materijala cilja `runc`-style okruženja jednostavno zato što su česta i zato što `runc` definiše osnovu na koju mnogi pomisle kada zamišljaju Linux container. Razumevanje `runc`-a zato čitaocu pruža dobar mentalni model za klasični container isolation.

### `crun`

`crun` je još jedan OCI runtime, napisan u C-u i široko korišćen u modernim Podman okruženjima. Često se hvali zbog dobre podrške za cgroup v2, kvalitetne rootless ergonomije i manjeg overhead-a. Iz security perspektive, važno nije to što je napisan drugim jezikom, već to što i dalje ima istu ulogu: to je komponenta koja OCI konfiguraciju pretvara u pokrenuto stablo procesa pod kernelom. Rootless Podman workflow često deluje bezbednije ne zato što `crun` magično rešava sve, već zato što ceo stack oko njega obično snažnije koristi user namespace-ove i least privilege.

### `runsc` From gVisor

`runsc` je runtime koji koristi gVisor. Ovde se granica značajno menja. Umesto da većinu syscall-ova na uobičajen način direktno prosleđuje host kernelu, gVisor ubacuje userspace kernel layer koji emulira ili posreduje velikim delovima Linux interface-a. Rezultat nije običan `runc` container sa nekoliko dodatnih flag-ova; to je drugačiji sandbox dizajn čija je svrha smanjenje attack surface-a host kernela. Tradeoff-i u kompatibilnosti i performansama deo su tog dizajna, pa okruženja koja koriste `runsc` treba dokumentovati drugačije od standardnih OCI runtime okruženja.

### `kata-runtime`

Kata Containers dodatno pomeraju granicu tako što workload pokreću unutar lightweight virtual machine-a. Administrativno, ovo i dalje može izgledati kao container deployment, a orchestration layer-i ga i dalje mogu tretirati kao takav, ali je underlying isolation boundary bliži virtualization-u nego klasičnom container-u koji deli host kernel. Zbog toga je Kata koristan kada je potrebna jača tenant isolation bez napuštanja container-centric workflow-a.

## Engines And Container Managers

Ako je low-level runtime komponenta koja direktno komunicira sa kernelom, engine ili manager je komponenta sa kojom korisnici i operatori obično rade. On upravlja image pull-ovima, metadata-om, logovima, network-ovima, volume-ima, lifecycle operacijama i API exposure-om. Ovaj sloj je izuzetno važan zato što se mnogi kompromisi u realnim okruženjima dešavaju upravo ovde: pristup runtime socket-u ili daemon API-ju može biti ekvivalent kompromitovanju hosta čak i kada je sam low-level runtime potpuno ispravan.

### Docker Engine

Docker Engine je najprepoznatljivija container platforma za developere i jedan od razloga zbog kojih je container vocabulary postao toliko Docker-oblikovan. Tipičan put je od `docker` CLI-ja do `dockerd`-a, koji zatim koordinira komponente nižeg nivoa kao što su `containerd` i OCI runtime. Istorijski gledano, Docker deployment-i su često bili **rootful**, pa je pristup Docker socket-u zbog toga bio veoma moćan primitive. Zato se veliki deo praktičnog privilege-escalation materijala fokusira na `docker.sock`: ako proces može da zatraži od `dockerd`-a da kreira privileged container, mount-uje host path-ove ili se pridruži host namespace-ovima, možda mu uopšte nije potreban kernel exploit.

### Podman

Podman je projektovan oko više daemonless modela. Operativno, to pomaže u učvršćivanju ideje da su container-i samo procesi kojima se upravlja kroz standardne Linux mehanizme, a ne kroz jedan dugotrajni privileged daemon. Podman takođe ima znatno snažniju **rootless** priču od klasičnih Docker deployment-a na kojima su mnogi prvo učili. To ne čini Podman automatski bezbednim, ali značajno menja podrazumevani risk profile, naročito u kombinaciji sa user namespace-ovima, SELinux-om i `crun`-om.

### containerd

containerd je osnovna runtime management komponenta u mnogim modernim stack-ovima. Koristi se ispod Docker-a i jedan je od dominantnih Kubernetes runtime backend-a. Izlaže moćne API-je, upravlja image-ima i snapshot-ovima i delegira konačno kreiranje procesa low-level runtime-u. Security diskusije o containerd-u treba da naglase da pristup containerd socket-u ili `ctr`/`nerdctl` funkcionalnosti može biti jednako opasan kao pristup Docker API-ju, čak i ako interface i workflow deluju manje „developer friendly“.

### CRI-O

CRI-O je užeg fokusa od Docker Engine-a. Umesto da bude general-purpose developer platforma, napravljen je oko čistog implementiranja Kubernetes Container Runtime Interface-a. Zbog toga je naročito čest u Kubernetes distribucijama i SELinux-heavy ecosystem-ima kao što je OpenShift. Iz security perspektive, taj uži scope je koristan zato što smanjuje conceptual clutter: CRI-O je pre svega deo sloja „run containers for Kubernetes“, a ne everything-platforma.

### Incus, LXD, And LXC

Incus/LXD/LXC sistemi zaslužuju odvojeno razmatranje od Docker-style application container-a zato što se često koriste kao **system containers**. Od system container-a se obično očekuje da više liči na lightweight machine sa potpunijim userspace-om, dugotrajnim servisima, bogatijim device exposure-om i obimnijom host integracijom. Isolation mehanizmi i dalje predstavljaju kernel primitives, ali su operativna očekivanja drugačija. Zbog toga pogrešne konfiguracije ovde često više liče na greške u lightweight virtualization-u ili host delegation-u nego na „bad app-container defaults“.

### systemd-nspawn

systemd-nspawn zauzima zanimljivo mesto zato što je systemd-native i veoma koristan za testing, debugging i pokretanje OS-like okruženja. Nije dominantan cloud-native production runtime, ali se dovoljno često pojavljuje u labovima i distro-oriented okruženjima da zaslužuje pomen. Za security analysis, to je još jedan podsetnik da pojam „container“ obuhvata više ecosystem-a i operativnih stilova.

### Apptainer / Singularity

Apptainer (ranije Singularity) čest je u research i HPC okruženjima. Njegove trust assumptions, user workflow i execution model značajno se razlikuju od Docker/Kubernetes-centric stack-ova. Konkretno, ova okruženja često pridaju veliki značaj tome da korisnicima omoguće pokretanje packaged workload-a bez davanja širokih privileged container-management ovlašćenja. Ako reviewer pretpostavi da je svako container okruženje praktično „Docker na serveru“, ozbiljno će pogrešno razumeti ovakve deployment-e.

## Build-Time Tooling

Mnoge security diskusije govore samo o runtime-u, ali build-time tooling je takođe važan jer određuje sadržaj image-a, exposure build secret-a i količinu trusted context-a koja se ugrađuje u finalni artifact.

**BuildKit** i `docker buildx` su moderni build backend-i koji podržavaju funkcije kao što su caching, secret mounting, SSH forwarding i multi-platform build-ovi. To su korisne funkcije, ali iz security perspektive stvaraju i mesta na kojima secret-i mogu da leak-uju u image layer-e ili gde preširok build context može da izloži fajlove koji nikada nisu smeli da budu uključeni. **Buildah** ima sličnu ulogu u OCI-native ecosystem-ima, naročito oko Podman-a, dok se **Kaniko** često koristi u CI okruženjima koja ne žele da build pipeline-u dodele privileged Docker daemon.

Ključna lekcija jeste da su image creation i image execution različite faze, ali weak build pipeline može stvoriti slab runtime posture mnogo pre nego što se container pokrene.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes ne treba mentalno izjednačavati sa samim runtime-om. Kubernetes je orchestrator. On schedule-uje Pod-ove, čuva desired state i izražava security policy kroz workload konfiguraciju. Kubelet zatim komunicira sa CRI implementacijom kao što su containerd ili CRI-O, koja potom poziva low-level runtime kao što su `runc`, `crun`, `runsc` ili `kata-runtime`.

Ovo razdvajanje je važno zato što mnogi pogrešno pripisuju neku zaštitu „Kubernetesu“, iako je ona zapravo nametnuta od strane node runtime-a, ili krive „containerd defaults“ za ponašanje koje potiče iz Pod spec-a. U praksi, final security posture predstavlja kompoziciju: orchestrator nešto zahteva, runtime stack to prevodi, a kernel konačno nameće pravilo.

## Why Runtime Identification Matters During Assessment

Ako rano identifikujete engine i runtime, mnoge kasnije opservacije postaju lakše za tumačenje. Rootless Podman container ukazuje na to da su user namespace-ovi verovatno deo priče. Docker socket mount-ovan u workload ukazuje na to da je API-driven privilege escalation realan put. CRI-O/OpenShift node odmah treba da vas navede da razmišljate o SELinux label-ovima i restricted workload policy-ju. gVisor ili Kata okruženje treba da vas učini opreznijim pri pretpostavci da će se klasični `runc` breakout PoC ponašati na isti način.

Zato jedan od prvih koraka u container assessment-u uvek treba da bude odgovor na dva jednostavna pitanja: **koja komponenta upravlja container-om** i **koji runtime je zapravo pokrenuo proces**. Kada su ti odgovori jasni, ostatak okruženja obično postaje mnogo lakši za analizu.

## Runtime Vulnerabilities

Ne potiče svaki container escape od operator misconfiguration-a. Ponekad je sam runtime vulnerable component. Ovo je važno zato što workload može raditi sa konfiguracijom koja deluje pažljivo podešeno, a ipak biti izložen low-level runtime flaw-u.

Klasičan primer je **CVE-2019-5736** u `runc`-u, gde je malicious container mogao da overwrite-uje host `runc` binary i zatim sačeka da kasniji `docker exec` ili slična runtime invocation aktivira attacker-controlled code. Exploit path se veoma razlikuje od jednostavne bind-mount ili capability greške zato što zloupotrebljava način na koji runtime ponovo ulazi u container process space tokom exec handling-a.

Minimalni reproduction workflow iz red-team perspektive je:
```bash
go build main.go
./main
```
Zatim, sa hosta:
```bash
docker exec -it <container-name> /bin/sh
```
Ključna pouka nije tačna istorijska implementacija exploita, već implikacija za procenu: ako je verzija runtime-a ranjiva, obično izvršavanje koda unutar kontejnera može biti dovoljno za kompromitovanje hosta, čak i kada vidljiva konfiguracija kontejnera ne deluje očigledno slabo.

Nedavni runtime CVE-ovi, kao što su `CVE-2024-21626` u alatu `runc`, BuildKit mount race uslovi i greške u parsiranju alata containerd, dodatno potvrđuju istu činjenicu. Verzija runtime-a i nivo patch-a deo su bezbednosne granice, a ne samo nevažni detalji održavanja.
{{#include ../../../banners/hacktricks-training.md}}
