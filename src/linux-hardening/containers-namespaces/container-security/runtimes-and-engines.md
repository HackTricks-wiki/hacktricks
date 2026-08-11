# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Jedan od najvećih izvora zabune u container security oblasti jeste to što se nekoliko potpuno različitih komponenti često svodi na istu reč. "Docker" može označavati format image-a, CLI, daemon, build system, runtime stack ili jednostavno opštu ideju containera. Za security rad to predstavlja problem, jer su različiti slojevi odgovorni za različite zaštite. Breakout izazvan lošim bind mount-om nije isto što i breakout izazvan propustom u low-level runtime-u, a ni jedno ni drugo nije isto što i greška u cluster policy-ju u Kubernetesu.

Ova stranica razdvaja ekosistem prema ulogama, kako bi ostatak sekcije mogao precizno da govori o tome gde se određena zaštita ili slabost zaista nalazi.

## OCI As The Common Language

Moderni Linux container stack-ovi često međusobno sarađuju zato što koriste skup OCI specifikacija. **OCI Image Specification** opisuje način predstavljanja image-a i layer-a. **OCI Runtime Specification** opisuje kako runtime treba da pokrene proces, uključujući namespace-ove, mount-ove, cgroup-ove i security podešavanja. **OCI Distribution Specification** standardizuje način na koji registry-ji izlažu sadržaj.

Ovo je važno zato što objašnjava kako image napravljen jednim tool-om često može da se pokrene drugim, kao i zašto više engine-a može da koristi isti low-level runtime. Takođe objašnjava zašto security ponašanje može izgledati slično u različitim proizvodima: mnogi od njih kreiraju istu OCI runtime konfiguraciju i prosleđuju je istom malom skupu runtime-a.

## Low-Level OCI Runtimes

Low-level runtime je komponenta koja se nalazi najbliže granici kernel-a. To je deo koji zaista kreira namespace-ove, upisuje cgroup podešavanja, primenjuje capabilities i seccomp filtere i na kraju poziva `execve()` za container proces. Kada ljudi govore o "container isolation" na mehaničkom nivou, obično misle upravo na ovaj sloj, čak i kada to ne kažu eksplicitno.

### `runc`

`runc` je referentni OCI runtime i i dalje najpoznatija implementacija. Intenzivno se koristi u Docker-u, containerd-u i mnogim Kubernetes deployment-ima. Veliki deo javno dostupnog research-a i exploitation materijala cilja `runc`-style okruženja jednostavno zato što su česta i zato što `runc` definiše osnovu koju mnogi zamišljaju kada pomisle na Linux container. Razumevanje `runc`-a zato čitaocu daje dobar mentalni model klasičnog container isolation-a.

### `crun`

`crun` je još jedan OCI runtime, napisan u C-u i široko korišćen u modernim Podman okruženjima. Često se ističe zbog dobre podrške za cgroup v2, dobre rootless ergonomije i manjeg overhead-a. Iz security perspektive važno je to što nije napisan u drugom jeziku, već što i dalje ima istu ulogu: to je komponenta koja OCI konfiguraciju pretvara u pokrenuto stablo procesa pod kernel-om. Rootless Podman workflow često deluje bezbednije ne zato što `crun` magično rešava sve probleme, već zato što celokupan stack oko njega obično više koristi user namespace-ove i least privilege princip.

### `runsc` From gVisor

`runsc` je runtime koji koristi gVisor. Ovde se granica značajno menja. Umesto da većinu syscall-ova prosleđuje direktno host kernel-u na uobičajen način, gVisor umeće userspace kernel layer koji emulira ili posreduje u velikim delovima Linux interfejsa. Rezultat nije običan `runc` container sa nekoliko dodatnih flag-ova; to je drugačiji sandbox dizajn čija je svrha smanjenje attack surface-a host kernel-a. Tradeoff-i u kompatibilnosti i performansama deo su tog dizajna, pa okruženja koja koriste `runsc` treba dokumentovati drugačije od normalnih OCI runtime okruženja.

### `kata-runtime`

Kata Containers pomeraju granicu još dalje tako što workload pokreću unutar lightweight virtual machine-a. Administrativno to i dalje može izgledati kao container deployment, a orchestration layer-i ga i dalje mogu tretirati na isti način, ali je osnovna isolation granica bliža virtualization-u nego klasičnom containeru koji deli host kernel. Zbog toga je Kata koristan kada je potrebna jača tenant isolation zaštita, bez napuštanja container-centric workflow-a.

## Engines And Container Managers

Ako je low-level runtime komponenta koja direktno komunicira sa kernel-om, engine ili manager je komponenta sa kojom korisnici i operatori obično rade. On upravlja image pull-ovima, metadata-ma, logovima, mrežama, volume-ima, lifecycle operacijama i API exposure-om. Ovaj sloj je izuzetno važan zato što se mnogi real-world compromise-i dešavaju upravo ovde: pristup runtime socket-u ili daemon API-ju može biti ekvivalentan host compromise-u čak i kada je sam low-level runtime potpuno ispravan.

### Docker Engine

Docker Engine je najprepoznatljivija container platforma za developere i jedan od razloga zbog kojih je container terminologija postala toliko oblikovana prema Docker-u. Tipičan put je `docker` CLI do `dockerd`-a, koji zatim koordinira low-level komponente kao što su `containerd` i OCI runtime. Istorijski su Docker deployment-i često bili **rootful**, pa je pristup Docker socket-u zato predstavljao veoma moćan primitive. Zbog toga se veliki deo praktičnog privilege-escalation materijala fokusira na `docker.sock`: ako proces može da zatraži od `dockerd`-a kreiranje privileged container-a, mount-ovanje host path-ova ili pridruživanje host namespace-ovima, možda mu uopšte nije potreban kernel exploit.

### Podman

Podman je projektovan oko više daemonless modela. Operativno, to pomaže u jačanju ideje da su container-i samo procesi kojima se upravlja kroz standardne Linux mehanizme, a ne kroz jedan dugotrajni privileged daemon. Podman takođe ima mnogo snažniju **rootless** priču od klasičnih Docker deployment-a sa kojima se većina ljudi prvo upoznala. To ne čini Podman automatski bezbednim, ali značajno menja podrazumevani risk profile, naročito u kombinaciji sa user namespace-ovima, SELinux-om i `crun`-om.

### containerd

containerd je osnovna runtime management komponenta u mnogim modernim stack-ovima. Koristi se ispod Docker-a i jedan je od dominantnih Kubernetes runtime backend-a. Izlaže moćne API-je, upravlja image-ima i snapshot-ovima i delegira konačno kreiranje procesa low-level runtime-u. Security diskusije o containerd-u treba da naglase da pristup containerd socket-u ili `ctr`/`nerdctl` funkcionalnosti može biti jednako opasan kao pristup Docker API-ju, čak i kada interfejs i workflow deluju manje "developer friendly".

### CRI-O

CRI-O je užeg fokusa od Docker Engine-a. Umesto da bude general-purpose developer platforma, napravljen je oko čistog implementiranja Kubernetes Container Runtime Interface-a. Zbog toga je naročito čest u Kubernetes distribucijama i SELinux-heavy ekosistemima kao što je OpenShift. Iz security perspektive, taj uži scope je koristan zato što smanjuje konceptualnu složenost: CRI-O je veoma jasno deo sloja "run containers for Kubernetes", a ne platforma za sve namene.

### Incus, LXD, And LXC

Incus/LXD/LXC sistemi zaslužuju da budu odvojeni od Docker-style application container-a zato što se često koriste kao **system containers**. Od system container-a se obično očekuje da više liči na lightweight machine sa potpunijim userspace-om, dugotrajnim servisima, bogatijom izloženošću uređaja i obimnijom integracijom sa host-om. Isolation mehanizmi su i dalje kernel primitives, ali su operativna očekivanja drugačija. Zbog toga pogrešne konfiguracije ovde često više liče na greške u lightweight virtualization-u ili host delegation-u nego na "bad app-container defaults".

### systemd-nspawn

systemd-nspawn zauzima zanimljivo mesto zato što je systemd-native i veoma koristan za testing, debugging i pokretanje OS-like okruženja. Nije dominantni cloud-native production runtime, ali se dovoljno često pojavljuje u labovima i distro-oriented okruženjima da zaslužuje pomen. Za security analizu, on je još jedan podsetnik da pojam "container" obuhvata više ekosistema i operativnih stilova.

### Apptainer / Singularity

Apptainer (ranije Singularity) je čest u research i HPC okruženjima. Njegove trust pretpostavke, user workflow i execution model bitno se razlikuju od Docker/Kubernetes-centric stack-ova. Ova okruženja naročito vode računa o tome da korisnicima omoguće pokretanje packaged workload-a bez davanja širokih privileged container-management ovlašćenja. Ako reviewer pretpostavi da je svako container okruženje praktično "Docker on a server", ozbiljno će pogrešno razumeti ove deployment-e.

## Build-Time Tooling

Mnoge security diskusije govore samo o runtime-u, ali build-time tooling je takođe važan zato što određuje sadržaj image-a, exposure build secret-a i količinu trusted context-a koja se ugrađuje u finalni artifact.

**BuildKit** i `docker buildx` su moderni build backend-i koji podržavaju funkcije kao što su caching, secret mounting, SSH forwarding i multi-platform builds. To su korisne funkcije, ali iz security perspektive one takođe stvaraju mesta na kojima secret-i mogu da leak-uju u image layer-e ili gde preširok build context može da izloži fajlove koji nikada nisu smeli da budu uključeni. **Buildah** ima sličnu ulogu u OCI-native ekosistemima, naročito uz Podman, dok se **Kaniko** često koristi u CI okruženjima koja ne žele da build pipeline-u daju privileged Docker daemon.

Ključna lekcija jeste da su image creation i image execution različite faze, ali slab build pipeline može da stvori slab runtime posture mnogo pre nego što se container pokrene.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes ne treba mentalno izjednačavati sa samim runtime-om. Kubernetes je orchestrator. On schedule-uje Pod-ove, čuva desired state i izražava security policy kroz workload konfiguraciju. Kubelet zatim komunicira sa CRI implementacijom kao što su containerd ili CRI-O, koja dalje poziva low-level runtime kao što su `runc`, `crun`, `runsc` ili `kata-runtime`.

Ovo je važno zato što mnogi pogrešno pripisuju neku zaštitu "Kubernetes-u", iako je ona zapravo enforced od strane node runtime-a, ili krive "containerd defaults" za ponašanje koje potiče iz Pod spec-a. U praksi, finalni security posture predstavlja kompoziciju: orchestrator nešto zahteva, runtime stack to prevodi, a kernel to na kraju enforced-uje.

## Why Runtime Identification Matters During Assessment

Ako rano identifikujete engine i runtime, mnoga kasnija zapažanja postaju lakša za tumačenje. Rootless Podman container ukazuje na to da su user namespace-ovi verovatno deo priče. Docker socket mount-ovan u workload ukazuje da je API-driven privilege escalation realan put. CRI-O/OpenShift node odmah treba da vas navede da razmišljate o SELinux label-ovima i restricted workload policy-ju. gVisor ili Kata okruženje treba da vas učini opreznijim pri pretpostavci da će se klasični `runc` breakout PoC ponašati na isti način.

Zato jedan od prvih koraka u container assessment-u uvek treba da bude odgovor na dva jednostavna pitanja: **koja komponenta upravlja container-om** i **koji runtime je zaista pokrenuo proces**. Kada su ti odgovori jasni, ostatak okruženja obično postaje mnogo lakši za razumevanje.

## Runtime Vulnerabilities

Ne potiče svaki container escape iz operator misconfiguration-a. Ponekad je sam runtime ranjiva komponenta. Ovo je važno zato što workload može biti pokrenut sa konfiguracijom koja deluje pažljivo podešeno, a ipak biti izložen low-level runtime flaw-u.

Klasičan primer je **CVE-2019-5736** u `runc`-u, gde je malicious container mogao da prepiše host `runc` binary, a zatim sačeka da kasniji `docker exec` ili slična runtime invocation aktivira attacker-controlled code. Exploit path se veoma razlikuje od jednostavne bind-mount ili capability greške zato što zloupotrebljava način na koji runtime ponovo ulazi u process space container-a tokom exec handling-a.<sup>[[1]](#references)</sup>

Minimalni reproduction workflow iz red-team perspektive je:
```bash
go build main.go
./main
```
Zatim, sa hosta:
```bash
docker exec -it <container-name> /bin/sh
```
Ključna pouka nije sama istorijska implementacija exploita, već implikacija po procenu: ako je verzija runtime-a ranjiva, obično izvršavanje koda unutar kontejnera može biti dovoljno za kompromitovanje hosta, čak i kada vidljiva konfiguracija kontejnera ne deluje očigledno slabo.

Nedavni runtime CVE-ovi, kao što su `CVE-2024-21626` u alatu `runc`, race condition-i pri mountovanju u BuildKit-u i greške pri parsiranju u containerd-u, dodatno potvrđuju istu činjenicu. Verzija runtime-a i nivo zakrpljenosti deo su bezbednosne granice, a ne samo nebitni detalji održavanja.

## References

- [1] [Izlazak iz Docker-a putem runC-a – Objašnjenje CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
