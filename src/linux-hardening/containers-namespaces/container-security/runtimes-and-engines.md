# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Jedan od najvećih izvora zabune u bezbednosti containera jeste to što se nekoliko potpuno različitih komponenti često svodi na istu reč. „Docker“ može označavati format image-a, CLI, daemon, build sistem, runtime stack ili jednostavno opštu ideju containera. Za bezbednosni rad ta dvosmislenost predstavlja problem, jer su različiti slojevi odgovorni za različite zaštite. Breakout izazvan lošim bind mount-om nije isto što i breakout izazvan greškom u low-level runtime-u, a nijedno od toga nije isto što i greška u cluster policy-ju u Kubernetes-u.

Ova stranica razdvaja ekosistem prema ulogama kako bi ostatak sekcije mogao precizno da govori o tome gde se određena zaštita ili slabost zapravo nalazi.

## OCI Kao Zajednički Jezik

Moderni Linux container stack-ovi često mogu međusobno da sarađuju zato što koriste skup OCI specifikacija. **OCI Image Specification** opisuje način predstavljanja image-a i layer-a. **OCI Runtime Specification** opisuje kako runtime treba da pokrene proces, uključujući namespaces, mount-ove, cgroups i security settings. **OCI Distribution Specification** standardizuje način na koji registry-ji izlažu sadržaj.

Ovo je važno jer objašnjava zašto image izgrađen jednim alatom često može da se pokrene drugim alatom i zašto više engine-a može da koristi isti low-level runtime. Takođe objašnjava zašto security ponašanje može izgledati slično u različitim proizvodima: mnogi od njih kreiraju istu OCI runtime konfiguraciju i prosleđuju je istom malom skupu runtime-a.

## Low-Level OCI Runtimes

Low-level runtime je komponenta koja je najbliža granici kernela. To je deo koji zaista kreira namespaces, upisuje cgroup settings, primenjuje capabilities i seccomp filters i na kraju poziva `execve()` za container proces. Kada se govori o „container isolation“ na mehaničkom nivou, obično se misli upravo na ovaj sloj, čak i kada se to ne kaže eksplicitno.

### `runc`

`runc` je referentni OCI runtime i i dalje najpoznatija implementacija. Intenzivno se koristi u Docker-u, containerd-u i mnogim Kubernetes deployment-ima. Veliki deo javnih istraživanja i exploitation materijala cilja `runc`-style okruženja jednostavno zato što su česta i zato što `runc` definiše osnovu koju mnogi zamišljaju kada pomisle na Linux container. Razumevanje `runc`-a zato čitaocu daje dobar mentalni model klasične container isolation.

### `crun`

`crun` je drugi OCI runtime, napisan u C-u i široko korišćen u modernim Podman okruženjima. Često se hvali zbog dobre podrške za cgroup v2, kvalitetne rootless ergonomije i manjeg overhead-a. Iz bezbednosne perspektive važno je to što, iako je napisan u drugom jeziku, i dalje ima istu ulogu: to je komponenta koja OCI konfiguraciju pretvara u pokrenuto stablo procesa pod kernelom. Rootless Podman workflow često deluje bezbednije ne zato što `crun` magično rešava sve probleme, već zato što ceo stack oko njega obično više naginje user namespaces i least privilege principu.

### `runsc` Iz gVisor-a

`runsc` je runtime koji koristi gVisor. Ovde se granica značajno menja. Umesto da većinu syscall-ova prosleđuje direktno host kernelu na uobičajen način, gVisor umeće userspace kernel layer koji emulira ili posreduje u velikim delovima Linux interfejsa. Rezultat nije običan `runc` container sa nekoliko dodatnih flag-ova; to je drugačiji sandbox dizajn čija je svrha smanjenje attack surface-a host kernela. Kompatibilnost i performance tradeoff-i deo su tog dizajna, pa okruženja koja koriste `runsc` treba dokumentovati drugačije od normalnih OCI runtime okruženja.

### `kata-runtime`

Kata Containers pomeraju granicu još dalje tako što workload pokreću unutar lightweight virtual machine-a. Administrativno, ovo i dalje može izgledati kao container deployment, a orchestration layer-i ga i dalje mogu tretirati na isti način, ali je osnovna isolation boundary bliža virtualization-u nego klasičnom containeru koji deli host kernel. Zbog toga je Kata koristan kada je potrebna jača tenant isolation bez napuštanja container-centric workflow-a.

## Engines And Container Managers

Ako je low-level runtime komponenta koja direktno komunicira sa kernelom, engine ili manager je komponenta sa kojom korisnici i operatori najčešće rade. On upravlja image pull-ovima, metadata podacima, logovima, networks, volumes, lifecycle operacijama i API exposure-om. Ovaj sloj je izuzetno važan jer se mnogi kompromisi iz stvarnog sveta dešavaju upravo ovde: pristup runtime socket-u ili daemon API-ju može biti ekvivalentan kompromitovanju hosta čak i kada je sam low-level runtime potpuno ispravan.

### Docker Engine

Docker Engine je najprepoznatljivija container platforma za developere i jedan od razloga zbog kojih je container terminologija postala toliko oblikovana prema Docker-u. Tipičan put je `docker` CLI do `dockerd`-a, koji zatim koordinira low-level komponente kao što su `containerd` i OCI runtime. Istorijski gledano, Docker deployment-i su često bili **rootful**, pa je pristup Docker socket-u zbog toga predstavljao veoma moćan primitive. Zato se veliki deo praktičnog privilege-escalation materijala fokusira na `docker.sock`: ako proces može da zatraži od `dockerd`-a da kreira privileged container, mount-uje host paths ili se pridruži host namespaces, možda mu uopšte nije potreban kernel exploit.

### Podman

Podman je projektovan oko modela bez daemon-a. Operativno, ovo pomaže u naglašavanju ideje da su containeri samo procesi kojima se upravlja kroz standardne Linux mehanizme, a ne kroz jedan dugotrajni privileged daemon. Podman takođe ima znatno bolju **rootless** podršku od klasičnih Docker deployment-a sa kojima se većina ljudi prvo susrela. To ne čini Podman automatski bezbednim, ali značajno menja podrazumevani risk profile, naročito u kombinaciji sa user namespaces, SELinux-om i `crun`-om.

### containerd

containerd je osnovna runtime management komponenta u mnogim modernim stack-ovima. Koristi se ispod Docker-a i jedan je od dominantnih Kubernetes runtime backend-ova. Izlaže moćne API-je, upravlja image-ima i snapshot-ovima i delegira konačno kreiranje procesa low-level runtime-u. Security diskusije o containerd-u treba da naglase da pristup containerd socket-u ili `ctr`/`nerdctl` funkcionalnosti može biti jednako opasan kao pristup Docker API-ju, čak i ako interfejs i workflow deluju manje „developer friendly“.

### CRI-O

CRI-O je užeg fokusa od Docker Engine-a. Umesto da bude general-purpose developer platforma, napravljen je oko čistog implementiranja Kubernetes Container Runtime Interface-a. Zbog toga je naročito čest u Kubernetes distribucijama i SELinux-heavy ekosistemima kao što je OpenShift. Iz bezbednosne perspektive, uži scope je koristan jer smanjuje konceptualnu zbrku: CRI-O je jasno deo sloja „pokretanje container-a za Kubernetes“, a ne platforma za sve.

### Incus, LXD, And LXC

Incus/LXD/LXC sistemi zaslužuju da se odvoje od Docker-style application container-a zato što se često koriste kao **system containers**. Od system container-a se obično očekuje da više liči na lightweight machine sa potpunijim userspace-om, dugotrajnim servisima, bogatijim izlaganjem uređaja i širom integracijom sa hostom. Isolation mehanizmi su i dalje kernel primitives, ali su operativna očekivanja drugačija. Zbog toga pogrešne konfiguracije ovde često više liče na greške u lightweight virtualization-u ili host delegation-u nego na „loše podrazumevane vrednosti za app container“.

### systemd-nspawn

systemd-nspawn zauzima zanimljivo mesto zato što je native za systemd i veoma koristan za testing, debugging i pokretanje OS-like okruženja. Nije dominantni cloud-native production runtime, ali se dovoljno često pojavljuje u labovima i distro-orijentisanim okruženjima da zaslužuje pomen. Za security analysis, on je još jedan podsetnik da pojam „container“ obuhvata više ekosistema i operativnih stilova.

### Apptainer / Singularity

Apptainer (ranije Singularity) čest je u research i HPC okruženjima. Njegove trust assumptions, user workflow i execution model značajno se razlikuju od Docker/Kubernetes-centric stack-ova. Ova okruženja naročito vode računa o tome da korisnicima omoguće pokretanje packaged workload-a bez davanja širokih privileged container-management ovlašćenja. Ako reviewer pretpostavi da je svako container okruženje praktično „Docker na serveru“, ozbiljno će pogrešno razumeti ove deployment-e.

## Build-Time Tooling

Mnoge security diskusije govore samo o run time-u, ali build-time tooling je takođe važan jer određuje sadržaj image-a, izlaganje build secrets-a i količinu trusted context-a koja se ugrađuje u finalni artifact.

**BuildKit** i `docker buildx` su moderni build backend-i koji podržavaju funkcije kao što su caching, secret mounting, SSH forwarding i multi-platform builds. To su korisne funkcije, ali iz security perspektive one takođe stvaraju mesta na kojima secrets mogu da leak-uju u image layers ili gde preširok build context može da izloži fajlove koji nikada nisu smeli da budu uključeni. **Buildah** ima sličnu ulogu u OCI-native ekosistemima, naročito uz Podman, dok se **Kaniko** često koristi u CI okruženjima koja ne žele da build pipeline-u dodele privileged Docker daemon.

Ključna pouka jeste da su image creation i image execution različite faze, ali slab build pipeline može da stvori slab runtime posture mnogo pre nego što se container pokrene.

## Orchestration Je Drugi Sloj, A Ne Runtime

Kubernetes ne treba mentalno izjednačavati sa samim runtime-om. Kubernetes je orchestrator. On schedule-uje Pods, čuva desired state i izražava security policy kroz workload configuration. Kubelet zatim komunicira sa CRI implementacijom kao što su containerd ili CRI-O, koja dalje poziva low-level runtime kao što su `runc`, `crun`, `runsc` ili `kata-runtime`.

Ovo je važno zato što mnogi pogrešno pripisuju određenu zaštitu „Kubernetes-u“, iako je ona zapravo enforced od strane node runtime-a, ili krive „containerd defaults“ za ponašanje koje potiče iz Pod spec-a. U praksi, final security posture predstavlja kompoziciju: orchestrator nešto zahteva, runtime stack to prevodi, a kernel konačno enforcement-uje pravila.

## Zašto Je Identifikacija Runtime-a Važna Tokom Assessment-a

Ako rano identifikujete engine i runtime, mnoga kasnija zapažanja postaju lakša za tumačenje. Rootless Podman container ukazuje na to da su user namespaces verovatno deo priče. Docker socket mount-ovan u workload ukazuje da je API-driven privilege escalation realističan put. CRI-O/OpenShift node odmah treba da vas navede da razmišljate o SELinux labels i restricted workload policy-ju. gVisor ili Kata okruženje treba da vas učini opreznijim pri pretpostavci da će se klasični `runc` breakout PoC ponašati na isti način.

Zato jedan od prvih koraka u container assessment-u uvek treba da bude odgovor na dva jednostavna pitanja: **koja komponenta upravlja containerom** i **koji runtime je zaista pokrenuo proces**. Kada su ti odgovori jasni, ostatak okruženja obično postaje znatno lakši za analizu.

## Runtime Vulnerabilities

Ne potiče svaki container escape od pogrešne konfiguracije operatora. Ponekad je sam runtime ranjiva komponenta. Ovo je važno zato što workload može imati pažljivo podešenu konfiguraciju, a da i dalje bude izložen low-level runtime flaw-u.

Klasičan primer je **CVE-2019-5736** u `runc`-u, gde je malicious container mogao da overwrite-uje host `runc` binary i zatim sačeka da kasniji `docker exec` ili slična runtime invocation pokrene attacker-controlled code. Exploit path se veoma razlikuje od jednostavne bind-mount ili capability greške zato što zloupotrebljava način na koji runtime ponovo ulazi u container process space tokom obrade exec-a.<sup>[[1]](#references)</sup>

Minimalni reproduction workflow iz red-team perspektive je:
```bash
go build main.go
./main
```
Zatim, sa hosta:
```bash
docker exec -it <container-name> /bin/sh
```
Ključna pouka nije tačna istorijska implementacija exploita, već implikacija po procenu: ako je verzija runtime-a ranjiva, uobičajeno izvršavanje koda unutar kontejnera može biti dovoljno za kompromitovanje hosta, čak i kada vidljiva konfiguracija kontejnera ne deluje očigledno slabo.

Nedavni runtime CVE-ovi, kao što su `CVE-2024-21626` u `runc`-u, BuildKit mount race uslovi i containerd greške pri parsiranju, potvrđuju istu činjenicu. Verzija runtime-a i nivo zakrpa deo su bezbednosne granice, a ne samo nebitni detalji održavanja.

## Reference

- [1] [Breaking out of Docker via runC – Explaining CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)

{{#include ../../../banners/hacktricks-training.md}}
