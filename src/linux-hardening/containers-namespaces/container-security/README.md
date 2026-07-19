# Bezbednost kontejnera

{{#include ../../../banners/hacktricks-training.md}}

## Šta Kontejner Zapravo Jeste

Praktičan način da se definiše kontejner jeste sledeći: kontejner je **regularno stablo Linux procesa** koje je pokrenuto u okviru posebne OCI-style konfiguracije, tako da vidi kontrolisani filesystem, kontrolisani skup kernel resursa i ograničeni model privilegija. Proces može verovati da je PID 1, može verovati da ima sopstveni network stack, može verovati da poseduje sopstveni hostname i IPC resurse, a može čak raditi kao root unutar sopstvenog user namespace-a. Međutim, ispod svega toga on je i dalje host proces koji kernel raspoređuje kao i svaki drugi.

Zato je container security zapravo proučavanje načina na koji se ta iluzija konstruiše i načina na koji ona može da zakaže. Ako je mount namespace slab, proces može videti host filesystem. Ako user namespace ne postoji ili je onemogućen, root unutar kontejnera može biti previše direktno mapiran na root na hostu. Ako je seccomp unconfined, a skup capabilities preširok, proces može doći do syscall-ova i privilegovanih kernel funkcija koje su morale ostati nedostupne. Ako je runtime socket montiran unutar kontejnera, kontejneru možda uopšte nije potreban kernel breakout, jer jednostavno može zatražiti od runtime-a da pokrene moćniji susedni kontejner ili direktno montirati host root filesystem.

## Kako Se Kontejneri Razlikuju Od Virtualnih Mašina

VM obično ima sopstveni kernel i granicu hardverske apstrakcije. To znači da guest kernel može da se sruši, izazove panic ili bude exploited bez automatskog podrazumevanja direktne kontrole nad host kernelom. U kontejnerima workload ne dobija zaseban kernel. Umesto toga, dobija pažljivo filtriran i namespaced prikaz istog kernel-a koji koristi host. Zbog toga su kontejneri obično lakši, brže se pokreću, lakše se gusto raspoređuju na mašini i pogodniji su za kratkotrajno pokretanje aplikacija. Cena toga je što granica izolacije mnogo direktnije zavisi od ispravne konfiguracije hosta i runtime-a.

To ne znači da su kontejneri "nebezbedni", a VM-ovi "bezbedni". To znači da je security model drugačiji. Dobro konfigurisan container stack sa rootless izvršavanjem, user namespace-ovima, podrazumevanim seccomp-om, strogim skupom capabilities, bez deljenja host namespace-ova i uz snažno SELinux ili AppArmor enforcement može biti veoma robustan. Nasuprot tome, kontejner pokrenut sa `--privileged`, deljenjem host PID/network prostora, Docker socket-om montiranim unutar njega i writable bind mount-om `/` funkcionalno je mnogo bliži pristupu host root-u nego bezbedno izolovanom application sandbox-u. Razlika potiče od slojeva koji su omogućeni ili onemogućeni.

Postoji i sredina koju čitaoci treba da razumeju, jer se sve češće pojavljuje u realnim okruženjima. **Sandboxed container runtimes** kao što su **gVisor** i **Kata Containers** namerno dodatno ojačavaju granicu u odnosu na klasični `runc` kontejner. gVisor postavlja userspace kernel sloj između workload-a i mnogih host kernel interfejsa, dok Kata pokreće workload unutar lagane virtualne mašine. Oni se i dalje koriste kroz container ekosisteme i orchestration workflow-e, ali se njihove security osobine razlikuju od običnih OCI runtime-ova i ne treba ih mentalno svrstavati sa "normalnim Docker kontejnerima", kao da se sve ponaša na isti način.

## Container Stack: Više Slojeva, Ne Samo Jedan

Kada neko kaže "ovaj kontejner je nebezbedan", korisno pitanje koje sledi jeste: **koji sloj ga je učinio nebezbednim?** Containerized workload je obično rezultat zajedničkog rada više komponenti.

Na vrhu se često nalazi **image build layer** kao što su BuildKit, Buildah ili Kaniko, koji kreira OCI image i metadata. Iznad low-level runtime-a može postojati **engine ili manager** kao što su Docker Engine, Podman, containerd, CRI-O, Incus ili systemd-nspawn. U cluster okruženjima može postojati i **orchestrator** kao što je Kubernetes, koji kroz workload konfiguraciju određuje zahtevani security posture. Na kraju, **kernel** je taj koji zaista enforcement-uje namespaces, cgroups, seccomp i MAC policy.

Ovaj layered model važan je za razumevanje default-a. Ograničenje može biti zatraženo od strane Kubernetes-a, prevedeno kroz CRI pomoću containerd-a ili CRI-O-a, konvertovano u OCI spec od strane runtime wrapper-a, a tek zatim enforcement-ovano pomoću `runc`, `crun`, `runsc` ili drugog runtime-a protiv kernel-a. Kada se default-i razlikuju između okruženja, često je razlog to što je jedan od ovih slojeva promenio finalnu konfiguraciju. Isti mehanizam zato može izgledati kao CLI flag u Docker-u ili Podman-u, kao Pod ili `securityContext` field u Kubernetes-u i kao OCI konfiguracija generisana za workload u low-level runtime stack-ovima. Iz tog razloga, CLI primeri u ovom odeljku treba da se čitaju kao **runtime-specific syntax za opšti container koncept**, a ne kao univerzalni flag-ovi koje podržava svaki alat.

## Stvarna Granica Container Security-ja

U praksi, container security potiče od **preklapajućih kontrola**, a ne od jedne savršene kontrole. Namespaces izoluju vidljivost. cgroups upravljaju upotrebom resursa i ograničavaju je. Capabilities smanjuju ono što proces koji izgleda privilegovano zaista može da uradi. seccomp blokira opasne syscall-ove pre nego što stignu do kernel-a. AppArmor i SELinux dodaju Mandatory Access Control preko uobičajenih DAC provera. `no_new_privs`, masked procfs putanje i read-only system putanje otežavaju uobičajene lance zloupotrebe privilegija i proc/sys mehanizama. Sam runtime je takođe važan, jer odlučuje kako se kreiraju mount-ovi, socket-i, label-e i namespace join-ovi.

Zato veliki deo dokumentacije o container security-ju deluje repetitivno. Isti escape chain često zavisi od više mehanizama istovremeno. Na primer, writable host bind mount je loš, ali postaje mnogo gori ako kontejner takođe radi kao stvarni root na hostu, ima `CAP_SYS_ADMIN`, nije ograničen seccomp-om i nije ograničen SELinux-om ili AppArmor-om. Slično tome, deljenje host PID prostora predstavlja ozbiljnu izloženost, ali postaje dramatično korisnije attacker-u kada se kombinuje sa `CAP_SYS_PTRACE`, slabim procfs zaštitama ili alatima za ulazak u namespace, kao što je `nsenter`. Ispravan način dokumentovanja ove teme zato nije ponavljanje istog attack-a na svakoj stranici, već objašnjenje doprinosa svakog sloja konačnoj granici.

## Kako Čitati Ovaj Odeljak

Odeljak je organizovan od najopštijih ka najkonkretnijim konceptima.

Počnite sa pregledom runtime-a i ekosistema:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Zatim pregledajte control plane-ove i supply-chain površine koje često određuju da li attacker-u uopšte treba kernel escape:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
authorization-plugins.md
{{#endref}}

{{#ref}}
image-security-and-secrets.md
{{#endref}}

{{#ref}}
assessment-and-hardening.md
{{#endref}}

Zatim pređite na protection model:

{{#ref}}
protections/
{{#endref}}

Stranice o namespace-ovima pojedinačno objašnjavaju kernel isolation primitive:

{{#ref}}
protections/namespaces/
{{#endref}}

Stranice o cgroups, capabilities, seccomp, AppArmor-u, SELinux-u, `no_new_privs`, masked putanjama i read-only system putanjama objašnjavaju mehanizme koji se obično postavljaju preko namespace-ova:

{{#ref}}
protections/cgroups.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/no-new-privileges.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
distroless.md
{{#endref}}

{{#ref}}
privileged-containers.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Dobar Početni Mindset Za Enumeration

Prilikom procene containerized target-a, mnogo je korisnije postaviti mali skup preciznih tehničkih pitanja nego odmah preći na poznate escape PoC-ove. Prvo identifikujte **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer ili nešto specijalizovanije. Zatim identifikujte **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` ili drugu OCI-compatible implementaciju. Nakon toga proverite da li je okruženje **rootful ili rootless**, da li su **user namespace-ovi** aktivni, da li se dele neki **host namespace-ovi**, koje **capabilities** su preostale, da li je **seccomp** omogućen, da li **MAC policy** zaista vrši enforcement, da li postoje **opasni mount-ovi ili socket-i** i da li proces može da komunicira sa container runtime API-jem.

Ti odgovori govore mnogo više o stvarnom security posture-u nego ime base image-a. U mnogim assessment-ima možete predvideti verovatnu breakout familiju pre nego što pročitate ijedan application file, samo na osnovu razumevanja konačne container konfiguracije.

## Obuhvat

Ovaj odeljak obuhvata stari Docker-focused materijal pod container-oriented organizacijom: runtime i daemon exposure, authorization plugins, image trust i build secrets, sensitive host mounts, distroless workload-e, privileged containers i kernel protections koje se obično postavljaju oko izvršavanja kontejnera.
{{#include ../../../banners/hacktricks-training.md}}
