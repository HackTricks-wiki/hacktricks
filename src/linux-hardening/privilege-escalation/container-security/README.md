# Bezbednost kontejnera

{{#include ../../../banners/hacktricks-training.md}}

## Šta kontejner zapravo jeste

Praktičan način da se definiše kontejner je ovakav: kontejner je **običan Linux process tree** koji je pokrenut pod specifičnom OCI-style konfiguracijom tako da vidi kontrolisan filesystem, kontrolisan skup kernel resursa i ograničen model privilegija. Proces može verovati da je PID 1, može verovati da ima sopstveni network stack, može verovati da poseduje svoj hostname i IPC resurse, i može čak da se izvršava kao root unutar svoje user namespace. Ali ispod haube on je i dalje host process koji kernel raspoređuje kao i svaki drugi.

Zato je bezbednost kontejnera u suštini proučavanje kako ta iluzija biva konstruisana i kako puca. Ako je mount namespace slab, proces može videti host filesystem. Ako user namespace nedostaje ili je onemogućen, root unutar kontejnera može mapirati preblizu root-u na hostu. Ako je seccomp nekonfiguran i skup capabilities preširok, proces može dohvatiti syscalls i privilegovane kernel funkcije koje su trebalo da ostanu nedostupne. Ako je runtime socket mountovan unutar kontejnera, kontejner možda i ne treba kernel breakout jer jednostavno može tražiti od runtime-a da pokrene moćnijeg sibling kontejner ili da mount-uje host root filesystem direktno.

## Kako se kontejneri razlikuju od virtuelnih mašina

VM obično nosi sopstveni kernel i hardversku apstrakciju. To znači da guest kernel može crash-ovati, paničiti ili biti eksploatisan bez automatskog impliciranja direktne kontrole nad host kernel-om. U kontejnerima, workload ne dobija zaseban kernel. Umesto toga, dobija pažljivo filtriran i namespaced pogled na isti kernel koji host koristi. Kao rezultat, kontejneri su obično lakši, brže se startuju, lakše se gustiraju na mašini i bolje odgovaraju za kratkotrajne deploy-e aplikacija. Cena je ta što boundary izolacije mnogo direktnije zavisi od ispravne host i runtime konfiguracije.

Ovo ne znači da su kontejneri "nesigurni" a VM "sigurni". To znači da je model bezbednosti drugačiji. Dobro konfigurisan container stack sa rootless izvršavanjem, user namespaces, podrazumevanim seccomp-om, strogim setom capabilities, bez deljenja host namespace-a i jakim SELinux ili AppArmor enforce-om može biti veoma robustan. Nasuprot tome, kontejner koji je pokrenut sa `--privileged`, deljenim host PID/network-om, sa Docker socket-om mountovanim unutra i sa writable bind mount-om `/` funkcionalno je mnogo bliži pristupu host root-u nego bezbednom izolovanom sandbox-u. Razlika potiče iz slojeva koji su omogućeni ili onemogućeni.

Postoji i sredina koju čitaoci treba da razumeju jer se sve češće pojavljuje u realnim okruženjima. **Sandboxed container runtimes** kao što su **gVisor** i **Kata Containers** namerno ojačavaju boundary iznad klasičnog `runc` kontejnera. gVisor postavlja userspace kernel layer između workload-a i mnogih host kernel interfejsa, dok Kata pokreće workload unutar lagane virtuelne mašine. Oni se i dalje koriste kroz container ekosisteme i orchestration workflow-e, ali njihove sigurnosne osobine se razlikuju od običnih OCI runtimes i ne bi trebalo mentalno grupisati sve sa "normal Docker containers" kao da se sve ponaša isto.

## Container stack: nekoliko slojeva, ne jedan

Kada neko kaže "taj kontejner je nesiguran", korisno pitanje je: **koji sloj ga je učinio nesigurnim?** Containerized workload je obično rezultat nekoliko komponenti koje rade zajedno.

Na vrhu često postoji **image build layer** kao BuildKit, Buildah, ili Kaniko, koji kreira OCI image i metadata. Iznad low-level runtime-a može postojati **engine ili manager** kao Docker Engine, Podman, containerd, CRI-O, Incus, ili systemd-nspawn. U cluster okruženjima može postojati i **orchestrator** kao Kubernetes koji odlučuje o traženom security posture-u kroz workload konfiguraciju. Na kraju, **kernel** je onaj koji zapravo primenjuje namespaces, cgroups, seccomp i MAC policy.

Ovaj slojeviti model je važan za razumevanje podrazumevanih vrednosti. Ograničenje može biti zatraženo od Kubernetes-a, prevođen kroz CRI od strane containerd-a ili CRI-O, konvertovano u OCI spec od runtime wrapper-a, i tek onda sprovedeno od strane `runc`, `crun`, `runsc` ili nekog drugog runtime-a prema kernel-u. Kada se podrazumevane vrednosti razlikuju između okruženja, često je zato što je jedan od ovih slojeva promenio finalnu konfiguraciju. Isti mehanizam se stoga može pojaviti u Docker ili Podman kao CLI flag, u Kubernetes-u kao Pod ili `securityContext` polje, i u niže-level runtime stack-ovima kao OCI konfiguracija generisana za workload. Iz tog razloga, CLI primeri u ovom odeljku treba da se čitaju kao **runtime-specific sintaksa za opšti container koncept**, a ne kao univerzalni flagovi podržani od strane svakog alata.

## Prava granica bezbednosti kontejnera

U praksi, bezbednost kontejnera proizilazi iz **preklapajućih kontrola**, ne iz jedne savršene kontrole. Namespaces izoluju vidljivost. cgroups upravljaju i ograničavaju upotrebu resursa. Capabilities smanjuju šta proces koji izgleda privilegovano zapravo može da uradi. seccomp blokira opasne syscalls pre nego što stignu do kernel-a. AppArmor i SELinux dodaju Mandatory Access Control preko normalnih DAC provera. `no_new_privs`, masked procfs paths i read-only system paths otežavaju uobičajene lanca zloupotrebe privilegija i proc/sys. I runtime sam po sebi takođe znači jer odlučuje kako se mounts, sockets, labels i namespace joins kreiraju.

Zato mnogo dokumentacije o bezbednosti kontejnera deluje repetitivno. Isti escape chain često zavisi od više mehanizama odjednom. Na primer, writable host bind mount je loš, ali postaje daleko gori ako kontejner takođe radi kao real root na hostu, ima `CAP_SYS_ADMIN`, nije ograničen seccomp-om i nije restriktovan od strane SELinux ili AppArmor. Slično, host PID deljenje je ozbiljna izloženost, ali postaje dramatičnije korisno napadaču kada se kombinuje sa `CAP_SYS_PTRACE`, slabim procfs zaštitama ili namespace-entry alatima kao `nsenter`. Pravi način dokumentovanja teme stoga nije ponavljati isti napad na svakoj stranici, nego objasniti šta svaki sloj doprinosi finalnoj granici.

## Kako čitati ovaj odeljak

Odeljak je organizovan od najopštijih koncepata do najspecifičnijih.

Počnite sa pregledom runtime-a i ekosistema:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Zatim pregledajte control planes i supply-chain površine koje često odlučuju da li napadaču uopšte treba kernel escape:

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

Stranice o namespaces objašnjavaju kernel isolation primitive pojedinačno:

{{#ref}}
protections/namespaces/
{{#endref}}

Stranice o cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths i read-only paths objašnjavaju mehanizme koji se obično slažu iznad namespaces:

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

## Dobar početni mindset za enumeraciju

Prilikom procene containerized target-a mnogo je korisnije postaviti mali skup preciznih tehničkih pitanja nego odmah prelaziti na poznate escape PoC-eve. Prvo, identifikujte **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer, ili nešto specijalizovanije. Zatim identifikujte **runtime**: `runc`, `crun`, `runsc`, `kata-runtime`, ili neku drugu OCI-compatible implementaciju. Nakon toga, proverite da li je okruženje **rootful ili rootless**, da li su **user namespaces** aktivne, da li su deljeni neki **host namespaces**, koje **capabilities** ostaju, da li je **seccomp** omogućen, da li **MAC policy** zaista sprovodi, da li su prisutni **opasni mount-ovi ili sockets**, i da li proces može da komunicira sa container runtime API-jem.

Ta odgovori govore mnogo više o stvarnom security posture-u nego ime base image-a. U mnogim procenama možete predvideti verovatnu familiju breakou­ta pre nego što pročitate ijedan application fajl samo razumevanjem finalne container konfiguracije.

## Pokrivenost

Ovaj odeljak pokriva stariji Docker-fokusirani materijal organizovan po container-temama: runtime i daemon exposure, authorization plugins, image trust i build secrets, sensitive host mounts, distroless workloads, privileged containers i kernel zaštite koje se obično slažu oko izvršavanja kontejnera.
{{#include ../../../banners/hacktricks-training.md}}
