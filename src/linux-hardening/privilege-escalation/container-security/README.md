# Sigurnost kontejnera

{{#include ../../../banners/hacktricks-training.md}}

## Šta je kontejner zapravo

Praktičan način da se definiše kontejner je ovakav: kontejner je **regularno Linux procesno stablo** koje je pokrenuto pod specifičnom OCI-style konfiguracijom tako da vidi kontrolisani filesystem, kontrolisani skup kernel resursa i ograničeni model privilegija. Proces možda veruje da je PID 1, možda veruje da ima sopstveni network stack, možda misli da poseduje sopstveni hostname i IPC resurse, i može čak da radi kao root unutar svog user namespace. Ali ispod haube on je i dalje host proces koji kernel raspoređuje kao i svaki drugi.

Zato je sigurnost kontejnera zapravo proučavanje kako je ta iluzija konstruisana i kako puca. Ako je mount namespace slab, proces može videti host filesystem. Ako user namespace nedostaje ili je onemogućen, root unutar kontejnera može se previše poklapati sa root-om na hostu. Ako je seccomp nekonfigurisano i skup capabilities je preširok, proces može dohvatiti syscalls i privilegovane kernel funkcije koje su trebale ostati nedostižne. Ako je runtime socket mounted unutar kontejnera, kontejner možda uopšte ne treba kernel breakout jer jednostavno može tražiti od runtime-a da pokrene moćnijeg sibling kontejner ili montira host root filesystem direktno.

## Kako se kontejneri razlikuju od virtuelnih mašina

VM normalno nosi svoj kernel i granicu apstrakcije hardvera. To znači da guest kernel može crash-ovati, panic-ovati ili biti iskorišćen bez automatskog impliciranja direktne kontrole nad host kernelom. U kontejnerima, workload ne dobija zaseban kernel. Umesto toga, dobija pažljivo filtriran i namespaced pogled na isti kernel koji host koristi. Kao rezultat, kontejneri su obično lakši, brže se pokreću, lakše ih je gusto raspakovati na mašini i bolje su pogodni za kratkotrajno deployovanje aplikacija. Cena je u tome što granica izolacije mnogo direktnije zavisi od ispravne host i runtime konfiguracije.

Ovo ne znači da su kontejneri "nesigurni" a VM "sigurni". To znači da je bezbednosni model drugačiji. Dobro konfigurisani kontejnerski stack sa rootless izvršavanjem, user namespaces, podrazumevanim seccomp-om, strogim skupom capabilities, bez deljenja host namespace-a i snažnim SELinux ili AppArmor sprovođenjem može biti veoma robustan. Suprotno tome, kontejner pokrenut sa `--privileged`, deljenjem host PID/network, Docker socket-om mountovanim unutar njega i upisivim bind mount-om `/` funkcionalno je mnogo bliži pristupu host root-u nego bezbednom izolovanom sandbox-u aplikacije. Razlika proizlazi iz slojeva koji su bili omogućeni ili onemogućeni.

Postoji i sredina koju čitaoci treba da razumeju jer se pojavljuje sve češće u realnim okruženjima. **Sandboxed container runtimes** kao što su **gVisor** i **Kata Containers** namerno ojačavaju granicu iznad klasičnog `runc` kontejnera. gVisor postavlja userspace kernel sloj između workload-a i mnogih host kernel interfejsa, dok Kata pokreće workload unutar lagane virtuelne mašine. Oni se i dalje koriste kroz container ekosisteme i orchestration workflow-e, ali njihove sigurnosne osobine se razlikuju od običnih OCI runtime-a i ne bi trebalo mentalno da se grupišu sa "normalnim Docker kontejnerima" kao da se sve ponaša na isti način.

## Stog kontejnera: više slojeva, a ne jedan

Kada neko kaže "ovaj kontejner je nesiguran", korisno pitanje za nastavak je: **koji sloj ga je učinio nesigurnim?** Containerized workload obično je rezultat više komponenti koje rade zajedno.

Na vrhu često postoji **image build layer** kao što su BuildKit, Buildah, ili Kaniko, koji kreira OCI image i metadata. Iznad low-level runtime-a može postojati **engine ili manager** kao što su Docker Engine, Podman, containerd, CRI-O, Incus, ili systemd-nspawn. U cluster okruženjima, može postojati i **orchestrator** kao što je Kubernetes koji odlučuje o traženom sigurnosnom posturu kroz konfiguraciju workload-a. Konačno, **kernel** je ono što zapravo sprovodi namespaces, cgroups, seccomp i MAC politiku.

Ovaj model sa slojevima je važan za razumevanje default-a. Ograničenje može biti zatraženo od Kubernetes-a, prevedeno kroz CRI od strane containerd-a ili CRI-O, konvertovano u OCI spec od strane runtime wrapper-a, i tek onda sprovedeno od strane `runc`, `crun`, `runsc`, ili nekog drugog runtime-a prema kernelu. Kada se default-i razlikuju između okruženja, često je zato što je jedan od ovih slojeva promenio finalnu konfiguraciju. Isti mehanizam se stoga može pojaviti u Docker-u ili Podman-u kao CLI flag, u Kubernetes-u kao Pod ili `securityContext` polje, i u nižim runtime stack-ovima kao OCI konfiguracija generisana za workload. Iz tog razloga, CLI primeri u ovom odeljku treba da se čitaju kao **runtime-specifična sintaksa za opšti container koncept**, a ne kao univerzalni flagovi podržani od svih alata.

## Prava granica bezbednosti kontejnera

U praksi, sigurnost kontejnera dolazi iz **preklapajućih kontrola**, a ne iz jedne savršene kontrole. Namespaces izoluje vidljivost. cgroups upravljaju i ograničavaju upotrebu resursa. Capabilities smanjuju šta proces koji izgleda privilegovano zapravo može da uradi. seccomp blokira opasne syscalls pre nego što dođu do kernela. AppArmor i SELinux dodaju Mandatory Access Control preko normalnih DAC provera. `no_new_privs`, masked procfs paths, i read-only sistemske staze otežavaju uobičajene lance zloupotrebe privilegija i proc/sys. Runtime sam po sebi takođe znači jer odlučuje kako se mount-ovi, socket-i, label-e i namespace join-ovi kreiraju.

Zato mnogo dokumentacije o sigurnosti kontejnera deluje repetitivno. Isti escape chain često zavisi od više mehanizama odjednom. Na primer, upisivi host bind mount je loš, ali postaje mnogo gori ako kontejner takođe radi kao real root na hostu, ima `CAP_SYS_ADMIN`, nije ogranicen seccomp-om i nije ograničen od strane SELinux-a ili AppArmor-a. Slično tome, host PID deljenje je ozbiljno izlaganje, ali postaje dramatično korisnije za napadača kada se kombinuje sa `CAP_SYS_PTRACE`, slabim procfs zaštitama, ili alatima za ulazak u namespace kao što je `nsenter`. Pravi način dokumentovanja teme stoga nije ponavljanje istog napada na svakoj stranici, već objašnjavanje šta svaki sloj doprinosi finalnoj granici.

## Kako čitati ovaj odeljak

Odeljak je organizovan od najopštijih koncepata ka najkonkretnijim.

Počnite sa runtime i overview-om ekosistema:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Zatim pregledajte control plane-ove i supply-chain površine koje često odlučuju da li napadaču uopšte treba kernel escape:

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

## Dobar početni pristup pri enumeraciji

Prilikom procene containerized target-a, mnogo je korisnije postaviti mali skup preciznih tehničkih pitanja nego odmah skakati na poznate escape PoC-eve. Prvo, identifikujte **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer, ili nešto specijalizovanije. Zatim identifikujte **runtime**: `runc`, `crun`, `runsc`, `kata-runtime`, ili neku drugu OCI-kompatibilnu implementaciju. Nakon toga proverite da li je okruženje **rootful ili rootless**, da li su **user namespaces** aktivni, da li su deljeni neki **host namespaces**, koje **capabilities** su ostale, da li je **seccomp** omogućen, da li **MAC politika** zapravo sprovodi, da li su prisutni **opasni mount-ovi ili socket-i**, i da li proces može da komunicira sa container runtime API-jem.

Ta pitanja vam govore mnogo više o stvarnom sigurnosnom položaju nego što će ikada reći naziv base image-a. U mnogim procenama možete predvideti verovatnu porodicu breakout-a pre nego što pročitate i jedan aplikacioni fajl, samo razumevanjem finalne container konfiguracije.

## Obuhvat

Ovaj odeljak pokriva stariji Docker-fokusirani materijal organizovan prema kontejnerima: runtime i daemon exposure, authorization plugins, image trust i build secrets, sensitive host mounts, distroless workloads, privileged containers, i kernel zaštite koje se normalno slažu oko uitvoering-a kontejnera.
