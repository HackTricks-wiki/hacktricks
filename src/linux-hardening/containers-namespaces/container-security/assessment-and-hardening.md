# Procena i ojačavanje

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Dobra procena kontejnera treba da odgovori na dva paralelna pitanja. Prvo, šta napadač može da uradi iz trenutnog workload-a? Drugo, koji su izbori operatera to omogućili? Alati za enumeraciju pomažu u odgovoru na prvo pitanje, a smernice za ojačavanje pomažu u odgovoru na drugo. Ako su oba pitanja obrađena na istoj stranici, odeljak je korisniji kao terenska referenca, a ne samo kao katalog tehnika za bekstvo.

Jedno praktično ažuriranje za moderna okruženja jeste da mnogi stariji tekstovi o kontejnerima prećutno pretpostavljaju **rootful runtime**, **bez izolacije user namespace-a** i često **cgroup v1**. Te pretpostavke više nisu bezbedne. Pre nego što utrošite vreme na stare primitive za bekstvo, prvo proverite da li je workload rootless ili koristi userns-remapping, da li host koristi cgroup v2 i da li Kubernetes ili runtime sada primenjuje podrazumevane seccomp i AppArmor profile. Ovi detalji često određuju da li je poznati breakout i dalje primenljiv.

## Alati za enumeraciju

Brojni alati i dalje su korisni za brzu karakterizaciju okruženja kontejnera:

- `linpeas` može da identifikuje mnoge indikatore kontejnera, montirane sockete, skupove capability-ja, opasne fajl-sisteme i nagoveštaje mogućeg bekstva.
- `CDK` je posebno namenjen okruženjima kontejnera i obuhvata enumeraciju, kao i neke automatizovane provere mogućnosti bekstva.
- `amicontained` je lagan alat i koristan za identifikovanje ograničenja kontejnera, capability-ja, izloženosti namespace-ova i verovatnih klasa bekstva.
- `deepce` je još jedan enumerator namenjen kontejnerima, sa proverama usmerenim na bekstvo.
- `grype` je koristan kada procena obuhvata pregled ranjivosti paketa u image-u, a ne samo analizu bekstva tokom izvršavanja.
- `Tracee` je koristan kada su vam potrebni **dokazi tokom izvršavanja**, a ne samo statička procena bezbednosnog stanja, naročito za sumnjivo pokretanje procesa, pristup fajlovima i prikupljanje događaja uz kontekst kontejnera.
- `Inspektor Gadget` je koristan u istragama Kubernetes-a i Linux hostova kada vam je potrebna vidljivost zasnovana na eBPF-u, povezana sa podovima, kontejnerima, namespace-ovima i drugim konceptima višeg nivoa.

Vrednost ovih alata ogleda se u brzini i obuhvatu, a ne u izvesnosti. Pomažu da se brzo stekne opšta slika bezbednosnog stanja, ali zanimljive nalaze i dalje treba ručno tumačiti u kontekstu konkretnog modela runtime-a, namespace-ova, capability-ja i mount-ova.

## Prioriteti ojačavanja

Najvažniji principi ojačavanja su jednostavni u teoriji, iako se njihova primena razlikuje od platforme do platforme. Izbegavajte privilegovane kontejnere. Izbegavajte montirane runtime sockete. Nemojte kontejnerima davati host putanje sa dozvolom za upis osim ako za to ne postoji konkretan razlog. Koristite user namespace-ove ili rootless izvršavanje kad god je to izvodljivo. Uklonite sve capability-je i dodajte samo one koji su zaista potrebni workload-u. Ostavite seccomp, AppArmor i SELinux omogućene umesto da ih isključujete zbog problema sa kompatibilnošću aplikacija. Ograničite resurse da kompromitovani kontejner ne bi mogao trivijalno da uskrati uslugu hostu.

Higijena image-a i build procesa jednako je važna kao i bezbednosno stanje tokom izvršavanja. Koristite minimalne image-e, često ih ponovo pravite, skenirajte ih, zahtevajte dokaz o poreklu gde je to praktično i ne čuvajte tajne u slojevima. Mnogo je lakše zaštititi kontejner koji radi kao non-root, koristi mali image i ima usku površinu sistemskih poziva i capability-ja nego veliki image namenjen praktičnosti koji radi kao root sa privilegijama ekvivalentnim hostu i unapred instaliranim alatima za otklanjanje grešaka.

Za Kubernetes su aktuelne osnovne smernice za ojačavanje strože nego što mnogi operateri još uvek pretpostavljaju. Ugrađeni **Pod Security Standards** tretiraju `restricted` kao profil koji predstavlja „trenutnu najbolju praksu“: `allowPrivilegeEscalation` treba da bude `false`, workload-i treba da rade kao non-root, seccomp treba izričito da bude podešen na `RuntimeDefault` ili `Localhost`, a skupove capability-ja treba agresivno uklanjati. Tokom procene, ovo je važno zato što klaster koji koristi samo oznake `warn` ili `audit` može na papiru delovati ojačano, a u praksi i dalje prihvatati rizične podove.<sup>[[1]](#references)</sup>

Kada pod ima montiran token service account-a, procenite njegova ovlašćenja **za svaki ciljni namespace posebno**. Pravilo koje navodi podove u jednom namespace-u ne potvrđuje ovlašćenja u drugom; token montiran u drugom podu može imati drugačija prava. Koristite `kubectl auth can-i list pods -n <target-namespace>` i `kubectl auth can-i list secrets -n <target-namespace>` sa identitetom koji se procenjuje. Dozvoljena provera listanja Secret-a predstavlja ozbiljan trag, jer odgovor na listanje može da sadrži sadržaj Secret-a, ali ne dokazuje da postoji privilegovani token. Pristup hostu dodatno zahteva upotrebljivo pravo za kreiranje workload-a, prihvatanje predloženog mount-a `hostPath` i bezbednosni kontekst čvora/poda koji dozvoljava predviđenu operaciju nad fajlom. Pogledajte Kubernetes dokumentaciju o [proverama autorizacije](https://kubernetes.io/docs/reference/access-authn-authz/authorization/) i [smernice za eskalaciju privilegija RBAC-a](https://kubernetes.io/docs/concepts/security/rbac-good-practices/).

## Pitanja za savremenu trijažu

Pre nego što pređete na stranice posvećene bekstvu, odgovorite na sledeća kratka pitanja:

1. Da li je workload **rootful**, **rootless** ili koristi **userns-remapped**?
2. Da li čvor koristi **cgroup v1** ili **cgroup v2**?
3. Da li su **seccomp** i **AppArmor/SELinux** izričito podešeni ili se samo nasleđuju kada su dostupni?
4. U Kubernetes-u, da li namespace zaista **sprovodi** `baseline` ili `restricted`, ili samo izdaje upozorenja/vrši nadzor?

Korisne provere:

```bash
id
cat /proc/self/uid_map 2>/dev/null
cat /proc/self/gid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/1/attr/current 2>/dev/null
find /var/run/secrets -maxdepth 3 -type f 2>/dev/null | head
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get ns "$NS" -o jsonpath='{.metadata.labels}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.supplementalGroupsPolicy}{"\n"}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.seccompProfile.type}{"\n"}{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.capabilities.drop}{"\n"}' 2>/dev/null
```

Šta je ovde zanimljivo:

- Ako `/proc/self/uid_map` prikazuje da je root u kontejneru mapiran na **visok UID opseg hosta**, mnogi stariji writeup-i o upisivanju kao root na hostu postaju manje relevantni, jer root u kontejneru više nije ekvivalent root-u na hostu.
- Ako je `/sys/fs/cgroup` tipa `cgroup2fs`, stari writeup-i specifični za **cgroup v1**, kao što je zloupotreba `release_agent`, ne bi trebalo da budu prva pretpostavka.
- Ako se seccomp i AppArmor nasleđuju samo implicitno, prenosivost može biti slabija nego što odbrana očekuje. U Kubernetes-u je eksplicitno postavljanje na `RuntimeDefault` često pouzdanije nego prećutno oslanjanje na podrazumevane postavke čvora.
- Ako je `supplementalGroupsPolicy` postavljen na `Strict`, pod bi trebalo da izbegne tiho nasleđivanje dodatnih članstava u grupama iz `/etc/group` unutar image-a, što čini ponašanje pristupa grupama, volume-ima i fajlovima predvidljivijim.
- Vredi direktno proveriti oznake namespace-a kao što je `pod-security.kubernetes.io/enforce=restricted`. `warn` i `audit` su korisni, ali ne sprečavaju kreiranje rizičnog poda.

## Trijaža osnovne konfiguracije runtime-a

Osnovna konfiguracija runtime-a je brza provera koja vam govori da li kontejner izgleda kao uobičajeno izolovano opterećenje ili kao foothold u control plane-u koji može da utiče na host. Treba prikupiti dovoljno podataka da biste odredili šta sledeće proveriti: zloupotrebu runtime socket-a, mount-ove hosta, namespace-ove, cgroup-e, capabilities ili proveru tajni u image-u.

Korisne provere iz radnog opterećenja:

```bash
id
hostname
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/uid_map 2>/dev/null
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
readlink /proc/self/ns/{pid,mnt,net,ipc,cgroup,user} 2>/dev/null
mount
find /run /var/run -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```

Tumačenje:

- Nedostajući ili neograničeni `memory.max` / `pids.max` ukazuju na slabe kontrole blast radius-a, čak i bez čistog escape-a.
- Root shell sa `NoNewPrivs: 0`, širokim capabilities i permisivnim seccomp-om mnogo je zanimljiviji od uskog non-root workload-a.
- Runtime socket-i i host mount-ovi sa dozvolom za upis obično imaju veći prioritet od kernel exploit-a jer već izlažu putanju za upravljanje ili kontrolu fajl-sistema.
- Deljeni PID, network, IPC ili cgroup namespace-ovi sami po sebi ne predstavljaju uvek potpune escape-ove, ali olakšavaju pronalaženje sledećeg koraka.

## Primeri iscrpljivanja resursa

Kontrole resursa nisu glamurozne, ali su deo bezbednosti kontejnera jer ograničavaju blast radius kompromitacije. Bez ograničenja memorije, CPU-a ili PID-ova, običan shell može biti dovoljan da naruši rad host-a ili susednih workload-ova.

Primeri testova koji utiču na host:

```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```

Ovi primeri su korisni jer pokazuju da se svaki opasan ishod u kontejneru ne svodi na čist „escape“. Slaba cgroup ograničenja i dalje mogu da pretvore code execution u stvaran operativni uticaj.

U okruženjima zasnovanim na Kubernetes-u, proverite i da li kontrole resursa uopšte postoje pre nego što DoS smatrate samo teorijskim:

```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```

## Alati za ojačavanje bezbednosti

Za okruženja usmerena na Docker, `docker-bench-security` i dalje predstavlja korisnu osnovu za reviziju na strani hosta jer proverava uobičajene probleme s konfiguracijom u odnosu na široko prihvaćene smernice referentnih testova. Bezbednosna obaveštenja za runtime treba pregledati zasebno, jer referentni test konfiguracije ne može da utvrdi da li je instalirani runtime pogođen nedavno otkrivenom ranjivošću. <sup>[[2]](#references)</sup>

```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```

Alat nije zamena za modelovanje pretnji, ali je i dalje koristan za pronalaženje nemarno podešenih podrazumevanih vrednosti za daemon-e, mount-ove, mrežu i runtime koje se vremenom nagomilavaju.

Za Kubernetes okruženja i okruženja koja se u velikoj meri oslanjaju na runtime, uparite statičke provere sa vidljivošću u runtime-u:

- `Tracee` je koristan za detekciju u runtime-u koja uzima u obzir kontejnere i brzu forenziku kada treba da potvrdite čemu je kompromitovano radno opterećenje zaista pristupilo.
- `Inspektor Gadget` je koristan kada procena zahteva telemetriju na nivou kernela povezanu sa podovima, kontejnerima, DNS aktivnostima, izvršavanjem datoteka ili mrežnim ponašanjem.

## Provere

Koristite ove komande kao brze početne provere tokom procene:

```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```

Šta je ovde zanimljivo:

- Root proces sa širokim skupom capabilities i `Seccomp: 0` zahteva hitnu pažnju.
- Root proces koji takođe ima **1:1 UID map** mnogo je zanimljiviji od „root“ procesa unutar pravilno izolovanog user namespace-a.
- `cgroup2fs` obično znači da mnogi stariji **cgroup v1** escape chains nisu najbolje polazište, dok nedostajući `memory.max` ili `pids.max` i dalje ukazuju na slabe kontrole za ograničavanje posledica.
- Sumnjivi mount-ovi i runtime socket-i često omogućavaju brži put do uticaja nego bilo koji kernel exploit.
- Kombinacija slabih runtime podešavanja i slabih ograničenja resursa obično ukazuje na generalno permisivno container okruženje, a ne na jednu izolovanu grešku.

## References

- [1] [Kubernetes standardi bezbednosti podova](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Bezbednosno obaveštenje za Docker: višestruke ranjivosti u runc, BuildKit i Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
