# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` je kernel hardening funkcija koja sprečava proces da stekne veće privilegije kroz `execve()`. Praktično, kada je flag postavljen, izvršavanje setuid binary-ja, setgid binary-ja ili fajla sa Linux file capabilities ne dodeljuje dodatne privilegije izvan onoga što je proces već imao. U containerized okruženjima ovo je važno zato što se mnogi privilege-escalation chain-ovi oslanjaju na pronalaženje executable-a unutar image-a koji menja privilegije prilikom pokretanja.

Sa defensive stanovišta, `no_new_privs` nije zamena za namespaces, seccomp ili capability dropping. To je dodatni zaštitni sloj. Blokira specifičnu klasu naknadne eskalacije nakon što je code execution već dobijen. Zbog toga je posebno vredan u okruženjima čiji image-i sadrže helper binary-je, package-manager artefakte ili legacy alate koji bi inače bili opasni u kombinaciji sa delimičnim kompromitovanjem.

## Operation

Kernel flag iza ovog ponašanja je `PR_SET_NO_NEW_PRIVS`. Kada se postavi za proces, kasniji `execve()` pozivi ne mogu povećati privilegije. Važan detalj je da proces i dalje može da pokreće binary-je; jednostavno ne može da ih koristi za prelazak granice privilegija koju bi kernel inače poštovao.

Kernel ponašanje je takođe **nasleđeno i nepovratno**: kada task postavi `no_new_privs`, bit se nasleđuje kroz `fork()`, `clone()` i `execve()`, i kasnije ne može biti uklonjen. Ovo je korisno tokom assessment-a zato što jedan `NoNewPrivs: 1` na container procesu obično znači da bi potomci takođe trebalo da ostanu u tom režimu, osim ako posmatrate potpuno drugo stablo procesa.

U Kubernetes-oriented okruženjima, `allowPrivilegeEscalation: false` preslikava se na ovo ponašanje za container proces. U Docker i Podman style runtime-ovima, ekvivalent se obično eksplicitno omogućava kroz security option. Na OCI nivou, isti koncept se pojavljuje kao `process.noNewPrivileges`.

## Important Nuances

`no_new_privs` blokira **dobijanje privilegija tokom exec-a**, ali ne svaku promenu privilegija. Konkretno:

- setuid i setgid tranzicije prestaju da rade kroz `execve()`
- file capabilities ne dodaju privilegije u permitted set pri `execve()`
- LSM-ovi kao što su AppArmor ili SELinux ne ublažavaju ograničenja nakon `execve()`
- privilegija koja je već posedovana i dalje ostaje posedovana

Ova poslednja tačka je operativno važna. Ako proces već radi kao root, već poseduje opasnu capability ili već ima pristup moćnom runtime API-ju ili writable host mount-u, postavljanje `no_new_privs` ne neutralizuje te exposure-e. Ono samo uklanja jedan uobičajeni **sledeći korak** u privilege-escalation chain-u.

Takođe imajte u vidu da flag ne blokira promene privilegija koje ne zavise od `execve()`. Na primer, task koji već ima dovoljno privilegija i dalje može direktno pozvati `setuid(2)` ili primiti privilegovani file descriptor preko Unix socket-a. Zato `no_new_privs` treba posmatrati zajedno sa [seccomp](seccomp.md), capability set-ovima i izloženošću namespace-ova, a ne kao samostalno rešenje.

## Lab

Proverite trenutno stanje procesa:
```bash
grep NoNewPrivs /proc/self/status
```
Uporedite to sa kontejnerom u kojem runtime omogućava zastavicu:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Na hardenovanom workload-u, rezultat treba da prikaže `NoNewPrivs: 1`.

Stvarni efekat možete demonstrirati i nad setuid binary-jem:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
Poenta poređenja nije u tome da je `su` univerzalno exploitable. Poenta je da se ista image može ponašati veoma različito u zavisnosti od toga da li je `execve()` i dalje dozvoljen da pređe granicu privilegija.

## Bezbednosni uticaj

Ako `no_new_privs` nije postavljen, foothold unutar containera i dalje može biti unapređen pomoću setuid helpera ili binarnih fajlova sa file capabilities. Ako je postavljen, te promene privilegija nakon exec-a su onemogućene. Efekat je naročito relevantan kod širokih base image-ova koji sadrže mnoge utilities-e koje aplikaciji uopšte nisu bile potrebne.

Postoji i važna interakcija sa seccomp-om. Unprivileged tasks uglavnom moraju imati podešen `no_new_privs` pre nego što mogu da instaliraju seccomp filter u filter mode-u. To je jedan od razloga zbog kojih hardened containers često istovremeno imaju omogućene `Seccomp` i `NoNewPrivs`. Iz perspektive napadača, prisustvo oba obično znači da je okruženje namerno konfigurisano, a ne slučajno.

## Pogrešne konfiguracije

Najčešći problem je jednostavno neomogućavanje ove kontrole u okruženjima u kojima bi bila kompatibilna. U Kubernetes-u, ostavljanje opcije `allowPrivilegeEscalation` omogućene često predstavlja podrazumevanu operativnu grešku. U Docker-u i Podman-u, izostavljanje relevantne security opcije ima isti efekat. Još jedan čest način nastanka problema jeste pretpostavka da su, zato što container nije "privileged", promene privilegija tokom exec-a automatski irelevantne.

Suptilniji Kubernetes problem je to što se `allowPrivilegeEscalation: false` **ne poštuje na način koji ljudi očekuju** kada je container `privileged` ili kada ima `CAP_SYS_ADMIN`. Kubernetes API navodi da je `allowPrivilegeEscalation` u tim slučajevima efektivno uvek true. U praksi, to znači da ovo polje treba posmatrati kao jedan signal u konačnom stanju, a ne kao garanciju da je runtime završio sa `NoNewPrivs: 1`.

## Zloupotreba

Ako `no_new_privs` nije postavljen, prvo pitanje je da li image sadrži binarne fajlove koji i dalje mogu da podignu nivo privilegija:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Zanimljivi rezultati obuhvataju:

- `NoNewPrivs: 0`
- setuid helpers kao što su `su`, `mount`, `passwd` ili administrativni alati specifični za distribuciju
- binaries sa file capabilities koje dodeljuju network ili filesystem privileges

U realnoj proceni, ovi nalazi sami po sebi ne dokazuju funkcionalnu eskalaciju, ali precizno identifikuju binaries koje vredi sledeće testirati.

U Kubernetes-u takođe proverite da li se YAML namera poklapa sa stvarnim stanjem kernela:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Interesting kombinacije uključuju:

- `allowPrivilegeEscalation: false` u Pod spec-u, ali `NoNewPrivs: 0` u container-u
- prisutan `cap_sys_admin`, zbog čega je Kubernetes polje znatno manje pouzdano
- `Seccomp: 0` i `NoNewPrivs: 0`, što obično ukazuje na široko oslabljenu runtime konfiguraciju, a ne na jednu izolovanu grešku

### Kompletan primer: In-Container Privilege Escalation Through setuid

Ova kontrola obično sprečava **in-container privilege escalation**, a ne direktan host escape. Ako je `NoNewPrivs` `0` i postoji setuid helper, eksplicitno ga testirajte:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Ako je poznata setuid binarna datoteka prisutna i funkcionalna, pokušajte da je pokrenete na način koji očuvava prelazak privilegija:
```bash
/bin/su -c id 2>/dev/null
```
Ovo samo po sebi ne omogućava escape iz containera, ali može pretvoriti foothold sa niskim privilegijama unutar containera u container-root, što često postaje preduslov za kasniji escape na host kroz mount-ove, runtime sockets ili interfejse koji komuniciraju sa kernelom.

## Provere

Cilj ovih provera jeste da se utvrdi da li je sticanje privilegija tokom izvršavanja blokirano i da li image i dalje sadrži pomoćne alate koji bi bili relevantni ako nije.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
Šta je ovde interesantno:

- `NoNewPrivs: 1` je obično bezbedniji rezultat.
- `NoNewPrivs: 0` znači da setuid i file-cap putanje za escalation i dalje ostaju relevantne.
- `NoNewPrivs: 1` zajedno sa `Seccomp: 2` čest je znak namernije hardening konfiguracije.
- Kubernetes manifest koji navodi `allowPrivilegeEscalation: false` je koristan, ali status kernela predstavlja stvarno stanje.
- Minimalni image sa malo ili nimalo setuid/file-cap binarnih datoteka napadaču daje manje post-exploitation opcija, čak i kada `no_new_privs` nedostaje.

## Podrazumevane postavke runtime-a

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Podrazumevano nije omogućen | Eksplicitno se omogućava pomoću `--security-opt no-new-privileges=true`; podrazumevana postavka na nivou daemon-a takođe postoji preko `dockerd --no-new-privileges` | izostavljanje flag-a, `--privileged` |
| Podman | Podrazumevano nije omogućen | Eksplicitno se omogućava pomoću `--security-opt no-new-privileges` ili ekvivalentne security konfiguracije | izostavljanje opcije, `--privileged` |
| Kubernetes | Kontroliše ga workload policy | `allowPrivilegeEscalation: false` zahteva ovaj efekat, ali `privileged: true` i `CAP_SYS_ADMIN` ga efektivno zadržavaju uključenim | `allowPrivilegeEscalation: true`, `privileged: true`, dodavanje `CAP_SYS_ADMIN` |
| containerd / CRI-O pod Kubernetes-om | Prati Kubernetes workload postavke / OCI `process.noNewPrivileges` | Obično se nasleđuje iz Pod security context-a i prevodi u OCI runtime konfiguraciju | isto kao u Kubernetes redu |

Ova zaštita često nedostaje jednostavno zato što je niko nije uključio, a ne zato što je runtime ne podržava.

## Reference

- [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
