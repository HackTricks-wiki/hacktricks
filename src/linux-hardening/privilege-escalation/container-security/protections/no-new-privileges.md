# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` je kernel hardening feature koja sprečava proces da stekne više privilegija kroz `execve()`. U praksi, kada se flag postavi, izvršavanje setuid binarnog fajla, setgid binarnog fajla, ili fajla sa Linux file capabilities ne daje dodatne privilegije iznad onoga što je proces već imao. U containerized okruženjima, ovo je važno jer se mnogi privilege-escalation lanci oslanjaju na pronalaženje izvršnog fajla unutar image-a koji menja privilegije pri pokretanju.

Sa odbrambenog stanovišta, `no_new_privs` nije zamena za namespaces, seccomp, ili capability dropping. To je sloj pojačanja. Blokira određenu klasu naknadne eskalacije nakon što je code execution već ostvaren. Zbog toga je posebno vredan u okruženjima gde image-i sadrže helper binarne fajlove, package-manager artefakte, ili legacy alate koji bi inače bili opasni u kombinaciji sa delimičnim kompromitovanjem.

## Operation

Kernel flag iza ovog ponašanja je `PR_SET_NO_NEW_PRIVS`. Kada se postavi za proces, kasniji `execve()` pozivi ne mogu povećati privilegije. Važan detalj je da proces i dalje može da pokreće binarne fajlove; jednostavno ne može da ih iskoristi da pređe preko privilege boundary koju bi kernel inače priznao.

Ponašanje kernela je takođe **nasleđeno i nepovratno**: jednom kada task postavi `no_new_privs`, bit se nasleđuje kroz `fork()`, `clone()`, i `execve()`, i ne može se kasnije poništiti. Ovo je korisno u procenama jer jedan `NoNewPrivs: 1` na container procesu obično znači da potomci takođe treba da ostanu u tom modu, osim ako ne gledate potpuno drugačije process tree.

U okruženjima zasnovanim na Kubernetesu, `allowPrivilegeEscalation: false` mapira se na ovo ponašanje za container process. U Docker i Podman stil runtimes, ekvivalent se obično eksplicitno uključuje kroz security option. Na OCI sloju, isti koncept se pojavljuje kao `process.noNewPrivileges`.

## Important Nuances

`no_new_privs` blokira privilege gain u trenutku `execve()`, ali ne i svaku promenu privilegija. Posebno:

- setuid i setgid tranzicije prestaju da rade kroz `execve()`
- file capabilities se ne dodaju u permitted set na `execve()`
- LSMs kao što su AppArmor ili SELinux ne ublažavaju ograničenja nakon `execve()`
- već posedovane privilegije i dalje ostaju već posedovane privilegije

Ta poslednja tačka je operativno važna. Ako proces već radi kao root, već ima opasnu capability, ili već ima pristup moćnom runtime API-ju ili writable host mount-u, postavljanje `no_new_privs` ne neutrališe te izloženosti. Ono samo uklanja jedan uobičajeni **sledeći korak** u privilege-escalation lancu.

Takođe imajte na umu da flag ne blokira promene privilegija koje ne zavise od `execve()`. Na primer, task koji je već dovoljno privilegovan i dalje može direktno da pozove `setuid(2)` ili da primi privilegovani file descriptor preko Unix socket-a. Zbog toga `no_new_privs` treba čitati zajedno sa [seccomp](seccomp.md), capability setovima, i namespace izloženošću, a ne kao samostalno rešenje.

## Lab

Pregledajte trenutno stanje procesa:
```bash
grep NoNewPrivs /proc/self/status
```
Uporedite to sa containerom gde runtime omogućava zastavicu:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Na ojačanom workload-u, rezultat treba da prikaže `NoNewPrivs: 1`.

Takođe možete demonstrirati stvarni efekat na setuid binary:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
Poenta poređenja nije da je `su` univerzalno exploitable. Poenta je da ista slika može da se ponaša veoma različito u zavisnosti od toga da li je `execve()` i dalje dozvoljen da pređe granicu privilegija.

## Security Impact

Ako `no_new_privs` nedostaje, uporište unutar kontejnera i dalje može da se unapredi kroz setuid pomoćne programe ili binarne fajlove sa file capabilities. Ako je prisutan, te post-exec promene privilegija su presečene. Efekat je posebno relevantan u širokim base images koje isporučuju mnogo utilitija koje aplikaciji prvobitno nisu ni bile potrebne.

Postoji i važna seccomp interakcija. Neprivilegovani taskovi uglavnom moraju da imaju postavljen `no_new_privs` pre nego što mogu da instaliraju seccomp filter u filter mode. Ovo je jedan od razloga zašto hardened kontejneri često prikazuju i `Seccomp` i `NoNewPrivs` uključene zajedno. Iz perspektive napadača, ako su obe uključene, to obično znači da je okruženje konfigurisanо namerno, a ne slučajno.

## Misconfigurations

Najčešći problem je jednostavno neuključivanje ove kontrole u okruženjima gde bi bila kompatibilna. U Kubernetes, ostavljanje `allowPrivilegeEscalation` uključenog je često podrazumevana operativna greška. U Docker i Podman, izostavljanje relevantne security opcije ima isti efekat. Još jedan čest propust je pretpostavka da, zato što kontejner nije "privileged", exec-time promene privilegija automatski nisu relevantne.

Suptilnija Kubernetes zamka je da se `allowPrivilegeEscalation: false` **ne** poštuje onako kako ljudi očekuju kada je kontejner `privileged` ili kada ima `CAP_SYS_ADMIN`. Kubernetes API dokumentuje da je `allowPrivilegeEscalation` u tim slučajevima efektivno uvek true. U praksi, to znači da ovo polje treba tretirati kao jedan signal u finalnom posture-u, a ne kao garanciju da je runtime završio sa `NoNewPrivs: 1`.

## Abuse

Ako `no_new_privs` nije postavljen, prvo pitanje je da li slika sadrži binarne fajlove koji i dalje mogu da podignu privilegiju:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Zanimljivi rezultati uključuju:

- `NoNewPrivs: 0`
- setuid helper-e kao što su `su`, `mount`, `passwd`, ili distribucijski specifični admin alati
- binarne fajlove sa file capabilities koji daju mrežne ili filesystem privilegije

U stvarnoj proceni, ovi nalazi sami po sebi ne dokazuju da eskalacija radi, ali tačno identifikuju binarne fajlove koje vredi sledeće testirati.

U Kubernetes, takođe proveri da li se YAML namera poklapa sa stvarnošću kernela:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Zanimljive kombinacije uključuju:

- `allowPrivilegeEscalation: false` u Pod spec ali `NoNewPrivs: 0` u containeru
- `cap_sys_admin` prisutan, što Kubernetes polje čini mnogo manje pouzdanim
- `Seccomp: 0` i `NoNewPrivs: 0`, što obično ukazuje na široko oslabljen runtime posture, a ne na jednu izolovanu grešku

### Full Example: In-Container Privilege Escalation Through setuid

Ova kontrola obično sprečava **in-container privilege escalation** pre nego direktno host escape. Ako je `NoNewPrivs` `0` i postoji setuid helper, testiraj ga eksplicitno:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Ako je poznati setuid binary prisutan i funkcionalan, pokušajte da ga pokrenete na način koji čuva prelazak privilegija:
```bash
/bin/su -c id 2>/dev/null
```
Ovo samo po sebi ne izlazi iz kontejnera, ali može da pretvori foothold sa niskim privilegijama unutar kontejnera u container-root, što često postaje preduslov za kasniji host escape kroz mounts, runtime sockets ili interfejse okrenute ka kernelu.

## Checks

Cilj ovih provera je da se utvrdi da li je exec-time privilege gain blokiran i da li image i dalje sadrži pomoćne alate koji bi bili važni ako nije.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
Šta je zanimljivo ovde:

- `NoNewPrivs: 1` je obično sigurniji rezultat.
- `NoNewPrivs: 0` znači da su setuid i file-cap putanje za eskalaciju i dalje relevantne.
- `NoNewPrivs: 1` plus `Seccomp: 2` je čest znak namernijeg hardening pristupa.
- Kubernetes manifest koji kaže `allowPrivilegeEscalation: false` je koristan, ali kernel status je izvor istine.
- Minimalna image sa malo ili bez setuid/file-cap binarnih fajlova daje napadaču manje post-exploitation opcija čak i kada `no_new_privs` nedostaje.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Not enabled by default | Enabled explicitly with `--security-opt no-new-privileges=true`; daemon-wide default also exists via `dockerd --no-new-privileges` | omitting the flag, `--privileged` |
| Podman | Not enabled by default | Enabled explicitly with `--security-opt no-new-privileges` or equivalent security configuration | omitting the option, `--privileged` |
| Kubernetes | Controlled by workload policy | `allowPrivilegeEscalation: false` requests the effect, but `privileged: true` and `CAP_SYS_ADMIN` keep it effectively true | `allowPrivilegeEscalation: true`, `privileged: true`, adding `CAP_SYS_ADMIN` |
| containerd / CRI-O under Kubernetes | Follows Kubernetes workload settings / OCI `process.noNewPrivileges` | Usually inherited from the Pod security context and translated into OCI runtime config | same as Kubernetes row |

Ova zaštita često izostaje jednostavno zato što je niko nije uključio, a ne zato što runtime ne podržava tu mogućnost.

## References

- [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
