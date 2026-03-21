# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` je mehanizam za učvršćivanje kernela koji sprečava proces da dobije više privilegija preko `execve()`. U praktičnom smislu, kada je zastavica postavljena, izvršavanje setuid binarnog fajla, setgid binarnog fajla, ili fajla sa Linux file capabilities ne daje dodatne privilegije iznad onih koje je proces već imao. U kontejnerizovanim okruženjima, ovo je važno zato što se mnogi privilege-escalation lanci oslanjaju na pronalaženje izvršnog fajla unutar image koji menja privilegije pri pokretanju.

Iz odbrambene perspektive, `no_new_privs` nije zamena za namespaces, seccomp, ili capability dropping. To je sloj ojačanja. On blokira specifičnu klasu daljih eskalacija nakon što je izvršenje koda već ostvareno. Zbog toga je posebno vredan u okruženjima gde image sadrže helper binaries, package-manager artifacts, ili legacy alate koji bi inače bili opasni kada se kombinuju sa delimičnim kompromitovanjem.

## Operacija

Kernel zastavica iza ovog ponašanja je `PR_SET_NO_NEW_PRIVS`. Kada je ona postavljena za proces, kasniji `execve()` pozivi ne mogu povećati privilegije. Bitan detalj je da proces i dalje može pokretati binarne fajlove; jednostavno ne može koristiti te binarne da pređe privilegijsku granicu koju bi kernel inače priznao.

U okruženjima orijentisanim na Kubernetes, `allowPrivilegeEscalation: false` odgovara ovom ponašanju za proces kontejnera. U runtime-ima tipa Docker i Podman, ekvivalent se obično eksplicitno omogućava kroz sigurnosnu opciju.

## Vežba

Pregledajte trenutno stanje procesa:
```bash
grep NoNewPrivs /proc/self/status
```
Uporedite to sa containerom gde runtime omogućava flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
On a hardened workload, the result should show `NoNewPrivs: 1`.

## Sigurnosni uticaj

Ako `no_new_privs` nedostaje, foothold unutar container-a može i dalje biti eskaliran kroz setuid helper-e ili binarije sa file capabilities. Ako je prisutan, te post-exec promene privilegija se prekidaju. Efekat je naročito značajan u širokim base image-ovima koji isporučuju mnoge utilite koje aplikacija uopšte nije trebala.

## Pogrešne konfiguracije

Najčešći problem je jednostavno neaktiviranje ove kontrole u okruženjima gde bi bila kompatibilna. U Kubernetes, ostavljanje `allowPrivilegeEscalation` omogućеним često je podrazumevana operativna greška. U Docker i Podman, izostavljanje relevantne bezbednosne opcije ima isti efekat. Još jedan ponavljajući način greške je pretpostavka da zato što kontejner nije "privileged", exec-time prelazi privilegija automatski nisu relevantni.

## Zloupotreba

Ako `no_new_privs` nije postavljen, prvo pitanje je da li image sadrži binarije koje i dalje mogu podići privilegije:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Zanimljivi nalazi uključuju:

- `NoNewPrivs: 0`
- setuid helpers such as `su`, `mount`, `passwd`, or distribution-specific admin tools
- binaries with file capabilities that grant network or filesystem privileges

U stvarnoj proceni, ovi nalazi sami po sebi ne dokazuju funkcionalan privilege escalation, ali tačno identifikuju koje binarne fajlove vredi testirati sledeće.

### Potpuni primer: In-Container Privilege Escalation Through setuid

Ova kontrola obično sprečava **in-container privilege escalation** više nego direktni host escape. Ako je `NoNewPrivs` `0` i postoji setuid helper, testirajte ga izričito:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Ako postoji poznat i funkcionalan setuid binary, pokušajte ga pokrenuti na način koji sačuva prelaz privilegija:
```bash
/bin/su -c id 2>/dev/null
```
Ovo samo po sebi ne omogućava escape the container, ali može pretvoriti low-privilege foothold unutar containera u container-root, što često postaje preduslov za kasniji host escape kroz mounts, runtime sockets, ili kernel-facing interfaces.

## Provere

Cilj ovih provera je da utvrde da li je exec-time privilege gain blokiran i da li image i dalje sadrži helpers koji bi bili bitni ako nije.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
- `NoNewPrivs: 1` je obično sigurniji rezultat.
- `NoNewPrivs: 0` znači da su setuid i file-cap bazirani putevi eskalacije i dalje relevantni.
- Minimalna image sa malo ili bez setuid/file-cap binarnih fajlova daje napadaču manje opcija za post-exploitation čak i kada `no_new_privs` nedostaje.

## Runtime podrazumevana podešavanja

| Runtime / platform | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Nije omogućen po defaultu | Omogućava se eksplicitno sa `--security-opt no-new-privileges=true` | izostavljanje zastavice, `--privileged` |
| Podman | Nije omogućen po defaultu | Omogućava se eksplicitno sa `--security-opt no-new-privileges` ili ekvivalentnom bezbednosnom konfiguracijom | izostavljanje opcije, `--privileged` |
| Kubernetes | Kontrolisano politikom workload-a | `allowPrivilegeEscalation: false` omogućava efekat; mnogi workload-i i dalje ostavljaju omogućeno | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Prati Kubernetes workload podešavanja | Obično nasleđeno iz Pod security context-a | isto kao red za Kubernetes |

Ova zaštita često nedostaje jednostavno zato što je niko nije uključio, ne zato što runtime nema podršku za nju.
