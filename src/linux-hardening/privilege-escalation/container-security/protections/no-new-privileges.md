# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` je kernel hardening funkcija koja sprečava proces da stekne više privilegija preko `execve()`. U praktičnom smislu, kada je zastavica postavljena, pokretanje setuid binarnog fajla, setgid binarnog fajla, ili fajla sa Linux file capabilities ne dodeljuje dodatne privilegije iznad onoga što je proces već imao. U okruženjima sa kontejnerima ovo je važno zato što se mnogi lanci eskalacije privilegija oslanjaju na pronalaženje izvršnog fajla unutar image-a koji menja privilegije pri pokretanju.

Sa odbrambenog stanovišta, `no_new_privs` nije zamena za namespaces, seccomp, ili capability dropping. To je sloj pojačanja. Blokira specifičnu klasu naknadne eskalacije nakon što je već dobijeno izvršenje koda. Zbog toga je posebno vredan u okruženjima gde image-i sadrže pomoćne binarije, package-manager artefakte, ili legacy alate koji bi inače bili opasni u kombinaciji sa delimičnim kompromitovanjem.

## Operacija

Kernel zastavica iza ovog ponašanja je `PR_SET_NO_NEW_PRIVS`. Kada je postavljena za proces, kasniji pozivi `execve()` ne mogu povećati privilegije. Važan detalj je da proces i dalje može pokretati binarije; jednostavno ne može koristiti te binarije da pređe granicu privilegija koju bi kernel inače poštovao.

U Kubernetes-orijentisanim okruženjima, `allowPrivilegeEscalation: false` mapira na ovo ponašanje za proces u kontejneru. U Docker i Podman style runtimes, ekvivalent je obično eksplicitno omogućen kroz security opciju.

## Lab

Ispitajte trenutno stanje procesa:
```bash
grep NoNewPrivs /proc/self/status
```
Uporedite to sa kontejnerom u kojem runtime omogućava zastavicu:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Na ojačanom radnom opterećenju, rezultat bi trebao da pokaže `NoNewPrivs: 1`.

## Security Impact

Ako `no_new_privs` nije prisutan, kompromitacija unutar containera i dalje može biti unapređena preko setuid helper-a ili binarnih fajlova sa file capabilities. Ako je prisutan, te promene privilegija posle exec-a se preseću. Efekat je posebno relevantan kod širokih osnovnih slika koje isporučuju mnogo utiliteta koje aplikacija nikada nije ni trebala.

## Misconfigurations

Najčešći problem je jednostavno to što se kontrola ne omogućava u okruženjima gde bi bila kompatibilna. U Kubernetesu, ostavljanje `allowPrivilegeEscalation` omogućеним je često podrazumevana operativna greška. U Docker i Podman, izostavljanje odgovarajuće bezbednosne opcije ima isti efekat. Još jedan ponavljajući modul greške je pretpostavka da zato što container nije "not privileged", prelazi privilegija u vreme exec-a automatski nisu relevantni.

## Abuse

Ako `no_new_privs` nije postavljen, prvo pitanje je da li image sadrži binarne fajlove koji i dalje mogu povećati privilegije:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Zanimljivi rezultati uključuju:

- `NoNewPrivs: 0`
- setuid pomoćni programi kao što su `su`, `mount`, `passwd`, ili administrativni alati specifični za distribuciju
- binarni fajlovi sa file capabilities koji dodeljuju network ili filesystem privilegije

U stvarnoj proceni, ovi nalazi sami po sebi ne dokazuju funkcionalnu eskalaciju, ali tačno identifikuju binarne fajlove koje vredi dalje testirati.

### Potpun primer: In-Container Privilege Escalation Through setuid

Ova kontrola obično sprečava **in-container privilege escalation** umesto direktnog host escape. Ako je `NoNewPrivs` `0` i postoji setuid helper, testirajte ga eksplicitno:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Ako je poznati setuid binary prisutan i funkcionalan, pokušajte ga pokrenuti na način koji zadržava prelazak privilegija:
```bash
/bin/su -c id 2>/dev/null
```
Ovo samo po sebi ne omogućava bekstvo iz containera, ali može da pretvori low-privilege foothold unutar containera u container-root, što često postane preduslov za kasnije host escape kroz mounts, runtime sockets, ili kernel-facing interfaces.

## Checks

Cilj ovih provera je da utvrdi da li je exec-time privilege gain blokiran i da li image i dalje sadrži helpers koji bi bili bitni ako nije.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
Zanimljivo ovde:

- `NoNewPrivs: 1` je obično sigurniji rezultat.
- `NoNewPrivs: 0` znači da su putanje eskalacije zasnovane na setuid i file-cap i dalje relevantne.
- Minimalna container image sa malo ili bez setuid/file-cap binarnih fajlova daje napadaču manje post-exploitation opcija čak i kada `no_new_privs` nedostaje.

## Podrazumevana podešavanja runtime-a

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Nije omogućen podrazumevano | Omogućeno eksplicitno pomoću `--security-opt no-new-privileges=true` | izostavljanje zastavice, `--privileged` |
| Podman | Nije omogućen podrazumevano | Omogućeno eksplicitno pomoću `--security-opt no-new-privileges` ili odgovarajuće sigurnosne konfiguracije | izostavljanje opcije, `--privileged` |
| Kubernetes | Kontrolisano politikom workload-a | `allowPrivilegeEscalation: false` omogućava efekat; mnogi workload-i i dalje ga ostavljaju omogućenim | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Sledi podešavanja workload-a iz Kubernetesa | Obično se nasleđuje iz Pod security context-a | isto kao i red za Kubernetes |

Ova zaštita često nedostaje jednostavno zato što je niko nije uključio, a ne zato što runtime ne podržava tu opciju.
{{#include ../../../../banners/hacktricks-training.md}}
