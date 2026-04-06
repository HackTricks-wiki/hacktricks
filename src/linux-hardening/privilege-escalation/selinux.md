# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux je **sistem obavezne kontrole pristupa (Mandatory Access Control, MAC) zasnovan na oznakama**. U praksi to znači da čak i ako DAC permissions, groups ili Linux capabilities izgledaju dovoljne za neku radnju, kernel i dalje može to odbiti zato što **source context** nije ovlašćen da pristupi **target context** sa traženom class/permission.

Kontekst obično izgleda ovako:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Sa aspekta privesc-a, `type` (domen za procese, tip za objekte) je obično najvažnije polje:

- Proces radi u **domenu** kao što su `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Fajlovi i socketi imaju **tip** kao što su `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Politika odlučuje da li jedan domen može čitati/pisati/izvršavati/prelaziti u drugi

## Brza enumeracija

Ako je SELinux omogućen, enumerišite ga rano jer može objasniti zašto uobičajeni Linux privesc putevi ne uspevaju ili zašto privilegovani wrapper oko "bezopasnog" SELinux alata zapravo može biti kritičan:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Korisne dodatne provere:
```bash
# Installed policy modules and local customizations
semodule -lfull 2>/dev/null
semanage fcontext -C -l 2>/dev/null
semanage permissive -l 2>/dev/null
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null

# Labels that frequently reveal mistakes or unusual paths
find / -context '*:default_t:*' -o -context '*:file_t:*' 2>/dev/null

# Compare current label vs policy default for a path
matchpathcon -V /path/of/interest 2>/dev/null
restorecon -n -v /path/of/interest 2>/dev/null
```
Zanimljivi nalazi:

- `Disabled` or `Permissive` mode uklanja većinu vrednosti SELinux-a kao granice.
- `unconfined_t` obično znači da je SELinux prisutan, ali taj proces nije značajno ograničen.
- `default_t`, `file_t`, or obviously wrong labels on custom paths često ukazuju na pogrešno označavanje ili nepotpunu primenu.
- Lokalne izmene u `file_contexts.local` imaju prioritet nad podrazumevanim vrednostima politike, zato ih pažljivo pregledajte.

## Analiza politike

SELinux je mnogo lakše napasti ili zaobići kada možete odgovoriti na dva pitanja:

1. **Do kojih resursa moj trenutni domen ima pristup?**
2. **U koje domene mogu da pređem?**

Najkorisniji alati za ovo su `sepolicy` i **SETools** (`seinfo`, `sesearch`, `sedta`):
```bash
# Transition graph from the current domain
sepolicy transition -s "$(id -Z | awk -F: '{print $3}')" 2>/dev/null

# Search allow and type_transition rules
sesearch -A -s staff_t 2>/dev/null | head
sesearch --type_transition -s staff_t 2>/dev/null | head

# Inspect policy components
seinfo -t 2>/dev/null | head
seinfo -r 2>/dev/null | head
```
Ovo je naročito korisno kada host koristi **ograničene korisnike** umesto mapiranja svih na `unconfined_u`. U tom slučaju, potraži:

- mapiranja korisnika pomoću `semanage login -l`
- dozvoljene uloge pomoću `semanage user -l`
- dostupne administratorske domene kao što su `sysadm_t`, `secadm_t`, `webadm_t`
- `sudoers` unosi koji koriste `ROLE=` ili `TYPE=`

Ako `sudo -l` sadrži unose poput ovih, SELinux je deo granice privilegija:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Takođe proverite da li je `newrole` dostupan:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` i `newrole` nisu automatski iskorišćivi, ali ako privilegovani wrapper ili `sudoers` pravilo dozvoljava da izaberete bolju ulogu/tip, oni postaju primitive visoke vrednosti za eskalaciju privilegija.

## Datoteke, preoznačavanje i visokovredne pogrešne konfiguracije

Najvažnija operativna razlika između uobičajenih SELinux alata je:

- `chcon`: privremena promena oznake na konkretnom putu
- `semanage fcontext`: trajno pravilo putanja->oznaka
- `restorecon` / `setfiles`: ponovo primeni politiku/podrazumevanu oznaku

Ovo je izuzetno važno tokom privesc zato što **preoznačavanje nije samo kozmetičko**. Može promeniti datoteku iz statusa "blocked by policy" u status "readable/executable by a privileged confined service".

Proverite lokalna pravila preoznačavanja i odstupanja u preoznačavanju:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Visoko vredne komande za traženje u `sudo -l`, root wrappers, skriptama za automatizaciju, ili file capabilities:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Posebno zanimljivo:

- `semanage fcontext`: trajno menja koji label putanja treba da primi
- `restorecon` / `setfiles`: ponovo primenjuje te izmene u većem obimu
- `semodule -i`: učitava prilagođeni policy modul
- `semanage permissive -a <domain_t>`: stavlja jedan domain u permissive režim bez menjanja celog hosta
- `setsebool -P`: trajno menja policy booleans
- `load_policy`: ponovo učitava aktivnu policy

Ovo su često **helper primitives**, a ne samostalni root exploits. Njihova vrednost je što vam omogućavaju da:

- stavite ciljnu domain u permissive režim
- proširite pristup između vaše domain i zaštićenog tipa
- relabel attacker-controlled fajlove tako da privilegovana usluga može da ih čita ili izvršava
- oslabite confined service dovoljno da postojeći local bug postane exploitable

Primeri provera:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Ako kao root možete učitati policy modul, obično kontrolišete granicu SELinux-a:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Zato bi `audit2allow`, `semodule` i `semanage permissive` trebalo tretirati kao osetljive admin površine tokom post-exploitation. Oni mogu tiho pretvoriti blokiran lanac u funkcionalan bez menjanja klasičnih UNIX permisija.

## Audit naznake

AVC denials su često ofanzivni signal, a ne samo odbrambeni šum. Oni vam ukazuju:

- koji cilj/objekat ili tip ste pogodili
- koja dozvola je uskraćena
- koji domen trenutno kontrolišete
- da li bi mala izmena politike omogućila da lanac radi
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Ako lokalni exploit ili pokušaj persistence stalno ne uspeva zbog `EACCES` ili čudnih grešaka "permission denied", uprkos DAC dozvolama koje izgledaju kao da su root, obično vredi proveriti SELinux pre nego što odbacite vektor.

## SELinux korisnici

Pored običnih Linux korisnika postoje i SELinux korisnici. Svaki Linux korisnik se mapira na SELinux korisnika kao deo politike, što omogućava sistemu da različitim nalozima nametne različite dozvoljene role i domene.

Brze provere:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
Na mnogim mainstream sistemima, korisnici su mapirani na `unconfined_u`, što smanjuje praktičan uticaj ograničenja korisnika. Na ojačanim deploymentima, međutim, ograničeni korisnici mogu učiniti `sudo`, `su`, `newrole` i `runcon` mnogo zanimljivijim zato što **put eskalacije može zavisiti od ulaska u bolju SELinux ulogu/tip, ne samo od postajanja UID 0**.

## SELinux u kontejnerima

Container runtimes obično pokreću zadatke u ograničenom domenu kao što je `container_t` i označavaju sadržaj kontejnera kao `container_file_t`. Ako proces iz kontejnera pobegne, ali i dalje radi sa oznakom kontejnera, zapisivanje na host može i dalje da ne uspe zato što je granica oznake ostala netaknuta.

Brzi primer:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Vredno je napomenuti moderne operacije sa kontejnerima:

- `--security-opt label=disable` može efektivno premestiti radno opterećenje u unconfined container-related type kao što je `spc_t`
- bind mount-ovi sa `:z` / `:Z` pokreću relabelovanje putanje hosta za deljenu/privatnu upotrebu u kontejneru
- široko relabelovanje sadržaja hosta može samo po sebi postati bezbednosni problem

Ova stranica sadrži kratak sadržaj o kontejnerima kako bi se izbegla duplikacija. Za slučajeve zloupotrebe specifične za kontejnere i primere pri izvršavanju, pogledajte:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## Reference

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
