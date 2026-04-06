# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux je **sistem obavezne kontrole pristupa (Mandatory Access Control — MAC) zasnovan na oznakama**. U praksi, to znači da čak i ako DAC dozvole, grupe ili Linux capabilities izgledaju dovoljni za neku akciju, kernel i dalje može odbiti tu akciju jer **source context** nema dozvolu da pristupi **target context** u traženoj klasi/dozvoli.

Kontekst obično izgleda ovako:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Sa privesc perspektive, `type` (domen za procese, tip za objekte) je obično najvažnije polje:

- Proces radi u **domenu** kao što su `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Fajlovi i socketi imaju **tip** kao što su `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Politika odlučuje da li jedan domen može da čita, piše, izvršava ili pređe u drugi

## Brza enumeracija

Ako je SELinux omogućen, enumerišite ga rano jer može objasniti zašto uobičajeni Linux privesc putevi ne uspevaju ili zašto privilegovani wrapper oko "harmless" SELinux alata zapravo može biti kritičan:
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
Zanimljiva zapažanja:

- `Disabled` ili `Permissive` režim uklanja većinu vrednosti SELinux-a kao granice.
- `unconfined_t` obično znači da je SELinux prisutan, ali da taj proces nije značajno ograničen.
- `default_t`, `file_t`, ili očigledno pogrešne oznake na prilagođenim putanjama često ukazuju na pogrešno označavanje ili nepotpunu implementaciju.
- Lokalna prepisivanja u `file_contexts.local` imaju prednost nad podrazumevanim vrednostima politike, zato ih pažljivo pregledajte.

## Analiza politike

SELinux je mnogo lakše napasti ili zaobići kada možete odgovoriti na dva pitanja:

1. **Kojim resursima moj trenutni domen može pristupiti?**
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
Ovo je naročito korisno kada host koristi **confined users** umesto da mapira sve na `unconfined_u`. U tom slučaju, potražite:

- mapiranja korisnika putem `semanage login -l`
- dozvoljene role putem `semanage user -l`
- dostupne administratorske domene kao što su `sysadm_t`, `secadm_t`, `webadm_t`
- `sudoers` unose koji koriste `ROLE=` ili `TYPE=`

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
`runcon` i `newrole` nisu automatski iskorišćivi, ali ako privilegovani wrapper ili `sudoers` pravilo dozvoljavaju da izaberete bolju ulogu/tip, oni postaju visoko vredne escalation primitives.

## Fajlovi, ponovno označavanje i pogrešne konfiguracije velike vrednosti

Najvažnija operativna razlika između uobičajenih SELinux alata je:

- `chcon`: privremena promena oznake na specifičnoj putanji
- `semanage fcontext`: trajno pravilo mapiranja putanje na oznaku
- `restorecon` / `setfiles`: ponovo primeni politiku/podrazumevanu oznaku

Ovo je veoma važno tokom privesc jer **ponovno označavanje nije samo kozmetičko**. Može promeniti fajl iz "blocked by policy" u "readable/executable by a privileged confined service".

Proverite lokalna pravila za ponovno označavanje i odstupanja u označavanju:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Komande visoke vrednosti koje treba tražiti u `sudo -l`, root wrappers, automation scripts, ili file capabilities:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Posebno zanimljivo:

- `semanage fcontext`: persistently changes what label a path should receive
- `restorecon` / `setfiles`: reapplies those changes at scale
- `semodule -i`: loads a custom policy module
- `semanage permissive -a <domain_t>`: makes one domain permissive without flipping the whole host
- `setsebool -P`: permanently changes policy booleans
- `load_policy`: reloads the active policy

Ovo su često **helper primitives**, a ne samostalni root exploits. Njihova vrednost je u tome što vam omogućavaju da:

- postavite ciljni domen u permissive režim
- proširite pristup između vašeg domena i zaštićenog type-a
- ponovo označite (relabel) fajlove kojima upravlja napadač tako da ih privilegovana usluga može pročitati ili izvršiti
- oslabite confined servis dovoljno da postojeći lokalni bug postane iskoristiv

Primeri provera:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Ako možete učitati policy module kao root, obično kontrolišete SELinux granicu:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Zato `audit2allow`, `semodule` i `semanage permissive` treba tretirati kao osetljive administratorske površine tokom post-exploitation. Mogu tiho pretvoriti blokirani lanac u funkcionalan bez menjanja klasičnih UNIX dozvola.

## Naznake audita

AVC denials često predstavljaju ofanzivni signal, a ne samo defanzivnu buku. Pokazuju vam:

- koji ciljni objekat/tip ste pogodili
- koja dozvola je bila odbijena
- koji domen trenutno kontrolišete
- da li bi mala izmena politike učinila lanac funkcionalnim
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Ako local exploit ili persistence attempt stalno pada sa `EACCES` ili čudnim "permission denied" greškama, uprkos root-looking DAC permissions, obično vredi proveriti SELinux pre nego što se vektor odbaci.

## SELinux korisnici

Postoje SELinux korisnici pored običnih Linux korisnika. Svaki Linux korisnik je mapiran na SELinux korisnika u okviru politike, što omogućava sistemu da primeni različite dozvoljene uloge i domene za različite naloge.

Brze provere:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
Na mnogim mainstream sistemima, korisnici su mapirani na `unconfined_u`, što smanjuje praktični uticaj ograničenja korisnika. U ojačanim (hardened) okruženjima, međutim, confined korisnici mogu učiniti `sudo`, `su`, `newrole` i `runcon` mnogo zanimljivijim jer **put eskalacije može zavisiti od ulaska u bolju SELinux rolu/tip, a ne samo od postizanja UID 0**.

## SELinux u kontejnerima

Container runtimes često pokreću workload-e u ograničenom domenu kao što je `container_t` i označavaju sadržaj kontejnera kao `container_file_t`. Ako proces iz kontejnera pobegne ali i dalje radi sa kontejnerskom oznakom, upisi na hostu i dalje mogu da ne uspeju jer je granica oznake ostala netaknuta.

Brzi primer:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Vredno pažnje u modernim operacijama sa kontejnerima:

- `--security-opt label=disable` može efikasno premestiti radno opterećenje u unconfined tip povezan sa kontejnerima, kao što je `spc_t`
- bind mounts sa `:z` / `:Z` pokreću relabelovanje host putanje za deljenu/privatnu upotrebu u kontejneru
- široko relabelovanje sadržaja hosta može samo po sebi postati bezbednosni problem

Ova stranica održava sadržaj o kontejnerima kratkim da bi se izbeglo dupliranje. Za slučajeve zlonamerne upotrebe specifične za kontejnere i primere u runtime-u, pogledajte:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## References

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
