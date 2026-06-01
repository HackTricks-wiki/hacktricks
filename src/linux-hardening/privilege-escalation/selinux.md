# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux je sistem **Mandatory Access Control (MAC)** zasnovan na oznakama. U praksi, to znači da čak i ako DAC dozvole, grupe ili Linux capabilities izgledaju dovoljni za neku radnju, kernel je i dalje može odbiti jer **source context** nema dozvolu da pristupi **target context** sa traženom class/permission.

Kontekst obično izgleda ovako:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Iz perspektive privesc-a, `type` (domain za procese, type za objekte) je obično najvažnije polje:

- Proces radi u **domain** kao što su `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Datoteke i socketi imaju **type** kao što su `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Policy odlučuje da li jedan domain može da read/write/execute/transition to the drugi

## Fast Enumeration

Ako je SELinux enabled, enumeriši ga rano jer može da objasni zašto uobičajene Linux privesc putanje fail-uju ili zašto je privileged wrapper oko "harmless" SELinux tool-a zapravo critical:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Korisne naknadne provere:
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

- `Disabled` ili `Permissive` režim uklanja najveći deo vrednosti SELinux-a kao granice.
- `unconfined_t` obično znači da je SELinux prisutan, ali ne ograničava taj proces na smislen način.
- `default_t`, `file_t`, ili očigledno pogrešne oznake na prilagođenim putanjama često ukazuju na pogrešno označavanje ili nepotpunu implementaciju.
- Lokalni override-i u `file_contexts.local` imaju prednost nad podrazumevanim policy vrednostima, pa ih pažljivo pregledaj.

## Policy Analysis

SELinux je mnogo lakše napasti ili zaobići kada možeš da odgovoriš na dva pitanja:

1. **Šta moj trenutni domain može da pristupi?**
2. **U koje domain-e mogu da pređem?**

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
Ovo je posebno korisno kada host koristi **confined users** umesto mapiranja svih na `unconfined_u`. U tom slučaju, tražite:

- user mappings preko `semanage login -l`
- dozvoljene roles preko `semanage user -l`
- dostupne admin domains kao što su `sysadm_t`, `secadm_t`, `webadm_t`
- `sudoers` unose koji koriste `ROLE=` ili `TYPE=`

Ako `sudo -l` sadrži unose poput ovih, SELinux je deo privilege boundary:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Takođe proverite da li je `newrole` dostupan:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` i `newrole` nisu automatski exploitable, ali ako privilegovani wrapper ili `sudoers` pravilo omogućava da izabereš bolji role/type, oni postaju visoko vredni escalation primitives.

## Files, Relabeling, and High-Value Misconfigurations

Najvažnija operativna razlika između uobičajenih SELinux alata je:

- `chcon`: privremena promena label-a na određenoj path
- `semanage fcontext`: trajno path-to-label pravilo
- `restorecon` / `setfiles`: ponovo primeni policy/default label

Ovo je veoma važno tokom privesc jer **relabeling nije samo kozmetika**. Može da pretvori fajl iz "blocked by policy" u "readable/executable by a privileged confined service".

Proveri local relabel rules i relabel drift:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Jedan suptilan, ali koristan detalj: običan `restorecon` **ne vraća uvek potpuno sumnjivu oznaku**. Ako je target type u `customizable_types`, možda će ti trebati `-F` da prisiliš potpuno resetovanje. Sa ofanzivne strane, ovo objašnjava zašto neobičan `chcon` ponekad može da preživi površno čišćenje tipa „već smo pokrenuli restorecon“.
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Komande visoke vrednosti za traženje u `sudo -l`, root wrapperima, automatizacionim skriptama ili file capabilities:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Ako se pojavi bilo koja MAC capability, proveri i [Linux capabilities page](linux-capabilities.md); `cap_mac_admin` i `cap_mac_override` su neobične, ali direktno relevantne kada je SELinux deo granice.

Posebno zanimljivo:

- `semanage fcontext`: trajno menja koji label treba da dobije putanja
- `restorecon` / `setfiles`: ponovo primenjuju te promene u velikom obimu
- `semodule -i`: učitava custom policy modul
- `semanage permissive -a <domain_t>`: čini jedan domain permissive bez menjanja celog hosta
- `setsebool -P`: trajno menja policy booleans
- `load_policy`: ponovo učitava aktivnu policy

Ovo su često **helper primitives**, a ne samostalni root exploits. Njihova vrednost je u tome što ti omogućavaju da:

- učiniš target domain permissive
- proširiš access između svog domaina i zaštićenog type-a
- relabel-uješ fajlove pod kontrolom napadača tako da ih privilegovani servis može čitati ili izvršavati
- dovoljno oslabiš confined servis da postojeći local bug postane exploitable

Primeri provera:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Ako možete da učitate policy module kao root, obično kontrolišete SELinux boundary:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Zato `audit2allow`, `semodule` i `semanage permissive` treba tretirati kao osetljive admin surface tokom post-exploitation. Oni mogu tiho da pretvore blokirani chain u funkcionalan, bez menjanja klasičnih UNIX permissions.

## Hidden Denials and Module Extraction

Vrlo česta offensive frustracija je chain koji pada sa običnim `EACCES`, dok očekivano AVC denial nikada ne pojavljuje. `dontaudit` rules mogu da skrivaju tačno permission koji vam treba. Ako možete da pokrenete `semodule` kroz `sudo` ili drugi privileged wrapper, privremeno onemogućavanje `dontaudit` može pretvoriti tihi failure u precizan policy clue:
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Ovo je takođe korisno za pregled šta su lokalni administratori već promenili. Mali custom module ili pravilo sa jednim domenom u permissive režimu je često razlog zbog kog se ciljna usluga ponaša mnogo labavije nego što bi osnovna politika sugerisala.

## Audit Clues

AVC odricanja su često ofanzivan signal, a ne samo defanzivna buka. Govore vam:

- koji target object/type ste pogodili
- koja je permission bila denied
- koji domain trenutno kontrolišete
- da li bi mala promena politike učinila chain funkcionalnim
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Ako lokalni exploit ili pokušaj persistence stalno pada sa `EACCES` ili čudnim "permission denied" greškama uprkos DAC dozvolama koje izgledaju kao root, SELinux obično vredi proveriti pre nego što odbaciš taj vektor.

## SELinux Users

Postoje SELinux users pored uobičajenih Linux users. Svaki Linux user se mapira na SELinux user kao deo policy-ja, što sistemu omogućava da nametne različite dozvoljene roles i domains za različite naloge.

Quick checks:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Na mnogim mainstream sistemima, korisnici su mapirani na `unconfined_u`, što smanjuje praktični uticaj user confinement. Na hardened deploymentima, međutim, confined korisnici mogu učiniti `sudo`, `su`, `newrole`, i `runcon` mnogo zanimljivijim jer **putanja eskalacije može zavisiti od ulaska u bolji SELinux role/type, a ne samo od postajanja UID 0**. Takođe zapamtite da neki confined korisnici uopšte ne mogu da pozovu `sudo`/`su` osim ako policy eksplicitno dozvoljava underlying setuid transition, pa host koji koristi `staff_u` + `sysadm_r` može naizgled minor `sudo ROLE=` / `TYPE=` rule pretvoriti u stvarnu privilege boundary.

## SELinux in Containers

Container runtimes obično pokreću workloads u confined domain-u kao što je `container_t` i označavaju container content kao `container_file_t`. Ako container process pobegne ali i dalje radi sa container label-om, host writes i dalje mogu da fail-uju jer je label boundary ostao netaknut.

Quick example:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Deo `c647,c780` nije dekoracija. U mnogim container deployments, runtimes dinamički dodeljuju MCS categories tako da su dva procesa koja rade kao `container_t` i dalje odvojena jedan od drugog. Ako escape završi tako što si u host namespace, ali zadrži originalni set kategorija, neslaganja kategorija i dalje mogu da objasne zašto neki host putevi ostaju nečitljivi ili neupisivi.

Modern container operations vredne pomena:

- `--security-opt label=disable` može efektivno prebaciti workload na unconfined container-related type kao što je `spc_t`
- bind mounts sa `:z` / `:Z` pokreću relabeling host path-a za shared/private container upotrebu
- široko relabeling host sadržaja može samo po sebi postati security issue

Ova strana drži container sadržaj kratak da bi se izbegla duplikacija. Za container-specific abuse cases i runtime primeri, pogledaj:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## References

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
- [Managing confined and unconfined users - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
