# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux je **Mandatory Access Control (MAC) sistem zasnovan na oznakama**. U praksi to znači da, čak i ako DAC dozvole, grupe ili Linux capabilities izgledaju dovoljnim za neku radnju, kernel je i dalje može odbiti zato što **source context** nije dozvoljen da pristupi **target context-u** sa zahtevanom klasom/dozvolom.

Context obično izgleda ovako:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Iz perspektive `privesc`, polje `type` (domain za procese, type za objekte) obično je najvažnije:

- Proces se izvršava u **domain** kao što su `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Fajlovi i socket-i imaju **type** kao što su `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Policy odlučuje da li jedan domain može da čita/piše/izvršava/vrši transition ka drugom

## Brza enumeracija

Ako je SELinux omogućen, rano ga enumerišite jer može objasniti zašto uobičajeni Linux privesc putevi ne uspevaju ili zašto je privilegovani wrapper oko naizgled "bezopasnog" SELinux alata zapravo kritičan:
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

- Režim `Disabled` ili `Permissive` uklanja većinu vrednosti SELinux-a kao granice.
- `unconfined_t` obično znači da je SELinux prisutan, ali da praktično ne ograničava taj proces.
- `default_t`, `file_t` ili očigledno pogrešne oznake na prilagođenim putanjama često ukazuju na pogrešno označavanje ili nepotpunu implementaciju.
- Lokalna preklapanja u `file_contexts.local` imaju prednost nad podrazumevanim pravilima policy-ja, zato ih pažljivo pregledajte.

## Analiza policy-ja

SELinux je mnogo lakše napasti ili zaobići kada možete odgovoriti na dva pitanja:

1. **Čemu moj trenutni domen može pristupiti?**
2. **U koje domene mogu preći?**

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
Ovo je posebno korisno kada host koristi **confined users** umesto mapiranja svih korisnika na `unconfined_u`. U tom slučaju proverite:

- mapiranja korisnika putem `semanage login -l`
- dozvoljene uloge putem `semanage user -l`
- dostupne administratorske domene kao što su `sysadm_t`, `secadm_t`, `webadm_t`
- `sudoers` unose koji koriste `ROLE=` ili `TYPE=`

Ako `sudo -l` sadrži unose poput ovog, SELinux je deo granice privilegija:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Takođe proverite da li je `newrole` dostupan:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` i `newrole` nisu automatski exploitable, ali ako privileged wrapper ili `sudoers` pravilo omogućavaju izbor bolje role/type, postaju high-value escalation primitives.

## Fajlovi, relabeling i high-value misconfigurations

Najvažnija operativna razlika između uobičajenih SELinux alata je:

- `chcon`: privremena promena label-a na određenoj putanji
- `semanage fcontext`: persistent path-to-label pravilo
- `restorecon` / `setfiles`: ponovna primena policy/default label-a

Ovo je veoma važno tokom privesc-a zato što **relabeling nije samo kozmetička promena**. Može pretvoriti fajl iz statusa „blokiran policy-jem” u fajl koji je „čitljiv/izvršiv od strane privileged confined service-a”.

Proverite lokalna relabel pravila i relabel drift:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Jedan suptilan, ali koristan detalj: običan `restorecon` **ne vraća uvek u potpunosti sumnjivu oznaku**. Ako se ciljni tip nalazi u `customizable_types`, možda ćete morati da koristite `-F` kako biste prinudno izvršili potpuno resetovanje. Iz ofanzivne perspektive, ovo objašnjava zašto neuobičajeni `chcon` ponekad može da preživi površno čišćenje uz komentar „već smo pokrenuli restorecon“.
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Komande visoke vrednosti koje treba tražiti u `sudo -l`, root wrappers, automation skriptama ili file capabilities:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Ako se pojavi bilo koja MAC capability, proverite i [Linux capabilities page](linux-capabilities.md); `cap_mac_admin` i `cap_mac_override` su neuobičajene, ali direktno relevantne kada je SELinux deo granice.

Posebno su interesantni:

- `semanage fcontext`: persistentno menja koju labelu putanja treba da dobije
- `restorecon` / `setfiles`: ponovo primenjuju te izmene u velikom obimu
- `semodule -i`: učitava prilagođeni policy module
- `semanage permissive -a <domain_t>`: čini jedan domain permissive bez promene celog hosta
- `setsebool -P`: trajno menja policy booleans
- `load_policy`: ponovo učitava aktivni policy

Ovo su često **helper primitives**, a ne samostalni root exploits. Njihova vrednost je u tome što vam omogućavaju da:

- učinite ciljni domain permissive
- proširite pristup između svog domain-a i zaštićenog type-a
- ponovo označite files pod kontrolom attackera tako da privileged service može da ih čita ili izvršava
- oslabite confined service dovoljno da postojeći lokalni bug postane exploitable

Primeri provera:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Ako kao root možete da učitate policy module, obično kontrolišete SELinux granicu:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Zato `audit2allow`, `semodule` i `semanage permissive` treba da se tretiraju kao osetljive administratorske površine tokom post-exploitation faze. Oni mogu neprimetno pretvoriti blokirani lanac u funkcionalan, bez menjanja klasičnih UNIX dozvola.

## Skrivene zabrane i izdvajanje modula

Veoma česta frustracija u ofanzivnom radu jeste lanac koji neuspešno završava sa nejasnim `EACCES`, dok se očekivana AVC zabrana nikada ne pojavi. Pravila `dontaudit` možda skrivaju upravo dozvolu koja vam je potrebna. Ako možete da pokrenete `semodule` preko `sudo` ili drugog privilegovanog wrapper-a, privremeno onemogućavanje `dontaudit` može pretvoriti tihi neuspeh u precizan trag o policy-ju:
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Ovo je takođe korisno za proveru onoga što su lokalni administratori već izmenili. Mali prilagođeni modul ili permissive pravilo za jedan domen često su razlog zbog kog se ciljana usluga ponaša mnogo manje restriktivno nego što bi osnovna policy sugerisala.

## Tragovi za audit

AVC denials su često ofanzivni signal, a ne samo defanzivni šum. Oni vam govore:

- koji ciljni objekat/tip ste pogodili
- koja permission je odbijena
- kojim domenom trenutno upravljate
- da li bi mala izmena policy-ja omogućila da chain funkcioniše
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Ako lokalni exploit ili pokušaj persistence-a stalno ne uspeva uz `EACCES` ili neobične greške „permission denied“, iako DAC permissions izgledaju kao da pripadaju root-u, SELinux obično vredi proveriti pre nego što odbacite taj vektor.

## SELinux korisnici

Pored standardnih Linux korisnika postoje i SELinux korisnici. Svaki Linux korisnik se, u okviru policy-ja, mapira na SELinux korisnika, što sistemu omogućava da različitim nalozima dodeli različite dozvoljene role i domene.

Brze provere:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Na mnogim mainstream sistemima, korisnici se mapiraju na `unconfined_u`, što smanjuje praktičan uticaj ograničavanja korisnika. Međutim, u hardened deployment-ima, ograničeni korisnici mogu učiniti `sudo`, `su`, `newrole` i `runcon` mnogo interesantnijim, jer **escalation path može zavisiti od ulaska u bolju SELinux rolu/tip, a ne samo od postajanja UID 0**. Takođe imajte na umu da neki ograničeni korisnici uopšte ne mogu da pozovu `sudo`/`su` osim ako policy izričito ne dozvoljava osnovni setuid transition, pa host koji koristi `staff_u` + `sysadm_r` može naizgled beznačajno `sudo ROLE=` / `TYPE=` pravilo pretvoriti u stvarnu privilege granicu.

## SELinux u kontejnerima

Container runtimes obično pokreću workload-e u ograničenom domain-u, kao što je `container_t`, i označavaju sadržaj kontejnera kao `container_file_t`. Ako container process izvrši escape, ali i dalje radi sa container label-om, upisivanje na hostu i dalje može biti neuspešno jer je label boundary ostao netaknut.

Brzi primer:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Deo `c647,c780` nije dekoracija. U mnogim container deployment-ima, runtime-ovi dinamički dodeljuju MCS kategorije tako da dva procesa koji rade kao `container_t` i dalje budu međusobno izolovana. Ako escape dospe u host namespace, ali zadrži originalni skup kategorija, neusklađenosti kategorija i dalje mogu objasniti zašto neke host putanje ostaju nečitljive ili neupisive.

Vredi napomenuti sledeće moderne container operacije:

- `--security-opt label=disable` može efektivno prebaciti workload u unconfined container-related tip, kao što je `spc_t`
- bind mount-ovi sa `:z` / `:Z` pokreću ponovno označavanje host putanje za shared/private container upotrebu
- široko ponovno označavanje host sadržaja samo po sebi može postati security issue

Ova stranica održava kratak sadržaj o container-ima kako bi se izbeglo dupliranje. Za abuse slučajeve specifične za container-e i runtime primere, pogledajte:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## Reference

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
- [Managing confined and unconfined users - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
