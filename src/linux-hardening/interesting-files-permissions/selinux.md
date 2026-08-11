# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux je **Mandatory Access Control (MAC)** sistem zasnovan na oznakama. U praksi, to znači da čak i ako DAC dozvole, grupe ili Linux capabilities deluju dovoljnim za neku radnju, kernel je i dalje može odbiti jer **source context** nema dozvolu da pristupi **target context**-u sa zahtevom za datu klasu/dozvolu.<sup>[[1]](#references)</sup>

Kontekst obično izgleda ovako:<sup>[[1]](#references)</sup>
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Iz perspektive privesc-a, `type` (domain za procese, type za objekte) je obično najvažnije polje:<sup>[[1]](#references)</sup>

- Proces se izvršava u **domain-u**, kao što su `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Fajlovi i socket-i imaju **type**, kao što su `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Policy odlučuje da li jedan domain može da čita/piše/izvršava ili prelazi u drugi

## Brza enumeracija

Ako je SELinux omogućen, enumerišite ga rano jer može objasniti zašto uobičajeni Linux privesc putevi ne uspevaju ili zašto je privilegovani wrapper oko „bezopasnog“ SELinux alata zapravo kritičan:<sup>[[1]](#references)</sup>
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Korisne naknadne provere:<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>
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
Zanimljiva zapažanja:<sup>[[1]](#references)[[3]](#references)[[7]](#references)[[19]](#references)</sup>

- Režim `Disabled` ili `Permissive` uklanja većinu vrednosti SELinux-a kao granice.
- `unconfined_t` obično znači da je SELinux prisutan, ali da ne ograničava taj proces na smislen način.
- `default_t`, `file_t` ili očigledno pogrešne oznake na prilagođenim putanjama često ukazuju na pogrešno označavanje ili nepotpunu implementaciju.
- Lokalna preusmeravanja u `file_contexts.local` imaju prednost nad podrazumevanim pravilima, zato ih pažljivo pregledajte.

## Analiza pravila

SELinux je mnogo lakše napasti ili zaobići kada možete odgovoriti na dva pitanja:

1. **Čemu moj trenutni domen može pristupiti?**
2. **U koje domene mogu da pređem?**

Najkorisniji alati za ovo su `sepolicy` i **SETools** (`seinfo`, `sesearch`, `sedta`):<sup>[[2]](#references)[[9]](#references)</sup>
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
Ovo je naročito korisno kada host koristi **confined users** umesto mapiranja svih korisnika na `unconfined_u`. U tom slučaju potražite:<sup>[[3]](#references)</sup>

- mapiranja korisnika pomoću `semanage login -l`
- dozvoljene role pomoću `semanage user -l`
- dostupne admin domene kao što su `sysadm_t`, `secadm_t`, `webadm_t`
- unose u `sudoers` koji koriste `ROLE=` ili `TYPE=`

Ako `sudo -l` sadrži unose poput ovog, SELinux je deo granice privilegija:<sup>[[3]](#references)</sup>
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Takođe proverite da li je `newrole` dostupan:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` i `newrole` nisu automatski exploitable, ali ako privilegovani wrapper ili `sudoers` pravilo omogućava izbor bolje role/type, postaju high-value escalation primitive.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

## Datoteke, Relabeling i High-Value Misconfigurations

Najvažnija operativna razlika između uobičajenih SELinux alata je:<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: privremena promena label-a na konkretnoj putanji
- `semanage fcontext`: trajno pravilo za mapiranje putanje na label
- `restorecon` / `setfiles`: ponovna primena policy/default label-a

Ovo je veoma važno tokom privesc-a jer **relabeling nije samo kozmetički**. Može pretvoriti datoteku iz „blokirane policy-jem“ u „čitljivu/izvršivu za privilegovani confined service“.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Proverite lokalna pravila za relabeling i odstupanja u relabeling-u:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Jedan suptilan, ali koristan detalj: običan `restorecon` **ne vraća uvek u potpunosti sumnjivu oznaku**. Ako se ciljni tip nalazi u `customizable_types`, možda će biti potrebna opcija `-F` kako bi se nametnulo potpuno resetovanje. Iz ofanzivne perspektive, ovo objašnjava zašto neobičan `chcon` ponekad može da preživi površno čišćenje nakon poruke „već smo pokrenuli restorecon“.<sup>[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Komande velike vrednosti za pretragu u `sudo -l`, root wrapperima, skriptama za automatizaciju ili capabilities datoteka:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Ako se pojavi bilo koja MAC capability, proverite i [Linux capabilities page](linux-capabilities.md); dokumentacija za Linux capabilities opisuje `cap_mac_admin` i `cap_mac_override` kao specifične za Smack, zato nemojte pretpostaviti da njihovi nazivi sami po sebi zaobilaze SELinux.<sup>[[5]](#references)</sup>

Posebno su zanimljivi:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: trajno menja koju label putanja treba da dobije
- `restorecon` / `setfiles`: ponovo primenjuju te izmene u velikom obimu
- `semodule -i`: učitava prilagođeni policy modul
- `semanage permissive -a <domain_t>`: čini jedan domain permissive, bez promene celog hosta
- `setsebool -P`: trajno menja policy booleans
- `load_policy`: ponovo učitava aktivni policy

Ovo su često **helper primitives**, a ne samostalni root exploits. Njihova vrednost je u tome što vam omogućavaju da:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- učinite ciljni domain permissive
- proširite pristup između svog domain-a i zaštićenog type-a
- ponovo dodelite label datotekama pod kontrolom napadača kako bi privilegovani servis mogao da ih čita ili izvršava
- oslabite confined servis dovoljno da postojeći lokalni bug postane exploitable

Primeri provera:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Ako možete učitati modul politike kao root, obično kontrolišete SELinux granicu:<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Zato `audit2allow`, `semodule` i `semanage permissive` treba smatrati osetljivim administratorskim površinama tokom post-exploitation aktivnosti. Oni mogu nečujno pretvoriti blokirani lanac u funkcionalan, bez menjanja klasičnih UNIX dozvola.<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## Skrivene zabrane i ekstrakcija modula

Veoma česta frustracija u offensive radu jeste lanac koji se završava neodređenim `EACCES`, dok se očekivana AVC zabrana nikada ne pojavi. Pravila `dontaudit` možda skrivaju upravo dozvolu koja vam je potrebna. Ako možete da pokrenete `semodule` putem `sudo` ili drugog privilegovanog wrapper-a, privremeno onemogućavanje `dontaudit` može tihi neuspeh pretvoriti u preciznu naznaku policy-ja:<sup>[[4]](#references)[[15]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Ovo je takođe korisno za proveru onoga što su lokalni administratori već promenili. Mali prilagođeni modul ili permissive pravilo za jedan domen često su razlog zbog kog se ciljana usluga ponaša mnogo manje restriktivno nego što bi osnovna policy sugerisala.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Tragovi za audit

AVC denials su često napadački signal, a ne samo odbrambeni šum. Govore vam:<sup>[[1]](#references)[[15]](#references)</sup>

- koji ciljani objekat/tip ste pogodili
- koja permission je odbijena
- kojim domenom trenutno upravljate
- da li bi mala izmena policy-ja omogućila da lanac funkcioniše
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Ako lokalni exploit ili pokušaj persistence-a stalno ne uspeva sa `EACCES` ili neobičnim greškama „permission denied“, uprkos DAC dozvolama koje izgledaju kao root, obično vredi proveriti SELinux pre nego što odbacite ovaj vektor.<sup>[[1]](#references)</sup>

## SELinux Users

Pored standardnih Linux korisnika postoje i SELinux korisnici. Svaki Linux korisnik je u okviru policy-ja mapiran na SELinux korisnika, što sistemu omogućava da nametne različite dozvoljene uloge i domene za različite naloge.<sup>[[3]](#references)</sup>

Brze provere:<sup>[[3]](#references)</sup>
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Na mnogim glavnim sistemima, korisnici se mapiraju na `unconfined_u`, što umanjuje praktični uticaj ograničavanja korisnika. Međutim, u ojačanim deploymentima, ograničeni korisnici mogu učiniti `sudo`, `su`, `newrole` i `runcon` mnogo zanimljivijim, jer **putanja eskalacije može zavisiti od ulaska u odgovarajuću SELinux ulogu/tip, a ne samo od postajanja UID 0**. Takođe imajte na umu da neki ograničeni korisnici uopšte ne mogu da pozovu `sudo`/`su` osim ako policy izričito ne dozvoli osnovni setuid transition, pa host koji koristi `staff_u` + `sysadm_r` može naizgled beznačajno `sudo ROLE=` / `TYPE=` pravilo pretvoriti u stvarnu granicu privilegija.<sup>[[3]](#references)</sup>

## SELinux u kontejnerima

Container runtimes obično pokreću workloads u ograničenom domainu kao što je `container_t` i označavaju sadržaj kontejnera kao `container_file_t`. Ako proces kontejnera izvrši escape, ali i dalje radi sa container labelom, upis na hostu i dalje može biti neuspešan jer je granica labela ostala očuvana.<sup>[[1]](#references)[[17]](#references)</sup>

Kratak primer:<sup>[[16]](#references)[[18]](#references)</sup>
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Deo `c647,c780` nije dekoracija. U mnogim container deploymentima, runtime-i dinamički dodeljuju MCS kategorije kako bi dva procesa koja rade kao `container_t` i dalje bila međusobno odvojena. Ako escape dospe u host namespace, ali zadrži originalni skup kategorija, nepodudaranja kategorija i dalje mogu objasniti zašto neki host paths ostaju nečitljivi ili neupisivi.<sup>[[17]](#references)</sup>

Savremene container operacije koje vredi pomenuti:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` isključuje SELinux label separation za container
- bind mounts sa `:z` / `:Z` pokreću ponovno označavanje host path-a za shared/private container upotrebu
- široko ponovno označavanje host sadržaja samo po sebi može postati security issue

Ova stranica zadržava kratak sadržaj o containerima kako bi se izbeglo dupliciranje. Za abuse slučajeve specifične za containere i runtime primere pogledajte:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## References

- [1] [Red Hat dokumentacija: Korišćenje SELinux-a](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Alati za analizu policy-ja za SELinux](https://github.com/SELinuxProject/setools)
- [3] [Upravljanje ograničenim i neograničenim korisnicima - RHEL 9 dokumentacija](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - Linux man stranica](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) - Linux man stranica](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) - Linux man stranica](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) - Linux man stranica](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) - Linux man stranica](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) - Linux man stranica](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) - Linux man stranica](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) - Linux man stranica](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) - Linux man stranica](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) - Linux man stranica](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) - Linux man stranica](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) - Linux man stranica](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Podman run dokumentacija](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [Zašto bi trebalo da koristite Multi-Category Security za svoje Linux containere](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Podman top dokumentacija](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - Linux man stranica](https://man7.org/linux/man-pages/man8/selinux.8.html)
{{#include ../../banners/hacktricks-training.md}}
