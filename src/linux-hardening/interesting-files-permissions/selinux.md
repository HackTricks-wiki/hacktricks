# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux je **sistem obavezne kontrole pristupa (MAC) zasnovan na oznakama**. U praksi, to znači da čak i ako DAC dozvole, grupe ili Linux capabilities deluju kao da su dovoljne za neku radnju, kernel i dalje može da je zabrani jer **izvorni kontekst** nema dozvolu da pristupi **ciljnom kontekstu** sa traženom klasom/dozvolom.<sup>[[1]](#references)</sup>

Kontekst obično izgleda ovako:<sup>[[1]](#references)</sup>

```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

Sa stanovišta privesc-a, `type` (domen za procese, tip za objekte) obično je najvažnije polje:<sup>[[1]](#references)</sup>

- Proces se izvršava u **domenu** kao što je `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Datoteke i soketi imaju **tip** kao što je `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Politika određuje da li jedan domen može da čita, upisuje, izvršava ili pređe u drugi

## Brza enumeracija

Ako je SELinux omogućen, rano ga enumerišite jer može da objasni zašto uobičajeni Linux privesc putevi ne rade ili zašto je privilegovani omotač oko „bezazlenog“ SELinux alata zapravo kritičan:<sup>[[1]](#references)</sup>

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
- `unconfined_t` obično znači da je SELinux prisutan, ali da ne ograničava značajno taj proces.
- `default_t`, `file_t` ili očigledno pogrešne oznake na prilagođenim putanjama često ukazuju na pogrešno označavanje ili nepotpunu implementaciju.
- Lokalna nadjačavanja u `file_contexts.local` imaju prednost nad podrazumevanim pravilima politike, pa ih pažljivo pregledajte.

## Analiza politike

Mnogo je lakše napasti SELinux ili ga zaobići kada možete da odgovorite na dva pitanja:

1. **Čemu može da pristupi moj trenutni domen?**
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

Ovo je posebno korisno kada host koristi **ograničene korisnike** umesto da sve mapira na `unconfined_u`. U tom slučaju potražite:<sup>[[3]](#references)</sup>

- mapiranja korisnika pomoću `semanage login -l`
- dozvoljene uloge pomoću `semanage user -l`
- dostupne administratorske domene kao što su `sysadm_t`, `secadm_t`, `webadm_t`
- unose u `sudoers` koji koriste `ROLE=` ili `TYPE=`

Ako `sudo -l` sadrži ovakve unose, SELinux je deo granice privilegija:<sup>[[3]](#references)</sup>

```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```

Takođe proverite da li je `newrole` dostupan:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
sudo -l
which newrole runcon
newrole -V 2>/dev/null
```

`runcon` i `newrole` nisu automatski iskoristivi, ali ako vam privilegovani wrapper ili pravilo u `sudoers` omogućava da izaberete bolju ulogu/tip, postaju veoma vredni primitivni alati za eskalaciju.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

### Proverite izvršne tačke tranzicije sa dozvolom za upis

Graf tranzicija samo je smernica za proveru politike. Da biste ga pretvorili u putanju za napad, utvrdite tip izvršne datoteke koji ulazi u korisniji domen, a zatim proverite da li možete da izmenite izvršnu datoteku sa tom oznakom ili da je zamenite preko njenog nadređenog direktorijuma.<sup>[[9]](#references)[[20]](#references)</sup> Za automatsku `execve` tranziciju potrebno je primenljivo pravilo `type_transition`, dozvola za izvršavanje u izvornom domenu, dozvola `entrypoint` u ciljnom domenu i dozvola za tranziciju između domena.<sup>[[20]](#references)</sup> Ciljni domen može dobiti SELinux pristup, ali samo izvršavanje ne menja Linux UID; zasebno proverite [SUID/SGID i ACL-ove](suid-sgid-and-acl-triage.md).<sup>[[20]](#references)[[21]](#references)</sup>

Upotrebite prijavljeni tip `entrypoint` da proverite osnovna pravila, a zatim proverite putanju i njen nadređeni direktorijum da biste utvrdili da li imate dozvolu za upis.<sup>[[9]](#references)[[20]](#references)[[22]](#references)</sup>

```bash
src=$(id -Z | cut -d: -f3)
sepolicy transition -s "$src"                 # Note target domain and entrypoint type
dst=target_t                                   # Substitute a domain from the report
entry=target_exec_t                            # Substitute its entrypoint type
sesearch -T -s "$src" -t "$entry" -c process
sesearch --allow -s "$src" -t "$dst" -c process -p transition
sesearch --allow -s "$src" -t "$entry" -c file -p execute
sesearch --allow -s "$dst" -t "$entry" -c file -p entrypoint
sesearch --allow -s "$src" -t "$entry" -c file -p write
ls -lZ /path/to/entrypoint
namei -l /path/to/entrypoint
getfacl -p /path/to/entrypoint
getfacl -p /path/to
```

Povežite tip ulazne tačke sa stvarnom putanjom izvršne datoteke. Proverite DAC, ACL-ove, SELinux dozvolu za pisanje nad datotekom ili nadređenim direktorijumom, oznaku datoteke i sve uslovne boolean vrednosti pre nego što pretpostavite da je moguće iskoristiti vezu u policy-ju.<sup>[[20]](#references)[[22]](#references)</sup> Ako se putanja zameni umesto da se izmeni na mestu, proverite kontekst novog inode-a: oznake sistema datoteka čuvaju se kao prošireni atributi, pa zamena možda neće zadržati tip ulazne tačke.<sup>[[21]](#references)</sup> Programi koji podržavaju SELinux mogu zatražiti tranziciju pomoću `setexeccon`, tako da odsustvo automatskog pravila `type_transition` ne isključuje svaku tranziciju.<sup>[[20]](#references)</sup>

## Datoteke, ponovno označavanje i visokorizične pogrešne konfiguracije

Najvažnija operativna razlika između uobičajenih SELinux alata je:<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: privremena promena oznake na određenoj putanji
- `semanage fcontext`: trajno pravilo za mapiranje putanje na oznaku
- `restorecon` / `setfiles`: ponovna primena oznake iz policy-ja/podrazumevane oznake

Ovo je veoma važno tokom privesc-a jer **ponovno označavanje nije samo kozmetička promena**. Može pretvoriti datoteku iz „blokirane policy-jem“ u „čitljivu/izvršivu za privilegovanu, ograničenu uslugu“.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Proverite lokalna pravila za ponovno označavanje i odstupanja u oznakama:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```

Jedan suptilan, ali koristan detalj: običan `restorecon` **ne vraća uvek u potpunosti sumnjivu oznaku**. Ako je ciljni tip u `customizable_types`, možda će biti potrebno da upotrebite `-F` kako biste nametnuli potpuno vraćanje na početno stanje. Iz ofanzivne perspektive, ovo objašnjava zašto neobičan `chcon` ponekad može da preživi površno čišćenje uz komentar „već smo pokrenuli restorecon“.<sup>[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```

Komande visoke vrednosti koje treba tražiti u `sudo -l`, root wrappers, skriptama za automatizaciju ili capabilities fajlova:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```

Ako se pojavi bilo koja MAC capability, proverite i [stranicu o Linux capabilities](linux-capabilities.md); dokumentacija za Linux capabilities navodi da su `cap_mac_admin` i `cap_mac_override` specifični za Smack, zato nemojte pretpostavljati da njihove nazive same po sebi omogućavaju zaobilaženje SELinux-a.<sup>[[5]](#references)</sup>

Posebno zanimljivo:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: trajno menja oznaku koju putanja treba da dobije
- `restorecon` / `setfiles`: ponovo primenjuju te izmene u većem obimu
- `semodule -i`: učitava prilagođeni policy modul
- `semanage permissive -a <domain_t>`: postavlja jedan domen u permissive režim bez promene celog hosta
- `setsebool -P`: trajno menja policy booleans
- `load_policy`: ponovo učitava aktivni policy

Ovo su često **pomoćni primitivi**, a ne samostalni root exploits. Njihova vrednost je u tome što omogućavaju da:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- postavite ciljni domen u permissive režim
- proširite pristup između svog domena i zaštićenog tipa
- promenite oznake fajlova pod kontrolom napadača tako da ih privilegovana usluga može čitati ili izvršavati
- oslabite ograničenja usluge dovoljno da postojeća lokalna ranjivost postane iskoristiva

Primeri provera:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```

Ako kao root možete da učitate modul politike, obično kontrolišete SELinux granicu:<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>

```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```

Zato `audit2allow`, `semodule` i `semanage permissive` treba tretirati kao osetljive administratorske površine tokom post-exploitation faze. Mogu neprimetno da pretvore blokirani lanac u funkcionalan, a da pritom ne promene klasične UNIX dozvole.<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## Skrivena odbijanja i izdvajanje modula

Veoma čest izvor frustracije u ofanzivnom radu jeste lanac koji se završava nejasnom greškom `EACCES`, dok se očekivano AVC odbijanje ne pojavljuje. Pravila `dontaudit` možda skrivaju tačnu dozvolu koja vam je potrebna. Ako možete da pokrenete `semodule` preko `sudo`-a ili drugog privilegovanog omotača, privremeno isključivanje pravila `dontaudit` može neprimetan neuspeh da pretvori u precizan trag o pravilima:<sup>[[4]](#references)[[15]](#references)</sup>

```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```

Ovo je korisno i za proveru šta su lokalni administratori već promenili. Mali prilagođeni modul ili permisivno pravilo za jedan domen često su razlog zbog kog se ciljna usluga ponaša mnogo manje restriktivno nego što bi osnovna politika sugerisala.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Tragovi za audit

AVC odbijanja često predstavljaju ofanzivni signal, a ne samo odbrambeni šum. Govore vam:<sup>[[1]](#references)[[15]](#references)</sup>

- koji ciljni objekat/tip ste pogodili
- koja dozvola je odbijena
- kojim domenom trenutno upravljate
- da li bi mala izmena politike omogućila da lanac funkcioniše

```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```

Ako lokalni exploit ili pokušaj persistence stalno ne uspeva uz `EACCES` ili neobične greške „permission denied“, iako DAC dozvole deluju kao da pripadaju root-u, obično vredi proveriti SELinux pre nego što odbacite ovaj vektor.<sup>[[1]](#references)</sup>

## SELinux korisnici

Pored običnih Linux korisnika, postoje i SELinux korisnici. U okviru politike, svaki Linux korisnik se mapira na SELinux korisnika, što sistemu omogućava da različitim nalozima dodeli različite dozvoljene uloge i domene.<sup>[[3]](#references)</sup>

Brze provere:<sup>[[3]](#references)</sup>

```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```

Na mnogim uobičajenim sistemima, korisnici se mapiraju na `unconfined_u`, što umanjuje praktični uticaj ograničavanja korisnika. Međutim, u ojačanim okruženjima, ograničeni korisnici mogu učiniti `sudo`, `su`, `newrole` i `runcon` mnogo zanimljivijim, jer **putanja eskalacije može zavisiti od prelaska u povoljniju SELinux ulogu/tip, a ne samo od postizanja UID 0**. Takođe, imajte na umu da neki ograničeni korisnici uopšte ne mogu da pozovu `sudo`/`su`, osim ako pravila izričito ne dozvoljavaju osnovni setuid prelaz, pa sistem koji koristi `staff_u` + `sysadm_r` može pretvoriti naizgled bezazleno pravilo `sudo ROLE=` / `TYPE=` u stvarnu granicu privilegija.<sup>[[3]](#references)</sup>

## SELinux u kontejnerima

Izvršna okruženja za kontejnere obično pokreću radna opterećenja u ograničenom domenu kao što je `container_t` i označavaju sadržaj kontejnera kao `container_file_t`. Ako proces kontejnera pobegne, ali i dalje radi sa oznakom kontejnera, upis na hostu i dalje može da ne uspe jer je granica oznake ostala nepromenjena.<sup>[[1]](#references)[[17]](#references)</sup>

Kratak primer:<sup>[[16]](#references)[[18]](#references)</sup>

```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```

Deo `c647,c780` nije ukras. U mnogim primenama kontejnera, runtime-ovi dinamički dodeljuju MCS kategorije, tako da su dva procesa koji rade kao `container_t` i dalje međusobno izolovana. Ako te bekstvo prebaci u host namespace, ali zadrži originalni skup kategorija, nepodudaranje kategorija i dalje može da objasni zašto neke host putanje ostaju nečitljive ili neupisive.<sup>[[17]](#references)</sup>

Vredi obratiti pažnju na sledeće savremene operacije s kontejnerima:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` isključuje SELinux izolaciju oznakama za kontejner
- bind mount-ovi sa `:z` / `:Z` pokreću ponovno označavanje host putanje za zajedničku/privatnu upotrebu kontejnera
- široko ponovno označavanje host sadržaja samo po sebi može postati bezbednosni problem

Ova stranica sadrži malo sadržaja o kontejnerima kako bi se izbeglo ponavljanje. Za slučajeve zloupotrebe specifične za kontejnere i primere runtime-ova, pogledaj:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}



## References

- [1] [Red Hat dokumentacija: Korišćenje SELinux-a](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Alatke za analizu SELinux politika](https://github.com/SELinuxProject/setools)
- [3] [Upravljanje ograničenim i neograničenim korisnicima - RHEL 9 dokumentacija](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - stranica Linux priručnika](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) - stranica Linux priručnika](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) - stranica Linux priručnika](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) - stranica Linux priručnika](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) - stranica Linux priručnika](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) - stranica Linux priručnika](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) - stranica Linux priručnika](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) - stranica Linux priručnika](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) - stranica Linux priručnika](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) - stranica Linux priručnika](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) - stranica Linux priručnika](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) - stranica Linux priručnika](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Podman dokumentacija za pokretanje](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [Zašto bi trebalo da koristite Multi-Category Security za Linux kontejnere](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Podman dokumentacija za top](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - stranica Linux priručnika](https://man7.org/linux/man-pages/man8/selinux.8.html)
- [20] [SELinux Notebook: Prelazi domena i objekata](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/domain_object_transitions.md)
- [21] [Red Hat Enterprise Linux 10: Korišćenje SELinux-a](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html-single/using_selinux/using_selinux)
- [22] [SETools sesearch(1) priručnik](https://manpages.debian.org/testing/setools/sesearch.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
