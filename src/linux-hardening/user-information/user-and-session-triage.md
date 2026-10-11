# Watumiaji, Vipindi, na Mabaki ya Vitambulisho

{{#include ../../banners/hacktricks-training.md}}

Anza na utambulisho unaomiliki shell ya sasa, kisha orodhesha watumiaji wengine, makundi, vipindi vinavyoendelea, na hifadhi za credentials. Ukurasa wa [ID halisi, inayotumika, na iliyohifadhiwa ya mtumiaji](euid-ruid-suid.md) unaeleza kwa nini ruhusa zinazotumika za mchakato zinaweza kutofautiana na akaunti yake ya kuingia.

## Orodhesha vitambulisho na ufikiaji unaotegemea makundi

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` hujumuisha akaunti zinazotegemea directory ambazo usomaji wa kawaida wa `/etc/passwd` unaweza kukosa. Kagua akaunti za UID 0, login shells, home directories, supplementary groups, na akaunti ambazo usanidi wake unaruhusu login ya mwingiliano bila kutarajiwa. Ukurasa wa [interesting groups](interesting-groups-linux-pe/README.md) unaeleza ufikiaji uliokasimiwa kama `sudo`, `docker`, `disk`, na `shadow`. Kagua ACL halisi za mfumo wa faili na sera za ndani kabla ya kuichukulia jina la group kuwa ruhusa ya juu.

Ikiwa [NSS inaelekeza utafutaji wa `passwd`, `group`, au `shadow`](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) kwenye database, kagua provider inayotumika na njia ya usanidi wake kabla ya kutathmini utambulisho unaotegemea database. Kwa uwekaji wa PostgreSQL NSS, `/etc/nss-pgsql.conf` na `/etc/nss-pgsql-root.conf` ni vidokezo vya njia pekee kwa sababu mipangilio ya muunganisho inaweza kuwa na credentials. Jukumu la database lina umuhimu tu ikiwa linaweza kubadilisha rekodi ambazo provider ya NSS inayotumika hurudisha, na akaunti inaweza kuthibitishwa kwa kutumia rekodi hizo. GID ya msingi ya 0 hutoa uanachama wa root-group, si UID 0; upangaji wa sudo-group unahitaji [sheria inayotumika ya sudoers group](https://man7.org/linux/man-pages/man5/sudoers.5.html) na uthibitishaji wowote unaohitajika. Upangaji wa UID 0 ni mpaka tofauti wa utambulisho. Usichapishe connection strings wala kubadilisha rekodi za akaunti wakati wa uorodheshaji tuli.

Pia linganisha UID za nambari kati ya majina ya akaunti ya ndani. Majina mawili katika [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) yanaweza kurejelea utambulisho uleule wa faili wa Unix, ilhali rekodi zao za uthibitishaji wa login zinaweza kutofautiana. Kwa hiyo, alias mpya iliyoongezwa yenye UID isiyo 0 inayoshirikiwa inaweza kufikia faili au michakato ya mtumiaji mwingine baada ya uthibitishaji kufanikiwa; haipei root isipokuwa UID hiyo au njia tofauti ya ruhusa ifanye hivyo. UID zinazoshirikiwa zinaweza kuwa za makusudi. Thibitisha chanzo cha akaunti (`/etc/passwd` dhidi ya NSS), historia ya kuundwa, shell na home, sera halisi ya uthibitishaji, na kama akaunti zimeidhinishwa kushiriki utambulisho huo. Ukaguzi wa nakala zinazojirudia wa akaunti za ndani pekee hauwezi kuondoa uwezekano wa alias inayotegemea directory.

## Tafuta sessions zinazotumika na za hivi karibuni

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

Socket ya `screen` au `tmux` inaweza kufichua shell iliyopo ikiwa ruhusa zake zinamruhusu mtumiaji wa sasa kujiunga nayo. Kagua mmiliki na mode ya socket kabla ya kujaribu kuifikia; kipindi cha mtumiaji mwingine hakiwezi kujiunganishwa nacho moja kwa moja. Muhuri wa muda wa sudo ulio hai au socket ya SSH agent pia inaweza kuwa muhimu, lakini kuitumia tena kunategemea utambulisho wa mtumiaji, ruhusa na sera. Kwa matumizi mabaya ya agent forwarding, tazama [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

Socket ya udhibiti ya [OpenSSH multiplex](https://man.openbsd.org/ssh_config#ControlMaster) ni tofauti na `SSH_AUTH_SOCK`: `ControlMaster` na `ControlPath` huruhusu wateja wa SSH wanaofuata kutumia muunganisho uliopo ambao tayari umethibitishwa, huku `ControlPersist` ikiweza kuweka master ipatikane baada ya kipindi cha kwanza kuisha. Kagua `.ssh/config` ya mtumiaji wa sasa na njia za socket za `.ssh` zilizo katika kiwango cha juu, ikijumuisha mmiliki na ruhusa. Jina la faili la socket pekee halithibitishi kwamba master bado inafanya kazi, kwamba mtumiaji wa sasa anaweza kuunganishwa nayo, au kwamba inatumia akaunti gani ya mbali.

## Kagua vipengee vya mtumiaji

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Historia ya Shell, startup files, funguo za SSH, usanidi wa programu, keyrings za GPG, na cache za Kerberos zinaweza kufichua credentials au sehemu za persistence zinazoweza kuandikika. `authorized_keys` au startup file inayoweza kuandikika ya akaunti yenye mamlaka zaidi inastahili kuchunguzwa. [Ukurasa wa post-exploitation](../post-exploitation/README.md) unaeleza uhamishaji wa GPG homedir na utafutaji wa credentials; [Linux Active Directory](linux-active-directory.md) unaeleza matumizi tena ya Kerberos cache na keytab. [Ukurasa wa PAM](../software-information/pam-pluggable-authentication-modules.md) unaeleza hatari za sera za uthibitishaji.
{{#include ../../banners/hacktricks-training.md}}
