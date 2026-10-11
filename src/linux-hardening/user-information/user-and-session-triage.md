# Watumiaji, Vipindi, na Mabaki ya Credential

{{#include ../../banners/hacktricks-training.md}}

Anza na utambulisho unaomiliki shell ya sasa, kisha orodhesha watumiaji wengine, vikundi, vipindi vilivyo hai, na hifadhi za credential. Ukurasa wa [ID halisi, inayotumika, na iliyohifadhiwa ya mtumiaji](euid-ruid-suid.md) unaeleza kwa nini ruhusa za mchakato zinazotumika zinaweza kutofautiana na akaunti yake ya kuingia.

## Orodhesha utambulisho na ufikiaji unaotegemea vikundi

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` hujumuisha akaunti zinazotoka kwenye directory ambazo usomaji wa kawaida wa `/etc/passwd` unaweza kukosa. Kagua akaunti za UID 0, login shells, home directories, supplementary groups, na akaunti ambazo usanidi wake unaruhusu login ya kuingiliana bila kutarajiwa. Ukurasa wa [interesting groups](interesting-groups-linux-pe/README.md) unashughulikia ufikiaji uliokabidhiwa kama vile `sudo`, `docker`, `disk`, na `shadow`. Kagua ACL halisi za filesystem na sera za eneo husika kabla ya kuchukulia jina la group kuwa fursa.

Ikiwa [NSS huelekeza utafutaji wa `passwd`, `group`, au `shadow`](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) kwenye database, kagua provider inayotumika na njia ya usanidi wake kabla ya kutathmini identities zinazotegemea database. Kwa deployments za PostgreSQL NSS, `/etc/nss-pgsql.conf` na `/etc/nss-pgsql-root.conf` ni vidokezo vya njia pekee, kwa sababu mipangilio ya muunganisho inaweza kuwa na credentials. Database role ina umuhimu tu ikiwa inaweza kubadilisha records ambazo provider ya NSS inayotumika hurejesha, na akaunti inaweza kuthibitisha utambulisho kwa kutumia records hizo. GID ya msingi ya 0 hutoa uanachama wa root-group, si UID 0; ulinganishaji wa sudo-group huhitaji [sudoers group rule](https://man7.org/linux/man-pages/man5/sudoers.5.html) inayotumika pamoja na uthibitishaji wowote unaohitajika. Ulinganishaji wa UID 0 ni mpaka tofauti wa utambulisho. Usichapishe connection strings au kubadilisha account records wakati wa enumeration tulivu.

Pia linganisha UID za nambari kati ya majina ya akaunti za eneo husika. Majina mawili katika [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) yanaweza kurejelea utambulisho uleule wa faili wa Unix, huku records zao za uthibitishaji wa login zikitofautiana. Kwa hivyo, alias iliyoongezwa hivi karibuni yenye UID isiyo sifuri inayoshirikiwa inaweza kumwezesha mtumiaji kufikia faili au michakato ya mtumiaji mwingine baada ya uthibitishaji kufanikiwa; haitoi root isipokuwa UID hiyo au njia tofauti ya kupata fursa itoe hivyo. UID zinazoshirikiwa zinaweza kuwa za makusudi. Thibitisha chanzo cha akaunti (`/etc/passwd` dhidi ya NSS), historia ya uundaji, shell na home, sera halisi ya uthibitishaji, na kama akaunti hizo zimeidhinishwa kushiriki utambulisho huo. Ukaguzi wa nakala zinazopatikana kwenye mfumo wa eneo husika pekee hauwezi kubaini kuwa hakuna alias inayotoka kwenye directory.

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

Socket ya `screen` au `tmux` inaweza kufichua shell iliyopo ikiwa ruhusa zake zinamruhusu mtumiaji wa sasa kujiunga. Kagua mmiliki na ruhusa za socket kabla ya kujaribu kuifikia; kipindi cha mtumiaji mwingine hakiwezi kujiunganishwa nacho moja kwa moja. Muda wa sudo ulio hai au socket ya SSH agent pia inaweza kuwa muhimu, lakini kuitumia tena kunategemea utambulisho wa mtumiaji, ruhusa na sera. Kwa matumizi mabaya ya agent forwarding, angalia [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

[OpenSSH multiplex control socket](https://man.openbsd.org/ssh_config#ControlMaster) ni tofauti na `SSH_AUTH_SOCK`: `ControlMaster` na `ControlPath` huruhusu wateja wa SSH wanaofuata kushiriki muunganisho uliopo ambao tayari umethibitishwa, huku `ControlPersist` ikiweza kuweka master ipatikane baada ya kipindi cha kwanza kuisha. Kagua `.ssh/config` ya mtumiaji wa sasa na njia za socket zilizo ndani ya `.ssh` kwa kina kidogo, ikijumuisha mmiliki na ruhusa. Jina la faili la socket pekee halithibitishi kwamba master bado iko hai, kwamba mtumiaji wa sasa anaweza kuunganishwa nayo, au ni akaunti gani ya mbali inayotumia.

## Kagua vitu vya mtumiaji

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Historia ya shell, faili za uanzishaji, funguo za SSH, usanidi wa programu, keyring za GPG na akiba za Kerberos zinaweza kufichua vitambulisho au sehemu za persistence zinazoweza kuandikwa. `authorized_keys` au faili ya uanzishaji wa shell inayoweza kuandikwa ya akaunti yenye ruhusa za juu zaidi inapaswa kuchunguzwa. [Ukurasa wa post-exploitation](../post-exploitation/README.md) unaeleza uhamishaji wa GPG homedir na utafutaji wa vitambulisho; [Linux Active Directory](linux-active-directory.md) unaeleza matumizi tena ya akiba za Kerberos na keytab. [Ukurasa wa PAM](../software-information/pam-pluggable-authentication-modules.md) unaeleza hatari za sera za uthibitishaji.
{{#include ../../banners/hacktricks-training.md}}
