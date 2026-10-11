# Watumiaji, Vipindi, na Mabaki ya Sifa za Kuingia

{{#include ../../banners/hacktricks-training.md}}

Anza na utambulisho wa mtumiaji unaomiliki shell ya sasa, kisha orodhesha watumiaji wengine, vikundi, vipindi vinavyoendelea, na hifadhi za sifa za kuingia. Ukurasa wa [ID halisi, inayotumika, na iliyohifadhiwa ya mtumiaji](euid-ruid-suid.md) unaeleza kwa nini ruhusa zinazotumika za mchakato zinaweza kutofautiana na akaunti yake ya kuingia.

## Orodhesha utambulisho na ufikiaji unaotegemea vikundi

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` inajumuisha akaunti zinazotoka kwenye directory ambazo usomaji wa kawaida wa `/etc/passwd` unaweza kukosa. Kagua akaunti za UID 0, login shells, home directories, supplementary groups, na akaunti ambazo usanidi wake unaruhusu login shirikishi bila kutarajiwa. Ukurasa wa [groups zinazovutia](interesting-groups-linux-pe/README.md) unaeleza ufikiaji uliokabidhiwa kama `sudo`, `docker`, `disk`, na `shadow`. Kagua ACL halisi za mfumo wa faili na sera za ndani kabla ya kuchukulia jina la group kama ruhusa maalum.

Ikiwa [NSS inaelekeza utafutaji wa `passwd`, `group`, au `shadow`](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) kwenye database, kagua provider inayotumika na njia yake ya usanidi kabla ya kutathmini identities zinazotegemea database. Kwa usanidi wa PostgreSQL NSS, `/etc/nss-pgsql.conf` na `/etc/nss-pgsql-root.conf` ni viashiria vya njia pekee kwa sababu mipangilio ya muunganisho inaweza kuwa na credentials. Database role ni muhimu tu ikiwa inaweza kubadilisha rekodi ambazo provider ya NSS inayotumika hurejesha na akaunti inaweza kujithibitisha kwa kutumia rekodi hizo. Primary GID ya 0 hutoa uanachama wa root-group, si UID 0; ramani ya sudo-group inahitaji [sheria inayotumika ya sudoers group](https://man7.org/linux/man-pages/man5/sudoers.5.html) na uthibitishaji wowote unaohitajika. Ramani ya UID 0 ni mpaka tofauti wa utambulisho. Usichapishe connection strings wala kubadilisha rekodi za akaunti wakati wa uorodheshaji tulivu.

Pia linganisha UID za nambari katika majina ya akaunti za ndani. Majina mawili katika [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) yanaweza kurejelea utambulisho uleule wa faili wa Unix, ilhali rekodi zake za uthibitishaji wa login zinaweza kutofautiana. Kwa hiyo, alias mpya iliyoongezwa yenye UID ileile isiyo sifuri inaweza kufikia faili au michakato ya mtumiaji mwingine baada ya uthibitishaji kufanikiwa; haitoi root isipokuwa UID hiyo au njia tofauti ya kupata ruhusa maalum itoe hivyo. UID zinazoshirikiwa zinaweza kuwa za makusudi. Thibitisha chanzo cha akaunti (`/etc/passwd` dhidi ya NSS), historia ya uundaji, shell na home, sera halisi ya uthibitishaji, na iwapo akaunti hizo zimeidhinishwa kushiriki utambulisho huo. Ukaguzi wa duplicate za akaunti za ndani pekee hauwezi kubaini alias inayotoka kwenye directory.

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

Socket ya `screen` au `tmux` inaweza kufichua shell iliyopo ikiwa ruhusa zake zinamruhusu mtumiaji wa sasa kuiunganisha. Kagua mmiliki na hali ya ruhusa ya socket kabla ya kujaribu kuifikia; kipindi cha mtumiaji mwingine hakiwezi kuunganishwa nacho moja kwa moja. Timestamp inayotumika ya sudo au socket ya SSH agent pia inaweza kuwa muhimu, lakini matumizi yake tena hutegemea utambulisho wa mtumiaji, ruhusa na sera. Kwa matumizi mabaya ya agent forwarding, tazama [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

Socket ya udhibiti ya [OpenSSH multiplex](https://man.openbsd.org/ssh_config#ControlMaster) ni tofauti na `SSH_AUTH_SOCK`: `ControlMaster` na `ControlPath` huruhusu wateja wa baadaye wa SSH kutumia muunganisho uliopo ulioidhinishwa, huku `ControlPersist` ikiweza kufanya master ipatikane hata baada ya kipindi cha kwanza kuisha. Kagua `.ssh/config` ya mtumiaji wa sasa na njia za socket zilizo ndani ya `.ssh`, ikiwemo mmiliki na ruhusa zake. Jina la faili la socket pekee halithibitishi kuwa master bado inafanya kazi, kuwa mtumiaji wa sasa anaweza kuunganishwa nayo, au akaunti gani ya mbali inatumiwa.

## Kagua vitu vya mtumiaji wa sasa

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Historia ya Shell, faili za uanzishaji, funguo za SSH, usanidi wa programu, keyring za GPG na cache za Kerberos zinaweza kufichua taarifa za uthibitishaji au sehemu za persistence zinazoweza kuandikwa. `authorized_keys` au faili ya uanzishaji wa shell inayoweza kuandikwa ya akaunti yenye marupurupu zaidi inapaswa kuchunguzwa. [Ukurasa wa post-exploitation](../post-exploitation/README.md) unaeleza uhamishaji wa GPG homedir na utafutaji wa credentials; [Linux Active Directory](linux-active-directory.md) unaeleza matumizi tena ya cache za Kerberos na keytab. [Ukurasa wa PAM](../software-information/pam-pluggable-authentication-modules.md) unaeleza hatari za sera za uthibitishaji.
{{#include ../../banners/hacktricks-training.md}}
