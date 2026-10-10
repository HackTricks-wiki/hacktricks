# Watumiaji, Vipindi, na Mabaki ya Vitambulisho

{{#include ../../banners/hacktricks-training.md}}

Anza na utambulisho wa mtumiaji anayemiliki shell ya sasa, kisha orodhesha watumiaji wengine, vikundi, vipindi vilivyo hai, na hifadhi za vitambulisho. Ukurasa wa [vitambulisho halisi, vinavyotumika, na vilivyohifadhiwa vya mtumiaji](euid-ruid-suid.md) unaeleza kwa nini ruhusa zinazotumika za mchakato zinaweza kutofautiana na akaunti yake ya kuingia.

## Orodhesha utambulisho na ufikiaji unaotegemea vikundi

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` hujumuisha akaunti zinazotolewa na directory ambazo usomaji wa kawaida wa `/etc/passwd` unaweza kukosa. Kagua akaunti za UID 0, shells za kuingia, saraka za nyumbani, vikundi vya ziada, na akaunti ambazo usanidi wake unaruhusu kuingia kwa njia shirikishi bila kutarajiwa. Ukurasa wa [interesting groups](interesting-groups-linux-pe/README.md) unaeleza ufikiaji uliokabidhiwa, kama vile `sudo`, `docker`, `disk`, na `shadow`. Kagua ACL halisi za mfumo wa faili na sera za ndani kabla ya kuchukulia jina la kikundi kuwa ruhusa ya juu.

Ikiwa [NSS inaelekeza utafutaji wa `passwd`, `group`, au `shadow`](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) kwenye hifadhidata, kagua mtoa huduma anayetumika na njia yake ya usanidi kabla ya kutathmini utambulisho unaotegemea hifadhidata. Kwa usanidi wa PostgreSQL NSS, `/etc/nss-pgsql.conf` na `/etc/nss-pgsql-root.conf` ni vielekezi vya njia pekee, kwa sababu mipangilio ya muunganisho inaweza kuwa na vitambulisho vya kuingia. Jukumu la hifadhidata lina umuhimu tu ikiwa linaweza kubadilisha rekodi ambazo mtoa huduma wa NSS anayetumika hurudisha, na akaunti inaweza kuthibitisha utambulisho kwa kutumia rekodi hizo. GID msingi ya 0 hutoa uanachama wa kikundi cha root, si UID 0; uelekezaji wa kikundi cha sudo unahitaji kanuni halali ya kikundi ya [sudoers](https://man7.org/linux/man-pages/man5/sudoers.5.html) na uthibitishaji wowote unaohitajika. Uelekezaji wa UID 0 ni mpaka tofauti wa utambulisho. Usichapishe mifuatano ya muunganisho au kubadilisha rekodi za akaunti wakati wa uorodheshaji tulivu.

Pia linganisha UID za nambari kati ya majina ya akaunti za ndani. Majina mawili katika [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) yanaweza kurejelea utambulisho uleule wa faili wa Unix, huku rekodi zao za uthibitishaji wa kuingia zikitofautiana. Kwa hiyo, jina la ziada lililoongezwa lenye UID isiyo sifuri inayoshirikiwa linaweza kutoa ufikiaji wa faili au michakato ya mtumiaji mwingine baada ya uthibitishaji kufanikiwa; halitoi ruhusa za root isipokuwa UID hiyo au njia tofauti ya kupata ruhusa ifanye hivyo. UID zinazoshirikiwa zinaweza kuwa za makusudi. Thibitisha chanzo cha akaunti (`/etc/passwd` dhidi ya NSS), historia ya uundaji, shell na saraka ya nyumbani, sera halisi ya uthibitishaji, na kama akaunti zimeidhinishwa kushiriki utambulisho huo. Ukaguzi wa nakala rudufu za akaunti za ndani pekee hauwezi kubaini ikiwa kuna jina la ziada linalotolewa na directory.

## Tafuta vipindi vya kuingia vilivyo hai na vya hivi karibuni

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

Socket ya `screen` au `tmux` inaweza kufichua shell iliyopo ikiwa ruhusa zake zinamruhusu mtumiaji wa sasa kujiunga nayo. Kagua mmiliki na hali ya socket kabla ya kujaribu kuifikia; kipindi cha mtumiaji mwingine hakiwezi kujiunganishwa nacho moja kwa moja. Alama ya muda ya sudo iliyo hai au socket ya SSH agent inaweza pia kuwa muhimu, lakini kuitumia tena hutegemea utambulisho wa mtumiaji, ruhusa na sera. Kwa matumizi mabaya ya agent forwarding, angalia [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

Socket ya udhibiti ya [OpenSSH multiplex](https://man.openbsd.org/ssh_config#ControlMaster) ni tofauti na `SSH_AUTH_SOCK`: `ControlMaster` na `ControlPath` huruhusu wateja wa baadaye wa SSH kushiriki muunganisho uliopo ambao tayari umethibitishwa, huku `ControlPersist` ikiweza kuweka master ipatikane hata baada ya kipindi cha kwanza kuisha. Kagua `.ssh/config` ya mtumiaji wa sasa na njia za socket zilizo ndani ya `.ssh`, pamoja na mmiliki na ruhusa zake. Jina la faili ya socket pekee halithibitishi kuwa master bado iko hai, kwamba mtumiaji wa sasa anaweza kuiunganisha, au ni akaunti ipi ya mbali inayotumia.

## Kagua mabaki ya mtumiaji

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Historia ya shell, faili za kuanzisha, funguo za SSH, usanidi wa programu, keyring za GPG, na cache za Kerberos zinaweza kufichua credentials au maeneo ya persistence yanayoweza kuandikwa. `authorized_keys` au faili ya kuanzisha shell inayoweza kuandikwa kwa akaunti yenye mamlaka zaidi inapaswa kukaguliwa. [Ukurasa wa post-exploitation](../post-exploitation/README.md) unaeleza uhamishaji wa GPG homedir na utafutaji wa credentials; [Linux Active Directory](linux-active-directory.md) unaeleza utumiaji upya wa cache za Kerberos na keytab. [Ukurasa wa PAM](../software-information/pam-pluggable-authentication-modules.md) unaeleza hatari za sera za uthibitishaji.
{{#include ../../banners/hacktricks-training.md}}
