# Gebruikers, sessies en aanmeldbewysartefakte

{{#include ../../banners/hacktricks-training.md}}

Begin met die identiteit waaraan die huidige shell behoort, en enumereer dan ander gebruikers, groepe, aktiewe sessies en bewaarplekke vir geloofsbriewe. Die bladsy oor die [werklike, effektiewe en gestoorde gebruikers-ID](euid-ruid-suid.md) verduidelik waarom ’n proses se effektiewe voorregte kan verskil van dié van sy aanmeldrekening.

## Enumereer identiteite en groepgebaseerde toegang

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` sluit gids-gesteunde rekeninge in wat ’n gewone lees van `/etc/passwd` kan miskyk. Gaan UID 0-rekeninge, aanmeldingshells, tuisgidse, aanvullende groepe en rekeninge na waarvan die opstelling interaktiewe aanmelding onverwags toelaat. Die bladsy oor [interessante groepe](interesting-groups-linux-pe/README.md) dek gedelegeerde toegang soos `sudo`, `docker`, `disk` en `shadow`. Gaan werklike lêerstelsel-ACL's en plaaslike beleid na voordat jy ’n groepnaam as ’n voorreg beskou.

As [NSS `passwd`-, `group`- of `shadow`-navrae na ’n databasis herlei](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html), gaan die aktiewe verskaffer en sy konfigurasiepad na voordat jy databasisgesteunde identiteite beoordeel. Vir PostgreSQL NSS-ontplooiings is `/etc/nss-pgsql.conf` en `/etc/nss-pgsql-root.conf` slegs leidrade na lêerpaaie, omdat verbindinginstellings geloofsbriewe kan bevat. ’n Databasisrol is slegs van belang as dit rekords kan verander wat die aktiewe NSS-verskaffer werklik teruggee, en ’n rekening daarmee kan staaf. ’n Primêre GID van 0 gee lidmaatskap van die root-groep, nie UID 0 nie; ’n sudo-groeptoewysing vereis ’n effektiewe [sudoers-groepreël](https://man7.org/linux/man-pages/man5/sudoers.5.html) en enige vereiste stawing. ’n UID 0-toewysing is ’n ander identiteitsgrens. Moenie verbindingstringe uitdruk of rekeningrekords tydens passiewe enumerasie verander nie.

Vergelyk ook numeriese UID's oor plaaslike rekeningname heen. Twee name in [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) kan na dieselfde Unix-lêeridentiteit verwys, terwyl hul aanmeldingsstawingsrekords kan verskil. ’n Nuut bygevoegde alias met ’n gedeelde nie-nul UID kan dus toegang tot ’n ander gebruiker se lêers of prosesse gee ná suksesvolle stawing; dit verleen nie root-toegang nie, tensy daardie UID of ’n afsonderlike voorregroete dit doen. Gedeelde UID's kan opsetlik wees. Verifieer die rekeningbron (`/etc/passwd` teenoor NSS), skeppingsgeskiedenis, shell en tuisgids, werklike stawingsbeleid, en of die rekeninge gemagtig is om die identiteit te deel. ’n Kontrole wat net plaaslike rekeninge dek, kan nie ’n gids-gesteunde alias uitsluit nie.

## Vind aktiewe en onlangse sessies

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

’n `screen`- of `tmux`-sok kan ’n bestaande shell blootstel as die toestemmings die huidige gebruiker toelaat om daaraan te koppel. Gaan die eienaar en sokmodus na voordat jy toegang probeer kry; ’n ander gebruiker se sessie is nie outomaties toeganklik nie. ’n Aktiewe sudo-tydstempel of SSH-agent-sok kan ook saak maak, maar hergebruik daarvan hang af van die gebruikeridentiteit, toestemmings en beleid. Sien [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md) vir misbruik van agent forwarding.

’n [OpenSSH multiplex-beheersok](https://man.openbsd.org/ssh_config#ControlMaster) is apart van `SSH_AUTH_SOCK`: `ControlMaster` en `ControlPath` laat latere SSH-kliënte ’n bestaande geverifieerde verbinding deel, terwyl `ControlPersist` die master beskikbaar kan hou nadat die eerste sessie geëindig het. Gaan die huidige gebruiker se `.ssh/config` en vlak `.ssh`-sokpaaie na, insluitend die eienaar en toestemmings. ’n Soklêernaam alleen bewys nie dat die master aktief is, dat die huidige gebruiker kan koppel, of watter afgeleë rekening dit gebruik nie.

## Hersien gebruikerartefakte

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Shellgeskiedenis, opstartlêers, SSH-sleutels, toepassingkonfigurasie, GPG-sleutelringe en Kerberos-kasgeheues kan geloofsbriewe of skryfbare volhardingspunte blootlê. ’n Skryfbare `authorized_keys`-lêer of shell-opstartlêer vir ’n rekening met hoër voorregte verdien ondersoek. Die [post-exploitation-bladsy](../post-exploitation/README.md) dek GPG-homedir-verskuiwing en die soektog na geloofsbriewe; [Linux Active Directory](linux-active-directory.md) dek die hergebruik van Kerberos-kasgeheues en keytabs. Die [PAM-bladsy](../software-information/pam-pluggable-authentication-modules.md) verduidelik die risiko’s van verifikasiebeleide.
{{#include ../../banners/hacktricks-training.md}}
