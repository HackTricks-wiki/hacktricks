# Gebruikers, sessies en bewysartefakte

{{#include ../../banners/hacktricks-training.md}}

Begin met die identiteit wat eienaar van die huidige shell is, en lys dan ander gebruikers, groepe, aktiewe sessies en bewysbergings. Die bladsy oor [werklike, effektiewe en gestoorde gebruikers-ID's](euid-ruid-suid.md) verduidelik waarom 'n proses se effektiewe voorregte kan verskil van dié van sy aanmeldrekening.

## Lys identiteite en groepgebaseerde toegang

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` sluit gids-gesteunde rekeninge in wat ’n gewone lees van `/etc/passwd` kan mis. Gaan UID 0-rekeninge, aanmeldingsdoppe, tuisgidse, aanvullende groepe en rekeninge na waarvan die konfigurasie onverwags interaktiewe aanmelding toelaat. Die bladsy oor [interessante groepe](interesting-groups-linux-pe/README.md) dek gedelegeerde toegang soos `sudo`, `docker`, `disk` en `shadow`. Gaan werklike lêerstelsel-ACL's en plaaslike beleid na voordat jy ’n groepnaam as ’n voorreg beskou.

As [NSS `passwd`-, `group`- of `shadow`-opsoeke na ’n databasis karteer](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html), gaan die aktiewe verskaffer en sy konfigurasiepad na voordat jy databasis-gesteunde identiteite beoordeel. Vir PostgreSQL NSS-ontplooiings is `/etc/nss-pgsql.conf` en `/etc/nss-pgsql-root.conf` slegs leidrade na lêerpaaie, omdat verbindinginstellings geloofsbriewe kan bevat. ’n Databasisrol is slegs relevant as dit rekords kan verander wat die aktiewe NSS-verskaffer werklik teruggee, en ’n rekening daarmee kan staaf. ’n Primêre GID van 0 gee lidmaatskap van die root-groep, nie UID 0 nie; ’n sudo-groepkartering vereis ’n effektiewe [sudoers-groepreël](https://man7.org/linux/man-pages/man5/sudoers.5.html) en enige vereiste stawing. ’n UID 0-kartering is ’n ander identiteitsgrens. Moenie verbindingstringe druk of rekeningrekords verander tydens passiewe enumerasie nie.

Vergelyk ook numeriese UID's oor plaaslike rekeningname heen. Twee name in [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) kan na dieselfde Unix-lêeridentiteit verwys, terwyl hul aanmeldingsstawingsrekords kan verskil. ’n Nuut bygevoegde alias met ’n gedeelde nie-nul-UID kan dus toegang tot ’n ander gebruiker se lêers of prosesse gee ná suksesvolle stawing; dit verleen nie root-toegang nie, tensy daardie UID of ’n afsonderlike voorregroete dit doen. Gedeelde UID's kan doelbewus wees. Verifieer die rekeningbron (`/etc/passwd` teenoor NSS), skeppingsgeskiedenis, dop en tuisgids, werklike stawingsbeleid, en of die rekeninge gemagtig is om die identiteit te deel. ’n Kontrole wat slegs plaaslike rekeninge nagaan, kan nie ’n gids-gesteunde alias uitsluit nie.

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

’n `screen`- of `tmux`-soket kan ’n bestaande shell blootstel as die toestemmings die huidige gebruiker toelaat om te attach. Gaan die eienaar en soketmodus na voordat jy toegang probeer kry; ’n ander gebruiker se sessie is nie outomaties toeganklik om aan te koppel nie. ’n Aktiewe sudo-tydstempel of SSH-agent-soket kan ook van belang wees, maar hergebruik daarvan hang af van gebruikersidentiteit, toestemmings en beleid. Sien [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md) vir misbruik van agent forwarding.

’n [OpenSSH-multiplexbeheersoket](https://man.openbsd.org/ssh_config#ControlMaster) is apart van `SSH_AUTH_SOCK`: `ControlMaster` en `ControlPath` laat latere SSH-kliënte ’n bestaande geverifieerde verbinding deel, terwyl `ControlPersist` die master beskikbaar kan hou nadat die eerste sessie geëindig het. Ondersoek die huidige gebruiker se `.ssh/config` en soketpaaie op die boonste vlak van `.ssh`, insluitend die eienaar en toestemmings. ’n Soketlêernaam alleen bewys nie dat die master aktief is, dat die huidige gebruiker kan koppel, of watter afgeleë rekening dit gebruik nie.

## Hersien gebruikersartefakte

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Shell-geskiedenis, opstartlêers, SSH-sleutels, toepassingskonfigurasie, GPG-sleutelringe en Kerberos-kasgeheue kan geloofsbriewe of skryfbare volhardingspunte blootlê. ’n Skryfbare `authorized_keys`-lêer of dop-opstartlêer vir ’n rekening met meer voorregte verdien ondersoek. Die [post-exploitation-bladsy](../post-exploitation/README.md) dek GPG-homedir-herverskuiwing en die opsporing van geloofsbriewe; [Linux Active Directory](linux-active-directory.md) dek hergebruik van Kerberos-kasgeheue en keytabs. Die [PAM-bladsy](../software-information/pam-pluggable-authentication-modules.md) verduidelik die risiko’s van verifikasiebeleide.
{{#include ../../banners/hacktricks-training.md}}
