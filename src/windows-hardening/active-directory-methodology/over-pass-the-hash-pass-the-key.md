# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

L'attaque **Overpass The Hash/Pass The Key (PTK)** est conçue pour des environnements où le protocole NTLM traditionnel est restreint, et l'authentification Kerberos prend le pas. Cette attaque exploite le hachage NTLM ou les clés AES d'un utilisateur pour solliciter des tickets Kerberos, permettant un accès non autorisé aux ressources au sein d'un réseau.

Pour exécuter cette attaque, la première étape consiste à acquérir le hachage NTLM ou le mot de passe du compte de l'utilisateur ciblé. Une fois cette information sécurisée, un Ticket Granting Ticket (TGT) pour le compte peut être obtenu, permettant à l'attaquant d'accéder aux services ou machines auxquels l'utilisateur a des permissions.

Le processus peut être initié avec les commandes suivantes :
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Pour les scénarios nécessitant AES256, l'option `-aesKey [AES key]` peut être utilisée. De plus, le ticket acquis peut être employé avec divers outils, y compris smbexec.py ou wmiexec.py, élargissant ainsi la portée de l'attaque.

Les problèmes rencontrés tels que _PyAsn1Error_ ou _KDC cannot find the name_ sont généralement résolus en mettant à jour la bibliothèque Impacket ou en utilisant le nom d'hôte au lieu de l'adresse IP, garantissant la compatibilité avec le KDC Kerberos.

Une séquence de commandes alternative utilisant Rubeus.exe démontre un autre aspect de cette technique :
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Cette méthode reflète l'approche **Pass the Key**, en se concentrant sur la prise de contrôle et l'utilisation directe du ticket à des fins d'authentification. Il est crucial de noter que l'initiation d'une demande de TGT déclenche l'événement `4768: A Kerberos authentication ticket (TGT) was requested`, signifiant une utilisation par défaut de RC4-HMAC, bien que les systèmes Windows modernes préfèrent AES256.

Pour se conformer à la sécurité opérationnelle et utiliser AES256, la commande suivante peut être appliquée :
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Version plus discrète

> [!WARNING]
> Chaque session de connexion ne peut avoir qu'un seul TGT actif à la fois, donc soyez prudent.

1. Créez une nouvelle session de connexion avec **`make_token`** de Cobalt Strike.
2. Ensuite, utilisez Rubeus pour générer un TGT pour la nouvelle session de connexion sans affecter l'existante.


## Références

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)


{{#include ../../banners/hacktricks-training.md}}
