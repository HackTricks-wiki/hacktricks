# Informations présentes dans les imprimantes

{{#include ../../banners/hacktricks-training.md}}

Plusieurs blogs sur Internet **soulignent les dangers liés au fait de laisser des imprimantes configurées avec LDAP et des identifiants de connexion par défaut/faibles**.  \
Cela est dû au fait qu’un attaquant pourrait **inciter l’imprimante à s’authentifier auprès d’un serveur LDAP rogue** (généralement, un `nc -vv -l -p 389` ou `slapd -d 2` suffit) et intercepter les **identifiants de l’imprimante en clair**.

De plus, plusieurs imprimantes contiennent des **logs avec des noms d’utilisateur** ou pourraient même être capables de **télécharger tous les noms d’utilisateur** depuis le Domain Controller.

Toutes ces **informations sensibles**, ainsi que le **manque fréquent de sécurité**, rendent les imprimantes très intéressantes pour les attaquants.

Quelques blogs d’introduction sur le sujet :

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Configuration de l’imprimante

- **Emplacement** : La liste des serveurs LDAP se trouve généralement dans l’interface web (par exemple *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Comportement** : De nombreux serveurs web intégrés permettent de modifier les serveurs LDAP **sans saisir à nouveau les identifiants** (fonctionnalité d’ergonomie → risque de sécurité).
- **Exploitation** : Redirigez l’adresse du serveur LDAP vers un hôte contrôlé par l’attaquant et utilisez le bouton *Test Connection* / *Address Book Sync* pour forcer l’imprimante à effectuer un bind vers votre serveur.

---

## Interception des identifiants

### Method 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
Les MFPs de petite taille/anciens peuvent envoyer un simple *simple-bind* en clair, que netcat peut intercepter. Les appareils modernes effectuent généralement d’abord une requête anonyme, puis tentent le bind ; les résultats peuvent donc varier.<sup>[[1]](#references)</sup>

### Méthode 2 – Full Rogue LDAP server (recommandé)

Comme de nombreux appareils effectuent une recherche anonyme *avant* de s’authentifier, la mise en place d’un véritable daemon LDAP donne des résultats bien plus fiables :<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Lorsque l’imprimante effectue sa recherche, vous verrez les identifiants en clair dans la sortie de débogage.

> 💡  Vous pouvez également utiliser `impacket/examples/ldapd.py` (Python rogue LDAP) ou `Responder -w -r -f` pour récolter des hashes NTLMv2 via LDAP/SMB.

---

## Vulnérabilités récentes de Pass-Back (2024-2025)

Le pass-back n’est *pas* un problème théorique – les vendors continuent de publier des avis en 2024/2025 qui décrivent précisément cette classe d’attaque.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Le firmware ≤ 57.69.91 des MFP Xerox VersaLink C70xx permettait à un administrateur authentifié (ou à n’importe qui lorsque les identifiants par défaut étaient conservés) de :

* **CVE-2024-12510 – LDAP pass-back** : modifier l’adresse du serveur LDAP et déclencher une recherche, ce qui provoquait le leak des identifiants Windows configurés vers l’hôte contrôlé par l’attaquant.
* **CVE-2024-12511 – SMB/FTP pass-back** : problème identique via les destinations *scan-to-folder*, avec le leak des identifiants NetNTLMv2 ou FTP en clair.<sup>[[2]](#references)</sup>

Un simple listener tel que :
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
ou un serveur SMB rogue (`impacket-smbserver`) suffit à récupérer les identifiants.

### Canon imageRUNNER / imageCLASS – Avis du 20 mai 2025

Canon a confirmé une faiblesse de **SMTP/LDAP pass-back** dans des dizaines de gammes de produits Laser & MFP. Un attaquant disposant d'un accès administrateur peut modifier la configuration du serveur et récupérer les identifiants stockés pour LDAP **ou** SMTP (de nombreuses organisations utilisent un compte privilégié pour autoriser la numérisation vers une adresse e-mail).<sup>[[3]](#references)</sup>

Les recommandations du fournisseur préconisent explicitement :

1. Mettre à jour le firmware avec une version corrigée dès qu'elle est disponible.
2. Utiliser des mots de passe administrateur forts et uniques.
3. Éviter les comptes AD privilégiés pour l'intégration des imprimantes.

---

## Outils d'énumération / d'exploitation automatisés

| Outil | Fonction | Exemple |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Exploitation de PostScript/PJL/PCL, accès au système de fichiers, vérification des identifiants par défaut, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Récupération de la configuration (notamment des carnets d'adresses et des identifiants LDAP) via HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Capture et relais des hash NetNTLM via le pass-back SMB/FTP | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | Service LDAP rogue léger permettant de recevoir des binds en clair | `python ldapd.py -debug` |

---

## Renforcement et détection

1. **Appliquer rapidement les correctifs / mises à jour du firmware** des MFP (consulter les bulletins PSIRT des fournisseurs).
2. **Comptes de service à privilèges minimaux** – ne jamais utiliser Domain Admin pour LDAP/SMB/SMTP ; limiter les comptes à des étendues d'OU en *lecture seule*.
3. **Restreindre l'accès à la gestion** – placer les interfaces web/IPP/SNMP des imprimantes dans un VLAN de gestion ou derrière une ACL/VPN.
4. **Désactiver les protocoles inutilisés** – FTP, Telnet, raw-9100 et les anciens chiffrements SSL.
5. **Activer la journalisation d'audit** – certains appareils peuvent envoyer les échecs LDAP/SMTP à syslog ; corréler les binds inattendus.
6. **Surveiller les binds LDAP en clair** provenant de sources inhabituelles (les imprimantes ne devraient normalement communiquer qu'avec les DC).
7. **Utiliser SNMPv3 ou désactiver SNMP** – la communauté `public` entraîne souvent un leak de la configuration de l'appareil et de LDAP.

---

## Références

- [1] [Ce n'est qu'une imprimante… Qu'est-ce qui pourrait mal tourner ?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Imprimante multifonction Xerox Versalink C7025 : vulnérabilités d'attaque Pass-Back (corrigées)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Mesures d'atténuation / correction des vulnérabilités pour les imprimantes de production, les imprimantes multifonctions de bureau / petit bureau et les imprimantes laser](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Obtention d'identifiants de domaine via une imprimante avec Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Exploitation des imprimantes multifonctions lors d'une mission de penetration test](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

{{#include ../../banners/hacktricks-training.md}}
