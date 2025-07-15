# Informations dans les imprimantes

{{#include ../../banners/hacktricks-training.md}}

Il existe plusieurs blogs sur Internet qui **mettent en évidence les dangers de laisser les imprimantes configurées avec LDAP avec des** identifiants de connexion par défaut/faibles.  \
C'est parce qu'un attaquant pourrait **tromper l'imprimante pour s'authentifier contre un serveur LDAP malveillant** (typiquement un `nc -vv -l -p 389` ou `slapd -d 2` suffit) et capturer les **identifiants de l'imprimante en clair**.

De plus, plusieurs imprimantes contiendront **des journaux avec des noms d'utilisateur** ou pourraient même être capables de **télécharger tous les noms d'utilisateur** du contrôleur de domaine.

Toutes ces **informations sensibles** et le **manque de sécurité** commun rendent les imprimantes très intéressantes pour les attaquants.

Quelques blogs d'introduction sur le sujet :

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

---
## Configuration de l'imprimante

- **Emplacement** : La liste des serveurs LDAP se trouve généralement dans l'interface web (par exemple *Réseau ➜ Paramètre LDAP ➜ Configuration de LDAP*).
- **Comportement** : De nombreux serveurs web intégrés permettent des modifications du serveur LDAP **sans ressaisir les identifiants** (fonctionnalité d'utilisabilité → risque de sécurité).
- **Exploitation** : Redirigez l'adresse du serveur LDAP vers un hôte contrôlé par l'attaquant et utilisez le bouton *Tester la connexion* / *Synchronisation du carnet d'adresses* pour forcer l'imprimante à se lier à vous.

---
## Capture des identifiants

### Méthode 1 – Écouteur Netcat
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
Les petits anciens MFP peuvent envoyer un simple *simple-bind* en texte clair que netcat peut capturer. Les appareils modernes effectuent généralement d'abord une requête anonyme, puis tentent le bind, donc les résultats varient.

### Méthode 2 – Serveur LDAP rogue complet (recommandé)

Parce que de nombreux appareils effectueront une recherche anonyme *avant* de s'authentifier, mettre en place un véritable démon LDAP donne des résultats beaucoup plus fiables :
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Lorsque l'imprimante effectue sa recherche, vous verrez les identifiants en texte clair dans la sortie de débogage.

> 💡  Vous pouvez également utiliser `impacket/examples/ldapd.py` (Python rogue LDAP) ou `Responder -w -r -f` pour récolter des hachages NTLMv2 via LDAP/SMB.

---
## Vulnérabilités Pass-Back Récentes (2024-2025)

Le pass-back n'est *pas* un problème théorique – les fournisseurs continuent de publier des avis en 2024/2025 qui décrivent exactement cette classe d'attaques.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Le firmware ≤ 57.69.91 des MFP Xerox VersaLink C70xx a permis à un administrateur authentifié (ou à quiconque lorsque les identifiants par défaut restent) de :

* **CVE-2024-12510 – LDAP pass-back** : changer l'adresse du serveur LDAP et déclencher une recherche, provoquant la fuite des identifiants Windows configurés vers l'hôte contrôlé par l'attaquant.
* **CVE-2024-12511 – SMB/FTP pass-back** : problème identique via des destinations *scan-to-folder*, fuyant des identifiants NetNTLMv2 ou FTP en texte clair.

Un simple écouteur tel que :
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
ou un serveur SMB malveillant (`impacket-smbserver`) suffit à récolter les identifiants.

### Canon imageRUNNER / imageCLASS – Avis 20 mai 2025

Canon a confirmé une faiblesse de **pass-back SMTP/LDAP** dans des dizaines de lignes de produits Laser et MFP. Un attaquant ayant un accès administrateur peut modifier la configuration du serveur et récupérer les identifiants stockés pour LDAP **ou** SMTP (de nombreuses organisations utilisent un compte privilégié pour permettre le scan vers le mail).

Les recommandations du fournisseur indiquent explicitement :

1. Mettre à jour le firmware corrigé dès qu'il est disponible.
2. Utiliser des mots de passe administratifs forts et uniques.
3. Éviter les comptes AD privilégiés pour l'intégration des imprimantes.

---
## Outils d'énumération / exploitation automatisés

| Outil | Objectif | Exemple |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Abus de PostScript/PJL/PCL, accès au système de fichiers, vérification des identifiants par défaut, *découverte SNMP* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Récolter la configuration (y compris les annuaires et les identifiants LDAP) via HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Capturer et relayer les hachages NetNTLM depuis le pass-back SMB/FTP | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | Service LDAP malveillant léger pour recevoir des liaisons en texte clair | `python ldapd.py -debug` |

---
## Renforcement et détection

1. **Patch / mise à jour du firmware** des MFP rapidement (vérifiez les bulletins PSIRT du fournisseur).
2. **Comptes de service à privilège minimal** – ne jamais utiliser Domain Admin pour LDAP/SMB/SMTP ; restreindre aux portées OU *en lecture seule*.
3. **Restreindre l'accès à la gestion** – placer les interfaces web/IPP/SNMP des imprimantes dans un VLAN de gestion ou derrière un ACL/VPN.
4. **Désactiver les protocoles inutilisés** – FTP, Telnet, raw-9100, anciens chiffrements SSL.
5. **Activer la journalisation des audits** – certains appareils peuvent syslog les échecs LDAP/SMTP ; corréler les liaisons inattendues.
6. **Surveiller les liaisons LDAP en texte clair** provenant de sources inhabituelles (les imprimantes ne devraient normalement parler qu'aux DC).
7. **SNMPv3 ou désactiver SNMP** – la communauté `public` fuit souvent la configuration des appareils et LDAP.

---
## Références

- [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)
- Rapid7. “Vulnérabilités d'attaque pass-back de Xerox VersaLink C7025 MFP.” Février 2025.
- Canon PSIRT. “Atténuation des vulnérabilités contre le pass-back SMTP/LDAP pour les imprimantes laser et les multifonctions de petit bureau.” Mai 2025.

{{#include ../../banners/hacktricks-training.md}}
