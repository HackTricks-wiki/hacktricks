# Informations présentes dans les imprimantes

{{#include ../../banners/hacktricks-training.md}}

Plusieurs blogs sur Internet **soulignent les dangers liés aux imprimantes configurées avec LDAP et utilisant des identifiants de connexion par défaut/faibles**.  \
En effet, un attaquant pourrait **piéger l’imprimante pour qu’elle s’authentifie auprès d’un serveur LDAP rogue** (en général, un `nc -vv -l -p 389` ou `slapd -d 2` suffit) et intercepter les **identifiants de l’imprimante en clair**.

De plus, plusieurs imprimantes contiennent des **journaux avec des noms d’utilisateur** ou peuvent même être capables de **télécharger tous les noms d’utilisateur** depuis le Domain Controller.

Toutes ces **informations sensibles**, ainsi que le **manque fréquent de sécurité**, rendent les imprimantes très intéressantes pour les attaquants.

Quelques blogs d’introduction sur le sujet :

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Configuration de l’imprimante

- **Emplacement** : La liste des serveurs LDAP se trouve généralement dans l’interface web (par exemple, *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Comportement** : De nombreux serveurs web embarqués permettent de modifier les serveurs LDAP **sans saisir à nouveau les identifiants** (fonctionnalité d’ergonomie → risque de sécurité).
- **Exploit** : Redirigez l’adresse du serveur LDAP vers un hôte contrôlé par l’attaquant et utilisez le bouton *Test Connection* / *Address Book Sync* pour forcer l’imprimante à effectuer une liaison auprès de votre serveur.

---

## Interception des identifiants

### Méthode 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```
Les MFP petites/anciennes peuvent envoyer un *simple-bind* dont le DN de bind et le mot de passe sont visibles dans le flux BER brut. Les appareils modernes effectuent généralement d'abord une requête anonyme, puis tentent le bind, les résultats peuvent donc varier.<sup>[[1]](#references)</sup>

Un listener `nc` classique sur 636/3269 ne reçoit que du texte chiffré TLS ; tester LDAPS nécessite un endpoint LDAP compatible TLS, et la redirection devrait échouer lorsque l'appareil valide correctement le certificat du serveur.

### Method 2 – Serveur LDAP Rogue complet (recommandé)

Comme de nombreux appareils effectuent une recherche anonyme *avant* de s'authentifier, mettre en place un véritable daemon LDAP fournit des résultats beaucoup plus fiables :<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Lorsque l'imprimante effectue sa requête, vous verrez les identifiants en clair dans la sortie de debug.

> 💡  Responder inclut des services d'authentification LDAP et SMB rogue. Un simple bind LDAP peut exposer le mot de passe configuré, tandis que l'authentification NTLM produit des éléments challenge-response ; ne décrivez pas ces deux résultats comme un mot de passe en clair.

---

## Vulnérabilités récentes de Pass-Back (2024-2025)

Le Pass-Back n'est *pas* un problème théorique : les vendors continuent de publier des advisories en 2024/2025 qui décrivent précisément cette classe d'attaque.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Les firmwares ≤ 57.69.91 des MFP Xerox VersaLink C70xx permettaient à un administrateur authentifié (ou à n'importe qui lorsque les identifiants par défaut étaient toujours utilisés) de :

* **CVE-2024-12510 – LDAP pass-back** : modifier l'adresse du serveur LDAP et déclencher une requête, ce qui provoque le leak des identifiants Windows configurés vers l'hôte contrôlé par l'attaquant.
* **CVE-2024-12511 – SMB/FTP pass-back** : problème identique via les destinations *scan-to-folder*, avec leak des identifiants NetNTLMv2 ou FTP en clair.<sup>[[2]](#references)</sup>

Un simple listener tel que :
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
ou un serveur SMB rogue (`impacket-smbserver`) suffit à récolter les identifiants.

### Canon imageRUNNER / imageCLASS – Avis du 20 mai 2025

Canon a confirmé une faiblesse de **SMTP/LDAP pass-back** affectant des dizaines de gammes de produits Laser & MFP. Un attaquant disposant d’un accès administrateur peut modifier la configuration du serveur et récupérer les identifiants stockés pour LDAP **ou** SMTP (de nombreuses organisations utilisent un compte privilégié pour autoriser la numérisation vers une adresse e-mail).<sup>[[3]](#references)</sup>

Les recommandations du fabricant préconisent explicitement :

1. Mettre à jour le firmware vers une version corrigée dès que possible.
2. Utiliser des mots de passe administrateur forts et uniques.
3. Éviter les comptes AD privilégiés pour l’intégration des imprimantes.

---

### Appareils Brother et variantes OEM – accès administrateur dérivé du numéro de série aux identifiants de service

Une divulgation coordonnée menée en 2025 a démontré une chaîne particulièrement utile sur les appareils Brother concernés ; certaines parties de l’ensemble de vulnérabilités affectent également les modèles OEM. Vérifiez donc le modèle exact dans l’avis de sécurité du fabricant. Un attaquant non authentifié peut obtenir le numéro de série de l’appareil via HTTP/HTTPS/IPP sur un firmware vulnérable, tandis que les numéros de série peuvent également être disponibles via des protocoles de gestion tels que SNMP ou PJL. Si le mot de passe d’usine n’a jamais été modifié, le numéro de série permet de déterminer le mot de passe administrateur. Après authentification, la faille distincte de pass-back CVE-2024-51984 expose en clair les mots de passe des services externes configurés, tels que LDAP ou FTP, transformant l’accès à la gestion de l’imprimante en identifiants réseau réutilisables. Le firmware corrige la divulgation des mots de passe de service, mais les appareils fabriqués précédemment nécessitent toujours que l’opérateur remplace le mot de passe administrateur initial dérivé du numéro de série.<sup>[[6]](#references)</sup>

La version actuelle de Metasploit inclut un module auxiliaire qui découvre le numéro de série via HTTP, SNMP ou PJL, génère le mot de passe initial candidat et peut éventuellement le vérifier auprès de la console web. `DiscoverSerialVia=AUTO` essaie les chemins de découverte pris en charge ; indiquez plutôt `TargetSerial` lorsque l’inventaire des actifs contient déjà le numéro de série.<sup>[[7]](#references)</sup>
```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```
Utilisez le résultat uniquement pour valider des assets autorisés. Le fonctionnement du mot de passe dépend du modèle exact et, surtout, du fait que le mot de passe administrateur d’usine ait déjà été modifié ou non.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Outils d’énumération / d’exploitation automatisés

| Outil | Objectif | Exemple |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Abus de PostScript/PJL/PCL, accès au système de fichiers, vérification des identifiants par défaut, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Collecte de la configuration (y compris les carnets d’adresses et les identifiants LDAP) via HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Exécution de services d’authentification rogue et capture/relais de NetNTLM depuis les callbacks SMB | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Découverte d’un numéro de série, dérivation du mot de passe administrateur d’usine candidat et vérification de l’accès à la console web | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Sécurisation et détection

1. **Appliquer rapidement les correctifs / mises à jour du firmware** des MFP (consultez les bulletins PSIRT du fournisseur).
2. **Remplacer les mots de passe administrateur d’usine** – le firmware seul ne supprime pas les mots de passe initiaux dérivés du numéro de série des appareils Brother/OEM concernés déjà fabriqués.<sup>[[6]](#references)</sup>
3. **Comptes de service avec le principe du moindre privilège** – n’utilisez jamais Domain Admin pour LDAP/SMB/SMTP ; limitez-les à des périmètres d’OU en *lecture seule*.
4. **Restreindre l’accès de gestion** – placez les interfaces web/IPP/SNMP des imprimantes dans un VLAN de gestion ou derrière une ACL/VPN.
5. **Limiter les connexions sortantes des imprimantes** – autorisez chaque appareil à contacter uniquement les destinations DC/LDAP, e-mail, DNS/NTP, impression et fichiers de scan prévues. Le pass-back nécessite un callback vers un endpoint sélectionné par l’attaquant.
6. **Désactiver les protocoles inutilisés** – FTP, Telnet, raw-9100, anciens chiffrements SSL.
7. **Activer les journaux d’audit** – certains appareils peuvent envoyer les échecs LDAP/SMTP à syslog ; corrélez les binds inattendus.
8. **Surveiller les destinations d’authentification** – déclenchez une alerte lorsqu’une imprimante initie une connexion LDAP, SMB, SMTP ou FTP vers un hôte absent de sa liste d’autorisation, en particulier immédiatement après une connexion de gestion ou une modification de configuration.
9. **SNMPv3 ou désactivation de SNMP** – la communauté `public` leak souvent des informations sur l’appareil et son numéro de série.

---



---

## References

- [1] [Ce n’est qu’une imprimante… Quelle est la pire chose qui puisse arriver ?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Imprimante multifonction Xerox Versalink C7025 : vulnérabilités d’attaque par pass-back (corrigées)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 : atténuation et correction des vulnérabilités pour les imprimantes de production, les imprimantes multifonction de bureau/petit bureau et les imprimantes laser](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Obtention d’identifiants de domaine via une imprimante avec Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Exploitation d’imprimantes multifonction lors d’une mission de penetration test](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Plusieurs appareils Brother : plusieurs vulnérabilités (CORRIGÉES)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit : module de contournement de l’authentification administrateur par défaut de Brother](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
