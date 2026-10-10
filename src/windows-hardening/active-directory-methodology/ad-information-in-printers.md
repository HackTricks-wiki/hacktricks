# Informations dans les imprimantes

{{#include ../../banners/hacktricks-training.md}}

Plusieurs blogs sur Internet **soulignent les dangers liés aux imprimantes configurées avec LDAP et des identifiants de connexion par défaut/faibles**.  \
En effet, un attaquant pourrait **piéger l’imprimante pour qu’elle s’authentifie auprès d’un serveur LDAP malveillant** (généralement, un `nc -vv -l -p 389` ou un `slapd -d 2` suffit) et capturer les **identifiants de l’imprimante en clair**.

De plus, plusieurs imprimantes contiennent des **journaux avec des noms d’utilisateur** ou peuvent même **télécharger tous les noms d’utilisateur** depuis le Domain Controller.

Toutes ces **informations sensibles** et le **manque de sécurité** courant rendent les imprimantes très intéressantes pour les attaquants.

Quelques blogs d’introduction sur le sujet :

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Configuration de l’imprimante

- **Emplacement** : La liste des serveurs LDAP se trouve généralement dans l’interface web (p. ex. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Comportement** : De nombreux serveurs web embarqués permettent de modifier les serveurs LDAP **sans saisir à nouveau les identifiants** (fonctionnalité pratique → risque de sécurité).
- **Exploit** : Redirigez l’adresse du serveur LDAP vers un hôte contrôlé par l’attaquant, puis utilisez le bouton *Test Connection* / *Address Book Sync* pour forcer l’imprimante à établir une liaison avec vous.

---

## Capture des identifiants

### Méthode 1 – Listener Netcat

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

Les MFP de petite taille ou anciens peuvent envoyer un *simple-bind* dont le DN de bind et le mot de passe sont visibles dans le flux BER brut. Les appareils modernes effectuent généralement d’abord une requête anonyme, puis tentent le bind ; les résultats varient donc.<sup>[[1]](#references)</sup>

Un simple listener `nc` sur 636/3269 ne reçoit que le texte chiffré TLS ; tester LDAPS nécessite un endpoint LDAP compatible TLS, et la redirection devrait échouer si l’appareil valide correctement le certificat du serveur.

### Méthode 2 – Serveur LDAP rogue complet (recommandé)

Comme de nombreux appareils effectuent une recherche anonyme *avant* l’authentification, le déploiement d’un véritable daemon LDAP donne des résultats beaucoup plus fiables :<sup>[[1]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

Lorsque l’imprimante effectue sa recherche, les identifiants en clair apparaissent dans la sortie de débogage.

> 💡 Responder inclut des services d’authentification LDAP et SMB malveillants. Une simple liaison LDAP peut exposer le mot de passe configuré, tandis qu’une authentification NTLM produit des éléments de réponse au défi ; ne décrivez pas ces deux résultats comme un mot de passe en clair.

---

## Vulnérabilités récentes de Pass-Back (2024-2025)

Le Pass-Back n’est *pas* un problème théorique : les fournisseurs publient encore, en 2024/2025, des avis qui décrivent précisément cette catégorie d’attaque.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Les versions de firmware ≤ 57.69.91 des MFP Xerox VersaLink C70xx permettaient à un administrateur authentifié (ou à n’importe qui si les identifiants par défaut étaient toujours utilisés) de :

* **CVE-2024-12510 – LDAP pass-back** : modifier l’adresse du serveur LDAP et déclencher une recherche, ce qui amène l’appareil à divulguer les identifiants Windows configurés à l’hôte contrôlé par l’attaquant.
* **CVE-2024-12511 – SMB/FTP pass-back** : même problème via les destinations *scan-to-folder*, avec divulgation de NetNTLMv2 ou d’identifiants FTP en clair.<sup>[[2]](#references)</sup>

Un simple écouteur, par exemple :

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

ou un serveur SMB malveillant (`impacket-smbserver`) suffit pour récupérer les identifiants.  

### Canon imageRUNNER / imageCLASS – Avis du 20 mai 2025

Canon a confirmé une vulnérabilité de **SMTP/LDAP pass-back** touchant des dizaines de gammes de produits Laser et MFP. Un attaquant disposant d’un accès administrateur peut modifier la configuration du serveur et récupérer les identifiants stockés pour LDAP **ou** SMTP (de nombreuses organisations utilisent un compte privilégié pour permettre la numérisation vers une adresse e-mail).<sup>[[3]](#references)</sup>

Les recommandations du fournisseur préconisent explicitement :

1. Installer les mises à jour du firmware dès qu’elles sont disponibles.
2. Utiliser des mots de passe administrateur robustes et uniques.
3. Éviter d’utiliser des comptes AD privilégiés pour l’intégration des imprimantes.

---

### Appareils Brother et variantes OEM – Accès administrateur dérivé du numéro de série et récupération des identifiants de services

Une divulgation coordonnée en 2025 a démontré une chaîne particulièrement utile sur les appareils Brother concernés ; certaines vulnérabilités de cet ensemble touchent aussi des modèles OEM. Vérifiez donc le modèle exact dans l’avis de sécurité du fournisseur. Sur les firmwares vulnérables, un attaquant non authentifié peut obtenir le numéro de série de l’appareil via HTTP/HTTPS/IPP. Les numéros de série peuvent également être accessibles par des protocoles de gestion tels que SNMP ou PJL. Si le mot de passe d’usine n’a jamais été modifié, le numéro de série permet de déterminer le mot de passe administrateur. Une fois authentifié, l’attaquant peut exploiter la vulnérabilité distincte de pass-back CVE-2024-51984, qui expose en texte clair les mots de passe configurés pour des services externes, tels que LDAP ou FTP. L’accès à la gestion de l’imprimante donne ainsi accès à des identifiants réseau réutilisables. Le firmware corrige la divulgation des mots de passe de service, mais les appareils fabriqués précédemment nécessitent toujours que l’opérateur remplace le mot de passe administrateur initial dérivé du numéro de série.<sup>[[6]](#references)</sup>

Metasploit comprend actuellement un module auxiliaire qui découvre le numéro de série via HTTP, SNMP ou PJL, génère le mot de passe initial potentiel et vérifie éventuellement sa validité dans la console web. `DiscoverSerialVia=AUTO` essaie les méthodes de découverte prises en charge ; indiquez plutôt `TargetSerial` si le numéro de série figure déjà dans l’inventaire des équipements.<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

Utilisez le résultat uniquement pour valider des actifs autorisés. La validité du mot de passe dépend du modèle exact et, surtout, du fait que le mot de passe administrateur d’usine ait déjà été modifié ou non.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Outils d’énumération / d’exploitation automatisés

| Outil | Objectif | Exemple |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Exploitation de PostScript/PJL/PCL, accès au système de fichiers, vérification des identifiants par défaut, *découverte SNMP* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Récupération de la configuration (y compris les carnets d’adresses et les identifiants LDAP) via HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Exécution de services d’authentification malveillants et capture/relais de NetNTLM via des callbacks SMB | `sudo responder -I eth0 -v` |
| **Module auxiliaire Brother de Metasploit** | Découvrir un numéro de série, en déduire le mot de passe administrateur d’usine possible et vérifier l’accès à la console Web | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Renforcement de la sécurité et détection

1. **Appliquez les correctifs / mettez à jour le firmware** des MFP rapidement (consultez les bulletins PSIRT des fournisseurs).
2. **Remplacez les mots de passe administrateur d’usine** – le firmware seul ne supprime pas les mots de passe initiaux dérivés du numéro de série sur les appareils Brother/OEM concernés déjà fabriqués.<sup>[[6]](#references)</sup>
3. **Comptes de service à privilèges minimaux** – n’utilisez jamais Domain Admin pour LDAP/SMB/SMTP ; limitez les comptes à des étendues d’OU en *lecture seule*.
4. **Limitez l’accès à la gestion** – placez les interfaces Web/IPP/SNMP de l’imprimante dans un VLAN de gestion ou derrière une ACL/VPN.
5. **Limitez le trafic sortant des imprimantes** – autorisez chaque appareil à contacter uniquement les destinations DC/LDAP, messagerie, DNS/NTP, impression et fichiers de numérisation prévues. Une attaque pass-back nécessite un callback vers un endpoint choisi par l’attaquant.
6. **Désactivez les protocoles inutilisés** – FTP, Telnet, raw-9100, anciens chiffrements SSL.
7. **Activez la journalisation d’audit** – certains appareils peuvent envoyer les échecs LDAP/SMTP à syslog ; corrélez les binds inattendus.
8. **Surveillez les destinations d’authentification** – déclenchez une alerte lorsqu’une imprimante initie une connexion LDAP, SMB, SMTP ou FTP vers un hôte hors de sa liste d’autorisation, en particulier juste après une connexion de gestion ou une modification de configuration.
9. **Utilisez SNMPv3 ou désactivez SNMP** – la communauté `public` divulgue souvent des informations sur l’appareil et son numéro de série.

---

---

## References

- [1] [Ce n’est qu’une imprimante… Que pourrait-il arriver de pire ?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Imprimante multifonction Xerox Versalink C7025 : vulnérabilités aux attaques pass-back (corrigées)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Mesures d’atténuation/correction des vulnérabilités pour les imprimantes de production, les imprimantes multifonctions pour bureaux/petits bureaux et les imprimantes laser](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Obtention d’identifiants de domaine via une imprimante avec Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Exploitation d’imprimantes multifonctions lors d’un test de pénétration](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Plusieurs appareils Brother : multiples vulnérabilités (CORRIGÉES)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit : module de contournement de l’authentification administrateur par défaut de Brother](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
