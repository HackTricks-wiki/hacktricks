# Informations présentes dans les imprimantes

{{#include ../../banners/hacktricks-training.md}}

Une imprimante qui a enregistré des identifiants LDAP peut les exposer si ses paramètres de serveur sont modifiés et qu’elle s’authentifie ensuite auprès d’un point de terminaison malveillant.<sup>[[2]](#references)</sup> Le résultat dépend de la méthode de bind : un simple bind non protégé révèle le mot de passe, tandis qu’un bind avec réponse à un défi SASL ne le révèle pas en texte clair.<sup>[[8]](#references)</sup> Voir [LDAP authentication and transport security](../../network-services-pentesting/pentesting-ldap.md#cleartext-credentials-and-tls-downgrade-risks).

Par ailleurs, plusieurs imprimantes contiennent des **journaux avec des noms d’utilisateur** ou peuvent même **télécharger tous les noms d’utilisateur** depuis le contrôleur de domaine.

Toutes ces **informations sensibles** et le **manque de sécurité** fréquent rendent les imprimantes très intéressantes pour les attaquants.

Quelques blogs d’introduction sur le sujet :

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Configuration de l’imprimante

- **Emplacement** : La liste des serveurs LDAP se trouve généralement dans l’interface web (p. ex. *Réseau ➜ Paramètres LDAP ➜ Configuration LDAP*).
- **Comportement** : De nombreux serveurs web intégrés permettent de modifier les serveurs LDAP **sans saisir à nouveau les identifiants** (fonctionnalité pratique → risque de sécurité).
- **Exploitation** : Redirigez l’adresse du serveur LDAP vers un hôte contrôlé par un attaquant, puis utilisez le bouton *Tester la connexion* / *Synchronisation du carnet d’adresses* pour forcer l’imprimante à effectuer un bind auprès de votre serveur.

---

## Capture des identifiants

### Méthode 1 – Écouteur Netcat

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

Une simple BindRequest peut exposer le bind DN et le mot de passe dans le flux BER, même si le serveur rejette ensuite la connexion. Une recherche anonyme ou une négociation SASL à elle seule n’expose pas ce mot de passe stocké.<sup>[[8]](#references)</sup>

Un simple listener `nc` sur le port 636/3269 voit une négociation TLS, pas un bind LDAP. LDAPS nécessite un endpoint compatible TLS. La validation du certificat ne suffit pas à empêcher le pass-back si l’imprimante accepte un changement de nom d’hôte et que le nouvel endpoint possède un certificat valide pour ce nom d’hôte ; le client doit également limiter les serveurs autorisés à recevoir les identifiants stockés.<sup>[[8]](#references)</sup>

### Méthode 2 – Serveur LDAP rogue complet (recommandé)

Une imprimante peut exiger une réponse LDAP valide avant de tenter un bind.<sup>[[10]](#references)</sup> Un serveur LDAP complet peut gérer cet échange préliminaire, mais il ne peut pas pousser un client configuré pour utiliser un mécanisme SASL robuste ou le serveur TLS prévu à révéler son mot de passe.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # use a base DN compatible with the printer lookup

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

Treat a lookup comme une preuve de connexion, et non comme une preuve de divulgation du mot de passe. Un mot de passe n’est exposé que si le client envoie un bind contenant un mot de passe en clair ; vérifiez le mécanisme de bind réellement utilisé et l’état de TLS.<sup>[[8]](#references)</sup>

> 💡 Responder inclut des services d’authentification LDAP et SMB malveillants. Un simple bind LDAP peut exposer le mot de passe configuré, tandis qu’une authentification NTLM produit des données de challenge-response ; ne décrivez pas ces deux résultats comme un mot de passe en clair.

### Sélection du mécanisme SASL

Certains clients LDAP d’imprimantes choisissent parmi les mécanismes annoncés par un serveur LDAP.<sup>[[8]](#references)[[10]](#references)</sup> Des recherches ont montré qu’un client acceptant un mécanisme SASL en clair annoncé pouvait envoyer un mot de passe, alors que sa négociation NTLM habituelle ne fournirait que des données de challenge-response.<sup>[[9]](#references)[[10]](#references)</sup> Il s’agit d’une **défaillance de la politique du client**, et non d’une propriété de tous les binds SASL : un client qui exige un mécanisme plus robuste ou qui épingle le serveur TLS prévu devrait plutôt échouer de manière sécurisée.<sup>[[8]](#references)</sup> OpenLDAP désactive par défaut les mécanismes SASL permettant l’envoi en clair ; un daemon standard ne prouve donc pas que ce comportement existe sur une imprimante.<sup>[[11]](#references)</sup>

---

## Vulnérabilités récentes de pass-back (2024-2025)

Le pass-back n’est *pas* un problème théorique – les fournisseurs continuent de publier des avis en 2024/2025 qui décrivent précisément cette catégorie d’attaque.

### Xerox VersaLink – CVE-2024-12510 et CVE-2024-12511

Le firmware ≤ 57.69.91 des MFP Xerox VersaLink C70xx permettait à un administrateur authentifié (ou à n’importe qui si les identifiants par défaut étaient conservés) de :

* **CVE-2024-12510 – pass-back LDAP** : modifier l’adresse du serveur LDAP et déclencher une recherche, ce qui amenait l’appareil à divulguer les identifiants Windows configurés à l’hôte contrôlé par l’attaquant.
* **CVE-2024-12511 – pass-back SMB/FTP** : problème identique via les destinations *scan-to-folder*, avec divulgation des identifiants NetNTLMv2 ou FTP en clair.<sup>[[2]](#references)</sup>

Un simple listener tel que :

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

ou un serveur SMB malveillant (`impacket-smbserver`) suffit pour récupérer les identifiants.  

### Canon imageRUNNER / imageCLASS – Avis du 20 mai 2025

Canon a confirmé une faille de **SMTP/LDAP pass-back** touchant des dizaines de gammes de produits Laser et MFP. Un attaquant disposant d’un accès administrateur peut modifier la configuration du serveur et récupérer les identifiants enregistrés pour LDAP **ou** SMTP (de nombreuses organisations utilisent un compte privilégié pour permettre la fonction de numérisation vers e-mail).<sup>[[3]](#references)</sup>

Les recommandations du fournisseur préconisent explicitement :

1. Installer le firmware corrigé dès qu’il est disponible.
2. Utiliser des mots de passe administrateur forts et uniques.
3. Éviter d’utiliser des comptes AD privilégiés pour l’intégration des imprimantes.

---

### Appareils Brother et variantes OEM – accès administrateur dérivé du numéro de série aux identifiants de service

Une divulgation coordonnée en 2025 a démontré une chaîne particulièrement utile sur les appareils Brother concernés ; certaines vulnérabilités de l’ensemble touchent également des modèles OEM. Vérifiez donc le modèle exact dans l’avis de sécurité de son fournisseur. Sur un firmware vulnérable, un attaquant non authentifié peut obtenir le numéro de série de l’appareil via HTTP/HTTPS/IPP, tandis que les numéros de série peuvent également être accessibles par des protocoles de gestion tels que SNMP ou PJL. Si le mot de passe d’usine n’a jamais été modifié, le numéro de série permet de déterminer le mot de passe administrateur. Après authentification, la faille distincte de pass-back CVE-2024-51984 expose en clair les mots de passe des services externes configurés, tels que LDAP ou FTP, transformant l’accès à la gestion de l’imprimante en identifiants réseau réutilisables. Le firmware corrige la divulgation des mots de passe de service, mais les appareils déjà fabriqués nécessitent toujours que l’opérateur remplace le mot de passe administrateur initial dérivé du numéro de série.<sup>[[6]](#references)</sup>

Metasploit inclut actuellement un module auxiliaire qui découvre le numéro de série via HTTP, SNMP ou PJL, génère le mot de passe initial possible et vérifie éventuellement sa validité auprès de la console web. `DiscoverSerialVia=AUTO` essaie les méthodes de découverte prises en charge ; indiquez plutôt `TargetSerial` si l’inventaire des actifs contient déjà le numéro de série.<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

Utilisez le résultat uniquement pour valider des actifs autorisés. La validité du mot de passe dépend du modèle exact et, surtout, du fait que le mot de passe administrateur d’usine ait déjà été changé ou non.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Outils d’énumération / d’exploitation automatisés

| Outil | Fonction | Exemple |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Abus de PostScript/PJL/PCL, accès au système de fichiers, vérification des default-creds, *découverte SNMP* ; voir [évaluation PJL](../../network-services-pentesting/9100-pjl.md) | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Récupération de la configuration (y compris des carnets d’adresses et des identifiants LDAP) via HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Exécution de services d’authentification malveillants et capture/relais de NetNTLM depuis les callbacks SMB | `sudo responder -I eth0 -v` |
| **Module auxiliaire Brother de Metasploit** | Découverte d’un numéro de série, dérivation du mot de passe administrateur d’usine candidat et vérification de l’accès à la console web | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Sécurisation et détection

1. **Appliquer les correctifs / mettre à jour le firmware** des MFP rapidement (consultez les bulletins PSIRT du fabricant).
2. **Remplacer les mots de passe administrateur d’usine** – le firmware seul ne supprime pas les mots de passe initiaux dérivés du numéro de série sur les appareils Brother/OEM concernés déjà fabriqués.<sup>[[6]](#references)</sup>
3. **Comptes de service à privilèges minimaux** – n’utilisez jamais Domain Admin pour LDAP/SMB/SMTP ; limitez les portées d’OU à un accès *en lecture seule*.
4. **Restreindre l’accès à la gestion** – placez les interfaces web/IPP/SNMP de l’imprimante dans un VLAN de gestion ou derrière une ACL/VPN.
5. **Limiter le trafic sortant des imprimantes** – autorisez chaque appareil à contacter uniquement les destinations DC/LDAP, mail, DNS/NTP, impression et fichiers de scan attendues. Un pass-back nécessite un callback vers un endpoint choisi par l’attaquant.
6. **Désactiver les protocoles inutilisés** – FTP, Telnet, raw-9100, anciens chiffrements SSL.
7. **Activer la journalisation d’audit** – certains appareils peuvent envoyer les échecs LDAP/SMTP à syslog ; corrélez les connexions inattendues.
8. **Surveiller les destinations d’authentification** – déclenchez une alerte lorsqu’une imprimante initie une connexion LDAP, SMB, SMTP ou FTP vers un hôte hors de sa liste d’autorisation, en particulier juste après une connexion de gestion ou une modification de configuration.
9. **Utiliser SNMPv3 ou désactiver SNMP** – la communauté `public` leak souvent des informations sur l’appareil et son numéro de série.

---



---



## References

- [1] [Ce n’est qu’une imprimante… Que pourrait-il arriver de pire ?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Imprimante multifonction Xerox Versalink C7025 : vulnérabilités de l’attaque Pass-Back (corrigées)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Mesures d’atténuation et de correction des vulnérabilités pour les imprimantes de production, les imprimantes multifonctions de bureau/petit bureau et les imprimantes laser](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Obtenir des identifiants de domaine via une imprimante avec Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Exploiter des imprimantes multifonctions lors d’un engagement de penetration test](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Plusieurs appareils Brother : plusieurs vulnérabilités (CORRIGÉES)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit : module de contournement de l’authentification administrateur par défaut de Brother](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
- [8] [RFC 4513 – Méthodes d’authentification LDAP et mécanismes de sécurité](https://datatracker.ietf.org/doc/html/rfc4513)
- [9] [Serveur Docker LDAP passback](https://github.com/cybertrinchera/ldap-passback-docker)
- [10] [Attaque LDAP pass back – ACCEIS](https://www.acceis.fr/ldap-pass-back-attack/)
- [11] [slapd-config(5) – Propriétés de sécurité SASL](https://man7.org/linux/man-pages/man5/slapd-config.5.html)
{{#include ../../banners/hacktricks-training.md}}
