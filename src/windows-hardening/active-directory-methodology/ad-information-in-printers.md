{{#include ../../banners/hacktricks-training.md}}

Il existe plusieurs blogs sur Internet qui **mettent en évidence les dangers de laisser les imprimantes configurées avec LDAP avec des** identifiants de connexion par défaut/faibles.\
Ceci est dû au fait qu'un attaquant pourrait **tromper l'imprimante pour s'authentifier contre un serveur LDAP malveillant** (typiquement un `nc -vv -l -p 444` suffit) et capturer les **identifiants de l'imprimante en clair**.

De plus, plusieurs imprimantes contiendront **des journaux avec des noms d'utilisateur** ou pourraient même être capables de **télécharger tous les noms d'utilisateur** du contrôleur de domaine.

Toutes ces **informations sensibles** et le **manque de sécurité** commun rendent les imprimantes très intéressantes pour les attaquants.

Quelques blogs sur le sujet :

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Configuration de l'imprimante

- **Emplacement** : La liste des serveurs LDAP se trouve à : `Network > LDAP Setting > Setting Up LDAP`.
- **Comportement** : L'interface permet des modifications du serveur LDAP sans avoir à réintroduire les identifiants, visant la commodité de l'utilisateur mais posant des risques de sécurité.
- **Exploitation** : L'exploitation consiste à rediriger l'adresse du serveur LDAP vers une machine contrôlée et à utiliser la fonction "Tester la connexion" pour capturer les identifiants.

## Capture des identifiants

**Pour des étapes plus détaillées, référez-vous à la [source](https://grimhacker.com/2018/03/09/just-a-printer/).**

### Méthode 1 : Écouteur Netcat

Un simple écouteur netcat pourrait suffire :
```bash
sudo nc -k -v -l -p 386
```
Cependant, le succès de cette méthode varie.

### Méthode 2 : Serveur LDAP complet avec Slapd

Une approche plus fiable consiste à mettre en place un serveur LDAP complet car l'imprimante effectue un null bind suivi d'une requête avant d'essayer le binding des identifiants.

1. **Configuration du serveur LDAP** : Le guide suit les étapes de [cette source](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Étapes clés** :
- Installer OpenLDAP.
- Configurer le mot de passe administrateur.
- Importer des schémas de base.
- Définir le nom de domaine sur la base de données LDAP.
- Configurer LDAP TLS.
3. **Exécution du service LDAP** : Une fois configuré, le service LDAP peut être exécuté en utilisant :
```bash
slapd -d 2
```
## Références

- [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)

{{#include ../../banners/hacktricks-training.md}}
