# Services réseau et protocoles macOS

{{#include ../../banners/hacktricks-training.md}}

## Services d'accès à distance

Voici les services macOS courants permettant d'y accéder à distance.\
Vous pouvez activer/désactiver ces services dans `Réglages Système` --> `Partage`

- **VNC**, connu sous le nom de « Partage d'écran » (tcp:5900)
- **SSH**, appelé « Connexion à distance » (tcp:22)
- **Apple Remote Desktop** (ARD), ou « Gestion à distance » (tcp:3283, tcp:5900)
- **AppleEvent**, connu sous le nom d'« Apple Event à distance » (tcp:3031)

Vérifiez si l'un d'entre eux est activé en exécutant :
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Énumération de la configuration du partage en local

Lorsque vous disposez déjà d'une exécution de code locale sur un Mac, **vérifiez l'état configuré**, et pas seulement les sockets en écoute. `systemsetup` et `launchctl` indiquent généralement si le service est activé administrativement, tandis que `kickstart` et `system_profiler` aident à confirmer la configuration effective d'ARD/Sharing :
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) est une version améliorée de [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) adaptée à macOS, offrant des fonctionnalités supplémentaires. Une vulnérabilité notable d'ARD concerne sa méthode d'authentification pour le mot de passe de l'écran de contrôle, qui n'utilise que les 8 premiers caractères du mot de passe, le rendant vulnérable aux [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) avec des outils comme Hydra ou [GoRedShell](https://github.com/ahhh/GoRedShell/), car aucune limite de débit par défaut n'est appliquée.<sup>[[3]](#references)</sup>

Les instances vulnérables peuvent être identifiées à l'aide du script `vnc-info` de **nmap**. Les services prenant en charge `VNC Authentication (2)` sont particulièrement vulnérables aux brute force attacks en raison de la troncature du mot de passe à 8 caractères.

Pour activer ARD afin d'effectuer diverses tâches administratives comme la privilege escalation, l'accès à l'interface graphique ou la surveillance des utilisateurs, utilisez la commande suivante :
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD fournit des niveaux de contrôle polyvalents, notamment l'observation, le contrôle partagé et le contrôle total, avec des sessions qui persistent même après la modification des mots de passe utilisateur. Il permet d'envoyer directement des commandes Unix et de les exécuter en tant que root pour les utilisateurs administrateurs. La planification des tâches et la recherche Remote Spotlight sont des fonctionnalités notables, facilitant les recherches distantes et à faible impact de fichiers sensibles sur plusieurs machines.

Du point de vue de l'opérateur, **Monterey 12.1+ a modifié les workflows d'activation à distance** dans les flottes gérées. Si vous contrôlez déjà le MDM de la victime, la commande Apple `EnableRemoteDesktop` est souvent le moyen le plus propre d'activer la fonctionnalité de bureau à distance sur les systèmes récents. Si vous avez déjà un foothold sur l'hôte, `kickstart` reste utile pour inspecter ou reconfigurer les privilèges ARD depuis la ligne de commande.

#### Apple Screen Sharing (RFB 003.889 / security type 36) pre-auth file-copy abuse

Des recherches récentes sur `screensharingd` ont montré qu'Apple Screen Sharing n'utilise pas toujours la classique authentification VNC : les versions récentes parlent **RFB `003.889`** et annoncent le **security type `36`**, où **SRP** authentifie d'abord la session et où **ChaCha20-Poly1305** n'est installé qu'après la réussite de `ccsrp_server_verify_session`. La publication rapporte que le bug a été corrigé dans **macOS Tahoe 26.6** (**27 juillet 2026**).<sup>[[8]](#references)[[9]](#references)</sup>

Un pattern utile à retenir est le **stale-status parser bypass** : après une lecture réussie d'une longueur de 4 octets, chaque branche de taille excessive ou d'erreur doit retourner une nouvelle erreur. Sur les versions affectées, une longueur de trame SRP big-endian **`>= 32768`** fait que le chemin de rejet réutilise le succès précédent de `NetBufferRead` (`0`), de sorte que l'appelant définit la session comme authentifiée alors qu'aucune preuve de mot de passe n'a été exécutée et qu'aucun chiffrement du transport n'a été installé. Comme les octets non lus restent dans le buffer socket partagé, un attaquant peut **mettre en pipeline des données SRP malformées et des messages RFB post-auth dans le même burst TCP** et les faire analyser comme du **trafic authentifié en clair**.<sup>[[8]](#references)</sup>

Après le bypass, le message propriétaire de **file-copy** d'Apple **`0x22`** devient une **primitive de lecture/écriture de fichiers en tant que root**, car `screensharingd` s'exécute en tant que root :<sup>[[8]](#references)</sup>
```text
[u8 0x22][u8 sub][be32 L]
[be16 ver][be16 kind][be32 sid][be32 arg]
[L-12 bytes payload]
```
- `kind=1` / `StartFileSend`: lecture arbitraire de fichiers
- `kind=2` / `StartFileReceive`: écriture arbitraire de fichiers
- Différentes valeurs de `sid` permettent de mettre en pipeline plusieurs transactions dans une même connexion
- Dans `kind=101` (`NewItem`), définissez l’octet `14` / `arg[0]` à `0x01` pour un fichier ordinaire, l’offset de payload `+42` à une taille de fichier big-endian **non nulle**, et l’offset de payload `+0x5a` au mode Unix souhaité (`0600` si vous ciblez une crontab)

Les pivots post-write intéressants sur les chemins accessibles en écriture incluent **`/etc/sudoers.d/`**, **`/etc/zshenv`**, **`/Library/LaunchDaemons/`** et **`/var/root/.ssh/authorized_keys`**. **SIP n’empêche ni l’auth bypass ni la lecture de fichiers en tant que root**, mais il bloque certaines cibles d’écriture comme **`/var/at`** ; l’exécution basée sur cron ne fonctionne donc qu’avec SIP désactivé. Sur les hôtes utilisant la configuration par défaut avec SIP activé, pensez plutôt en termes d’**« écriture de fichiers en tant que root dans des fichiers privilégiés consommés automatiquement »** que d’exécution immédiate de code.<sup>[[8]](#references)</sup>

Un autre piège SRP relevé par la même étude : les serveurs doivent valider **`A mod N != 0`** (conformément à la RFC 5054), et pas seulement **`A > 0`**. Accepter **`A = N`** peut forcer le secret partagé à zéro et compromettre la vérification du mot de passe.<sup>[[8]](#references)[[10]](#references)</sup>

**Idées de détection**

- Sessions de type de sécurité `36` où la longueur de la première trame SRP est **`>= 32768`**
- Sessions qui commencent à traiter du trafic de copie de fichiers en clair **`0x22`** avant toute preuve SRP réussie / installation du cipher
- Tentatives répétées de courte durée vers **TCP/5900**, ainsi que plusieurs valeurs de `sid` de copie de fichiers dans une même rafale
- Création inattendue de **`/etc/zshenv`**, **`/etc/sudoers.d/*`**, **`/Library/LaunchDaemons/*.plist`** ou **`/var/root/.ssh/authorized_keys`** après l’exposition de Screen Sharing

### Pentesting Remote Apple Events (RAE / EPPC)

Apple appelle cette fonctionnalité **Remote Application Scripting** dans les System Settings modernes. En interne, elle expose l’**Apple Event Manager** à distance via **EPPC** sur **TCP/3031**, par l’intermédiaire du service `com.apple.AEServer`. Palo Alto Unit 42 l’a de nouveau présentée comme un primitive pratique de **macOS lateral movement**, car des credentials valides associés à un service RAE activé permettent à un opérateur de piloter des applications scriptables sur un Mac distant.<sup>[[6]](#references)</sup>

Vérifications utiles :
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
Si vous disposez déjà des privilèges admin/root sur la cible et souhaitez l’activer :
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
Test de connectivité de base depuis un autre Mac :
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
En pratique, le cas d'abus ne se limite pas à Finder. Toute **scriptable application** qui accepte les Apple events requis devient une surface d'attaque distante, ce qui rend RAE particulièrement intéressant après le vol d'identifiants sur des réseaux macOS internes.

#### Vulnérabilités récentes de Screen-Sharing / ARD (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Un rendu incorrect de la session pouvait entraîner la transmission du *mauvais* bureau ou de la *mauvaise* fenêtre, provoquant une fuite d'informations sensibles|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|Un utilisateur disposant d'un accès au partage d'écran pouvait être en mesure de voir **l'écran d'un autre utilisateur** en raison d'un problème de gestion d'état|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

**Conseils de hardening**

* Désactivez *Screen Sharing*/*Remote Management* lorsqu'ils ne sont pas strictement nécessaires.
* Maintenez macOS entièrement à jour (Apple fournit généralement des correctifs de sécurité pour les trois dernières versions majeures).
* Utilisez un **Strong Password** *et* maintenez l'option *“VNC viewers may control screen with password”* **désactivée** lorsque cela est possible.
* Placez le service derrière un VPN au lieu d'exposer TCP 5900/3283 à Internet.
* Ajoutez une règle d'Application Firewall pour limiter `ARDAgent` au sous-réseau local :

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Protocole Bonjour

Bonjour, une technologie conçue par Apple, permet aux **appareils présents sur le même réseau de détecter les services proposés par les uns et les autres**. Également connu sous les noms de Rendezvous, **Zero Configuration** ou Zeroconf, il permet à un appareil de rejoindre un réseau TCP/IP, de **choisir automatiquement une adresse IP** et de diffuser ses services aux autres appareils du réseau.

Le Zero Configuration Networking, fourni par Bonjour, garantit que les appareils peuvent :

- **Obtenir automatiquement une adresse IP**, même en l'absence de serveur DHCP.
- Effectuer une **traduction nom-adresse** sans nécessiter de serveur DNS.
- **Découvrir les services** disponibles sur le réseau.

Les appareils utilisant Bonjour s'attribuent une **adresse IP de la plage 169.254/16** et vérifient son unicité sur le réseau. Les Macs maintiennent une entrée de table de routage pour ce sous-réseau, vérifiable avec `netstat -rn | grep 169`.

Pour le DNS, Bonjour utilise le **protocole Multicast DNS (mDNS)**. mDNS fonctionne sur le **port 5353/UDP**, en utilisant des **requêtes DNS standard**, mais en ciblant l'**adresse multicast 224.0.0.251**. Cette approche garantit que tous les appareils à l'écoute sur le réseau peuvent recevoir les requêtes et y répondre, ce qui facilite la mise à jour de leurs enregistrements.

Lorsqu'il rejoint le réseau, chaque appareil sélectionne automatiquement un nom, se terminant généralement par **.local**, qui peut être dérivé du hostname ou généré aléatoirement.

La découverte des services au sein du réseau est assurée par le **DNS Service Discovery (DNS-SD)**. En s'appuyant sur le format des enregistrements DNS SRV, DNS-SD utilise des **enregistrements DNS PTR** pour permettre de répertorier plusieurs services. Un client recherchant un service spécifique demande un enregistrement PTR pour `<Service>.<Domain>`, et reçoit en retour une liste d'enregistrements PTR au format `<Instance>.<Service>.<Domain>` si le service est disponible depuis plusieurs hosts.

L'utilitaire `dns-sd` peut être utilisé pour **découvrir et annoncer des services réseau**. Voici quelques exemples d'utilisation :

### Recherche de services SSH

Pour rechercher des services SSH sur le réseau, la commande suivante est utilisée :
```bash
dns-sd -B _ssh._tcp
```
Cette commande lance la recherche de services \_ssh.\_tcp et affiche des informations telles que l’horodatage, les flags, l’interface, le domaine, le type de service et le nom de l’instance.

### Annoncer un service HTTP

Pour annoncer un service HTTP, vous pouvez utiliser :
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Cette commande enregistre un service HTTP nommé « Index » sur le port 80 avec un chemin `/index.html`.

Pour rechercher ensuite des services HTTP sur le réseau :
```bash
dns-sd -B _http._tcp
```
Lorsqu’un service démarre, il annonce sa disponibilité à tous les appareils du sous-réseau en multicastant sa présence. Les appareils intéressés par ces services n’ont pas besoin d’envoyer de requêtes, mais peuvent simplement écouter ces annonces.

Pour une interface plus conviviale, l’application **Discovery - DNS-SD Browser**, disponible sur l’Apple App Store, peut visualiser les services proposés sur votre réseau local.

Vous pouvez également écrire des scripts personnalisés pour parcourir et découvrir les services à l’aide de la bibliothèque `python-zeroconf`. Le script [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) montre comment créer un navigateur de services pour les services `_http._tcp.local.`, en affichant les services ajoutés ou supprimés :
```python
from zeroconf import ServiceBrowser, Zeroconf

class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
### Hunting Bonjour spécifique à macOS

Sur les réseaux macOS, Bonjour est souvent le moyen le plus simple de trouver des **surfaces d'administration à distance** sans interagir directement avec la cible. Apple Remote Desktop peut lui-même découvrir les clients via Bonjour ; les mêmes données de découverte sont donc utiles à un attaquant.
```bash
# Enumerate every advertised service type first
dns-sd -B _services._dns-sd._udp local

# Then look for common macOS admin surfaces
dns-sd -B _rfb._tcp local      # Screen Sharing / VNC
dns-sd -B _ssh._tcp local      # Remote Login
dns-sd -B _eppc._tcp local     # Remote Apple Events / EPPC

# Resolve a specific instance to hostname, port and TXT data
dns-sd -L "<Instance>" _rfb._tcp local
dns-sd -L "<Instance>" _eppc._tcp local
```
Pour des techniques plus larges de **mDNS spoofing, impersonation et cross-subnet discovery**, consultez la page dédiée :

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Énumération de Bonjour sur le réseau

* **Nmap NSE** – découverte des services annoncés par un seul hôte :

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

Le script `dns-service-discovery` envoie une requête `_services._dns-sd._udp.local`, puis énumère chaque type de service annoncé.

* **mdns_recon** – outil Python qui analyse des plages entières à la recherche de responders mDNS *mal configurés* répondant aux requêtes unicast (utile pour trouver des appareils accessibles au-delà des subnets/WAN) :

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Cette commande renverra les hôtes exposant SSH via Bonjour en dehors du link local.

### Considérations de sécurité et vulnérabilités récentes (2024-2025)

| Année | CVE | Gravité | Problème | Corrigé dans |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Moyenne|Une erreur logique dans *mDNSResponder* permettait à un paquet spécialement conçu de déclencher un **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (sept. 2024) |
|2025|CVE-2025-31222|Élevée|Un problème de correction dans *mDNSResponder* pouvait être exploité pour une **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (mai 2025) |

**Recommandations d’atténuation**

1. Restreindre UDP 5353 à la portée *link-local* – le bloquer ou limiter son débit sur les contrôleurs wireless, les routeurs et les host-based firewalls.
2. Désactiver complètement Bonjour sur les systèmes qui ne nécessitent pas la service discovery :

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Dans les environnements où Bonjour est requis en interne mais ne doit jamais traverser les limites du réseau, utiliser les restrictions du profil *AirPlay Receiver* (MDM) ou un proxy mDNS.
4. Activer **System Integrity Protection (SIP)** et maintenir macOS à jour – les deux vulnérabilités ci-dessus ont été corrigées rapidement, mais reposaient sur l'activation de SIP pour assurer une protection complète.

### Désactivation de Bonjour

Si des préoccupations de sécurité ou d'autres raisons justifient la désactivation de Bonjour, il est possible de le faire à l'aide de la commande suivante :
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Références

- [1] [Le manuel du hacker Mac](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Volume I: Analyse - Patrick Wardle](https://taomm.org/vol1/analysis.html)
- [3] [LockBoxx - macOS Red Teaming 206: ARD (Apple Remote Desktop Protocol)](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [4] [NVD – CVE-2023-42940](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [5] [NVD – CVE-2024-44183](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [6] [Palo Alto Unit 42 - Lateral Movement on macOS: Techniques uniques et populaires et exemples In-the-Wild](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [7] [Apple Support - À propos du contenu de sécurité de macOS Sonoma 14.7.2](https://support.apple.com/en-us/121840)
- [8] [Apple Screen Sharing Pre-Auth RCE](https://warez.sl0p.foo/apple-screensharing-rce/)
- [9] [Apple Support - À propos du contenu de sécurité de macOS Tahoe 26.6](https://support.apple.com/en-us/128067)
- [10] [RFC 5054 - Utilisation du protocole Secure Remote Password (SRP) pour l'authentification TLS](https://www.rfc-editor.org/rfc/rfc5054)

{{#include ../../banners/hacktricks-training.md}}
