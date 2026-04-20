# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## Remote Access Services

Voici les services macOS courants pour y accéder à distance.\
Vous pouvez activer/désactiver ces services dans `System Settings` --> `Sharing`

- **VNC**, connu sous le nom de “Screen Sharing” (tcp:5900)
- **SSH**, appelé “Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD), ou “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, connu sous le nom de “Remote Apple Event” (tcp:3031)

Vérifiez si l’un d’eux est activé en exécutant :
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Énumérer la configuration de partage localement

Lorsque vous avez déjà une exécution de code locale sur un Mac, **vérifiez l’état configuré**, pas seulement les sockets en écoute. `systemsetup` et `launchctl` indiquent généralement si le service est activé par l’administrateur, tandis que `kickstart` et `system_profiler` aident à confirmer la configuration ARD/Sharing effective :
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) est une version améliorée de [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) adaptée à macOS, offrant des fonctionnalités supplémentaires. Une vulnérabilité notable dans ARD concerne sa méthode d'authentification pour le mot de passe de l'écran de contrôle, qui n'utilise que les 8 premiers caractères du mot de passe, ce qui la rend vulnérable aux [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) avec des outils comme Hydra ou [GoRedShell](https://github.com/ahhh/GoRedShell/), car il n'y a pas de limites de débit par défaut.

Les instances vulnérables peuvent être identifiées à l'aide du script `vnc-info` de **nmap**. Les services prenant en charge `VNC Authentication (2)` sont particulièrement susceptibles aux brute force attacks en raison de la troncature du mot de passe à 8 caractères.

Pour activer ARD pour diverses tâches administratives comme privilege escalation, l'accès GUI ou la surveillance des utilisateurs, utilisez la commande suivante :
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD fournit plusieurs niveaux de contrôle polyvalents, notamment l’observation, le contrôle partagé et le contrôle total, avec des sessions qui persistent même après des changements de mot de passe utilisateur. Il permet d’envoyer directement des commandes Unix, en les exécutant en tant que root pour les utilisateurs administratifs. La planification des tâches et la recherche à distance via Spotlight sont des fonctionnalités notables, facilitant des recherches distantes à faible impact de fichiers sensibles sur plusieurs machines.

Du point de vue de l’opérateur, **Monterey 12.1+ a modifié les workflows d’activation à distance** dans les parcs gérés. Si vous contrôlez déjà le MDM de la victime, la commande `EnableRemoteDesktop` d’Apple est souvent la méthode la plus propre pour activer la fonctionnalité de bureau à distance sur les systèmes récents. Si vous avez déjà un foothold sur l’hôte, `kickstart` reste utile pour inspecter ou reconfigurer les privilèges ARD depuis la ligne de commande.

### Pentesting Remote Apple Events (RAE / EPPC)

Apple appelle cette fonctionnalité **Remote Application Scripting** dans les réglages système modernes. En interne, elle expose le **Apple Event Manager** à distance via **EPPC** sur **TCP/3031** à travers le service `com.apple.AEServer`. Palo Alto Unit 42 l’a de nouveau mise en avant comme un primitive pratique de **macOS lateral movement** car des identifiants valides, plus un service RAE activé, permettent à un opérateur de piloter des applications scriptables sur un Mac distant.

Vérifications utiles :
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
Si vous avez déjà admin/root sur la cible et que vous voulez l’activer :
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
Test de connectivité de base depuis un autre Mac :
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
En pratique, le cas d'abus ne se limite pas à Finder. Toute **application scriptable** qui accepte les Apple events requis devient une surface d'attaque distante, ce qui rend RAE particulièrement intéressant après un vol d'identifiants sur des réseaux macOS internes.

#### Vulnérabilités récentes de Screen Sharing / ARD (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Un rendu de session incorrect pouvait faire transmettre le *mauvais* bureau ou la *mauvaise* fenêtre, entraînant une fuite d'informations sensibles|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|Un utilisateur ayant accès au screen sharing peut être en mesure de voir **l'écran d'un autre utilisateur** en raison d'un problème de gestion d'état|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

**Conseils de hardening**

* Désactivez *Screen Sharing*/*Remote Management* quand ce n'est pas strictement nécessaire.
* Maintenez macOS entièrement à jour (Apple publie généralement des correctifs de sécurité pour les trois dernières versions majeures).
* Utilisez un **Strong Password** *et* imposez, si possible, l'option *“VNC viewers may control screen with password”* **désactivée**.
* Placez le service derrière un VPN au lieu d'exposer TCP 5900/3283 sur Internet.
* Ajoutez une règle de pare-feu applicatif pour limiter `ARDAgent` au sous-réseau local :

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour Protocol

Bonjour, une technologie conçue par Apple, permet aux **devices sur le même réseau de détecter les services offerts par chacun**. Également connue sous le nom de Rendezvous, **Zero Configuration**, ou Zeroconf, elle permet à un device de rejoindre un réseau TCP/IP, **de choisir automatiquement une adresse IP**, et d'annoncer ses services aux autres devices du réseau.

Zero Configuration Networking, fourni par Bonjour, garantit que les devices peuvent :

- **Obtenir automatiquement une adresse IP** même en l'absence d'un serveur DHCP.
- Effectuer une **traduction nom-vers-adresse** sans nécessiter de serveur DNS.
- **Découvrir les services** disponibles sur le réseau.

Les devices utilisant Bonjour s'attribuent une **adresse IP de la plage 169.254/16** et en vérifient l'unicité sur le réseau. Les Mac conservent une entrée de table de routage pour ce sous-réseau, vérifiable via `netstat -rn | grep 169`.

Pour DNS, Bonjour utilise le **protocole Multicast DNS (mDNS)**. mDNS fonctionne sur le **port 5353/UDP**, en utilisant des **requêtes DNS standard** mais en ciblant l'**adresse multicast 224.0.0.251**. Cette approche garantit que tous les devices à l'écoute sur le réseau peuvent recevoir et répondre aux requêtes, facilitant la mise à jour de leurs enregistrements.

Lors de la connexion au réseau, chaque device choisit lui-même un nom, se terminant généralement par **.local**, qui peut être dérivé du hostname ou généré aléatoirement.

La découverte de services sur le réseau est facilitée par **DNS Service Discovery (DNS-SD)**. En s'appuyant sur le format des enregistrements DNS SRV, DNS-SD utilise des **enregistrements DNS PTR** pour permettre le référencement de plusieurs services. Un client cherchant un service spécifique demandera un enregistrement PTR pour `<Service>.<Domain>`, recevant en retour une liste d'enregistrements PTR formatés comme `<Instance>.<Service>.<Domain>` si le service est disponible sur plusieurs hosts.

L'utilitaire `dns-sd` peut être utilisé pour **découvrir et annoncer des services réseau**. Voici quelques exemples de son utilisation :

### Rechercher des services SSH

Pour rechercher des services SSH sur le réseau, la commande suivante est utilisée :
```bash
dns-sd -B _ssh._tcp
```
Cette commande lance la recherche des services \_ssh.\_tcp et affiche des détails tels que l'horodatage, les flags, l'interface, le domaine, le type de service et le nom de l'instance.

### Advertising an HTTP Service

Pour annoncer un service HTTP, vous pouvez utiliser :
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Cette commande enregistre un service HTTP nommé "Index" sur le port 80 avec un chemin `/index.html`.

Pour ensuite rechercher des services HTTP sur le réseau :
```bash
dns-sd -B _http._tcp
```
Lorsqu’un service démarre, il annonce sa disponibilité à tous les appareils du sous-réseau en diffusant sa présence par multicast. Les appareils intéressés par ces services n’ont pas besoin d’envoyer de requêtes, ils n’ont qu’à écouter ces annonces.

Pour une interface plus conviviale, l’app **Discovery - DNS-SD Browser** disponible sur l’Apple App Store peut visualiser les services proposés sur votre réseau local.

Sinon, des scripts personnalisés peuvent être écrits pour parcourir et découvrir des services à l’aide de la bibliothèque `python-zeroconf`. Le script [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) montre comment créer un navigateur de services pour les services `_http._tcp.local.`, en affichant les services ajoutés ou supprimés :
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
### Chasse Bonjour spécifique à macOS

Sur les réseaux macOS, Bonjour est souvent le moyen le plus simple de trouver des **surfaces d’administration à distance** sans toucher directement la cible. Apple Remote Desktop lui-même peut découvrir des clients via Bonjour, donc ces mêmes données de découverte sont utiles à un attaquant.
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

* **Nmap NSE** – découvrir les services annoncés par un seul hôte :

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

Le script `dns-service-discovery` envoie une requête `_services._dns-sd._udp.local` puis énumère chaque type de service annoncé.

* **mdns_recon** – outil Python qui analyse des plages entières à la recherche de *misconfigured* mDNS responders qui répondent aux requêtes unicast (utile pour trouver des appareils accessibles à travers des subnets/WAN) :

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Cela retournera les hôtes exposant SSH via Bonjour en dehors du lien local.

### Considérations de sécurité et vulnérabilités récentes (2024-2025)

| Année | CVE | Gravité | Problème | Corrigé dans |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|Une erreur de logique dans *mDNSResponder* permettait à un paquet forgé de déclencher un **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|Un problème de correctness dans *mDNSResponder* pouvait être exploité pour une **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) |

**Conseils de mitigation**

1. Restreignez UDP 5353 au périmètre *link-local* – bloquez-le ou limitez son débit sur les contrôleurs sans fil, les routeurs et les pare-feu côté hôte.
2. Désactivez complètement Bonjour sur les systèmes qui n’ont pas besoin de service discovery :

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Pour les environnements où Bonjour est requis en interne mais ne doit jamais traverser les frontières réseau, utilisez des restrictions de profil *AirPlay Receiver* (MDM) ou un proxy mDNS.
4. Activez **System Integrity Protection (SIP)** et maintenez macOS à jour – les deux vulnérabilités ci-dessus ont été corrigées rapidement mais dépendaient de SIP activé pour une protection complète.

### Désactiver Bonjour

S’il existe des préoccupations de sécurité ou d’autres raisons de désactiver Bonjour, il peut être désactivé avec la commande suivante :
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Références

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [**NVD – CVE-2023-42940**](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [**NVD – CVE-2024-44183**](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [**Palo Alto Unit 42 - Lateral Movement on macOS: Unique and Popular Techniques and In-the-Wild Examples**](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [**Apple Support - About the security content of macOS Sonoma 14.7.2**](https://support.apple.com/en-us/121840)

{{#include ../../banners/hacktricks-training.md}}
