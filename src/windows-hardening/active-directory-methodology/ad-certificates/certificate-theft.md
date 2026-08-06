# AD CS-Zertifikatsdiebstahl

{{#include ../../../banners/hacktricks-training.md}}

**Dies ist eine kurze Zusammenfassung der Kapitel zum Diebstahl aus der großartigen Forschungsarbeit von [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**<sup>[[1]](#references)</sup>

## Was kann ich mit einem Zertifikat tun?

Bevor wir uns ansehen, wie man die Zertifikate stiehlt, findest du hier einige Informationen darüber, wofür das Zertifikat verwendet werden kann:
```bash
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## Exportieren von Zertifikaten mithilfe der Crypto APIs – THEFT1

In einer **interaktiven Desktop-Sitzung** kann ein Benutzer- oder Maschinenzertifikat zusammen mit dem privaten Schlüssel problemlos extrahiert werden, insbesondere wenn der **private Schlüssel exportierbar** ist. Dazu navigiert man in `certmgr.msc` zum Zertifikat, klickt mit der rechten Maustaste darauf und wählt `All Tasks → Export`, um eine passwortgeschützte .pfx-Datei zu erstellen.<sup>[[1]](#references)</sup>

Für einen **programmgesteuerten Ansatz** stehen Tools wie das PowerShell-Cmdlet `ExportPfxCertificate` oder Projekte wie [TheWover’s CertStealer C# project](https://github.com/TheWover/CertStealer) zur Verfügung. Diese verwenden die **Microsoft CryptoAPI** (CAPI) oder die Cryptography API: Next Generation (CNG), um mit dem Zertifikatsspeicher zu interagieren. Diese APIs stellen eine Reihe kryptografischer Dienste bereit, darunter auch die für die Zertifikatspeicherung und Authentifizierung erforderlichen.

Wenn ein privater Schlüssel jedoch als nicht exportierbar festgelegt ist, blockieren sowohl CAPI als auch CNG normalerweise die Extraktion solcher Zertifikate. Um diese Einschränkung zu umgehen, können Tools wie **Mimikatz** eingesetzt werden. Mimikatz stellt die Befehle `crypto::capi` und `crypto::cng` bereit, um die jeweiligen APIs zu patchen und dadurch den Export privater Schlüssel zu ermöglichen. Konkret patcht `crypto::capi` die CAPI innerhalb des aktuellen Prozesses, während `crypto::cng` den Speicher von **lsass.exe** zum Patchen verwendet.

## Diebstahl von Benutzerzertifikaten über DPAPI – THEFT2

Weitere Informationen zu DPAPI:

{{#ref}}
../../windows-local-privilege-escalation/dpapi-extracting-passwords.md
{{#endref}}

Unter Windows werden **private Schlüssel von Zertifikaten durch DPAPI geschützt**. Es ist wichtig zu beachten, dass die **Speicherorte für private Benutzer- und Maschinenschlüssel** voneinander getrennt sind und die Dateistrukturen je nach verwendeter kryptografischer API des Betriebssystems variieren. **SharpDPAPI** kann diese Unterschiede beim Entschlüsseln der DPAPI-Blobs automatisch berücksichtigen.<sup>[[1]](#references)</sup>

**Benutzerzertifikate** werden überwiegend in der Registry unter `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates` gespeichert, einige können jedoch auch im Verzeichnis `%APPDATA%\Microsoft\SystemCertificates\My\Certificates` zu finden sein. Die zugehörigen **privaten Schlüssel** dieser Zertifikate werden typischerweise für **CAPI**-Schlüssel unter `%APPDATA%\Microsoft\Crypto\RSA\User SID\` und für **CNG**-Schlüssel unter `%APPDATA%\Microsoft\Crypto\Keys\` gespeichert.

Um **ein Zertifikat und den zugehörigen privaten Schlüssel zu extrahieren**, umfasst der Prozess folgende Schritte:

1. **Auswählen des Zielzertifikats** aus dem Benutzerspeicher und Abrufen seines Schlüsselspeichernamens.
2. **Auffinden des erforderlichen DPAPI-Masterkeys**, um den zugehörigen privaten Schlüssel zu entschlüsseln.
3. **Entschlüsseln des privaten Schlüssels** mithilfe des DPAPI-Masterkeys im Klartext.

Zum **Abrufen des DPAPI-Masterkeys im Klartext** können die folgenden Ansätze verwendet werden:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Um die Entschlüsselung von Masterkey-Dateien und privaten Schlüsseldateien zu vereinfachen, erweist sich der Befehl `certificates` aus [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) als hilfreich. Er akzeptiert `/pvk`, `/mkfile`, `/password` oder `{GUID}:KEY` als Argumente, um die privaten Schlüssel und verknüpften Zertifikate zu entschlüsseln und anschließend eine `.pem`-Datei zu erzeugen.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Diebstahl von Machine-Zertifikaten via DPAPI – THEFT3

Machine-Zertifikate, die von Windows in der Registry unter `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` gespeichert werden, sowie die zugehörigen privaten Schlüssel unter `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (für CAPI) und `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (für CNG) werden mithilfe der DPAPI-Masterkeys der Machine verschlüsselt. Diese Keys können nicht mit dem DPAPI-Backup-Key der Domain entschlüsselt werden. Stattdessen wird das **DPAPI_SYSTEM LSA secret** benötigt, auf das nur der SYSTEM-User zugreifen kann.<sup>[[1]](#references)</sup>

Eine manuelle Entschlüsselung kann erreicht werden, indem der Befehl `lsadump::secrets` in **Mimikatz** ausgeführt wird, um das DPAPI_SYSTEM LSA secret zu extrahieren, und anschließend dieser Key zum Entschlüsseln der Machine-Masterkeys verwendet wird. Alternativ kann nach dem zuvor beschriebenen Patchen von CAPI/CNG der Befehl `crypto::certificates /export /systemstore:LOCAL_MACHINE` von Mimikatz verwendet werden.

**SharpDPAPI** bietet mit seinem certificates command einen stärker automatisierten Ansatz. Wenn das `/machine`-Flag mit erhöhten Berechtigungen verwendet wird, eskaliert es zu SYSTEM, dumpt das DPAPI_SYSTEM LSA secret, verwendet es zum Entschlüsseln der Machine-DPAPI-Masterkeys und nutzt diese Klartext-Keys anschließend als Lookup-Tabelle, um private Keys von Machine-Zertifikaten zu entschlüsseln.

## Zertifikatdateien finden – THEFT4

Zertifikate werden manchmal direkt im Filesystem gefunden, beispielsweise in File-Shares oder im Downloads-Ordner. Die am häufigsten anzutreffenden Typen von Zertifikatdateien, die auf Windows-Umgebungen abzielen, sind `.pfx`- und `.p12`-Dateien. Seltener kommen auch Dateien mit den Endungen `.pkcs12` und `.pem` vor. Weitere bemerkenswerte zertifikatbezogene Dateiendungen sind:<sup>[[1]](#references)</sup>

- `.key` für private Keys,
- `.crt`/`.cer` ausschließlich für Zertifikate,
- `.csr` für Certificate Signing Requests, die keine Zertifikate oder privaten Keys enthalten,
- `.jks`/`.keystore`/`.keys` für Java Keystores, die Zertifikate zusammen mit privaten Keys enthalten können, die von Java-Anwendungen verwendet werden.

Diese Dateien können mithilfe von PowerShell oder der Command Prompt gesucht werden, indem nach den genannten Endungen gesucht wird.

Wenn eine PKCS#12-Zertifikatdatei gefunden wird und durch ein Passwort geschützt ist, kann mithilfe von `pfx2john.py`, das unter [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html) verfügbar ist, ein Hash extrahiert werden. Anschließend kann JohnTheRipper verwendet werden, um zu versuchen, das Passwort zu cracken.
```bash
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## NTLM Credential Theft via PKINIT – THEFT5 (UnPAC the hash)

Der angegebene Inhalt beschreibt eine Methode zum Diebstahl von NTLM Credentials via PKINIT, insbesondere über die als THEFT5 bezeichnete theft method. Hier folgt eine Erklärung in passiver Form, wobei der Inhalt anonymisiert und, sofern zutreffend, zusammengefasst wurde:<sup>[[1]](#references)</sup>

Um die NTLM-Authentifizierung `MS-NLMP` für Anwendungen zu unterstützen, die keine Kerberos-Authentifizierung ermöglichen, ist der KDC so konzipiert, dass die NTLM One-Way Function (OWF) des Benutzers innerhalb des Privilege Attribute Certificate (PAC) zurückgegeben wird, genauer gesagt im Puffer `PAC_CREDENTIAL_INFO`, wenn PKCA verwendet wird. Wenn sich ein Account daher authentifiziert und über PKINIT ein Ticket-Granting Ticket (TGT) erhält, wird dadurch ein Mechanismus bereitgestellt, der es dem aktuellen Host ermöglicht, den NTLM hash aus dem TGT zu extrahieren, um Legacy-Authentifizierungsprotokolle zu unterstützen. Dieser Vorgang umfasst die Entschlüsselung der Struktur `PAC_CREDENTIAL_DATA`, bei der es sich im Wesentlichen um eine mittels NDR serialisierte Darstellung des NTLM-Plaintexts handelt.

Das unter [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo) verfügbare Tool **Kekeo** kann laut Beschreibung ein TGT mit diesen spezifischen Daten anfordern und dadurch den NTLM des Benutzers abrufen. Der hierfür verwendete Befehl lautet:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
**`Rubeus`** kann diese Informationen ebenfalls mit der Option **`asktgt [...] /getcredentials`** abrufen.

Außerdem wird darauf hingewiesen, dass Kekeo Smartcard-geschützte Zertifikate verarbeiten kann, sofern die PIN abgerufen werden kann. Dabei wird auf [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe) verwiesen. Es wird angegeben, dass dieselbe Funktion auch von **Rubeus** unterstützt wird, das unter [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus) verfügbar ist.

Diese Erklärung fasst den Prozess und die beteiligten Tools beim NTLM credential theft über PKINIT zusammen. Der Schwerpunkt liegt auf dem Abrufen von NTLM-Hashes über ein mittels PKINIT erhaltenes TGT sowie auf den Dienstprogrammen, die diesen Prozess ermöglichen.

## Referenzen

- [1] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
