# Windows Credentials Protections

{{#include ../../banners/hacktricks-training.md}}

## WDigest

Das [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>)-Protokoll, das mit Windows XP eingeführt wurde, ist für die Authentifizierung über das HTTP-Protokoll vorgesehen und **unter Windows XP bis Windows 8.0 sowie unter Windows Server 2003 bis Windows Server 2012 standardmäßig aktiviert**. Diese Standardeinstellung führt zur **Speicherung von Passwörtern im Klartext in LSASS** (Local Security Authority Subsystem Service). Ein Angreifer kann Mimikatz verwenden, um **diese Zugangsdaten zu extrahieren**, indem er Folgendes ausführt:<sup>[[8]](#references)</sup>
```bash
sekurlsa::wdigest
```
Um diese Funktion **zu deaktivieren oder zu aktivieren**, müssen die Registrierungsschlüssel _**UseLogonCredential**_ und _**Negotiate**_ unter _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ auf „1“ gesetzt werden. Wenn diese Schlüssel **fehlen oder auf „0“ gesetzt sind**, ist WDigest **deaktiviert**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection (durch PP und PPL geschützte Prozesse)

**Protected Process (PP)** und **Protected Process Light (PPL)** sind **Schutzmechanismen auf Windows-Kernel-Ebene**, die den unbefugten Zugriff auf sensible Prozesse wie **LSASS** verhindern sollen. Das **PP-Modell** wurde in **Windows Vista** eingeführt und ursprünglich zur Durchsetzung von **DRM** entwickelt. Es erlaubte nur den Schutz von Binärdateien, die mit einem **speziellen Medienzertifikat** signiert waren. Auf einen als **PP** markierten Prozess können nur andere Prozesse zugreifen, die **ebenfalls PP** sind und über eine **gleichwertige oder höhere Schutzstufe** verfügen. Selbst dann ist der Zugriff nur mit **eingeschränkten Zugriffsrechten** möglich, sofern er nicht ausdrücklich erlaubt wurde.

**PPL**, eingeführt in **Windows 8.1**, ist eine flexiblere Variante von PP. Es ermöglicht **breitere Anwendungsfälle** (z. B. LSASS und Defender), indem es **„Schutzstufen“** auf Grundlage des **EKU-Felds (Enhanced Key Usage) der digitalen Signatur** einführt. Die Schutzstufe wird im Feld `EPROCESS.Protection` gespeichert, das eine `PS_PROTECTION`-Struktur mit folgenden Bestandteilen ist:
- **Type** (`Protected` oder `ProtectedLight`)
- **Signer** (z. B. `WinTcb`, `Lsa`, `Antimalware` usw.)

Diese Struktur wird in einem einzelnen Byte gespeichert und bestimmt, **wer auf wen zugreifen kann**:
- **Signer mit höheren Werten können auf niedrigere Werte zugreifen**
- **PPLs können nicht auf PPs zugreifen**
- **Nicht geschützte Prozesse können auf keine PPLs/PPs zugreifen**

### Was du aus offensiver Sicht wissen musst

- Wenn **LSASS als PPL ausgeführt wird**, schlagen Versuche fehl, den Prozess aus einem normalen Administratorkontext mit `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` zu öffnen. Das Ergebnis ist `0x5 (Access Denied)`, selbst wenn `SeDebugPrivilege` aktiviert ist.
- Du kannst die **LSASS-Schutzstufe** mit Tools wie Process Hacker oder programmgesteuert durch das Auslesen des Werts `EPROCESS.Protection` überprüfen.
- LSASS verwendet typischerweise `PsProtectedSignerLsa-Light` (`0x41`). Darauf können **nur Prozesse zugreifen, die mit einem Signer einer höheren Stufe** signiert sind, beispielsweise `WinTcb` (`0x61` oder `0x62`).
- PPL ist eine **reine Userland-Einschränkung**; **Code auf Kernel-Ebene kann sie vollständig umgehen**.
- Dass LSASS als PPL ausgeführt wird, **verhindert kein Credential Dumping**, wenn du Kernel-Shellcode ausführen oder einen privilegierten Prozess mit den erforderlichen Zugriffsrechten nutzen kannst.
- Das **Setzen oder Entfernen von PPL** erfordert einen Neustart oder **Secure-Boot-/UEFI-Einstellungen**. Diese können die PPL-Einstellung auch dann beibehalten, wenn Registry-Änderungen rückgängig gemacht wurden.

### Einen PPL-Prozess beim Start erstellen (dokumentierte API)

Windows stellt eine dokumentierte Möglichkeit bereit, beim Erstellen eines Child-Prozesses mithilfe der erweiterten Startup-Attributliste eine Protected Process Light-Stufe anzufordern. Dadurch werden die Anforderungen an die Signatur nicht umgangen — das Ziel-Image muss für die angeforderte Signer-Klasse signiert sein.

Minimaler Ablauf in C/C++:
```c
// Request a PPL protection level for the child process at creation time
// Requires Windows 8.1+ and a properly signed image for the selected level
#include <windows.h>

int wmain(int argc, wchar_t **argv) {
STARTUPINFOEXW si = {0};
PROCESS_INFORMATION pi = {0};
si.StartupInfo.cb = sizeof(si);

SIZE_T attrSize = 0;
InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
if (!si.lpAttributeList) return 1;

if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize)) return 1;

DWORD level = PROTECTION_LEVEL_ANTIMALWARE_LIGHT; // or WINDOWS_LIGHT/LSA_LIGHT/WINTCB_LIGHT
if (!UpdateProcThreadAttribute(
si.lpAttributeList, 0,
PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
&level, sizeof(level), NULL, NULL)) {
return 1;
}

DWORD flags = EXTENDED_STARTUPINFO_PRESENT;
if (!CreateProcessW(L"C\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE,
flags, NULL, NULL, &si.StartupInfo, &pi)) {
// If the image isn't signed appropriately for the requested level,
// CreateProcess will fail with ERROR_INVALID_IMAGE_HASH (577).
return 1;
}

// cleanup
DeleteProcThreadAttributeList(si.lpAttributeList);
HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
CloseHandle(pi.hThread);
CloseHandle(pi.hProcess);
return 0;
}
```
Hinweise und Einschränkungen:
- Verwende `STARTUPINFOEX` mit `InitializeProcThreadAttributeList` und `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`, und übergib `EXTENDED_STARTUPINFO_PRESENT` an `CreateProcess*`.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- Der Schutz-`DWORD` kann auf Konstanten wie `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` oder `PROTECTION_LEVEL_LSA_LIGHT` gesetzt werden.
- Das Kind startet nur dann als PPL, wenn sein Image für diese Signer-Klasse signiert ist; andernfalls schlägt die Prozesserstellung fehl, üblicherweise mit `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`.
- Dies ist kein Bypass – es handelt sich um eine unterstützte API für entsprechend signierte Images. Nützlich zum Hardening von Tools oder zur Validierung von PPL-geschützten Konfigurationen.

Beispiel-CLI mit einem minimalen Loader:<sup>[[1]](#references)</sup>
- Antimalware-Signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light-Signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**Optionen zum Umgehen des PPL-Schutzes:**

Wenn du LSASS trotz PPL dumpen möchtest, gibt es 3主要 Optionen:
1. **Verwende einen signierten Kernel-Treiber (z. B. Mimikatz + mimidrv.sys)**, um **das Schutz-Flag von LSASS zu entfernen**:

![Mimikatz-mimidrv-Treiberausgabe mit Interaktion mit dem Credential-Schutz](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)**, um eigenen Kernel-Code auszuführen und den Schutz zu deaktivieren. Tools wie **PPLKiller**, **gdrv-loader** oder **kdmapper** machen dies möglich.
3. **Stiehl einen bestehenden LSASS-Handle** aus einem anderen Prozess, der ihn geöffnet hat (z. B. einem AV-Prozess), und **dupliziere ihn** in deinen Prozess. Dies bildet die Grundlage der Technik `pypykatz live lsa --method handledup`.
4. **Missbrauche einen privilegierten Prozess**, der das Laden beliebigen Codes in seinen Adressraum oder in einen anderen privilegierten Prozess erlaubt, wodurch die PPL-Einschränkungen effektiv umgangen werden. Ein Beispiel dafür findest du unter [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) oder [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Aktuellen Status des LSA-Schutzes (PPL/PP) für LSASS prüfen:**
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
Beim Ausführen von **`mimikatz privilege::debug sekurlsa::logonpasswords`** schlägt der Vorgang aufgrund dieses Schutzes wahrscheinlich mit dem Fehlercode `0x00000005` fehl.

- Weitere Informationen zu dieser Prüfung: [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)<sup>[[5]](#references)</sup>


## Credential Guard

**Credential Guard**, eine Funktion, die exklusiv für **Windows 10 (Enterprise- und Education-Editionen)** verfügbar ist, erhöht die Sicherheit von Computeranmeldeinformationen mithilfe von **Virtual Secure Mode (VSM)** und **Virtualization Based Security (VBS)**. Dabei werden CPU-Virtualisierungserweiterungen verwendet, um wichtige Prozesse innerhalb eines geschützten Speicherbereichs zu isolieren, der vom Hauptbetriebssystem nicht erreichbar ist. Diese Isolation stellt sicher, dass selbst der Kernel nicht auf den Speicher in VSM zugreifen kann, und schützt Anmeldeinformationen dadurch effektiv vor Angriffen wie **pass-the-hash**. Die **Local Security Authority (LSA)** läuft als Trustlet innerhalb dieser sicheren Umgebung, während der **LSASS**-Prozess im Hauptbetriebssystem lediglich als Kommunikator mit der LSA von VSM fungiert.

Standardmäßig ist **Credential Guard** nicht aktiv und muss innerhalb einer Organisation manuell aktiviert werden. Er ist entscheidend für eine verbesserte Sicherheit gegenüber Tools wie **Mimikatz**, deren Fähigkeit zum Extrahieren von Anmeldeinformationen dadurch eingeschränkt wird. Schwachstellen können jedoch weiterhin durch das Hinzufügen benutzerdefinierter **Security Support Providers (SSP)** ausgenutzt werden, um Anmeldeinformationen während Anmeldeversuchen im Klartext abzufangen.

Um den Aktivierungsstatus von **Credential Guard** zu überprüfen, kann der Registrierungsschlüssel _**LsaCfgFlags**_ unter _**HKLM\System\CurrentControlSet\Control\LSA**_ überprüft werden. Der Wert "**1**" weist auf eine Aktivierung mit **UEFI lock** hin, "**2**" auf eine Aktivierung ohne Sperre, und "**0**" bedeutet, dass die Funktion nicht aktiviert ist. Diese Registrierungsprüfung ist zwar ein starker Indikator, stellt jedoch nicht den einzigen Schritt zur Aktivierung von Credential Guard dar. Detaillierte Anleitungen und ein PowerShell-Skript zur Aktivierung dieser Funktion sind online verfügbar.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Für ein umfassendes Verständnis und Anweisungen zum Aktivieren von **Credential Guard** in Windows 10 sowie zur automatischen Aktivierung auf kompatiblen Systemen von **Windows 11 Enterprise and Education (version 22H2)** besuchen Sie die [Microsoft-Dokumentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).<sup>[[9]](#references)</sup>

Weitere Informationen zur Implementierung benutzerdefinierter SSPs für die Erfassung von Credentials finden Sie in [diesem Leitfaden](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin-Modus

**Windows 8.1 und Windows Server 2012 R2** führten mehrere neue Sicherheitsfunktionen ein, darunter den _**Restricted Admin mode for RDP**_. Dieser Modus wurde entwickelt, um die Sicherheit zu erhöhen, indem die mit [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/)-Angriffen verbundenen Risiken reduziert werden.

Traditionell werden beim Herstellen einer Verbindung zu einem Remotecomputer über RDP Ihre Credentials auf dem Zielcomputer gespeichert. Dies stellt ein erhebliches Sicherheitsrisiko dar, insbesondere bei der Verwendung von Konten mit erweiterten Berechtigungen. Mit der Einführung des _**Restricted Admin mode**_ wird dieses Risiko jedoch deutlich reduziert.

Beim Initiieren einer RDP-Verbindung mit dem Befehl **mstsc.exe /RestrictedAdmin** erfolgt die Authentifizierung am Remotecomputer, ohne Ihre Credentials dort zu speichern. Dadurch wird sichergestellt, dass Ihre Credentials im Falle einer Malware-Infektion oder wenn sich ein böswilliger Benutzer Zugriff auf den Remoteserver verschafft, nicht kompromittiert werden, da sie nicht auf dem Server gespeichert sind.

Es ist wichtig zu beachten, dass im **Restricted Admin mode** Zugriffe auf Netzwerkressourcen aus der RDP-Sitzung nicht Ihre persönlichen Credentials verwenden, sondern die **Identität des Computers**.

Diese Funktion stellt einen bedeutenden Fortschritt bei der Absicherung von Remote-Desktop-Verbindungen dar und schützt vertrauliche Informationen davor, im Falle einer Sicherheitsverletzung offengelegt zu werden.

![Windows-RAM-Speicherdiagramm für den Kontext der Credential-Extraktion](../../images/RAM.png)

Weitere Informationen finden Sie unter [dieser Ressource](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).<sup>[[6]](#references)</sup>

## Cached Credentials

Windows schützt **Domänen-Credentials** mithilfe der **Local Security Authority (LSA)** und unterstützt Anmeldevorgänge mit Sicherheitsprotokollen wie **Kerberos** und **NTLM**. Eine wichtige Funktion von Windows ist die Möglichkeit, die **letzten zehn Domänenanmeldungen** zwischenzuspeichern, damit Benutzer weiterhin auf ihre Computer zugreifen können, selbst wenn der **Domänencontroller offline** ist – ein Vorteil für Laptopbenutzer, die sich häufig außerhalb des Netzwerks ihres Unternehmens befinden.

Die Anzahl der zwischengespeicherten Anmeldungen kann über einen bestimmten **Registrierungsschlüssel oder eine Gruppenrichtlinie** angepasst werden. Zum Anzeigen oder Ändern dieser Einstellung wird der folgende Befehl verwendet:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Der Zugriff auf diese zwischengespeicherten Anmeldedaten ist streng kontrolliert, wobei nur das Konto **SYSTEM** über die erforderlichen Berechtigungen verfügt, um sie einzusehen. Administratoren, die auf diese Informationen zugreifen müssen, müssen dies mit den Berechtigungen des SYSTEM-Benutzers tun. Die Anmeldedaten werden hier gespeichert: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** kann verwendet werden, um diese zwischengespeicherten Anmeldedaten mit dem Befehl `lsadump::cache` zu extrahieren.

Weitere Informationen bietet die ursprüngliche [Quelle](http://juggernaut.wikidot.com/cached-credentials).<sup>[[7]](#references)</sup>

## Protected Users

Die Mitgliedschaft in der **Protected Users group** führt mehrere Sicherheitsverbesserungen für Benutzer ein und gewährleistet einen höheren Schutz vor credential theft und Missbrauch:

- **Credential Delegation (CredSSP)**: Selbst wenn die Group-Policy-Einstellung **Allow delegating default credentials** aktiviert ist, werden Plaintext-Anmeldedaten von Protected Users nicht zwischengespeichert.
- **Windows Digest**: Ab **Windows 8.1 und Windows Server 2012 R2** cached das System keine Plaintext-Anmeldedaten von Protected Users, unabhängig vom Status von Windows Digest.
- **NTLM**: Das System cached weder die Plaintext-Anmeldedaten von Protected Users noch NT one-way functions (NTOWF).
- **Kerberos**: Bei Protected Users erzeugt die Kerberos-Authentifizierung weder **DES**- noch **RC4-Schlüssel** und cached weder Plaintext-Anmeldedaten noch langfristige Schlüssel über den erstmaligen Erwerb des Ticket-Granting Tickets (TGT) hinaus.
- **Offline Sign-In**: Für Protected Users wird bei der Anmeldung oder beim Entsperren kein gecachter Verifier erstellt. Daher wird die Offline-Anmeldung für diese Konten nicht unterstützt.

Diese Schutzmaßnahmen werden in dem Moment aktiviert, in dem sich ein Benutzer, der Mitglied der **Protected Users group** ist, am Gerät anmeldet. Dadurch wird sichergestellt, dass wichtige Sicherheitsmaßnahmen zum Schutz vor verschiedenen Methoden des credential compromise aktiv sind.

Weitere Informationen finden Sie in der offiziellen [Dokumentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).<sup>[[10]](#references)</sup>

**Tabelle aus** [**der Dokumentation**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**<sup>[[11]](#references)</sup>

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators        | Server Operators                                                              | Server Operators             |

## References

- [1] [CreateProcessAsPPL – minimaler PPL-Prozess-Launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [2] [STARTUPINFOEX-Struktur (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [3] [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [4] [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [LSASS RunAsPPL – Hintergrund und Interna](https://itm4n.github.io/lsass-runasppl/)
- [6] [Restricted Admin Mode für RDP](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)
- [7] [Cached Credentials – Juggernaut AppSec Wiki](http://juggernaut.wikidot.com/cached-credentials)
- [8] [WDigest Authentication (Microsoft TechNet)](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>)
- [9] [Manage Windows Defender Credential Guard (Microsoft Learn)](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)
- [10] [Protected Users Security Group (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [11] [Appendix C: Protected Accounts and Groups in Active Directory (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
{{#include ../../banners/hacktricks-training.md}}
