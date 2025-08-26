# Schutz von Windows-Anmeldeinformationen

{{#include ../../banners/hacktricks-training.md}}

## WDigest

Das [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) Protokoll, das mit Windows XP eingeführt wurde, ist für die Authentifizierung über das HTTP-Protokoll ausgelegt und ist **standardmäßig auf Windows XP bis Windows 8.0 sowie Windows Server 2003 bis Windows Server 2012 aktiviert**. Diese Standardeinstellung führt zu **Klartext-Passwortspeicherung in LSASS** (Local Security Authority Subsystem Service). Ein Angreifer kann Mimikatz verwenden, um **diese Anmeldeinformationen zu extrahieren**, indem er Folgendes ausführt:
```bash
sekurlsa::wdigest
```
Um diese Funktion **aus- oder einzuschalten**, müssen die Registry-Schlüssel _**UseLogonCredential**_ und _**Negotiate**_ unter _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ auf "1" gesetzt sein. Wenn diese Schlüssel **nicht vorhanden sind oder auf "0" gesetzt sind**, ist WDigest **deaktiviert**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA-Schutz (PP & PPL geschützte Prozesse)

**Protected Process (PP)** und **Protected Process Light (PPL)** sind **Windows-Kernel-Schutzmechanismen**, die verhindern sollen, dass unautorisierte Prozesse auf sensible Prozesse wie **LSASS** zugreifen. Eingeführt in **Windows Vista**, wurde das **PP-Modell** ursprünglich für **DRM**-Durchsetzung geschaffen und erlaubte nur Binärdateien, die mit einem **speziellen Medienzertifikat** signiert waren, geschützt zu werden. Ein als **PP** markierter Prozess kann nur von anderen Prozessen geöffnet werden, die **ebenfalls PP** sind und ein **gleiches oder höheres Schutzniveau** haben — und selbst dann **nur mit eingeschränkten Zugriffsrechten**, sofern nicht ausdrücklich erlaubt.

**PPL**, eingeführt in **Windows 8.1**, ist eine flexiblere Version von PP. Es erlaubt **breitere Anwendungsfälle** (z. B. LSASS, Defender), indem es **„Schutzniveaus“** basierend auf dem **EKU (Enhanced Key Usage)**-Feld der digitalen Signatur einführt. Das Schutzniveau wird im `EPROCESS.Protection`-Feld gespeichert, das eine `PS_PROTECTION`-Struktur mit folgenden Feldern ist:
- **Type** (`Protected` oder `ProtectedLight`)
- **Signer** (z. B. `WinTcb`, `Lsa`, `Antimalware`, etc.)

Diese Struktur ist in einem Byte verpackt und bestimmt **wer wen zugreifen kann**:
- **Höhere Signer-Werte können auf niedrigere zugreifen**
- **PPLs können nicht auf PPs zugreifen**
- **Unprotected Prozesse können auf keine PPL/PP zugreifen**

### Was du aus offensiver Sicht wissen musst

- Wenn **LSASS als PPL läuft**, schlagen Versuche, es mit `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` aus einem normalen Admin-Kontext zu öffnen, **mit `0x5 (Access Denied)` fehl**, selbst wenn `SeDebugPrivilege` aktiviert ist.
- Du kannst das **LSASS-Schutzlevel** mit Tools wie Process Hacker prüfen oder programmatisch den `EPROCESS.Protection`-Wert auslesen.
- LSASS hat typischerweise `PsProtectedSignerLsa-Light` (`0x41`), das **nur von Prozessen zugänglich ist, die mit einem höherwertigen Signer signiert sind**, z. B. `WinTcb` (`0x61` oder `0x62`).
- PPL ist **nur im Userland wirksam**; Kernel-Code kann es vollständig umgehen.
- Dass LSASS PPL ist, verhindert **credential dumping** nicht, wenn du **kernel shellcode** ausführen kannst oder einen hochprivilegierten Prozess mit entsprechendem Zugriff missbrauchst.
- Das Setzen oder Entfernen von PPL erfordert einen Reboot oder **Secure Boot/UEFI-Einstellungen**, die die PPL-Konfiguration auch nach Rückgängigmachung von Registry-Änderungen beibehalten können.

### Einen PPL-Prozess beim Start erstellen (dokumentierte API)

Windows bietet einen dokumentierten Weg, um beim Erstellen eines Child-Prozesses ein Protected Process Light-Level anzufordern, indem die erweiterte Startup-Attribute-Liste verwendet wird. Dies umgeht nicht die Signing-Anforderungen — das Zielimage muss für die angeforderte Signer-Klasse signiert sein.

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
- Verwende `STARTUPINFOEX` mit `InitializeProcThreadAttributeList` und `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`, und übergebe dann `EXTENDED_STARTUPINFO_PRESENT` an `CreateProcess*`.
- Das Schutz-`DWORD` kann auf Konstanten wie `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` oder `PROTECTION_LEVEL_LSA_LIGHT` gesetzt werden.
- Der Child-Prozess startet nur als PPL, wenn sein Image für diese Signer-Klasse signiert ist; andernfalls schlägt die Prozess-Erstellung fehl, häufig mit `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`.
- Dies ist kein bypass — es ist eine unterstützte API, die für entsprechend signierte Images gedacht ist. Nützlich, um Tools zu härten oder PPL-geschützte Konfigurationen zu validieren.

Beispiel-CLI mit einem minimalen Loader:
- Antimalware-Signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light-Signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**Bypass-Optionen für PPL-Schutz:**

Wenn du LSASS trotz PPL dumpen willst, hast du 3 Hauptoptionen:
1. **Use a signed kernel driver (e.g., Mimikatz + mimidrv.sys)**, um das **Schutz-Flag von LSASS zu entfernen**:

![](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)**, um eigenen Kernel-Code auszuführen und den Schutz zu deaktivieren. Tools wie **PPLKiller**, **gdrv-loader** oder **kdmapper** machen das möglich.
3. **Steal an existing LSASS handle** aus einem anderen Prozess, der es offen hat (z. B. ein AV-Prozess), und **dupliziere es** in deinen Prozess. Das ist die Grundlage der `pypykatz live lsa --method handledup` Technik.
4. **Missbrauche einen privilegierten Prozess**, der es dir erlaubt, beliebigen Code in seinen Adressraum zu laden oder innerhalb eines anderen privilegierten Prozesses auszuführen, und umgehst damit effektiv die PPL-Beschränkungen. Ein Beispiel dazu findest du in [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) oder [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Aktuellen Status des LSA-Schutzes (PPL/PP) für LSASS prüfen**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
Wenn Sie **`mimikatz privilege::debug sekurlsa::logonpasswords`** ausführen, schlägt dies wahrscheinlich mit dem Fehlercode `0x00000005` fehl.

- Für weitere Informationen zu dieser Prüfung [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)


## Credential Guard

**Credential Guard**, eine Funktion, die ausschließlich in **Windows 10 (Enterprise and Education editions)** verfügbar ist, erhöht die Sicherheit von Maschinen-Anmeldeinformationen mittels **Virtual Secure Mode (VSM)** und **Virtualization Based Security (VBS)**. Es nutzt CPU-Virtualisierungserweiterungen, um wichtige Prozesse in einem geschützten Speicherbereich zu isolieren, außerhalb der Reichweite des Hauptbetriebssystems. Diese Isolation stellt sicher, dass selbst der Kernel nicht auf den Speicher im VSM zugreifen kann und schützt Anmeldeinformationen effektiv vor Angriffen wie **pass-the-hash**. Die **Local Security Authority (LSA)** läuft innerhalb dieser sicheren Umgebung als Trustlet, während der **LSASS**-Prozess im Haupt-OS lediglich als Vermittler zur LSA im VSM fungiert.

Standardmäßig ist **Credential Guard** nicht aktiv und muss innerhalb einer Organisation manuell aktiviert werden. Es ist wichtig für die Erhöhung der Sicherheit gegenüber Tools wie **Mimikatz**, die dadurch in ihrer Fähigkeit, Anmeldeinformationen zu extrahieren, eingeschränkt werden. Allerdings können weiterhin Schwachstellen ausgenutzt werden, etwa durch das Hinzufügen benutzerdefinierter **Security Support Providers (SSP)**, um während Anmeldeversuchen Anmeldeinformationen im Klartext abzugreifen.

Um den Aktivierungsstatus von **Credential Guard** zu überprüfen, kann der Registry-Schlüssel _**LsaCfgFlags**_ unter _**HKLM\System\CurrentControlSet\Control\LSA**_ eingesehen werden. Ein Wert von "**1**" zeigt eine Aktivierung mit **UEFI lock** an, "**2**" ohne Lock und "**0**" bedeutet, dass es nicht aktiviert ist. Diese Registry-Prüfung ist zwar ein starker Indikator, ersetzt jedoch nicht alle Schritte zum Aktivieren von Credential Guard. Detaillierte Anleitungen und ein **PowerShell**-Skript zum Aktivieren dieser Funktion sind online verfügbar.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Für ein umfassendes Verständnis und Anleitungen zum Aktivieren von **Credential Guard** in Windows 10 und dessen automatischer Aktivierung in kompatiblen Systemen von **Windows 11 Enterprise and Education (version 22H2)**, besuchen Sie [Microsoft's documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Weitere Details zur Implementierung von custom SSPs zur Erfassung von Credentials finden Sie in [this guide](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin-Modus

**Windows 8.1 and Windows Server 2012 R2** führten mehrere neue Sicherheitsfunktionen ein, darunter den _**Restricted Admin mode for RDP**_. Dieser Modus wurde entwickelt, um die Risiken im Zusammenhang mit [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) Angriffen zu vermindern.

Traditionell werden beim Verbindungsaufbau zu einem entfernten Computer über RDP Ihre Anmeldeinformationen auf dem Zielrechner gespeichert. Dies stellt ein erhebliches Sicherheitsrisiko dar, insbesondere bei Konten mit erhöhten Rechten. Mit der Einführung des _**Restricted Admin mode**_ wird dieses Risiko jedoch deutlich reduziert.

Wenn eine RDP-Verbindung mit dem Befehl **mstsc.exe /RestrictedAdmin** initiiert wird, erfolgt die Authentifizierung gegenüber dem entfernten Computer, ohne dass Ihre Anmeldeinformationen dort gespeichert werden. Dieser Ansatz stellt sicher, dass im Falle einer Malware-Infektion oder wenn ein bösartiger Benutzer Zugriff auf den Remote-Server erhält, Ihre Anmeldeinformationen nicht kompromittiert werden, da sie nicht auf dem Server hinterlegt sind.

Es ist wichtig zu beachten, dass im **Restricted Admin mode** Versuche, von der RDP-Sitzung aus auf Netzwerkressourcen zuzugreifen, nicht Ihre persönlichen Anmeldeinformationen verwenden; stattdessen wird die **Identität des Computers** benutzt.

Diese Funktion stellt einen bedeutenden Fortschritt bei der Sicherung von Remote-Desktop-Verbindungen dar und schützt sensible Informationen davor, bei einem Sicherheitsvorfall offengelegt zu werden.

![](../../images/RAM.png)

Für detailliertere Informationen besuchen Sie [this resource](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Zwischengespeicherte Anmeldeinformationen

Windows sichert **Domänenanmeldeinformationen** über die **Local Security Authority (LSA)** und unterstützt Anmeldeprozesse mit Sicherheitsprotokollen wie **Kerberos** und **NTLM**. Eine wichtige Funktion von Windows ist die Möglichkeit, die **letzten zehn Domänenanmeldungen** zu zwischenspeichern, damit Benutzer weiterhin auf ihre Computer zugreifen können, auch wenn der **Domänencontroller offline** ist — besonders praktisch für Laptop-Benutzer, die oft außerhalb des Firmennetzwerks unterwegs sind.

Die Anzahl der zwischengespeicherten Anmeldungen lässt sich über einen bestimmten **Registrierungswert oder eine Gruppenrichtlinie** anpassen. Zum Anzeigen oder Ändern dieser Einstellung wird folgender Befehl verwendet:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Der Zugriff auf diese zwischengespeicherten Anmeldeinformationen ist streng kontrolliert; nur das Konto **SYSTEM** verfügt über die erforderlichen Berechtigungen, um sie einsehen zu können. Administratoren, die auf diese Informationen zugreifen müssen, müssen dies mit SYSTEM-Benutzerrechten tun. Die Anmeldeinformationen werden gespeichert unter: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

Mit **Mimikatz** können diese zwischengespeicherten Anmeldeinformationen mit dem Befehl `lsadump::cache` extrahiert werden.

Für weitere Details bietet die ursprüngliche [source](http://juggernaut.wikidot.com/cached-credentials) umfassende Informationen.

## Protected Users

Die Mitgliedschaft in der **Protected Users group** bringt mehrere Sicherheitsverbesserungen für Benutzer mit sich und sorgt für einen höheren Schutz vor Diebstahl und Missbrauch von Anmeldeinformationen:

- **Credential Delegation (CredSSP)**: Selbst wenn die Gruppenrichtlinieneinstellung **Allow delegating default credentials** aktiviert ist, werden die Klartext-Anmeldeinformationen von Protected Users nicht zwischengespeichert.
- **Windows Digest**: Ab **Windows 8.1 and Windows Server 2012 R2** wird das System die Klartext-Anmeldeinformationen von Protected Users nicht zwischenspeichern, unabhängig vom Status von Windows Digest.
- **NTLM**: Das System wird weder die Klartext-Anmeldeinformationen von Protected Users noch NT one-way functions (NTOWF) zwischenspeichern.
- **Kerberos**: Für Protected Users erzeugt die Kerberos-Authentifizierung keine **DES**- oder **RC4**-Schlüssel und speichert auch keine Klartext-Anmeldeinformationen oder langfristigen Schlüssel über den initialen Ticket-Granting Ticket (TGT)-Erwerb hinaus.
- **Offline Sign-In**: Für Protected Users wird beim Anmelden oder Entsperren kein zwischengespeicherter Verifier erstellt, das heißt Offline-Anmeldung wird für diese Konten nicht unterstützt.

Diese Schutzmaßnahmen werden aktiviert, sobald sich ein Benutzer, der Mitglied der **Protected Users group** ist, am Gerät anmeldet. Dadurch sind wichtige Sicherheitsmaßnahmen wirksam, um vor verschiedenen Methoden der Kompromittierung von Anmeldeinformationen zu schützen.

Für ausführlichere Informationen konsultieren Sie die offizielle [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Table from** [**the docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

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
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

## Referenzen

- [CreateProcessAsPPL – minimal PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [STARTUPINFOEX structure (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [LSASS RunAsPPL – background and internals](https://itm4n.github.io/lsass-runasppl/)

{{#include ../../banners/hacktricks-training.md}}
