# Zugriffstoken

{{#include ../../banners/hacktricks-training.md}}

## Zugriffstoken

Jeder **am System angemeldete Benutzer** verfügt über ein **Zugriffstoken mit Sicherheitsinformationen** für diese Anmeldesitzung. Das System erstellt ein Zugriffstoken, wenn sich der Benutzer anmeldet. **Jeder im Namen des Benutzers ausgeführte Prozess** besitzt **eine Kopie des Zugriffstokens**. Das Token identifiziert den Benutzer, die Gruppen des Benutzers und die Berechtigungen des Benutzers. Ein Token enthält außerdem eine Logon-SID (Security Identifier), die die aktuelle Anmeldesitzung identifiziert.

Diese Informationen können mit `whoami /all` angezeigt werden
```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
oder mit _Process Explorer_ von Sysinternals (Prozess auswählen und auf den Tab „Security“ zugreifen):

![Access Tokens - Access Tokens: oder mit Process Explorer von Sysinternals (Prozess auswählen und auf den Tab „Security“ zugreifen)](<../../images/image (772).png>)

### Lokaler Administrator

Wenn sich ein lokaler Administrator anmeldet, werden **zwei Zugriffstoken erstellt**: eines mit Administratorrechten und ein weiteres mit normalen Rechten. **Standardmäßig** wird beim Ausführen eines Prozesses durch diesen Benutzer das Token mit **regulären** (Nicht-Administrator-)**Rechten** verwendet. Wenn dieser Benutzer versucht, etwas **als Administrator** auszuführen (beispielsweise mit „Run as Administrator“), wird die **UAC** verwendet, um nach einer Berechtigung zu fragen.\
Wenn du [**mehr über die UAC erfahren möchtest, lies diese Seite**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

In der Praxis bedeutet das, dass eine **nicht erhöhte Administrator-Shell normalerweise mit einem gefilterten Token ausgeführt wird**. Deshalb zeigt `whoami /groups` häufig **`BUILTIN\Administrators` als `Deny only`** an, bis der Prozess erhöht wurde. Intern verwaltet Windows ein **verknüpftes erhöhtes Token** (`TokenLinkedToken`) und verfolgt den Status mit Feldern wie `TokenElevationType`.

### Identitätswechsel eines Benutzers mit Anmeldedaten

Wenn du **gültige Anmeldedaten eines beliebigen anderen Benutzers** besitzt, kannst du mit diesen Anmeldedaten eine **neue Anmeldesitzung erstellen**:
```
runas /user:domain\username cmd.exe
```
Der **Zugriffstoken** enthält außerdem einen **Verweis** auf die Anmeldesitzungen innerhalb von **LSASS**. Dies ist nützlich, wenn der Prozess auf bestimmte Netzwerkobjekte zugreifen muss.\
Du kannst einen Prozess starten, der **andere Anmeldeinformationen für den Zugriff auf Netzwerkdienste verwendet**, mit:
```
runas /user:domain\username /netonly cmd.exe
```
Dies ist nützlich, wenn Sie über gültige Credentials verfügen, um auf Objekte im Netzwerk zuzugreifen, diese Credentials jedoch innerhalb des aktuellen Hosts nicht gültig sind, da sie nur im Netzwerk verwendet werden (auf dem aktuellen Host werden die Berechtigungen des aktuellen Users verwendet).

#### Details zu `runas /netonly`

`runas /netonly` (und C2-Hilfsprogramme wie `make_token`) erstellt ein **`LOGON32_LOGON_NEW_CREDENTIALS`**-Token. Dies ist beim lateralen Bewegen sehr nützlich, weil:<sup>[[3]](#references)</sup>

- **Lokal** behält der neue Prozess dieselbe **lokale Identität**, dieselben Gruppen, dasselbe Integritätslevel und die meisten Zugriffsentscheidungen des aktuellen Tokens.
- **Remote** kann die ausgehende Authentifizierung die **bereitgestellten Credentials** für SMB / WinRM / LDAP / HTTP / Kerberos / NTLM verwenden.
- Daher kann `whoami` weiterhin den **ursprünglichen lokalen User** anzeigen, während der Netzwerkzugriff als **alternativer Account** erfolgt.

Dies ist eine gute Option, wenn die Credentials in der Domain oder auf einem anderen Host gültig sind, der User sich jedoch **nicht lokal anmelden kann oder sollte** auf dem aktuellen Computer.

### Token-Typen

Es gibt zwei verfügbare Token-Typen:

- **Primary Token**: Es dient als Repräsentation der Security-Credentials eines Prozesses. Die Erstellung und Zuordnung von Primary Tokens zu Prozessen erfordert erhöhte Berechtigungen und unterstreicht damit das Prinzip der Privilege Separation. Normalerweise ist ein Authentication Service für die Erstellung des Tokens verantwortlich, während ein Logon Service dessen Zuordnung zur Betriebssystem-Shell des Users übernimmt. Es ist erwähnenswert, dass Prozesse bei ihrer Erstellung das Primary Token ihres Parent-Prozesses erben.
- **Impersonation Token**: Ermöglicht einer Server-Anwendung, vorübergehend die Identität des Clients anzunehmen, um auf geschützte Objekte zuzugreifen. Dieser Mechanismus ist in vier Operationsstufen unterteilt:
- **Anonymous**: Gewährt dem Server einen Zugriff, der dem eines nicht identifizierten Users entspricht.
- **Identification**: Ermöglicht dem Server, die Identität des Clients zu überprüfen, ohne sie für den Objektzugriff zu verwenden.
- **Impersonation**: Ermöglicht dem Server, unter der Identität des Clients zu arbeiten.
- **Delegation**: Ähnelt Impersonation, beinhaltet jedoch zusätzlich die Möglichkeit, diese angenommene Identität auf Remote-Systeme auszuweiten, mit denen der Server interagiert, und dabei die Credentials zu erhalten.

#### Impersonate Tokens

Wenn Sie das _**incognito**_-Modul von metasploit verwenden und über ausreichende Berechtigungen verfügen, können Sie andere **Tokens** einfach **auflisten** und **impersonaten**. Dies kann nützlich sein, um **Aktionen so auszuführen, als wären Sie der andere User**. Sie könnten mit dieser Technik auch **Berechtigungen eskalieren**.

Einige praktische Hinweise, die während des Betriebs leicht vergessen werden:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** erfordert **`SeImpersonatePrivilege`** beim aufrufenden Prozess, und der neue Prozess wird in der **Session des aufrufenden Prozesses** ausgeführt.
- **`CreateProcessAsUserW`** ist der übliche Fallback, wenn `CreateProcessWithTokenW` mit `1314` fehlschlägt oder wenn der Prozess in der **im Token referenzierten Session** gestartet werden muss.
- Wenn ein Token von **`LogonUser(LOGON32_LOGON_NETWORK)`** stammt, handelt es sich normalerweise um ein **Impersonation Token**. Daher müssen Sie **`DuplicateTokenEx(..., TokenPrimary, ...)`** verwenden, bevor Sie versuchen, damit einen Prozess zu starten.
- Nicht jedes Impersonation Token ist gleich nützlich: **`SecurityIdentification`** ermöglicht es Ihnen, den User zu untersuchen, aber **nicht, als dieser User zu handeln**. Wenn ein Coercion Primitive oder ein Pipe/RPC-Client Ihnen nur ein Token auf Identification-Level liefert, überprüfen Sie **`TokenImpersonationLevel`** und wechseln Sie zu einem Primitive, das **`SecurityImpersonation`** oder höher liefert.

#### Token theft without touching LSASS

Wenn Sie bereits über einen **Service**- oder **SYSTEM**-Kontext verfügen und ein **privilegierter User angemeldet ist**, ist das Stehlen oder Duplizieren des Tokens dieses Users oft unauffälliger als das Dumpen von **LSASS**. Bei vielen realen Intrusionen reicht dies aus, um:<sup>[[2]](#references)</sup>

- lokale Aktionen als dieser User auszuführen
- auf Remote-Ressourcen als dieser User zuzugreifen
- AD-Operationen durchzuführen, ohne zuvor wiederverwendbare Credentials zu extrahieren

Beispiele für **Session/User-Token-Hijacking** aus einem privilegierten Kontext finden Sie unter [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Denken Sie daran, dass APIs wie **`WTSQueryUserToken`** für **hochgradig vertrauenswürdige Services** vorgesehen sind und normalerweise **`LocalSystem` + `SeTcbPrivilege`** erfordern. Daher sind sie hauptsächlich nützlich, sobald Sie bereits einen Service-Level-Kontext kontrollieren. Für privilegierspezifische Möglichkeiten, zunächst **SYSTEM** zu erlangen, finden Sie unten die entsprechenden Seiten.

### Token-Berechtigungen

Erfahren Sie, welche **Token-Berechtigungen zur Rechteausweitung missbraucht werden können:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Sehen Sie sich [**all the possible token privileges and some definitions on this external page**](https://github.com/gtworek/Priv2Admin) an.

## References

- [1] [Understanding and Abusing Access Tokens — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Demystifying Cobalt Strike's "make_token" Command](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
