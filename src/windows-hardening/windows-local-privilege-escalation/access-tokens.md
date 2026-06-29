# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

Jeder **am System angemeldete Benutzer** besitzt ein Access Token mit Sicherheitsinformationen für diese Anmeldesitzung. Das System erstellt ein Access Token, wenn sich der Benutzer anmeldet. **Jeder ausgeführte Prozess**, der im Namen des Benutzers läuft, **hat eine Kopie des Access Tokens**. Das Token identifiziert den Benutzer, die Gruppen des Benutzers und die Privilegien des Benutzers. Ein Token enthält außerdem eine logon SID (Security Identifier), die die aktuelle Anmeldesitzung identifiziert.

Diese Informationen kannst du mit `whoami /all` anzeigen.
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
oder mit _Process Explorer_ von Sysinternals (Prozess auswählen und den Tab "Security" aufrufen):

![Access Tokens - Access Tokens: or using Process Explorer from Sysinternals (select process and access"Security" tab)](<../../images/image (772).png>)

### Lokaler Administrator

Wenn sich ein lokaler Administrator anmeldet, **werden zwei access tokens erstellt**: Eines mit Admin-Rechten und ein weiteres mit normalen Rechten. **Standardmäßig** verwendet dieser Benutzer beim Ausführen eines Prozesses das mit **regulären** (nicht-Administrator-) **Rechten**. Wenn dieser Benutzer versucht, irgendetwas **als Administrator** auszuführen (zum Beispiel "Run as Administrator"), wird die **UAC** verwendet, um um Erlaubnis zu fragen.\
Wenn du mehr über die UAC erfahren möchtest, lies diese Seite [**read this page**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

In der Praxis bedeutet das, dass eine **nicht erhobene Admin-Shell normalerweise mit einem gefilterten Token läuft**. Deshalb zeigt `whoami /groups` oft **`BUILTIN\Administrators` als `Deny only`**, bis der Prozess erhöht wird. Intern behält Windows ein **verknüpftes erhöhtes Token** (`TokenLinkedToken`) und verfolgt den Zustand mit Feldern wie `TokenElevationType`.

### Credentials user impersonation

Wenn du **gültige credentials eines anderen Benutzers** hast, kannst du mit diesen credentials eine **neue Logon Session** erstellen:
```
runas /user:domain\username cmd.exe
```
Das **access token** hat auch eine **reference** auf die Logon-Sessions innerhalb von **LSASS**; das ist nützlich, wenn der Prozess auf bestimmte Objekte des Netzwerks zugreifen muss.\
Du kannst einen Prozess starten, der **different credentials for accessing network services** verwendet, mit:
```
runas /user:domain\username /netonly cmd.exe
```
Das ist nützlich, wenn du nützliche credentials hast, um auf Objekte im Netzwerk zuzugreifen, diese credentials aber auf dem aktuellen Host nicht gültig sind, da sie nur im Netzwerk verwendet werden sollen (auf dem aktuellen Host werden deine aktuellen Benutzerrechte verwendet).

#### `runas /netonly` details

`runas /netonly` (und C2-Helfer wie `make_token`) erstellt ein **`LOGON32_LOGON_NEW_CREDENTIALS`** token. Das ist sehr nützlich zu verstehen während lateral movement, weil:

- **Lokal** behält der neue Prozess die **gleiche lokale Identität**, Gruppen, Integritätsstufe und die meisten derselben Zugriffsentscheidungen wie das aktuelle token.
- **Remote** kann die ausgehende Authentifizierung die **bereitgestellten credentials** für SMB / WinRM / LDAP / HTTP / Kerberos / NTLM verwenden.
- Daher kann `whoami` weiterhin den **ursprünglichen lokalen Benutzer** anzeigen, während der Netzwerkzugriff als das **alternative Konto** erfolgt.

Das ist eine gute Option, wenn die credentials in der Domain oder auf einem anderen Host gültig sind, der Benutzer sich aber **nicht lokal auf der aktuellen Maschine anmelden kann oder sollte**.

### Types of tokens

Es gibt zwei Arten von tokens:

- **Primary Token**: Er dient als Repräsentation der Sicherheitscredentials eines Prozesses. Das Erstellen und Zuordnen von primary tokens zu Prozessen sind Aktionen, die erhöhte Privilegien erfordern, was das Prinzip der Privilegien-Trennung betont. Typischerweise ist ein Authentifizierungsdienst für die token-Erstellung verantwortlich, während ein Anmeldedienst deren Zuordnung zur Shell des Betriebssystems des Benutzers übernimmt. Es ist erwähnenswert, dass Prozesse bei ihrer Erstellung den primary token ihres Elternprozesses erben.
- **Impersonation Token**: Ermöglicht es einer Serveranwendung, vorübergehend die Identität des Clients anzunehmen, um auf geschützte Objekte zuzugreifen. Dieser Mechanismus ist in vier Betriebsstufen unterteilt:
- **Anonymous**: Gewährt Serverzugriff ähnlich dem eines nicht identifizierten Benutzers.
- **Identification**: Erlaubt dem Server, die Identität des Clients zu prüfen, ohne sie für den Objektzugriff zu verwenden.
- **Impersonation**: Ermöglicht dem Server, unter der Identität des Clients zu arbeiten.
- **Delegation**: Ähnlich wie Impersonation, enthält aber die Möglichkeit, diese Identitätsübernahme auf entfernte Systeme auszudehnen, mit denen der Server interagiert, und so die Aufrechterhaltung von credentials sicherzustellen.

#### Impersonate Tokens

Mit dem _**incognito**_-Modul von metasploit kannst du, wenn du genug Privilegien hast, problemlos andere **tokens** **auflisten** und **impersonate**. Das kann nützlich sein, um **Aktionen auszuführen, als wärst du der andere Benutzer**. Mit dieser Technik kannst du auch **Privilegien eskalieren**.

Einige praktische Hinweise, die während der Arbeit leicht zu vergessen sind:

- **`CreateProcessWithTokenW`** benötigt **`SeImpersonatePrivilege`** im aufrufenden Prozess, und der neue Prozess läuft in der **Session des Aufrufenden**.
- **`CreateProcessAsUserW`** ist die übliche Ausweichlösung, wenn `CreateProcessWithTokenW` mit `1314` fehlschlägt oder wenn du in der **Session starten** musst, auf die das token verweist.
- Wenn ein token von **`LogonUser(LOGON32_LOGON_NETWORK)`** stammt, ist es normalerweise ein **Impersonation Token**, daher brauchst du **`DuplicateTokenEx(..., TokenPrimary, ...)`**, bevor du versuchst, damit einen Prozess zu starten.
- Nicht jedes impersonation token ist gleich nützlich: **`SecurityIdentification`** erlaubt es dir, den Benutzer zu prüfen, aber **nicht, als er zu handeln**. Wenn dir ein coercion primitive oder pipe/RPC client nur ein token auf Identification-Ebene gibt, prüfe **`TokenImpersonationLevel`** und wechsle zu einem primitive, das **`SecurityImpersonation`** oder besser liefert.

#### Token theft without touching LSASS

Wenn du bereits einen **service**- oder **SYSTEM**-Kontext hast und ein **privileged user** angemeldet ist, ist das Stehlen oder Duplizieren des tokens dieses Benutzers oft unauffälliger als das Dumpen von **LSASS**. In vielen realen Intrusions reicht das aus, um:

- lokale Aktionen als dieser Benutzer auszuführen
- auf entfernte Ressourcen als dieser Benutzer zuzugreifen
- AD-Operationen durchzuführen, ohne zuerst wiederverwendbare credentials zu extrahieren

Für Beispiele zum **session/user token hijacking** aus einem privilegierten Kontext, schau dir [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md) an. Denk daran, dass APIs wie **`WTSQueryUserToken`** für **hochvertrauenswürdige Dienste** gedacht sind und normalerweise **`LocalSystem` + `SeTcbPrivilege`** erfordern, also primär nützlich sind, sobald du bereits einen service-level Kontext kontrollierst. Für privilegien-spezifische Wege, zuerst **SYSTEM** zu erhalten, schau dir die Seiten unten an.

### Token Privileges

Lerne, welche **token privileges missbraucht werden können, um Privilegien zu eskalieren:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Wirf einen Blick auf [**alle möglichen token privileges und einige Definitionen auf dieser externen Seite**](https://github.com/gtworek/Priv2Admin).

## References

- [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa)
- [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
