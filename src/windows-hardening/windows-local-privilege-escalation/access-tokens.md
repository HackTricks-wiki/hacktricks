# Zugriffstoken

{{#include ../../banners/hacktricks-training.md}}

## Zugriffstoken

Jeder Prozess hat ein **primäres Zugriffstoken**, das seinen Sicherheitskontext definiert. Ein Thread verwendet normalerweise dieses Token, kann aber vorübergehend auch ein **Impersonation-Token** haben. Token enthalten die Benutzer-SID, Gruppen-SIDs, Berechtigungen, Integritätsinformationen und eine Anmelde-SID für die Anmeldesitzung. Prozesse übernehmen im Allgemeinen eine Referenz auf das primäre Token des übergeordneten Prozesses; sie erhalten keine unabhängige Kopie seines Inhalts.<sup>[[4]](#references)</sup>

Diese Informationen lassen sich mit `whoami /all` anzeigen.

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

oder mit _Process Explorer_ von Sysinternals (Prozess auswählen und auf die Registerkarte „Security“ zugreifen):

![Zugriffstoken – Zugriffstoken: oder mit Process Explorer von Sysinternals (Prozess auswählen und auf die Registerkarte „Security“ zugreifen)](<../../images/image (772).png>)

### Lokaler Administrator

Wenn **UAC Admin Approval Mode** für einen Administrator gilt, erstellt die interaktive Anmeldung ein vollständiges Administratortoken und ein gefiltertes Token. Explorer und gewöhnliche untergeordnete Prozesse verwenden standardmäßig das gefilterte Token. Bei einer Anforderung zur Rechteerhöhung, etwa **Als Administrator ausführen**, fordert UAC Windows auf, das Programm mit dem vollständigen Token zu starten. Das genaue Verhalten unterscheidet sich beim integrierten Administratorkonto und wenn Admin Approval Mode deaktiviert ist.<sup>[[5]](#references)</sup>

Auf der speziellen [**UAC-Seite**](../authentication-credentials-uac-and-efs/uac-user-account-control.md) findest du Techniken zum Umgehen sowie Details zu Richtlinien.

In der Praxis bedeutet das, dass eine **nicht erhöhte Admin-Shell normalerweise mit einem gefilterten Token ausgeführt wird**. Deshalb zeigt `whoami /groups` häufig **`BUILTIN\Administrators` als `Deny only`** an, bis der Prozess erhöhte Rechte erhält. Intern verwaltet Windows ein **verknüpftes Token mit erhöhten Rechten** (`TokenLinkedToken`) und erfasst den Status mit Feldern wie `TokenElevationType`.

### Benutzer-Impersonation mit Anmeldedaten

Wenn du **gültige Anmeldedaten eines beliebigen anderen Benutzers** hast, kannst du mit diesen Anmeldedaten eine **neue Anmeldesitzung erstellen**:

```
runas /user:domain\username cmd.exe
```

Der **Zugriffstoken** enthält außerdem eine **Referenz** auf die Anmeldesitzungen innerhalb von **LSASS**. Das ist nützlich, wenn der Prozess auf Netzwerkobjekte zugreifen muss.\
Du kannst einen Prozess starten, der **andere Anmeldedaten für den Zugriff auf Netzwerkdienste verwendet**, mit:

```
runas /user:domain\username /netonly cmd.exe
```

Dies ist nützlich, wenn Sie über gültige Anmeldedaten für den Zugriff auf Objekte im Netzwerk verfügen, diese Anmeldedaten aber auf dem aktuellen Host nicht gültig sind, da sie nur im Netzwerk verwendet werden (auf dem aktuellen Host werden die Berechtigungen Ihres aktuellen Benutzers verwendet).

#### Details zu `runas /netonly`

`runas /netonly` (und C2-Helfer wie `make_token`) erstellt ein **`LOGON32_LOGON_NEW_CREDENTIALS`**-Token. Das ist während der lateralen Bewegung besonders wichtig zu verstehen:<sup>[[3]](#references)</sup>

- **Lokal** behält der neue Prozess dieselbe **lokale Identität**, dieselben Gruppen, dieselbe Integritätsstufe und größtenteils dieselben Zugriffsentscheidungen wie das aktuelle Token.
- **Remote** kann die ausgehende Authentifizierung die **angegebenen Anmeldedaten** für SMB / WinRM / LDAP / HTTP / Kerberos / NTLM verwenden.
- Daher kann `whoami` weiterhin den **ursprünglichen lokalen Benutzer** anzeigen, während der Netzwerkzugriff als **alternatives Konto** erfolgt.

Das ist eine gute Option, wenn die Anmeldedaten in der Domäne oder auf einem anderen Host gültig sind, der Benutzer sich aber **nicht lokal am aktuellen Rechner anmelden kann oder sollte**.

### Token-Typen

Es gibt zwei Arten von Tokens:<sup>[[4]](#references)[[6]](#references)</sup>

- **Primäres Token**: Repräsentiert den Sicherheitskontext eines Prozesses. Ein untergeordneter Prozess erbt normalerweise das primäre Token seines übergeordneten Prozesses, während die APIs zur Prozesserstellung mit explizitem Token eigene Anforderungen an den Tokenzugriff und die Berechtigungen des aufrufenden Prozesses stellen.
- **Impersonation-Token**: Ermöglicht einem Server-Thread, vorübergehend den Sicherheitskontext eines Clients für Zugriffsprüfungen zu verwenden. Es gibt vier Stufen:
  - **Anonymous**: Gewährt dem Server Zugriff, ähnlich dem eines nicht identifizierten Benutzers.
  - **Identification**: Ermöglicht dem Server, die Identität des Clients zu überprüfen, ohne sie für den Objektzugriff zu verwenden.
  - **Impersonation**: Ermöglicht dem Server, unter der Identität des Clients zu agieren.
  - **Delegation**: Ermöglicht dem Server, den Client auf Remotesystemen zu imitieren, sofern Authentifizierungsmechanismus und Kontokonfiguration die Delegierung unterstützen.

#### Ein erfasstes Token vor der Verwendung überprüfen

Wählen Sie ein Token nicht allein anhand des Benutzernamens aus. Dasselbe Konto kann mehrere Tokens mit unterschiedlichen Anmeldesitzungen, Dienst-SIDs, Berechtigungen, Integritätsstufen, Einschränkungen und Netzwerkanmeldedaten besitzen.<sup>[[9]](#references)</sup> Fragen Sie mit `GetTokenInformation` mindestens **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`** und **`TokenStatistics.AuthenticationId`** ab.<sup>[[7]](#references)</sup>

Ein eingeschränktes Token kann SIDs enthalten, die nur für Verweigerungen gelten, entfernte Berechtigungen und einschränkende SIDs. Sind einschränkende SIDs vorhanden, führt Windows eine Zugriffsprüfung mit den aktivierten SIDs und eine weitere mit den einschränkenden SIDs durch; **beide Prüfungen müssen den Zugriff zulassen**. Eine aussagekräftig wirkende Benutzer-SID oder eine aktivierte Gruppe in der Ausgabe beweist daher nicht allein, dass das Token auf das Zielobjekt zugreifen kann.<sup>[[8]](#references)</sup>

Verwenden Sie diesen Entscheidungsablauf für die dokumentierten Anforderungen an Tokens und die Prozesserstellung:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. Für ein **primäres Token** ist ein Handle mit `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` erforderlich, bevor es an `CreateProcessWithTokenW` oder `CreateProcessAsUserW` übergeben werden kann.
2. Konvertieren Sie ein **Impersonation-Token** mit `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)`. Tokens auf Identification-Ebene können Identitätsdaten offenlegen, aber keine Zugriffsprüfungen als dieser Client durchführen.
3. `CreateProcessWithTokenW` benötigt `SeImpersonatePrivilege` und startet den untergeordneten Prozess in der Sitzung des aufrufenden Prozesses. `CreateProcessAsUserW` verwendet stattdessen die Sitzung des Tokens, benötigt aber normalerweise `SeIncreaseQuotaPrivilege` und kann `SeAssignPrimaryTokenPrivilege` erfordern. Sind Anmeldedaten verfügbar und fehlen diese Berechtigungen, ist `CreateProcessWithLogonW` die dokumentierte Alternative.

#### Token-Handles suchen, nicht nur Prozesseigentümer

Das Öffnen des primären Tokens jedes Prozesses kann **Impersonation-Tokens übersehen, die als gewöhnliche Handles** in Diensten und Broker-Prozessen aufbewahrt werden. Ein wiederverwendbarer Workflow für Handle-Tabellen besteht darin, System-Handles aufzuzählen, Tokenobjekte herauszufiltern, jeden Eigentümer mit `PROCESS_DUP_HANDLE` zu öffnen, das infrage kommende Handle in den aktuellen Prozess zu duplizieren und anschließend die oben genannten Felder abzufragen. Stellen Sie sicher, dass das duplizierte Handle `TOKEN_QUERY` und `TOKEN_DUPLICATE` umfasst. Ein sichtbares Token-Handle bedeutet nicht, dass es zu einem verwendbaren primären Token dupliziert werden kann. Geschützte Prozesse und Prozess-DACLs können den Zugriff auf das Handle des Eigentümerprozesses weiterhin verhindern.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` automatisiert die Aufzählung sowohl primärer Prozesstokens als auch aufbewahrter Token-Handles. `list_token` behält pro Benutzername einen bevorzugten Kandidaten bei, während `list_all_token` alle Kandidaten ausgibt. Eine PID beschränkt die Aufzählung auf einen Eigentümerprozess.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

Für die manuelle Prüfung und Zugriffskontrolle kann **TokenUniverse** Prozess-/Thread-Tokens öffnen, nach vorhandenen Token-Handles suchen, Einschränkungen und Anmeldesitzungen untersuchen, Tokens duplizieren und verschiedene Methoden zur Prozesserstellung testen.<sup>[[13]](#references)</sup> Informationen zum zugrunde liegenden Primitive für prozessübergreifende Handles finden Sie hier:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

#### Impersonate Tokens

Mit dem _**incognito**_-Modul von metasploit können Sie, wenn Sie über ausreichende Berechtigungen verfügen, ganz einfach andere **Tokens** **auflisten** und **impersonieren**. Das kann nützlich sein, um **Aktionen so auszuführen, als wären Sie der andere Benutzer**. Mit dieser Technik können Sie auch **Berechtigungen erweitern**.

Einige praktische Hinweise, die während des Betriebs leicht in Vergessenheit geraten:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** erfordert **`SeImpersonatePrivilege`** beim aufrufenden Prozess, und der neue Prozess wird in der **Sitzung des aufrufenden Prozesses** ausgeführt.
- **`CreateProcessAsUserW`** ist ein möglicher Fallback, wenn `CreateProcessWithTokenW` mit `1314` fehlschlägt, aber nur, wenn der aufrufende Prozess die erforderlichen Berechtigungen besitzt. Die Funktion ist außerdem die richtige Wahl, wenn der untergeordnete Prozess in der **im Token angegebenen Sitzung** ausgeführt werden muss.<sup>[[9]](#references)[[10]](#references)</sup>
- Wenn ein Token von **`LogonUser(LOGON32_LOGON_NETWORK)`** stammt, handelt es sich normalerweise um ein **Impersonation-Token**. Daher müssen Sie **`DuplicateTokenEx(..., TokenPrimary, ...)`** aufrufen, bevor Sie versuchen, damit einen Prozess zu starten.
- Nicht jedes Impersonation-Token ist gleich nützlich: **`SecurityIdentification`** ermöglicht es Ihnen, den Benutzer zu untersuchen, aber **nicht, als dieser Benutzer zu handeln**. Wenn ein Coercion-Primitive oder ein Pipe-/RPC-Client Ihnen nur ein Token auf Identification-Ebene bereitstellt, prüfen Sie **`TokenImpersonationLevel`** und wechseln Sie zu einem Primitive, das **`SecurityImpersonation`** oder eine höhere Stufe liefert.

#### Token-Diebstahl ohne LSASS anzurühren

Wenn Sie bereits einen **Service-** oder **SYSTEM**-Kontext haben und ein **privilegierter Benutzer angemeldet ist**, ist es oft unauffälliger, das Token dieses Benutzers zu stehlen oder zu duplizieren, als **LSASS** auszulesen. Bei vielen realen Angriffen reicht das aus, um:<sup>[[2]](#references)</sup>

- lokale Aktionen als dieser Benutzer auszuführen
- auf Remote-Ressourcen als dieser Benutzer zuzugreifen
- AD-Operationen auszuführen, ohne vorher wiederverwendbare Anmeldedaten zu extrahieren

Beispiele für **Session-/Benutzer-Token-Hijacking** aus einem privilegierten Kontext finden Sie unter [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Beachten Sie, dass APIs wie **`WTSQueryUserToken`** für **hoch vertrauenswürdige Services** vorgesehen sind und normalerweise **`LocalSystem` + `SeTcbPrivilege`** erfordern. Daher sind sie vor allem dann nützlich, wenn Sie bereits einen Service-Kontext kontrollieren. Informationen zu Möglichkeiten, **SYSTEM** zunächst durch Ausnutzung bestimmter Berechtigungen zu erhalten, finden Sie auf den folgenden Seiten.

### Token-Berechtigungen

Erfahren Sie, **welche Token-Berechtigungen missbraucht werden können, um Berechtigungen zu erweitern:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Sehen Sie sich [**alle möglichen Token-Berechtigungen und einige Definitionen auf dieser externen Seite an**](https://github.com/gtworek/Priv2Admin).

## References

- [1] [Access Tokens verstehen und missbrauchen — Teil II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Windows-Tokens missbrauchen, um Active Directory ohne LSASS anzurühren zu kompromittieren](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Cobalt Strikes „make_token“-Befehl entmystifiziert](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Access Tokens - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [Funktionsweise der Benutzerkontensteuerung - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Impersonation-Ebenen - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [TOKEN_INFORMATION_CLASS-Enumeration - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Eingeschränkte Tokens - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [CreateProcessWithTokenW-Funktion - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [CreateProcessAsUserW-Funktion - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [DuplicateHandle-Funktion - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
{{#include ../../banners/hacktricks-training.md}}
