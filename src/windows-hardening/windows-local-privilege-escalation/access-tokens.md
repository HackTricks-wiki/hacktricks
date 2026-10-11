# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

Jeder Prozess verfügt über ein **primäres Zugriffstoken**, das seinen Sicherheitskontext definiert. Ein Thread verwendet normalerweise dieses Token, kann aber vorübergehend auch über ein **Impersonation-Token** verfügen. Token enthalten die Benutzer-SID, Gruppen-SIDs, Berechtigungen, Integritätsinformationen und eine Anmelde-SID für die Anmeldesitzung. Prozesse erben in der Regel eine Referenz auf das primäre Token des übergeordneten Prozesses; sie erhalten keine unabhängige Kopie seines Inhalts.<sup>[[4]](#references)</sup>

Diese Informationen können Sie mit `whoami /all` anzeigen.

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

or mithilfe des _Process Explorer_ von Sysinternals (Prozess auswählen und auf die Registerkarte „Security“ zugreifen):

![Access Tokens - Access Tokens: oder mithilfe des Process Explorer von Sysinternals (Prozess auswählen und auf die Registerkarte „Security“ zugreifen)](<../../images/image (772).png>)

### Lokaler Administrator

Wenn **UAC Admin Approval Mode** für einen Administrator gilt, erstellt die interaktive Anmeldung ein vollständiges Administratortoken und ein gefiltertes Token. Explorer und gewöhnliche untergeordnete Prozesse verwenden standardmäßig das gefilterte Token. Eine Elevation-Anforderung wie **Als Administrator ausführen** fordert UAC auf, das Programm mit dem vollständigen Token zu starten. Das genaue Verhalten unterscheidet sich beim integrierten Administratorkonto und wenn Admin Approval Mode deaktiviert ist.<sup>[[5]](#references)</sup>

Weitere Informationen zu Umgehungstechniken und Richtliniendetails findest du auf der entsprechenden [**UAC-Seite**](../authentication-credentials-uac-and-efs/uac-user-account-control.md).

In der Praxis bedeutet dies, dass eine **nicht erhöhte Admin-Shell normalerweise mit einem gefilterten Token ausgeführt wird**. Deshalb zeigt `whoami /groups` häufig **`BUILTIN\Administrators` als `Deny only`** an, bis der Prozess erhöht wird. Intern behält Windows ein **verknüpftes erhöhtes Token** (`TokenLinkedToken`) bei und verfolgt den Status mit Feldern wie `TokenElevationType`.

### Impersonation mit den Anmeldedaten eines Benutzers

Wenn du **gültige Anmeldedaten eines anderen Benutzers** hast, kannst du mit diesen Anmeldedaten eine **neue Anmeldesitzung erstellen** :

```
runas /user:domain\username cmd.exe
```

Der **access token** enthält außerdem eine **Referenz** auf die Anmeldesitzungen innerhalb von **LSASS**. Das ist nützlich, wenn der Prozess auf bestimmte Netzwerkobjekte zugreifen muss.\
Mit folgendem Befehl kannst du einen Prozess starten, der **andere Anmeldedaten für den Zugriff auf Netzwerkdienste verwendet**:

```
runas /user:domain\username /netonly cmd.exe
```

Dies ist nützlich, wenn Sie über gültige Anmeldedaten verfügen, um auf Objekte im Netzwerk zuzugreifen, diese Anmeldedaten aber auf dem aktuellen Host nicht gültig sind, da sie nur im Netzwerk verwendet werden (auf dem aktuellen Host werden die Berechtigungen Ihres aktuellen Benutzers verwendet).

#### Details zu `runas /netonly`

`runas /netonly` (und C2-Helfer wie `make_token`) erstellt ein **`LOGON32_LOGON_NEW_CREDENTIALS`**-Token. Das ist wichtig, um lateral movement zu verstehen, denn:<sup>[[3]](#references)</sup>

- **Lokal** behält der neue Prozess dieselbe **lokale Identität**, dieselben Gruppen, dieselbe Integritätsstufe und größtenteils dieselben Zugriffsentscheidungen wie das aktuelle Token.
- **Remote** kann die ausgehende Authentifizierung die **bereitgestellten Anmeldedaten** für SMB / WinRM / LDAP / HTTP / Kerberos / NTLM verwenden.
- Daher kann `whoami` weiterhin den **ursprünglichen lokalen Benutzer** anzeigen, während der Netzwerkzugriff mit dem **alternativen Konto** erfolgt.

Dies ist eine gute Option, wenn die Anmeldedaten in der Domäne oder auf einem anderen Host gültig sind, der Benutzer sich aber **nicht lokal am aktuellen Computer anmelden kann oder soll**.

### Token-Typen

Es gibt zwei verfügbare Token-Typen:<sup>[[4]](#references)[[6]](#references)</sup>

- **Primäres Token**: Repräsentiert den Sicherheitskontext eines Prozesses. Ein untergeordneter Prozess erbt normalerweise das primäre Token seines übergeordneten Prozesses, während die APIs zur Prozesserstellung mit explizitem Token eigene Anforderungen an den Tokenzugriff und die Berechtigungen des Aufrufers stellen.
- **Impersonation-Token**: Ermöglicht einem Server-Thread, vorübergehend den Sicherheitskontext eines Clients für Zugriffskontrollen zu verwenden. Es gibt vier Stufen:
  - **Anonymous**: Gewährt dem Server Zugriff ähnlich dem eines nicht identifizierten Benutzers.
  - **Identification**: Ermöglicht dem Server, die Identität des Clients zu überprüfen, ohne sie für den Objektzugriff zu verwenden.
  - **Impersonation**: Ermöglicht dem Server, unter der Identität des Clients zu agieren.
  - **Delegation**: Ermöglicht dem Server, den Client auf Remotesystemen zu impersonieren, wenn der Authentifizierungsmechanismus und die Kontokonfiguration Delegation unterstützen.

#### Ein erfasstes Token vor der Verwendung prüfen

Wählen Sie ein Token nicht allein anhand des Benutzernamens aus. Dasselbe Konto kann mehrere Tokens mit unterschiedlichen Anmeldesitzungen, Dienst-SIDs, Berechtigungen, Integritätsstufen, Einschränkungen und Netzwerk-Anmeldedaten besitzen.<sup>[[9]](#references)</sup> Fragen Sie mit `GetTokenInformation` mindestens **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`** und **`TokenStatistics.AuthenticationId`** ab.<sup>[[7]](#references)</sup>

Ein eingeschränktes Token kann SIDs enthalten, die nur für Zugriffsverweigerungen gelten, entfernte Berechtigungen und einschränkende SIDs. Sind einschränkende SIDs vorhanden, führt Windows eine Zugriffskontrolle mit den aktivierten SIDs und eine weitere mit den einschränkenden SIDs durch; **beide Prüfungen müssen den Zugriff erlauben**. Daher beweist eine attraktive Benutzer-SID oder eine aktivierte Gruppe in der Ausgabe allein nicht, dass das Token auf das Zielobjekt zugreifen kann.<sup>[[8]](#references)</sup>

Verwenden Sie diesen Entscheidungsablauf für die dokumentierten Anforderungen an Tokens und die Prozesserstellung:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. Ein **primäres Token** benötigt ein Handle mit `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`, bevor es an `CreateProcessWithTokenW` oder `CreateProcessAsUserW` übergeben werden kann.
2. Wandeln Sie ein **Impersonation-Token** mit `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)` um. Tokens auf Identification-Stufe können Identitätsdaten offenlegen, aber keine Zugriffskontrollen im Namen des Clients durchführen.
3. `CreateProcessWithTokenW` benötigt `SeImpersonatePrivilege` und startet den untergeordneten Prozess in der Sitzung des Aufrufers. `CreateProcessAsUserW` verwendet stattdessen die Sitzung des Tokens, benötigt aber normalerweise `SeIncreaseQuotaPrivilege` und kann `SeAssignPrimaryTokenPrivilege` erfordern. Wenn Anmeldedaten verfügbar sind, diese Berechtigungen aber fehlen, ist `CreateProcessWithLogonW` die dokumentierte Alternative.

#### Nach Token-Handles suchen, nicht nur nach Prozesseigentümern

Wenn nur das primäre Token jedes Prozesses geöffnet wird, können **als gewöhnliche Handles gespeicherte Impersonation-Tokens** in Diensten und Broker-Prozessen übersehen werden. Ein wiederverwendbarer Ablauf zur Arbeit mit Handle-Tabellen besteht darin, System-Handles aufzulisten, nach Token-Objekten zu filtern, jeden Besitzer mit `PROCESS_DUP_HANDLE` zu öffnen, das betreffende Handle in den aktuellen Prozess zu duplizieren und anschließend die oben genannten Felder abzufragen. Vergewissern Sie sich, dass das duplizierte Handle `TOKEN_QUERY` und `TOKEN_DUPLICATE` enthält; ein gefundenes Token-Handle bedeutet nicht, dass es zu einem verwendbaren primären Token dupliziert werden kann. Geschützte Prozesse und DACLs von Prozessen können den Zugriff auf das Handle des Besitzerprozesses weiterhin blockieren.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` automatisiert sowohl die Auflistung primärer Prozesstokens als auch die Auflistung gespeicherter Token-Handles. `list_token` behält pro Benutzername einen bevorzugten Kandidaten bei, während `list_all_token` alle Kandidaten ausgibt. Eine PID beschränkt die Auflistung auf einen Besitzerprozess.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

Zur manuellen Prüfung und Zugriffskontrolle kann **TokenUniverse** Prozess-/Thread-Tokens öffnen, nach vorhandenen Token-Handles suchen, Einschränkungen und Anmeldesitzungen untersuchen, Tokens duplizieren und verschiedene Methoden zum Erstellen von Prozessen testen.<sup>[[13]](#references)</sup> Informationen zum zugrunde liegenden Primitiv für prozessübergreifende Handles findest du hier:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

#### Impersonate Tokens

Wenn du mit dem _**incognito**_-Modul von metasploit über ausreichende Berechtigungen verfügst, kannst du einfach andere **Tokens** **auflisten** und **impersonieren**. Das kann nützlich sein, um **Aktionen so auszuführen, als wärst du der andere Benutzer**. Mit dieser Technik kannst du außerdem **Berechtigungen erweitern**.

Einige praktische Hinweise, die im Einsatz leicht in Vergessenheit geraten:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** erfordert **`SeImpersonatePrivilege`** beim aufrufenden Prozess. Der neue Prozess wird in der **Sitzung des aufrufenden Prozesses** ausgeführt.
- **`CreateProcessAsUserW`** ist eine mögliche Ausweichlösung, wenn `CreateProcessWithTokenW` mit `1314` fehlschlägt – allerdings nur, wenn der aufrufende Prozess die dafür erforderlichen Berechtigungen besitzt. Diese Funktion ist auch dann die richtige Wahl, wenn der untergeordnete Prozess in der **im Token referenzierten Sitzung** ausgeführt werden muss.<sup>[[9]](#references)[[10]](#references)</sup>
- Wenn ein Token von **`LogonUser(LOGON32_LOGON_NETWORK)`** stammt, handelt es sich in der Regel um ein **Impersonation-Token**. Daher musst du **`DuplicateTokenEx(..., TokenPrimary, ...)`** aufrufen, bevor du damit versuchst, einen Prozess zu starten.
- Nicht jedes Impersonation-Token ist gleich nützlich: Mit **`SecurityIdentification`** kannst du den Benutzer untersuchen, aber **nicht in seinem Namen handeln**. Wenn ein Coercion-Primitiv oder Pipe-/RPC-Client dir nur ein Token auf Identifikationsebene liefert, prüfe **`TokenImpersonationLevel`** und wechsle zu einem Primitiv, das **`SecurityImpersonation`** oder eine höhere Stufe liefert.

#### Token-Diebstahl, ohne LSASS anzurühren

Wenn du bereits über einen **Service**- oder **SYSTEM**-Kontext verfügst und ein **privilegierter Benutzer angemeldet ist**, ist es oft unauffälliger, dessen Token zu stehlen oder zu duplizieren, als **LSASS** auszulesen. Bei vielen realen Angriffen reicht das aus, um:<sup>[[2]](#references)</sup>

- lokale Aktionen als dieser Benutzer auszuführen
- als dieser Benutzer auf Remote-Ressourcen zuzugreifen
- AD-Operationen durchzuführen, ohne zuvor wiederverwendbare Anmeldedaten zu extrahieren

Beispiele für das Hijacking von **Sitzungs-/Benutzer-Tokens** aus einem privilegierten Kontext findest du unter [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Beachte, dass APIs wie **`WTSQueryUserToken`** für **besonders vertrauenswürdige Services** vorgesehen sind und normalerweise **`LocalSystem` + `SeTcbPrivilege`** erfordern. Sie sind daher vor allem dann nützlich, wenn du bereits einen Service-Kontext kontrollierst. Informationen zu Methoden, mit denen du zunächst **SYSTEM** erlangst, findest du auf den folgenden Seiten.

### Token-Berechtigungen

Hier erfährst du, **welche Token-Berechtigungen missbraucht werden können, um Berechtigungen zu erweitern:**

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Sieh dir [**alle möglichen Token-Berechtigungen und einige Definitionen auf dieser externen Seite an**](https://github.com/gtworek/Priv2Admin).

## References

- [1] [Zugriffstokens verstehen und missbrauchen — Teil II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Windows-Tokens missbrauchen, um Active Directory zu kompromittieren, ohne LSASS anzurühren](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Cobalt Strikes Befehl „make_token“ verständlich erklärt](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Zugriffstokens - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [Funktionsweise der Benutzerkontensteuerung - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Impersonation-Stufen - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [TOKEN_INFORMATION_CLASS-Aufzählung - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Eingeschränkte Tokens - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [CreateProcessWithTokenW-Funktion - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [CreateProcessAsUserW-Funktion - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [DuplicateHandle-Funktion - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
{{#include ../../banners/hacktricks-training.md}}
