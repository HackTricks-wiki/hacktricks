# Zugriffstoken

{{#include ../../banners/hacktricks-training.md}}

## Zugriffstoken

Jeder Prozess hat ein **primäres Zugriffstoken**, das seinen Sicherheitskontext festlegt. Ein Thread verwendet normalerweise dieses Token, kann aber vorübergehend auch ein **Identitätswechsel-Token** besitzen. Token enthalten die Benutzer-SID, Gruppen-SIDs, Berechtigungen, Integritätsinformationen und eine Anmelde-SID für die Anmeldesitzung. Prozesse erben im Allgemeinen einen Verweis auf das primäre Token des übergeordneten Prozesses; sie erhalten keine unabhängige Kopie seines Inhalts.<sup>[[4]](#references)</sup>

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

oder mit _Process Explorer_ von Sysinternals (Prozess auswählen und auf die Registerkarte „Security“ zugreifen):

![Access Tokens - Access Tokens: oder mit Process Explorer von Sysinternals (Prozess auswählen und auf die Registerkarte „Security“ zugreifen)](<../../images/image (772).png>)

### Lokaler Administrator

Wenn **UAC Admin Approval Mode** für einen Administrator gilt, werden bei der interaktiven Anmeldung ein vollständiges Administratortoken und ein gefiltertes Token erstellt. Explorer und gewöhnliche untergeordnete Prozesse verwenden standardmäßig das gefilterte Token. Eine Anforderung zur Rechteerweiterung, etwa **Als Administrator ausführen**, fordert UAC auf, das Programm mit dem vollständigen Token zu starten. Das genaue Verhalten unterscheidet sich beim integrierten Administratorkonto und wenn Admin Approval Mode deaktiviert ist.<sup>[[5]](#references)</sup>

Weitere Informationen zu Umgehungstechniken und Richtliniendetails findest du auf der entsprechenden [**UAC-Seite**](../authentication-credentials-uac-and-efs/uac-user-account-control.md).

In der Praxis bedeutet das, dass eine **nicht erhöhte Admin-Shell normalerweise mit einem gefilterten Token ausgeführt wird**. Deshalb zeigt `whoami /groups` häufig **`BUILTIN\Administrators` als `Deny only`** an, bis der Prozess erhöht wird. Intern hält Windows ein **verknüpftes erhöhtes Token** (`TokenLinkedToken`) vor und verfolgt den Status mit Feldern wie `TokenElevationType`.

### Identitätswechsel mit Benutzeranmeldedaten

Wenn du **gültige Anmeldedaten eines anderen Benutzers** hast, kannst du mit diesen Anmeldedaten eine **neue Anmeldesitzung erstellen**:

```
runas /user:domain\username cmd.exe
```

Das **access token** enthält außerdem eine **Referenz** auf die Anmeldesitzungen innerhalb von **LSASS**. Das ist nützlich, wenn der Prozess auf Netzwerkobjekte zugreifen muss.\
Mit folgendem Befehl können Sie einen Prozess starten, der **andere Anmeldedaten für den Zugriff auf Netzwerkdienste verwendet**:

```
runas /user:domain\username /netonly cmd.exe
```

Dies ist nützlich, wenn Sie über gültige Anmeldedaten für den Zugriff auf Objekte im Netzwerk verfügen, diese Anmeldedaten auf dem aktuellen Host jedoch nicht gültig sind, da sie nur im Netzwerk verwendet werden (auf dem aktuellen Host werden die Berechtigungen Ihres aktuellen Benutzers verwendet).

#### Details zu `runas /netonly`

`runas /netonly` (und C2-Helfer wie `make_token`) erstellt ein **`LOGON32_LOGON_NEW_CREDENTIALS`**-Token. Das ist beim Lateral Movement wichtig zu verstehen, denn:<sup>[[3]](#references)</sup>

- **Lokal** behält der neue Prozess dieselbe **lokale Identität**, dieselben Gruppen, dieselbe Integritätsstufe und größtenteils dieselben Zugriffsentscheidungen wie das aktuelle Token.
- **Remote** kann die ausgehende Authentifizierung die **angegebenen Anmeldedaten** für SMB / WinRM / LDAP / HTTP / Kerberos / NTLM verwenden.
- Daher zeigt `whoami` möglicherweise weiterhin den **ursprünglichen lokalen Benutzer** an, während der Netzwerkzugriff unter dem **alternativen Konto** erfolgt.

Dies ist eine gute Option, wenn die Anmeldedaten in der Domäne oder auf einem anderen Host gültig sind, der Benutzer sich aber **nicht lokal am aktuellen Computer anmelden kann oder sollte**.

### Token-Typen

Es gibt zwei Arten von Tokens:<sup>[[4]](#references)[[6]](#references)</sup>

- **Primäres Token**: Stellt den Sicherheitskontext eines Prozesses dar. Ein untergeordneter Prozess erbt normalerweise das primäre Token seines übergeordneten Prozesses. APIs zur Prozesserstellung mit explizitem Token haben jedoch eigene Anforderungen an Tokenzugriffe und Berechtigungen des aufrufenden Prozesses.
- **Impersonation-Token**: Ermöglicht einem Serverthread, vorübergehend den Sicherheitskontext eines Clients für Zugriffsprüfungen zu verwenden. Es gibt vier Stufen:
  - **Anonymous**: Gewährt dem Server Zugriff ähnlich dem eines nicht identifizierten Benutzers.
  - **Identification**: Ermöglicht dem Server, die Identität des Clients zu überprüfen, ohne sie für Objektzugriffe zu verwenden.
  - **Impersonation**: Ermöglicht dem Server, unter der Identität des Clients zu agieren.
  - **Delegation**: Ermöglicht dem Server, den Client auf Remotesystemen zu impersonieren, sofern Authentifizierungsmechanismus und Kontokonfiguration Delegation unterstützen.

#### Ein erfasstes Token vor der Verwendung prüfen

Wählen Sie ein Token nicht allein anhand des Benutzernamens aus. Für dasselbe Konto können mehrere Tokens mit unterschiedlichen Anmeldesitzungen, Dienst-SIDs, Berechtigungen, Integritätsstufen, Einschränkungen und Netzwerkanmeldedaten existieren.<sup>[[9]](#references)</sup> Fragen Sie mit `GetTokenInformation` mindestens **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`** und **`TokenStatistics.AuthenticationId`** ab.<sup>[[7]](#references)</sup>

Ein eingeschränktes Token kann SIDs mit „deny-only“, entfernte Berechtigungen und einschränkende SIDs enthalten. Sind einschränkende SIDs vorhanden, führt Windows eine Zugriffsprüfung mit den aktivierten SIDs und eine weitere mit den einschränkenden SIDs durch; **beide Prüfungen müssen den Zugriff erlauben**. Eine vielversprechende Benutzer-SID oder eine aktivierte Gruppe in der Ausgabe beweist daher nicht für sich allein, dass das Token auf das Zielobjekt zugreifen kann.<sup>[[8]](#references)</sup>

Verwenden Sie diesen Entscheidungsablauf für die dokumentierten Anforderungen an Tokens und die Prozesserstellung:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. Für ein **primäres Token** ist ein Handle mit `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` erforderlich, bevor es an `CreateProcessWithTokenW` oder `CreateProcessAsUserW` übergeben werden kann.
2. Wandeln Sie ein **Impersonation-Token** mit `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)` um. Tokens auf Identification-Stufe können Identitätsdaten offenlegen, aber keine Zugriffsprüfungen als dieser Client durchführen.
3. `CreateProcessWithTokenW` benötigt `SeImpersonatePrivilege` und startet den untergeordneten Prozess in der Sitzung des aufrufenden Prozesses. `CreateProcessAsUserW` verwendet stattdessen die Sitzung des Tokens, benötigt normalerweise `SeIncreaseQuotaPrivilege` und kann `SeAssignPrimaryTokenPrivilege` erfordern. Sind Anmeldedaten verfügbar, diese Berechtigungen jedoch nicht vorhanden, ist `CreateProcessWithLogonW` die dokumentierte Alternative.

#### Nach Token-Handles suchen, nicht nur nach Prozesseigentümern

Das Öffnen des primären Tokens jedes Prozesses kann **Impersonation-Tokens übersehen, die als gewöhnliche Handles** in Diensten und Brokerprozessen aufbewahrt werden. Ein wiederverwendbarer Workflow für Handle-Tabellen besteht darin, System-Handles aufzulisten, Tokenobjekte herauszufiltern, jeden Eigentümer mit `PROCESS_DUP_HANDLE` zu öffnen, das Kandidaten-Handle in den aktuellen Prozess zu duplizieren und anschließend die oben genannten Felder abzufragen. Vergewissern Sie sich, dass das duplizierte Handle `TOKEN_QUERY` und `TOKEN_DUPLICATE` enthält; ein sichtbares Token-Handle lässt nicht darauf schließen, dass es zu einem verwendbaren primären Token dupliziert werden kann. Geschützte Prozesse und Prozess-DACLs können den Zugriff auf das Handle des Eigentümerprozesses weiterhin verhindern.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` automatisiert sowohl die Auflistung primärer Prozesstokens als auch die von aufbewahrten Token-Handles. `list_token` behält pro Benutzername einen bevorzugten Kandidaten bei, während `list_all_token` alle Kandidaten ausgibt. Eine PID beschränkt die Auflistung auf einen einzigen Eigentümerprozess.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

Zur manuellen Prüfung und Zugriffskontrolle kann **TokenUniverse** Prozess-/Thread-Tokens öffnen, nach vorhandenen Token-Handles suchen, Einschränkungen und Anmeldesitzungen untersuchen, Tokens duplizieren und mehrere Methoden zur Prozesserstellung testen.<sup>[[13]](#references)</sup> Informationen zum zugrunde liegenden Primitive für prozessübergreifende Handles findest du hier:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

### Aktive Thread-Impersonation-Tokens suchen

Ein Service-Thread kann vorübergehend einen Client impersonieren, obwohl das **primäre Prozesstoken** zum Servicekonto gehört. Daher können Scans nach Prozesseigentümern den Client-Kontext übersehen.<sup>[[4]](#references)</sup> TokenUniverse kann zugängliche Prozess-/Thread-Tokens auflisten. Öffne in System Informer den Tab **Threads** eines Prozesses und prüfe die Spalte **Impersonation**, um mögliche Threads zu finden.<sup>[[13]](#references)[[14]](#references)</sup>

Für eine gezielte API-Prüfung erstellst du einen `TH32CS_SNAPTHREAD`-Snapshot, filterst `THREADENTRY32.th32OwnerProcessID` nach der Service-PID und rufst dann für jeden zugänglichen Thread `OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid)` sowie `OpenThreadToken(thread, TOKEN_QUERY | TOKEN_DUPLICATE, TRUE, &token)` auf.<sup>[[15]](#references)[[16]](#references)</sup> Mit `TRUE` verwendet die Zugriffskontrolle beim Öffnen des Tokens den **Prozess**-Kontext des Aufrufers. Das ist wichtig, wenn der Scanner selbst auf Identifikationsebene impersoniert.<sup>[[17]](#references)</sup> Frage Benutzer, Typ, Impersonation-Level und Anmelde-ID des Tokens ab, bevor du den oben beschriebenen Ablauf zum Duplizieren bzw. Erstellen eines Prozesses ausprobierst.<sup>[[7]](#references)</sup> Ein Thread kann zwischen Aufzählung und Öffnen die Impersonation beenden; außerdem können ein fehlendes Token, anonyme Tokens, geschützte Threads, Thread-DACLs und Token-DACLs das Erfassen verhindern.<sup>[[16]](#references)[[17]](#references)</sup> Anders als beim Durchsuchen gespeicherter Token-Handles eines Service wird hier das **aktuell zugewiesene Thread-Token** geprüft.

Für einen Angriffsweg, bei dem du ein Thread-Token erhältst, indem du einen privilegierten Client dazu bringst, sich mit deiner Pipe zu verbinden, statt vorhandene Threads zu durchsuchen, siehe [named-pipe client impersonation](named-pipe-client-impersonation.md).

#### Tokens impersonieren

Mit dem _**incognito**_-Modul von metasploit kannst du bei ausreichenden Berechtigungen ganz einfach andere **Tokens** **auflisten** und **impersonieren**. Das kann nützlich sein, um **Aktionen so auszuführen, als wärst du der andere Benutzer**. Mit dieser Technik kannst du außerdem **Berechtigungen erweitern**.

Einige praktische Hinweise, die beim Arbeiten leicht in Vergessenheit geraten:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** erfordert **`SeImpersonatePrivilege`** beim Aufrufer; der neue Prozess wird in der **Sitzung des Aufrufers** ausgeführt.
- **`CreateProcessAsUserW`** ist ein möglicher Fallback, wenn `CreateProcessWithTokenW` mit `1314` fehlschlägt, aber nur, wenn der Aufrufer die erforderlichen Berechtigungen besitzt. Die Funktion ist auch die richtige Wahl, wenn der untergeordnete Prozess in der **im Token angegebenen Sitzung** ausgeführt werden muss.<sup>[[9]](#references)[[10]](#references)</sup>
- **`LogonUser(LOGON32_LOGON_NETWORK)`** gibt ein **Impersonation-Token** zurück. Wandle es mit **`DuplicateTokenEx(..., TokenPrimary, ...)`** um, bevor du einen Prozess erstellst. Auch nach der Umwandlung kann der resultierende Prozess diese Netzwerkanmeldung nicht verwenden, um auf authentifizierte Remote-Freigaben oder Drucker zuzugreifen: Bei diesem Anmeldetyp werden keine Anmeldeinformationen zwischengespeichert. Verwende eine interaktive Anmeldung oder eine Anmeldung mit Klartext-Netzwerkanmeldeinformationen, wenn du über Anmeldeinformationen verfügst und anschließend auf das Netzwerk zugreifen musst. Verwechsle dies nicht mit `LOGON32_LOGON_NEW_CREDENTIALS` (`runas /netonly`), bei dem die lokale Identität beibehalten und nur für ausgehende Verbindungen andere Anmeldeinformationen verwendet werden.<sup>[[18]](#references)</sup>
- Nicht jedes Impersonation-Token ist gleich nützlich: **`SecurityIdentification`** erlaubt es dir, den Benutzer zu untersuchen, aber **nicht, in seinem Namen zu handeln**. Wenn ein Coercion-Primitive oder ein Pipe-/RPC-Client dir nur ein Token auf Identifikationsebene liefert, prüfe **`TokenImpersonationLevel`** und verwende ein Primitive, das **`SecurityImpersonation`** oder eine höhere Stufe ermöglicht.

#### Token-Diebstahl ohne Zugriff auf LSASS

Wenn du bereits über einen **Service**- oder **SYSTEM**-Kontext verfügst und ein **privilegierter Benutzer angemeldet ist**, ist es oft unauffälliger, dessen Token zu stehlen oder zu duplizieren, als **LSASS** zu dumpen. Bei vielen realen Eindringversuchen reicht das aus, um:<sup>[[2]](#references)</sup>

- lokale Aktionen als dieser Benutzer auszuführen
- als dieser Benutzer auf Remote-Ressourcen zuzugreifen
- AD-Vorgänge durchzuführen, ohne zuvor wiederverwendbare Anmeldeinformationen auszulesen

Beispiele für das Hijacking von **Sitzungs-/Benutzer-Tokens** aus einem privilegierten Kontext findest du unter [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Denk daran, dass APIs wie **`WTSQueryUserToken`** für **besonders vertrauenswürdige Services** vorgesehen sind und normalerweise **`LocalSystem` + `SeTcbPrivilege`** erfordern. Sie sind daher vor allem dann nützlich, wenn du bereits einen Service-Kontext kontrollierst. Auf den folgenden Seiten findest du Möglichkeiten, zunächst **SYSTEM** zu erlangen, die bestimmte Berechtigungen ausnutzen.

### Token-Berechtigungen

Hier erfährst du, **welche Token-Berechtigungen sich zur Rechteausweitung missbrauchen lassen:**

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Sieh dir [**alle möglichen Token-Berechtigungen und einige Definitionen auf dieser externen Seite an**](https://github.com/gtworek/Priv2Admin).



## References

- [1] [Access Tokens verstehen und missbrauchen — Teil II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Windows-Tokens missbrauchen, um Active Directory ohne Zugriff auf LSASS zu kompromittieren](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Cobalt Strikes Befehl „make_token“ verständlich erklärt](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Zugriffstokens - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [Funktionsweise der Benutzerkontensteuerung - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Impersonation-Levels - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [Aufzählung TOKEN_INFORMATION_CLASS - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Eingeschränkte Tokens - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [Funktion CreateProcessWithTokenW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [Funktion CreateProcessAsUserW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [Funktion DuplicateHandle - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
- [14] [Feature-Anfrage für Thread-Tokens in System Informer](https://github.com/winsiderss/systeminformer/issues/1275)
- [15] [Durchlaufen der Thread-Liste - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-thread-list)
- [16] [NtOpenThreadToken - Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntopenthreadtoken)
- [17] [OpenThreadToken - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken)
- [18] [LogonUserA - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera)
{{#include ../../banners/hacktricks-training.md}}
