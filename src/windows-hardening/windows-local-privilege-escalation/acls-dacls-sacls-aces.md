# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Access Control List (ACL)**

Eine Access Control List (ACL) besteht aus einer geordneten Gruppe von Access Control Entries (ACEs), die den Schutz eines Objekts und seiner Eigenschaften festlegen. Im Wesentlichen definiert eine ACL, welche Aktionen von welchen Sicherheitsprinzipalen (Benutzern oder Gruppen) für ein bestimmtes Objekt erlaubt oder verweigert werden.

Es gibt zwei Arten von ACLs:

- **Discretionary Access Control List (DACL):** Legt fest, welche Benutzer und Gruppen Zugriff auf ein Objekt haben oder nicht haben.
- **System Access Control List (SACL):** Regelt die Überwachung von Zugriffsversuchen auf ein Objekt.

Beim Zugriff auf eine Datei überprüft das System den Sicherheitsdeskriptor des Objekts anhand des Zugriffstokens des Benutzers, um zu bestimmen, ob Zugriff gewährt werden soll und welchen Umfang dieser Zugriff haben soll. Maßgeblich sind dabei die ACEs.<sup>[[1]](#references)</sup>

Wenn ein übergeordnetes Verzeichnis Full Control gewährt, eine untergeordnete Datei das Lesen jedoch verweigert, überprüfe die effektive DACL, den Besitzer und die Vererbung der **untergeordneten Datei** separat. Zum Ändern der DACL dieser Datei benötigst du `WRITE_DAC` für die Datei oder das entsprechende Besitzerrecht. [Microsoft definiert `WRITE_DAC`](https://learn.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights) und [dokumentiert den impliziten Zugriff des Besitzers](https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-of-a-new-object). Berechtigungen für das übergeordnete Verzeichnis allein belegen weder, dass die untergeordnete Datei gelesen werden kann, noch, dass ihre DACL geändert werden kann.

### **Key Components**

- **DACL:** Enthält ACEs, die Benutzern und Gruppen Zugriffsberechtigungen für ein Objekt gewähren oder verweigern. Sie ist im Wesentlichen die zentrale ACL, die die Zugriffsrechte festlegt.
- **SACL:** Dient der Überwachung von Zugriffen auf Objekte. Die ACEs legen fest, welche Arten von Zugriffen im Security Event Log protokolliert werden. Das kann bei der Erkennung nicht autorisierter Zugriffsversuche oder der Behebung von Zugriffsproblemen äußerst hilfreich sein.<sup>[[1]](#references)</sup>

### **System Interaction with ACLs**

Jede Benutzersitzung ist einem Zugriffstoken zugeordnet, das für diese Sitzung relevante Sicherheitsinformationen enthält, darunter Benutzer- und Gruppenidentitäten sowie Berechtigungen. Dieses Token enthält auch eine Logon-SID, die die Sitzung eindeutig identifiziert.

Die Local Security Authority (LSASS) verarbeitet Zugriffsanforderungen für Objekte, indem sie die DACL auf ACEs überprüft, die dem Sicherheitsprinzipal entsprechen, der den Zugriff anfordert. Wenn keine relevanten ACEs gefunden werden, wird der Zugriff sofort gewährt. Andernfalls vergleicht LSASS die ACEs mit der SID des Sicherheitsprinzipals im Zugriffstoken, um festzustellen, ob der Zugriff zulässig ist.<sup>[[1]](#references)</sup>

### **Summarized Process**

- **ACLs:** Legen mithilfe von DACLs Zugriffsberechtigungen und mithilfe von SACLs Überwachungsregeln fest.
- **Access Token:** Enthält die Benutzer-, Gruppen- und Berechtigungsinformationen einer Sitzung.
- **Access Decision:** Wird durch den Abgleich der DACL-ACEs mit dem Zugriffstoken getroffen; SACLs dienen der Überwachung.<sup>[[1]](#references)</sup>

### ACEs

Es gibt **drei Haupttypen von Access Control Entries (ACEs)**:<sup>[[1]](#references)</sup>

- **Access Denied ACE**: Diese ACE verweigert bestimmten Benutzern oder Gruppen explizit den Zugriff auf ein Objekt (in einer DACL).
- **Access Allowed ACE**: Diese ACE gewährt bestimmten Benutzern oder Gruppen explizit Zugriff auf ein Objekt (in einer DACL).
- **System Audit ACE**: Diese ACE befindet sich in einer System Access Control List (SACL) und ist dafür zuständig, bei Zugriffsversuchen von Benutzern oder Gruppen auf ein Objekt Überwachungsprotokolle zu erstellen. Sie dokumentiert, ob der Zugriff erlaubt oder verweigert wurde und um welche Art von Zugriff es sich handelte.

Jede ACE hat **vier wichtige Komponenten**:<sup>[[1]](#references)</sup>

1. Den **Security Identifier (SID)** des Benutzers oder der Gruppe (oder den Namen des Prinzipals in einer grafischen Darstellung).
2. Ein **Flag**, das den ACE-Typ kennzeichnet (Zugriff verweigert, gewährt oder Systemüberwachung).
3. **Vererbungsflags**, die festlegen, ob untergeordnete Objekte die ACE von ihrem übergeordneten Objekt erben können.
4. Eine [**access mask**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), einen 32-Bit-Wert, der die gewährten Rechte für das Objekt festlegt.

Die Zugriffsentscheidung wird getroffen, indem jede ACE der Reihe nach überprüft wird, bis:<sup>[[1]](#references)</sup>

- Eine **Access-Denied ACE** die angeforderten Rechte einem Trustee, der im Zugriffstoken identifiziert ist, explizit verweigert.
- Eine oder mehrere **Access-Allowed ACEs** einem Trustee im Zugriffstoken explizit alle angeforderten Rechte gewähren.
- Nach Überprüfung aller ACEs ein angefordertes Recht **nicht explizit gewährt wurde**; in diesem Fall wird der Zugriff implizit **verweigert**.

### Order of ACEs

Die Reihenfolge, in der **ACEs** (Regeln, die festlegen, wer auf etwas zugreifen darf oder nicht) in einer **DACL** aufgeführt werden, ist sehr wichtig. Denn sobald das System anhand dieser Regeln Zugriff gewährt oder verweigert, überprüft es die übrigen Regeln nicht mehr.<sup>[[1]](#references)</sup>

Es gibt eine optimale Art, diese ACEs anzuordnen, die **„kanonische Reihenfolge“** genannt wird. Diese Methode sorgt für einen reibungslosen und fairen Ablauf. Für Systeme wie **Windows 2000** und **Windows Server 2003** gilt folgende Reihenfolge:

- Setze zuerst alle Regeln, die **speziell für dieses Objekt** gelten, vor die Regeln, die von anderer Stelle stammen, etwa von einem übergeordneten Ordner.
- Bei diesen spezifischen Regeln kommen die Regeln, die **„nein“ (verweigern)** sagen, vor denen, die **„ja“ (gewähren)** sagen.
- Bei den Regeln, die von anderer Stelle stammen, kommen zuerst die Regeln aus der **nächstgelegenen Quelle**, etwa dem übergeordneten Objekt; anschließend folgen die weiter entfernten. Auch hier gilt: **„nein“** kommt vor **„ja“**.

Diese Anordnung bietet zwei wichtige Vorteile:

- Sie stellt sicher, dass ein spezifisches **„nein“** Vorrang hat, unabhängig davon, welche anderen **„ja“**-Regeln vorhanden sind.
- Sie ermöglicht es dem Besitzer eines Objekts, **zuletzt zu entscheiden**, wer Zugriff erhält, bevor Regeln aus übergeordneten Ordnern oder anderen weiter entfernten Quellen berücksichtigt werden.

Dadurch kann der Besitzer einer Datei oder eines Ordners genau festlegen, wer Zugriff erhält, sodass die richtigen Personen Zugriff haben und die falschen nicht.

![NTFS access control entry ordering diagram](https://www.ntfs.com/images/screenshots/ACEs.gif)

Bei dieser **„kanonischen Reihenfolge“** geht es also darum, für klare und effektive Zugriffsregeln zu sorgen, indem spezifische Regeln an den Anfang gesetzt und alle Regeln sinnvoll angeordnet werden.

### GUI Example

[**Beispiel von hier**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)<sup>[[2]](#references)</sup>

Dies ist die klassische Registerkarte „Sicherheit“ eines Ordners mit der ACL, DACL und den ACEs:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

Wenn wir auf die Schaltfläche **Advanced** klicken, erhalten wir weitere Optionen, etwa zur Vererbung:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

Und wenn du einen Security Principal hinzufügst oder bearbeitest:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

Zum Schluss sehen wir die SACL auf der Registerkarte „Auditing“:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Explaining Access Control in a Simplified Manner

Wenn wir den Zugriff auf Ressourcen wie einen Ordner verwalten, verwenden wir Listen und Regeln, die als Access Control Lists (ACLs) und Access Control Entries (ACEs) bezeichnet werden. Sie legen fest, wer auf bestimmte Daten zugreifen darf und wer nicht.<sup>[[1]](#references)</sup>

#### Denying Access to a Specific Group

Stell dir vor, du hast einen Ordner namens Cost und möchtest allen Zugriff darauf gewähren, außer einem Marketingteam. Durch die richtige Einrichtung der Regeln können wir sicherstellen, dass dem Marketingteam der Zugriff explizit verweigert wird, bevor allen anderen Zugriff gewährt wird. Dazu wird die Regel, die dem Marketingteam den Zugriff verweigert, vor die Regel gesetzt, die allen Zugriff gewährt.

#### Allowing Access to a Specific Member of a Denied Group

Nehmen wir an, Bob, der Marketingdirektor, benötigt Zugriff auf den Cost-Ordner, obwohl das Marketingteam im Allgemeinen keinen Zugriff haben sollte. Wir können eine spezifische Regel (ACE) für Bob hinzufügen, die ihm Zugriff gewährt, und sie vor die Regel setzen, die dem Marketingteam den Zugriff verweigert. So erhält Bob trotz der allgemeinen Einschränkung für sein Team Zugriff.

#### Understanding Access Control Entries

ACEs sind die einzelnen Regeln innerhalb einer ACL. Sie identifizieren Benutzer oder Gruppen, legen fest, welcher Zugriff gewährt oder verweigert wird, und bestimmen, wie diese Regeln für untergeordnete Elemente gelten (Vererbung). Es gibt zwei Haupttypen von ACEs:

- **Generic ACEs**: Diese gelten allgemein und betreffen entweder alle Arten von Objekten oder unterscheiden nur zwischen Containern (wie Ordnern) und Nicht-Containern (wie Dateien). Ein Beispiel ist eine Regel, die Benutzern erlaubt, den Inhalt eines Ordners anzuzeigen, nicht jedoch auf die darin enthaltenen Dateien zuzugreifen.
- **Object-Specific ACEs**: Diese ermöglichen eine präzisere Kontrolle, indem Regeln für bestimmte Objekttypen oder sogar einzelne Eigenschaften eines Objekts festgelegt werden können. Beispielsweise könnte eine Regel in einem Benutzerverzeichnis einem Benutzer erlauben, seine Telefonnummer zu ändern, nicht aber seine Anmeldezeiten.

Jede ACE enthält wichtige Informationen, etwa für wen die Regel gilt (mithilfe eines Security Identifier oder SID), was die Regel erlaubt oder verweigert (mithilfe einer access mask) und wie sie von anderen Objekten geerbt wird.

#### Key Differences Between ACE Types

- **Generic ACEs** eignen sich für einfache Zugriffskontrollszenarien, in denen dieselbe Regel für alle Aspekte eines Objekts oder für alle Objekte innerhalb eines Containers gilt.
- **Object-Specific ACEs** werden für komplexere Szenarien verwendet, insbesondere in Umgebungen wie Active Directory, in denen der Zugriff auf bestimmte Eigenschaften eines Objekts unterschiedlich geregelt werden muss.

Zusammenfassend lässt sich sagen, dass ACLs und ACEs dabei helfen, präzise Zugriffskontrollen festzulegen. So wird sichergestellt, dass nur die richtigen Personen oder Gruppen Zugriff auf vertrauliche Informationen oder Ressourcen haben. Zugriffsrechte lassen sich dabei bis auf die Ebene einzelner Eigenschaften oder Objekttypen abstimmen.

### Access Control Entry Layout

| ACE Field   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type        | Flag, das den ACE-Typ angibt. Windows 2000 und Windows Server 2003 unterstützen sechs ACE-Typen: drei generische ACE-Typen, die allen sicherungsfähigen Objekten zugeordnet werden, und drei objektspezifische ACE-Typen, die bei Active Directory-Objekten vorkommen können.                                                                                                                                                                                                                                                            |
| Flags       | Gruppe von Bitflags, die Vererbung und Überwachung steuern.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Size        | Anzahl der Byte im Speicher, die für die ACE reserviert sind.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Access mask | 32-Bit-Wert, dessen Bits den Zugriffsrechten für das Objekt entsprechen. Bits können ein- oder ausgeschaltet sein; die Bedeutung der Einstellung hängt jedoch vom ACE-Typ ab. Ist beispielsweise das Bit für das Recht, Berechtigungen zu lesen, eingeschaltet und ist der ACE-Typ „Deny“, verweigert die ACE das Recht, die Berechtigungen des Objekts zu lesen. Ist dasselbe Bit eingeschaltet und der ACE-Typ „Allow“, gewährt die ACE das Recht, die Berechtigungen des Objekts zu lesen. Weitere Einzelheiten zur Access mask enthält die nächste Tabelle. |
| SID         | Identifiziert einen Benutzer oder eine Gruppe, deren Zugriff durch diese ACE gesteuert oder überwacht wird.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Access Mask Layout

| Bit (Range) | Meaning                            | Description/Example                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Objektspezifische Zugriffsrechte   | Daten lesen, ausführen, Daten anhängen    |
| 16 - 22     | Standardzugriffsrechte             | Löschen, ACL schreiben, Besitzer ändern   |
| 23          | Zugriff auf die Sicherheits-ACL    |                                           |
| 24 - 27     | Reserviert                          |                                           |
| 28          | Generic ALL (Lesen, Schreiben, Ausführen) | Alles Folgende                          |
| 29          | Generic Execute                    | Alles, was zum Ausführen eines Programms erforderlich ist |
| 30          | Generic Write                      | Alles, was zum Schreiben in eine Datei erforderlich ist |
| 31          | Generic Read                       | Alles, was zum Lesen einer Datei erforderlich ist |

## References

- [1] [So verwendet das System ACLs - NTFS.com](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [2] [ACL, DACL, SACL und die ACE - secureidentity.se](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
{{#include ../../banners/hacktricks-training.md}}
