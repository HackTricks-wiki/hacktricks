{{#include ../../banners/hacktricks-training.md}}

**Der ursprüngliche Beitrag ist** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Zusammenfassung

Zwei Registrierungsschlüssel wurden gefunden, die vom aktuellen Benutzer beschreibbar sind:

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

Es wurde empfohlen, die Berechtigungen des **RpcEptMapper**-Dienstes mit der **regedit GUI** zu überprüfen, insbesondere den Tab **Effektive Berechtigungen** im Fenster **Erweiterte Sicherheitseinstellungen**. Dieser Ansatz ermöglicht die Bewertung der gewährten Berechtigungen für bestimmte Benutzer oder Gruppen, ohne jeden Access Control Entry (ACE) einzeln untersuchen zu müssen.

Ein Screenshot zeigte die Berechtigungen, die einem Benutzer mit niedrigen Rechten zugewiesen waren, unter denen die Berechtigung **Subschlüssel erstellen** auffiel. Diese Berechtigung, auch als **AppendData/AddSubdirectory** bezeichnet, entspricht den Ergebnissen des Skripts.

Es wurde festgestellt, dass bestimmte Werte nicht direkt geändert werden konnten, jedoch die Möglichkeit bestand, neue Unterschlüssel zu erstellen. Ein Beispiel war der Versuch, den Wert **ImagePath** zu ändern, was zu einer Zugriffsverweigerung führte.

Trotz dieser Einschränkungen wurde ein Potenzial für eine Privilegieneskalation identifiziert, indem die Möglichkeit genutzt wurde, den **Performance**-Unterschlüssel innerhalb der Registrierungsstruktur des **RpcEptMapper**-Dienstes zu verwenden, ein Unterschlüssel, der standardmäßig nicht vorhanden ist. Dies könnte die Registrierung von DLLs und die Leistungsüberwachung ermöglichen.

Dokumentationen zum **Performance**-Unterschlüssel und seiner Nutzung zur Leistungsüberwachung wurden konsultiert, was zur Entwicklung einer Proof-of-Concept-DLL führte. Diese DLL, die die Implementierung der Funktionen **OpenPerfData**, **CollectPerfData** und **ClosePerfData** demonstrierte, wurde über **rundll32** getestet, was ihren operationellen Erfolg bestätigte.

Das Ziel war es, den **RPC Endpoint Mapper-Dienst** dazu zu bringen, die erstellte Performance-DLL zu laden. Beobachtungen zeigten, dass das Ausführen von WMI-Klassenabfragen im Zusammenhang mit Leistungsdaten über PowerShell zur Erstellung einer Protokolldatei führte, die die Ausführung beliebigen Codes im Kontext des **LOCAL SYSTEM** ermöglichte, wodurch erhöhte Berechtigungen gewährt wurden.

Die Persistenz und die potenziellen Auswirkungen dieser Schwachstelle wurden hervorgehoben, wobei ihre Relevanz für Post-Exploitation-Strategien, laterale Bewegung und die Umgehung von Antivirus-/EDR-Systemen betont wurde.

Obwohl die Schwachstelle zunächst unbeabsichtigt durch das Skript offengelegt wurde, wurde betont, dass ihre Ausnutzung auf veraltete Windows-Versionen (z. B. **Windows 7 / Server 2008 R2**) beschränkt ist und lokalen Zugriff erfordert.

{{#include ../../banners/hacktricks-training.md}}
