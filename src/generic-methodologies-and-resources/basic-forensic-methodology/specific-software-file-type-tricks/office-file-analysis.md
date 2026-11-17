# Office-Dateianalyse

{{#include ../../../banners/hacktricks-training.md}}

Weitere Informationen finden Sie unter [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Dies ist nur eine Zusammenfassung:<sup>[[2]](#references)</sup>

Microsoft-Office-Dokumente liegen häufig in älteren Formaten wie RTF und OLE/CFBF-basierten DOC-, XLS- und PPT-Dateien oder in neueren **Office Open XML (OOXML)**-Formaten wie DOCX, XLSX und PPTX vor. Office-Dokumente können aktive Inhalte wie Makros enthalten und sind daher häufige Träger für Phishing und Malware. OOXML-Dateien sind ZIP-Container, deren Dateihierarchie und XML-Inhalte durch Entpacken untersucht werden können.<sup>[[1]](#references)[[2]](#references)</sup>

Zum Untersuchen der Struktur von OOXML-Dateien werden der Befehl zum Entpacken eines Dokuments und die resultierende Verzeichnisstruktur angegeben. Techniken zum Verbergen von Daten in diesen Dateien sind dokumentiert und zeigen die fortlaufende Weiterentwicklung der Datenverschleierung bei CTF-Challenges.<sup>[[2]](#references)</sup>

Für die Analyse bieten **oletools** und **OfficeDissector** umfassende Toolsets zur Untersuchung von OLE- und OOXML-Dokumenten. Diese Tools helfen dabei, eingebettete Makros zu erkennen und zu analysieren, die häufig als Vektoren zur Verbreitung von Malware dienen, indem sie zusätzliche schädliche Payloads herunterladen und ausführen. VBA-Makros lassen sich ohne Microsoft Office analysieren, indem LibreOffice verwendet wird. Damit können sie mithilfe von Breakpoints und Watch-Variablen debuggt werden.<sup>[[2]](#references)</sup>

**oletools** lässt sich einfach installieren und verwenden; die entsprechenden Befehle zur Installation über pip und zum Extrahieren von Makros aus Dokumenten sind angegeben. In Word gehören `AutoExec` und `AutoOpen` zu den automatischen Makros, während `Document_Open` eine Prozedur für das Öffnungsereignis ist.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

## VBA-Makroanalyse: Junk-Code und UserForms

## Junk-Code

Makros können **nicht erreichbaren oder irrelevanten Code** enthalten, der die Analyse verlangsamen soll. Identifizieren Sie konstante Bedingungen und verfolgen Sie das erreichbare Verhalten, bevor Sie Zeit in die Analyse eines Zweigs investieren. Das folgende Beispiel verwendet eine `If`-Bedingung, die niemals wahr sein kann, um Junk-Code zu verbergen.

![Ein Word-Makro mit einem nicht erreichbaren bedingten Zweig und Junk-Code](<../../../images/image (369).png>)

## Makroformulare

VBA-UserForms können Daten in Steuerelementen wie Textfeldern speichern. Da Formulare, Frames und Pages jeweils eine `Controls`-Sammlung bereitstellen können, sollten Analysten die gesamte Steuerelementhierarchie durchgehen und sich nicht nur darauf verlassen, was das Formular anzeigt. Das folgende Beispiel speichert verborgene Daten in überlappenden Textfeldern.<sup>[[6]](#references)</sup>

Bei der dynamischen Analyse kann die VBA-Funktion `GetObject` ein Automation-Objekt aus einer Datei abrufen oder eine Verbindung zu einem bereits laufenden Automation-Server herstellen. Makros können über diesen Objektzugriff auf Daten zugreifen, die im sichtbaren Dokument nicht offensichtlich sind. Untersuchen Sie sowohl das zurückgegebene Objekt als auch den Steuerelementbaum der UserForm.<sup>[[7]](#references)</sup>

![Eine Makro-UserForm mit verborgenen Daten in überlappenden Textfeldern](<../../../images/image (344).png>)

Informationen zu passwortverschlüsselten Office-Dokumenten finden Sie im [grammatikgesteuerten Offline-Recovery-Workflow](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

Informationen zu Revit-RFA-Dateien mit OLE/CFBF finden Sie unter [ECC-Neuberechnung, kontrolliertes gzip und Ausnutzung des Deserializers](../../../binary-exploitation/revit-rfa-ole-compound-file-exploitation.md); dieser Parser-Exploitation-Workflow ist von der Triage von Office-Dokumenten getrennt.

## References

- [1] [OLE Compound File (CFBF)-Dokumentation](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [2] [Forensics-CTF-Leitfaden](https://trailofbits.github.io/ctf/forensics/)
- [3] [olevba-Dokumentation (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [4] [Auto-Makros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [5] [Document.Open-Ereignis (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
- [6] [Microsoft Learn – Sammlungen, Steuerelemente und Objekte (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [7] [Microsoft Learn – Funktion `GetObject`](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../../../banners/hacktricks-training.md}}
