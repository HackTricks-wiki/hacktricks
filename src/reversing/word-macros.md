# Word Macros

{{#include ../banners/hacktricks-training.md}}

## Junk Code

Macros können **nicht erreichbaren oder irrelevanten Code** enthalten, der die Analyse verlangsamen soll. Identifizieren Sie konstante Bedingungen und verfolgen Sie das erreichbare Verhalten, bevor Sie Zeit in das Reversing eines Zweigs investieren. Das folgende Beispiel verwendet eine `If`-Bedingung, die niemals wahr sein kann, um Junk Code zu verbergen.

![Ein Word-Macro mit einem nicht erreichbaren bedingten Zweig mit Junk Code](<../images/image (369).png>)

## Macro Forms

VBA UserForms können Daten in Controls wie Textfeldern speichern. Da Forms, Frames und Pages jeweils eine `Controls`-Collection bereitstellen können, sollten Analysten die gesamte Control-Hierarchie aufzählen, anstatt sich nur darauf zu verlassen, was das Form anzeigt. Das folgende Beispiel speichert verborgene Daten in überlappenden Textfeldern.<sup>[[1]](#references)</sup>

Während der dynamischen Analyse kann die VBA-Funktion `GetObject` ein Automation-Objekt aus einer Datei abrufen oder eine Verbindung zu einem bereits laufenden Automation-Server herstellen. Macros können diesen Objektzugriff verwenden, um Daten zu erreichen, die im sichtbaren Dokument nicht offensichtlich sind; untersuchen Sie sowohl das zurückgegebene Objekt als auch den UserForm-Control-Baum.<sup>[[2]](#references)</sup>

![Ein Macro-UserForm mit in überlappenden Textfeldern verborgenen Daten](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - Collections, Controls und Objekte (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [2] [Microsoft Learn - `GetObject`-Funktion](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../banners/hacktricks-training.md}}
