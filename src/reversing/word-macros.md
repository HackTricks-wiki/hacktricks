# Word Macros

{{#include ../banners/hacktricks-training.md}}

## Junk Code

Macros können **unerreichbaren oder irrelevanten Code** enthalten, der die Analyse verlangsamen soll. Identifizieren Sie konstante Bedingungen und verfolgen Sie das erreichbare Verhalten, bevor Sie Zeit in das Reverse Engineering eines Zweigs investieren. Das folgende Beispiel verwendet eine `If`-Bedingung, die niemals wahr sein kann, um Junk Code zu verbergen.

![Ein Word-Makro mit einem unerreichbaren bedingten Zweig mit Junk Code](<../images/image (369).png>)

## Macro Forms

VBA UserForms können Daten in Controls wie Textfeldern speichern. Da Formulare, Frames und Seiten jeweils eine `Controls`-Sammlung bereitstellen können, sollten Analysten die gesamte Control-Hierarchie enumerieren, anstatt sich nur auf das zu verlassen, was das Formular anzeigt. Das folgende Beispiel speichert verborgene Daten in überlappenden Textfeldern.<sup>[[1]](#references)</sup>

![Eine Makro-UserForm mit in überlappenden Textfeldern verborgenen Daten](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - Sammlungen, Steuerelemente und Objekte (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
{{#include ../banners/hacktricks-training.md}}
