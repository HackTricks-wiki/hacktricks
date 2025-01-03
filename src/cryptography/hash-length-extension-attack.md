{{#include ../banners/hacktricks-training.md}}

# Zusammenfassung des Angriffs

Stellen Sie sich einen Server vor, der **Daten** **signiert**, indem er ein **Geheimnis** an einige bekannte Klartextdaten **anhängt** und dann diese Daten hasht. Wenn Sie wissen:

- **Die Länge des Geheimnisses** (dies kann auch aus einem gegebenen Längenbereich bruteforced werden)
- **Die Klartextdaten**
- **Der Algorithmus (und er ist anfällig für diesen Angriff)**
- **Das Padding ist bekannt**
- Normalerweise wird ein Standard verwendet, also wenn die anderen 3 Anforderungen erfüllt sind, ist dies auch der Fall
- Das Padding variiert je nach Länge des Geheimnisses + Daten, deshalb ist die Länge des Geheimnisses erforderlich

Dann ist es möglich für einen **Angreifer**, **Daten** **anzuhängen** und eine gültige **Signatur** für die **vorherigen Daten + angehängte Daten** zu **generieren**.

## Wie?

Grundsätzlich generieren die anfälligen Algorithmen die Hashes, indem sie zuerst einen Block von Daten **hashen** und dann, **aus** dem **zuvor** erstellten **Hash** (Zustand), den **nächsten Block von Daten** **hinzufügen** und **hashen**.

Stellen Sie sich vor, das Geheimnis ist "secret" und die Daten sind "data", der MD5 von "secretdata" ist 6036708eba0d11f6ef52ad44e8b74d5b.\
Wenn ein Angreifer die Zeichenfolge "append" anhängen möchte, kann er:

- Einen MD5 von 64 "A"s generieren
- Den Zustand des zuvor initialisierten Hash auf 6036708eba0d11f6ef52ad44e8b74d5b ändern
- Die Zeichenfolge "append" anhängen
- Den Hash beenden und der resultierende Hash wird ein **gültiger für "secret" + "data" + "padding" + "append"** sein

## **Tool**

{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}

## Referenzen

Sie können diesen Angriff gut erklärt finden in [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

{{#include ../banners/hacktricks-training.md}}
