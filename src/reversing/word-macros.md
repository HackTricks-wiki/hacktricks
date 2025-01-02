# Word-Makros

{{#include ../banners/hacktricks-training.md}}

### Junk-Code

Es ist sehr häufig, **Junk-Code, der nie verwendet wird**, zu finden, um das Reverse Engineering des Makros zu erschweren.\
Zum Beispiel sieht man im folgenden Bild, dass eine If-Bedingung, die niemals wahr sein wird, verwendet wird, um etwas Junk- und nutzlosen Code auszuführen.

![](<../images/image (369).png>)

### Makroformulare

Mit der **GetObject**-Funktion ist es möglich, Daten aus Formularen des Makros zu erhalten. Dies kann verwendet werden, um die Analyse zu erschweren. Das folgende Bild zeigt ein Makroformular, das verwendet wird, um **Daten in Textfeldern zu verbergen** (ein Textfeld kann andere Textfelder verbergen):

![](<../images/image (344).png>)

{{#include ../banners/hacktricks-training.md}}
