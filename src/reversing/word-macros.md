# Word-Makros

{{#include ../banners/hacktricks-training.md}}

### Junk Code

Es ist sehr üblich, **Junk Code zu finden, der nie verwendet wird**, um das Reversing des Makros zu erschweren.\
Im folgenden Bild können Sie beispielsweise sehen, dass ein `If`, das niemals wahr sein wird, verwendet wird, um etwas Junk Code und nutzlosen Code auszuführen.

![Word-Makros - Junk Code: Im folgenden Bild können Sie beispielsweise sehen, dass ein If, das niemals wahr sein wird, verwendet wird, um etwas Junk Code und nutzlosen Code auszuführen](<../images/image (369).png>)

### Makro-Formulare

Mit der Funktion **GetObject** ist es möglich, Daten aus Formularen des Makros abzurufen. Dies kann verwendet werden, um die Analyse zu erschweren. Das folgende Bild zeigt ein Makro-Formular, das verwendet wird, um **Daten in Textfeldern zu verbergen** (ein Textfeld kann weitere Textfelder verbergen):

![Junk Code - Makro-Formulare: Mit der Funktion GetObject ist es möglich, Daten aus Formularen des Makros abzurufen. Dies kann verwendet werden, um die Analyse zu erschweren. Das folgende Bild zeigt ein...](<../images/image (344).png>)

{{#include ../banners/hacktricks-training.md}}
