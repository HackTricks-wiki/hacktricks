# Makra Worda

{{#include ../banners/hacktricks-training.md}}

### Junk Code

Bardzo często można znaleźć **junk code, który nigdy nie jest używany**, aby utrudnić reversing makra.\
Na przykład na poniższym obrazie widać, że użyto instrukcji If, która nigdy nie będzie prawdziwa, aby wykonać pewien bezużyteczny junk code.

![Makra Worda - Junk Code: Na poniższym obrazie widać, że użyto instrukcji If, która nigdy nie będzie prawdziwa, aby wykonać pewien bezużyteczny junk code](<../images/image (369).png>)

### Formularze makr

Za pomocą funkcji **GetObject** można uzyskać dane z formularzy makra. Można to wykorzystać do utrudnienia analizy. Poniżej znajduje się zdjęcie formularza makra używanego do **ukrywania danych w polach tekstowych** (pole tekstowe może ukrywać inne pola tekstowe):

![Junk Code - Formularze makr: Za pomocą funkcji GetObject można uzyskać dane z formularzy makra. Można to wykorzystać do utrudnienia analizy. Poniżej znajduje się zdjęcie...](<../images/image (344).png>)

{{#include ../banners/hacktricks-training.md}}
