# Kradzież poufnych informacji ze strony internetowej

{{#include ../banners/hacktricks-training.md}}

Jeśli **strona internetowa wyświetla poufne informacje na podstawie bieżącej sesji** — takie jak cookies, dane konta lub dane karty kredytowej — napastnik może próbować je eksfiltrować. Główne techniki obejmują:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): Błędna konfiguracja CORS może pozwolić złośliwemu originowi na odczytywanie poufnych odpowiedzi za pośrednictwem żądań cross-origin.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): Luka XSS w docelowym originie może pozwolić wstrzykniętemu JavaScriptowi na odczytanie i eksfiltrację informacji.
- [**Dangling markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): Gdy wstrzyknięcie skryptu jest niedostępne, wstrzyknięte elementy HTML nadal mogą przechwytywać poufne treści.
- [**Clickjacking**](../pentesting-web/clickjacking.md): Jeśli nie ma zabezpieczeń przed osadzaniem w ramkach, napastnik może nakłonić użytkownika do wejścia w interakcję z poufną stroną. Powiązane case study przedstawia tę technikę.<sup>[[1]](#references)</sup>

## References

- [1] [Przykładowy servlet Apache prowadzi do ujawnienia informacji](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)
{{#include ../banners/hacktricks-training.md}}
