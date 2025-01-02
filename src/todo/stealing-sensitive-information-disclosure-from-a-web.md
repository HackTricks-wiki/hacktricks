# Kradzież ujawnienia wrażliwych informacji z sieci

{{#include ../banners/hacktricks-training.md}}

Jeśli w pewnym momencie znajdziesz **stronę internetową, która prezentuje ci wrażliwe informacje na podstawie twojej sesji**: Może odzwierciedla ciasteczka, lub drukuje dane karty kredytowej lub inne wrażliwe informacje, możesz spróbować je ukraść.\
Oto główne sposoby, które możesz spróbować osiągnąć:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): Jeśli możesz obejść nagłówki CORS, będziesz w stanie ukraść informacje, wykonując żądanie Ajax do złośliwej strony.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/): Jeśli znajdziesz lukę XSS na stronie, możesz być w stanie ją wykorzystać do kradzieży informacji.
- [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/): Jeśli nie możesz wstrzyknąć tagów XSS, nadal możesz być w stanie ukraść informacje, używając innych standardowych tagów HTML.
- [**Clickjaking**](../pentesting-web/clickjacking.md): Jeśli nie ma ochrony przed tym atakiem, możesz być w stanie oszukać użytkownika, aby wysłał ci wrażliwe dane (przykład [tutaj](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

{{#include ../banners/hacktricks-training.md}}
