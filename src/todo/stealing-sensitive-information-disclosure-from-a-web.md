# Kradzież ujawnionych poufnych informacji z aplikacji Web

{{#include ../banners/hacktricks-training.md}}

Jeśli w pewnym momencie znajdziesz **stronę Web, która wyświetla poufne informacje na podstawie Twojej sesji**: może odzwierciedlać cookies, wyświetlać dane kart kredytowych lub inne poufne informacje, możesz spróbować je ukraść.\
Poniżej przedstawiam główne sposoby, które możesz wypróbować, aby to osiągnąć:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): Jeśli uda Ci się ominąć nagłówki CORS, będziesz w stanie ukraść informacje, wykonując żądanie Ajax z użyciem złośliwej strony.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): Jeśli znajdziesz podatność XSS na stronie, możesz być w stanie ją wykorzystać do kradzieży informacji.
- [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): Jeśli nie możesz wstrzyknąć tagów XSS, nadal możesz być w stanie ukraść informacje, używając innych standardowych tagów HTML.
- [**Clickjaking**](../pentesting-web/clickjacking.md): Jeśli nie ma ochrony przed tym atakiem, możesz być w stanie nakłonić użytkownika do wysłania Ci poufnych danych (przykład znajduje się [tutaj](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).<sup>[[1]](#references)</sup>

## Referencje

- [1] [Apache example servlet leads to Information Disclosure](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)

{{#include ../banners/hacktricks-training.md}}
