# Robando la divulgación de información sensible desde una Web

{{#include ../banners/hacktricks-training.md}}

Si en algún momento encuentras una **página web que muestra información sensible basándose en tu sesión**: quizá refleja cookies, muestra datos de tarjetas de crédito o cualquier otro tipo de información sensible, puedes intentar robarla.\
Aquí presento las principales formas en las que puedes intentar conseguirlo:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): Si puedes evadir los headers de CORS, podrás robar la información realizando una petición Ajax desde una página maliciosa.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): Si encuentras una vulnerabilidad XSS en la página, es posible que puedas aprovecharla para robar la información.
- [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): Si no puedes inyectar tags XSS, quizá aún puedas robar la información utilizando otros tags HTML normales.
- [**Clickjaking**](../pentesting-web/clickjacking.md): Si no existe protección contra este ataque, es posible que puedas engañar al usuario para que te envíe los datos sensibles (un ejemplo [aquí](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).<sup>[[1]](#references)</sup>

## Referencias

- [1] [Apache example servlet leads to Information Disclosure](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)

{{#include ../banners/hacktricks-training.md}}
