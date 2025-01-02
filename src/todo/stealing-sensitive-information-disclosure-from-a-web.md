# Robo de Información Sensible desde una Web

{{#include ../banners/hacktricks-training.md}}

Si en algún momento encuentras una **página web que te presenta información sensible basada en tu sesión**: Tal vez esté reflejando cookies, o imprimiendo detalles de tarjetas de crédito u otra información sensible, puedes intentar robarla.\
Aquí te presento las principales formas en que puedes intentar lograrlo:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): Si puedes eludir los encabezados CORS, podrás robar la información realizando una solicitud Ajax a una página maliciosa.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/): Si encuentras una vulnerabilidad XSS en la página, es posible que puedas abusar de ella para robar la información.
- [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/): Si no puedes inyectar etiquetas XSS, aún puedes robar la información utilizando otras etiquetas HTML regulares.
- [**Clickjaking**](../pentesting-web/clickjacking.md): Si no hay protección contra este ataque, es posible que puedas engañar al usuario para que te envíe los datos sensibles (un ejemplo [aquí](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

{{#include ../banners/hacktricks-training.md}}
