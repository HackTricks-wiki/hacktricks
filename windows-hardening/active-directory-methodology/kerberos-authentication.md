# Autenticación Kerberos

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Consigue el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

**Esta información fue extraída del post:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## Kerberos (I): ¿Cómo funciona Kerberos? - Teoría

20 - MAR - 2019 - ELOY PÉREZ

El objetivo de esta serie de posts es aclarar cómo funciona Kerberos, más que simplemente presentar los ataques. Esto se debe a que en muchas ocasiones no está claro por qué algunas técnicas funcionan o no. Tener este conocimiento permite saber cuándo utilizar cualquiera de esos ataques en una prueba de penetración.

Por lo tanto, después de un largo viaje de inmersión en la documentación y varios posts sobre el tema, hemos intentado escribir en este post todos los detalles importantes que un auditor debería conocer para entender cómo aprovechar el protocolo Kerberos.

En este primer post solo se discutirá la funcionalidad básica. En los próximos posts se verá cómo realizar los ataques y cómo funcionan los aspectos más complejos, como la delegación.

Si tienes alguna duda sobre el tema que no esté bien explicado, no dudes en dejar un comentario o pregunta al respecto. Ahora, sobre el tema.

### ¿Qué es Kerberos?

En primer lugar, Kerberos es un protocolo de autenticación, no de autorización. En otras palabras, permite identificar a cada usuario, que proporciona una contraseña secreta, sin embargo, no valida a qué recursos o servicios puede acceder este usuario.

Kerberos se utiliza en Active Directory. En esta plataforma, Kerberos proporciona información sobre los privilegios de cada usuario, pero es responsabilidad de cada servicio determinar si el usuario tiene acceso a sus recursos.

### Elementos de Kerberos

En esta sección se estudiarán varios componentes del entorno de Kerberos.

**Capa de transporte**

Kerberos utiliza UDP o TCP como protocolo de transporte, que envía datos en texto claro. Debido a esto, Kerberos es responsable de proporcionar cifrado.

Los puertos utilizados por Kerberos son UDP/88 y TCP/88, que deben escucharse en KDC (explicado en la siguiente sección).

**Agentes**

Varios agentes trabajan juntos para proporcionar autenticación en Kerberos. Estos son los siguientes:

* **Cliente o usuario** que desea acceder al servicio.
* **AP** (Servidor de Aplicaciones) que ofrece el servicio requerido por el usuario.
* **KDC** (Centro de Distribución de Claves), el servicio principal de Kerberos, responsable de emitir los tickets, instalado en el DC (Controlador de Dominio). Es compatible con el **AS** (Servicio de Autenticación), que emite los TGT.

**Claves de cifrado**

Hay varias estructuras manejadas por Kerberos, como tickets. Muchas de esas estructuras están cifradas o firmadas para evitar que terceros las manipulen. Estas claves son las siguientes:

* **Clave KDC o krbtgt** que se deriva del hash NTLM de la cuenta krbtgt.
* **Clave de usuario** que se deriva del hash NTLM del usuario.
* **Clave de servicio** que se deriva del hash NTLM del propietario del servicio, que puede ser una cuenta de usuario o de equipo.
* **Clave de sesión** que se negocia entre el usuario y el KDC.
* **Clave de sesión de servicio** para ser utilizada entre el usuario y el servicio.

**Tickets**

Las principales estructuras manejadas por Kerberos son los tickets. Estos tickets se entregan a los usuarios para que los utilicen para realizar varias acciones en el reino de Kerberos. Hay 2 tipos:

* El **TGS** (Servicio de Concesión de Tickets) es el ticket que el usuario puede usar para autenticarse contra un servicio. Está cifrado con la clave del servicio.
* El **TGT** (Ticket de Concesión de Tickets) es el ticket presentado al KDC para solicitar TGS. Está cifrado con la clave KDC.

**PAC**

El **PAC** (Certificado de Atributos de Privilegio) es una estructura incluida en casi todos los tickets. Esta estructura contiene los privilegios del usuario y está firmada con la clave KDC.

Es posible que los servicios verifiquen el PAC comunicándose con el KDC, aunque esto no sucede con frecuencia. Sin embargo, la verificación del PAC consiste en verificar solo su firma, sin inspeccionar si los privilegios dentro del PAC son correctos.

Además, un cliente puede evitar la inclusión del PAC dentro del ticket especificándolo en el campo _KERB-PA-PAC-REQUEST_ de la solicitud de ticket.

**Mensajes**

Kerberos utiliza diferentes tipos de mensajes. Los más interesantes son los siguientes:

* **KRB\_AS\_REQ**: Se utiliza para solicitar el TGT al KDC.
* **KRB\_AS\_REP**: Se utiliza para entregar el TGT por el KDC.
* **KRB\_TGS\_REQ**: Se utiliza para solicitar el TGS al KDC, utilizando el TGT.
* **KRB\_TGS\_REP**: Se utiliza para entregar el TGS por el KDC.
* **KRB\_AP\_REQ**: Se utiliza para autenticar a un usuario contra un servicio, utilizando el TGS.
* **KRB\_AP\_REP**: (Opcional) Utilizado por el servicio para identificarse ante el usuario.
* **KRB\_ERROR**: Mensaje para comunicar condiciones de error.

Además, aunque no forma parte de Kerberos, pero de NRPC, el AP opcionalmente podría utilizar el mensaje **KERB\_VERIFY\_PAC\_REQUEST** para enviar al KDC la firma de PAC y verificar si es correcta.

A continuación se muestra un resumen de la secuencia de mensajes para realizar la autenticación.

![Resumen de mensajes de Kerberos](<../../.gitbook/assets/image (174) (1).png>)

### Proceso de autenticación

En esta sección, se estudiará la secuencia de mensajes para realizar la autenticación, comenzando desde un usuario sin tickets, hasta ser autenticado contra el servicio deseado.

**KRB\_AS\_REQ**

En primer lugar, el usuario debe obtener un TGT de KDC. Para lograr esto, se debe enviar un KRB\_AS\_REQ:

![Esquema de mensaje KRB\_AS\_REQ](<../../.gitbook/assets/image (175) (1).png>)

_KRB\_AS\_REQ_ tiene, entre otros, los siguientes campos:

* Una **marca de tiempo** cifrada con la clave del cliente, para autenticar al usuario y evitar ataques de repetición.
* **Nombre de usuario** del usuario autenticado.
* El **SPN** del servicio asociado con la cuenta **krbtgt**.
* Un **Nonce** generado por el usuario

Nota: El timestamp encriptado solo es necesario si el usuario requiere preautenticación, lo cual es común, excepto si se establece la bandera [_DONT\_REQ\_PREAUTH_](https://support.microsoft.com/en-us/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro) en la cuenta de usuario.

**KRB\_AS\_REP**

Después de recibir la solicitud, el KDC verifica la identidad del usuario descifrando el timestamp. Si el mensaje es correcto, entonces debe responder con un _KRB\_AS\_REP_:

![Esquema del mensaje KRB\_AS\_REP](<../../.gitbook/assets/image (176) (1).png>)

_KRB\_AS\_REP_ incluye la siguiente información:

* **Nombre de usuario**
* **TGT**, que incluye:
  * **Nombre de usuario**
  * **Clave de sesión**
  * **Fecha de vencimiento** de TGT
  * **PAC** con los privilegios del usuario, firmado por KDC
* Algunos **datos encriptados** con la clave del usuario, que incluyen:
  * **Clave de sesión**
  * **Fecha de vencimiento** de TGT
  * **Nonce** del usuario, para evitar ataques de repetición

Una vez finalizado, el usuario ya tiene el TGT, que se puede utilizar para solicitar TGS y, posteriormente, acceder a los servicios.

**KRB\_TGS\_REQ**

Para solicitar un TGS, se debe enviar un mensaje _KRB\_TGS\_REQ_ al KDC:

![Esquema del mensaje KRB\_TGS\_REQ](<../../.gitbook/assets/image (177).png>)

_KRB\_TGS\_REQ_ incluye:

* **Datos encriptados** con la clave de sesión:
  * **Nombre de usuario**
  * **Timestamp**
* **TGT**
* **SPN** del servicio solicitado
* **Nonce** generado por el usuario

**KRB\_TGS\_REP**

Después de recibir el mensaje _KRB\_TGS\_REQ_, el KDC devuelve un TGS dentro de _KRB\_TGS\_REP_:

![Esquema del mensaje KRB\_TGS\_REP](<../../.gitbook/assets/image (178) (1).png>)

_KRB\_TGS\_REP_ incluye:

* **Nombre de usuario**
* **TGS**, que contiene:
  * **Clave de sesión del servicio**
  * **Nombre de usuario**
  * **Fecha de vencimiento** de TGS
  * **PAC** con los privilegios del usuario, firmado por KDC
* **Datos encriptados** con la clave de sesión:
  * **Clave de sesión del servicio**
  * **Fecha de vencimiento** de TGS
  * **Nonce** del usuario, para evitar ataques de repetición

**KRB\_AP\_REQ**

Para finalizar, si todo ha ido bien, el usuario ya tiene un TGS válido para interactuar con el servicio. Para usarlo, el usuario debe enviar al AP un mensaje _KRB\_AP\_REQ_:

![Esquema del mensaje KRB\_AP\_REQ](<../../.gitbook/assets/image (179) (1).png>)

_KRB\_AP\_REQ_ incluye:

* **TGS**
* **Datos encriptados** con la clave de sesión del servicio:
  * **Nombre de usuario**
  * **Timestamp**, para evitar ataques de repetición

Después de eso, si los privilegios del usuario son correctos, este puede acceder al servicio. Si es el caso, lo cual no suele suceder, el AP verificará el PAC contra el KDC. Y también, si se necesita autenticación mutua, responderá al usuario con un mensaje _KRB\_AP\_REP_.

### Referencias

* Kerberos v5 RFC: [https://tools.ietf.org/html/rfc4120](https://tools.ietf.org/html/rfc4120)
* \[MS-KILE\] – Extensión de Kerberos: [https://msdn.microsoft.com/en-us/library/cc233855.aspx](https://msdn.microsoft.com/en-us/library/cc233855.aspx)
* \[MS-APDS\] – Soporte de protocolo de autenticación de dominio: [https://msdn.microsoft.com/en-us/library/cc223948.aspx](https://msdn.microsoft.com/en-us/library/cc223948.aspx)
* Ataques de Kerberos Mimikatz y Active Directory: [https://adsecurity.org/?p=556](https://adsecurity.org/?p=556)
* Explicado como si tuviera 5 años: Kerberos: [https://www.roguelynn.com/words/explain-like-im-5-kerberos/](https://www.roguelynn.com/words/explain-like-im-5-kerberos/)
* Kerberos y KRBTGT: [https://adsecurity.org/?p=483](https://adsecurity.org/?p=483)
* Mastering Windows Network Forensics and Investigation, 2nd Edition. Autores: S. Anson, S. Bunting, R. Johnson y S. Pearson. Editorial Sibex.
* Active Directory, 5ª edición. Autores: B. Desmond, J. Richards, R. Allen y A.G. Lowe-Norris
* Nombres principales de servicio: [https://msdn.microsoft.com/en-us/library/ms677949(v=vs.85).aspx](https://msdn.microsoft.com/en-us/library/ms677949\(v=vs.85\).aspx)
* Niveles funcionales de Active Directory: [https://technet.microsoft.com/en-us/library/dbf0cdec-d72f-4ba3-bc7a-46410e02abb0](https://technet.microsoft.com/en-us/library/dbf0cdec-d72f-4ba3-bc7a-46410e02abb0)
* OverPass The Hash – Blog de Gentilkiwi: [https://blog.gentilkiwi.com/securite/mimikatz/overpass-the-hash](https://blog.gentilkiwi.com/securite/mimikatz/overpass-the-hash)
* Pass The Ticket – Blog de Gentilkiwi: [https://blog.gentilkiwi.com/securite/mimikatz/pass-the-ticket-kerberos](https://blog.gentilkiwi.com/securite/mimikatz/pass-the-ticket-kerberos)
* Golden Ticket – Blog de Gent
