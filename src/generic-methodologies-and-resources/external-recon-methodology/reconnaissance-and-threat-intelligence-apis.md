# APIs de reconocimiento e inteligencia de amenazas

{{#include ../../banners/hacktricks-training.md}}

Estos servicios admiten flujos de trabajo de reconocimiento, reputación, filtraciones o enriquecimiento. Sus API, cuotas, precios y usos permitidos cambian con frecuencia; confirma la documentación actual del proveedor y la autorización del engagement antes de enviar identificadores de clientes o datos sensibles. Para la secuencia de descubrimiento de activos, consulta la [Metodología de reconocimiento externo](README.md).

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Consulta si una dirección IP se ha asociado con actividad sospechosa o maliciosa. El acceso puede requerir una cuenta o una clave de API.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Comprueba si una dirección IP, un nombre de usuario o una dirección de correo electrónico se ha asociado con registros automatizados de cuentas u otra actividad de bots denunciada.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Encuentra y verifica direcciones de correo electrónico profesionales y patrones de contacto relacionados con dominios. Consulta el plan actual para conocer los límites de solicitudes y los usos permitidos.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Busca indicadores de inteligencia de amenazas y actividad asociados con direcciones IP y dominios.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Enriquece una dirección de correo electrónico, un dominio o una empresa con los datos empresariales y de perfil disponibles. La cobertura, el acceso y las restricciones de privacidad dependen del producto y el plan actuales.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Identifica tecnologías detectadas en sitios web y obtiene datos históricos o de relaciones cuando el plan seleccionado lo permite.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Comprueba si una dirección IP está asociada con actividad sospechosa o maliciosa. Confirma los planes y límites actuales de la API.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Consulta la categorización y la inteligencia de amenazas de FortiGuard para dominios, URL o direcciones IP. La disponibilidad varía según el servicio.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Comprueba si una dirección IP aparece en listas por actividad de spam denunciada.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Obtiene la reputación de un dominio según la comunidad del servicio y otras señales.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Obtiene geolocalización, ASN, organización y metadatos relacionados de una dirección IP. Consulta el plan actual para conocer las cuotas.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Esta plataforma proporciona inteligencia de DNS e infraestructura, como resoluciones históricas, dominios asociados con IP o servidores de nombres y registros relacionados. El DNS histórico puede revelar una dirección de origen anterior, pero no elude de forma fiable una CDN y debe validarse.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Enriquece una dirección de correo electrónico, un dominio o el nombre de una empresa con los atributos de identidad y empresariales disponibles. Gestiona los datos personales de acuerdo con los requisitos de autorización y privacidad.

## RiskIQ / Microsoft Defender Threat Intelligence (transición heredada) <sup>[[14]](#references)</sup>

Las capacidades PassiveTotal de RiskIQ se integraron en Microsoft Defender Threat Intelligence. El acceso al producto, las API y las funcionalidades disponibles han cambiado; por ello, consulta la documentación actual de Microsoft en lugar de basarte en las suposiciones sobre PassiveTotal heredado.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Busca dominios, direcciones IP, direcciones de correo electrónico y datos históricos o filtrados indexados, sujeto a los controles de acceso del servicio.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Busca direcciones IP y otros indicadores para obtener datos de inteligencia de amenazas y reputación.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Busca direcciones IP o rangos para consultar observaciones de escaneo de Internet y actividad habitual de servicios. Consulta las condiciones actuales de las pruebas y del acceso comunitario.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Obtiene información de escaneos de Internet y servicios para una dirección IP, un host o una consulta de búsqueda. El acceso a la API depende del plan de la cuenta.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Busca en conjuntos de datos de hosts, certificados, dominios y servicios de Internet; su modelo de datos y cobertura difieren de los de Shodan.

## [Búsqueda de buckets de GrayHatWarfare](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Busca por palabra clave en el índice del proveedor de objetos y buckets de almacenamiento en la nube observados públicamente.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Busca en datos de filtraciones indexados direcciones de correo electrónico, nombres de usuario, dominios y registros relacionados. Utilízalo solo con autorización y evita la exposición innecesaria de datos filtrados.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Busca en contenido de paste indexado coincidencias de una dirección de correo electrónico u otro término. Verifica que el servicio siga disponible antes de integrarlo.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Obtiene señales de reputación y riesgo de una dirección de correo electrónico.

## GhostProject (histórico) <sup>[[24]](#references)</sup>

Históricamente ofrecía búsquedas de datos filtrados de correo electrónico y contraseñas. Trata el servicio como una opción de alto riesgo para el manejo de datos por parte de terceros y verifica su disponibilidad, legalidad y autorización antes de usarlo.

## BinaryEdge (descontinuado) <sup>[[25]](#references)</sup>

Ofrecía datos de escaneo de Internet, exposición e inteligencia de amenazas para direcciones IP y activos relacionados. Su sitio ahora redirige a un aviso de transición de Coalition y la API rechaza las solicitudes, por lo que debe considerarse no disponible.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Comprueba si una dirección de correo electrónico o un dominio verificado aparece en filtraciones conocidas. El servicio independiente Pwned Passwords comprueba hashes de contraseñas mediante un prefijo; **no** revela contraseñas en texto plano.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Obtiene geolocalización de IP, centro de datos, ASN, proxy/VPN y campos de enriquecimiento relacionados. Las cuotas dependen del plan actual.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
Geolocalización de IP y enriquecimiento orientado a OSINT con puntos de datos seleccionados. Consulta las condiciones actuales para el uso comercial.

### [NetAPI](https://netapi.com/) <sup>[[32]](#references)</sup>
Busca un dominio (registrador, fechas de registro y vencimiento, servidores de nombres, IP y país del alojamiento) o una dirección IP (los otros dominios alojados en ella), y comprueba si un dominio o una IP aparecen en sus listas gratuitas de sistemas comprometidos: dominios de phishing y malware dirigidos a sinkhole, y direcciones que atacaron sus sensores honeypot en las últimas 48 horas. Las consultas web y la API de comprobación de sistemas comprometidos no requieren cuenta; el acceso a la API para las consultas requiere un plan de pago.


[DNSDumpster](https://dnsdumpster.com/) proporciona resultados de reconocimiento de DNS.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) proporciona inteligencia sobre sitios, alojamiento e infraestructura de Internet.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) proporciona una interfaz en línea para descubrir subdominios.<sup>[[31]](#references)</sup>

## References

- [1] [Project Honey Pot](https://www.projecthoneypot.org/)
- [2] [API de BotScout](https://botscout.com/api.htm)
- [3] [API de Hunter](https://hunter.io/api-documentation)
- [4] [API de AlienVault OTX](https://otx.alienvault.com/api)
- [5] [Clearbit](https://dashboard.clearbit.com/)
- [6] [BuiltWith](https://builtwith.com/)
- [7] [FraudGuard](https://fraudguard.io/)
- [8] [FortiGuard Labs](https://www.fortiguard.com/)
- [9] [SpamCop](https://www.spamcop.net/)
- [10] [Web of Trust](https://www.mywot.com/)
- [11] [IPinfo](https://ipinfo.io/)
- [12] [SecurityTrails](https://securitytrails.com/)
- [13] [FullContact](https://www.fullcontact.com/)
- [14] [Microsoft Defender Threat Intelligence](https://learn.microsoft.com/en-us/defender/threat-intelligence/what-is-microsoft-defender-threat-intelligence-defender-ti)
- [15] [Intelligence X](https://intelx.io/)
- [16] [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/)
- [17] [GreyNoise](https://www.greynoise.io/)
- [18] [Shodan](https://www.shodan.io/)
- [19] [Censys](https://censys.com/)
- [20] [GrayHatWarfare](https://buckets.grayhatwarfare.com/)
- [21] [DeHashed](https://www.dehashed.com/)
- [22] [psbdmp](https://psbdmp.ws/)
- [23] [EmailRep](https://emailrep.io/)
- [24] [Investigación de Cornell — Protocolos para comprobar credenciales comprometidas (incluye GhostProject)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [API de Have I Been Pwned](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [Buscador de subdominios de NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/)
- [32] [Documentación de la API de NetAPI](https://netapi.com/help/api/)
{{#include ../../banners/hacktricks-training.md}}
