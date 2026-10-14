# APIs de reconocimiento e inteligencia de amenazas

{{#include ../../banners/hacktricks-training.md}}

Estos servicios respaldan flujos de trabajo de reconocimiento, reputación, filtraciones o enriquecimiento de datos. Sus APIs, cuotas, precios y usos permitidos cambian con frecuencia; confirma la documentación actual del proveedor y la autorización del engagement antes de enviar identificadores de clientes o datos confidenciales. Para la secuencia de descubrimiento de activos, consulta la [External Recon Methodology](README.md).

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Consulta si una dirección IP se ha asociado con actividad sospechosa o maliciosa. El acceso puede requerir una cuenta o una API key.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Comprueba si una dirección IP, un nombre de usuario o una dirección de correo electrónico se ha asociado con registros automatizados de cuentas u otra actividad de bots denunciada.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Encuentra y verifica direcciones de correo electrónico profesionales y patrones de contacto asociados a dominios. Consulta el plan actual para conocer los límites de solicitudes y los usos permitidos.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Busca indicadores de inteligencia de amenazas y actividad asociados a direcciones IP y dominios.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Enriquece una dirección de correo electrónico, un dominio o una empresa con los datos empresariales o de perfil disponibles. La cobertura, el acceso y las restricciones de privacidad dependen del producto y el plan actuales.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Identifica tecnologías detectadas en sitios web y obtiene datos históricos o de relaciones cuando el plan seleccionado lo permite.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Comprueba si una dirección IP está asociada con actividad sospechosa o maliciosa. Confirma los planes y límites actuales de la API.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Consulta la categorización y la inteligencia de amenazas de FortiGuard para dominios, URLs o direcciones IP. La disponibilidad varía según el servicio.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Comprueba si una dirección IP está incluida en listas por actividad de spam denunciada.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Obtiene la reputación de un dominio según la comunidad del servicio y otras señales.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Obtiene geolocalización, ASN, organización y metadatos relacionados de una dirección IP. Consulta el plan actual para conocer las cuotas.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Esta plataforma proporciona inteligencia de DNS e infraestructura, como resoluciones históricas, dominios asociados a IPs o servidores de nombres y registros relacionados. El DNS histórico puede revelar una dirección de origen anterior, pero no permite eludir una CDN de forma fiable y debe validarse.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Enriquece una dirección de correo electrónico, un dominio o el nombre de una empresa con los atributos de identidad y empresariales disponibles. Trata los datos personales de acuerdo con los requisitos de autorización y privacidad.

## RiskIQ / Microsoft Defender Threat Intelligence (transición heredada) <sup>[[14]](#references)</sup>

Las funcionalidades de PassiveTotal de RiskIQ se integraron en Microsoft Defender Threat Intelligence. El acceso al producto, las APIs y las funcionalidades conservadas han cambiado, así que consulta la documentación actual de Microsoft en lugar de basarte en suposiciones sobre el PassiveTotal heredado.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Busca dominios, direcciones IP, direcciones de correo electrónico y datos históricos indexados o filtrados, sujeto a los controles de acceso del servicio.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Busca direcciones IP y otros indicadores para obtener datos de inteligencia de amenazas y reputación.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Busca direcciones IP o rangos para consultar observaciones de escaneos de Internet y actividad habitual de servicios. Consulta las condiciones actuales de las pruebas y del acceso comunitario.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Obtiene información de escaneos de Internet y servicios para una dirección IP, un host o una consulta de búsqueda. El acceso a la API depende del plan de la cuenta.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Busca en conjuntos de datos de hosts, certificados, dominios y servicios de Internet; su modelo de datos y cobertura difieren de los de Shodan.

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Busca por palabra clave en el índice del proveedor de objetos y buckets de almacenamiento cloud observados públicamente.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Busca en datos indexados de filtraciones direcciones de correo electrónico, nombres de usuario, dominios y registros relacionados. Úsalo solo con autorización y evita la exposición innecesaria de datos filtrados.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Busca menciones de una dirección de correo electrónico u otro término en contenido de paste indexado. Verifica que el servicio siga disponible antes de integrarlo.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Obtiene señales de reputación y riesgo para una dirección de correo electrónico.

## GhostProject (histórico) <sup>[[24]](#references)</sup>

Históricamente ofrecía búsquedas en datos filtrados de correos electrónicos y contraseñas. Considera el servicio un tercero de alto riesgo para el tratamiento de datos y verifica su disponibilidad, legalidad y autorización antes de usarlo.

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

Obtiene datos de escaneos de Internet, exposición e inteligencia de amenazas para direcciones IP y activos relacionados.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Comprueba si una dirección de correo electrónico o un dominio verificado aparece en filtraciones conocidas. El servicio independiente Pwned Passwords comprueba hashes de contraseñas por prefijo; **no** revela contraseñas en texto plano.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Obtiene geolocalización IP, centro de datos, ASN, proxy/VPN y otros campos de enriquecimiento relacionados. Las cuotas dependen del plan actual.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
Enriquecimiento de geolocalización IP y orientado a OSINT con puntos de datos seleccionados. Consulta las condiciones actuales para el uso comercial.


[DNSDumpster](https://dnsdumpster.com/) proporciona resultados de reconocimiento de DNS.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) proporciona inteligencia sobre sitios, hosting e infraestructura de Internet.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) proporciona una interfaz online para descubrir subdominios.<sup>[[31]](#references)</sup>

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
{{#include ../../banners/hacktricks-training.md}}
