# Privacidad ofensiva, evasión de atribución y OPSEC

{{#include ../banners/hacktricks-training.md}}

Esta sección estudia la privacidad desde el punto de vista de un red team, un operador de intrusiones y el defensor que intenta reconstruir las acciones de dicho operador. **El anonimato no consiste simplemente en ocultar una dirección IP.** Las operaciones maduras separan a las personas, endpoints, cuentas, infraestructura, rutas de red, payloads y pagos que podrían conectarse en un grafo de atribución.

El material incluye deliberadamente técnicas documentadas en operaciones gubernamentales y de APT: redes de operational-relay-box (ORB), dispositivos perimetrales comprometidos, salidas residenciales, niveles de redirectors, fast flux, domain fronting, dead-drop resolvers, pivots inalámbricos cercanos, dispositivos de drop encubiertos, abuso de enlaces satelitales, falsas personas y layering financiero. Cada técnica se presenta como:

1. el objetivo operativo y el mapeo a ATT&CK;
2. el mecanismo y los límites de confianza;
3. lo que cada observador todavía puede registrar;
4. los errores y artefactos estables que la delatan;
5. la telemetría defensiva, analytics y mitigaciones; y
6. una emulación autorizada usando infraestructura propia o explícitamente dentro del scope.

Por tanto, esto es tanto una referencia de tradecraft ofensivo como un manual de atribución para defensores. El objetivo es hacer que el comportamiento avanzado sea comprensible y comprobable, no fingir que un único servicio comercial vuelve invisible a un operador.

**Corte de la investigación:** 8 de septiembre de 2026. La disponibilidad de proveedores, el comportamiento de los productos, las sanciones, los límites de efectivo/prepago, las normas de registro de SIM y la regulación de las criptomonedas cambian con frecuencia; vuelve a verificarlos antes de basarte en ellos.

{% hint style="danger" %}
Comprender una técnica no autoriza a ejecutarla. Las páginas explican abusos delictivos como routers comprometidos, el Wi-Fi de un vecino, dispositivos ocultos, identidades robadas y blanqueo a nivel de mecanismo y detección. Los pasos de reproducción utilizan únicamente sistemas de laboratorio propios, identidades sintéticas y activos de prueba. Nunca accedas a terceros, evadas KYC o sanciones, ni ocultes ganancias delictivas. El acceso no autorizado está penalizado en muchas jurisdicciones, incluido por la CFAA de EE. UU., la Computer Misuse Act del Reino Unido y las leyes de los Estados miembros de la UE que implementan la Directiva 2013/40/UE.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
{% endhint %}

## Mapa de objetivos del adversario

| Objetivo del adversario | Familias de técnicas | Pregunta defensiva principal |
|---|---|---|
| Ocultar el origen del operador | VPN/Tor, proxies externos y multi-hop, salidas residenciales/móviles, ORBs, enlaces satelitales | ¿La dirección del último salto pertenece a un activo del actor, a una víctima involuntaria o a un relay de corta duración? |
| Mantener el C2 real sin descubrir | redirectors, CDNs, domain fronting, dead-drop resolvers, DNS dinámico, fast flux | ¿Qué comportamiento estable sobrevive a la rotación de IP/dominio? |
| Tomar prestadas confianza y reputación | servidores, routers, cuentas de cloud y web-service comprometidos, domain shadowing | ¿Un activo reputado se está comportando de forma distinta a su baseline histórico? |
| Cruzar un límite físico o de red | pivots Wi-Fi nearest-neighbor, drops en el sitio, periféricos rogue, backhaul celular | ¿Qué nueva radio, dispositivo, switchport o túnel saliente apareció? |
| Separar a la persona de la operación | personas, compartimentación de cuentas/dispositivos, comunicaciones de cobertura, separación de adquisiciones | ¿Qué campo de recuperación, navegador, horario, idioma, pago o evento administrativo conecta las personas? |
| Ocultar la financiación y el cash-out | mulas/nominees, valor prepago, mixers, CoinJoin, peel chains, chain hopping, brokers OTC | ¿Dónde vuelven a conectarse los registros de identidad on-chain y off-chain? |

Los conceptos de ATT&CK más cercanos de desarrollo de recursos y C2 son **Acquire Infrastructure (T1583)**, **Compromise Infrastructure (T1584)**, **Establish/Compromise Accounts (T1585/T1586)**, **Proxy (T1090)**, **Dynamic Resolution (T1568)** y **Web Service (T1102)**.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

## Privacidad, pseudonimato, anonimato y seguridad

| Objetivo | Significado | Fallo típico |
|---|---|---|
| **Confidencialidad** | Los terceros no pueden leer el contenido | Los metadatos todavía identifican a las partes |
| **Privacidad** | La divulgación de información se limita a lo necesario | Un proveedor conserva más datos de lo esperado |
| **Pseudonimato** | La actividad utiliza una identidad estable que no está vinculada públicamente a una identidad legal | El email de recuperación, el pago, la IP, la foto o el estilo de escritura la vinculan |
| **Anonimato** | Un observador no puede distinguir al actor de un conjunto significativo de otras personas | El login, la fingerprint, los tiempos, la ubicación o la correlación de transacciones reducen el conjunto |
| **Inlinkabilidad** | Dos acciones no pueden atribuirse de forma fiable al mismo actor | Los identificadores reutilizados, la actividad simultánea o la infraestructura compartida las conectan |
| **Seguridad** | Los sistemas resisten el compromiso | Una cuenta segura pero identificada sigue sin ser anónima |

Estas propiedades dependen del observador. Un comerciante podría no ver el número de tarjeta, mientras que el emisor sigue conociendo al cliente y la transacción. Un sitio web podría ver una salida de Tor en lugar de una IP doméstica, mientras que un login de cuenta identifica inmediatamente al usuario.

## Empieza por el observador

Antes de elegir herramientas, anota:

1. **Activos:** identidad, ubicación, destinos de navegación, contenido de mensajes, grafo social, datos de pago, nombre del cliente, infraestructura de origen del red team o evidencias almacenadas.
2. **Observadores:** operador del Wi-Fi local, ISP/operador móvil, VPN, entrada/salida de Tor, resolver DNS, sitio web, red publicitaria, host de cloud, emisor de pagos, comerciante, exchange, contrapartes, empleador o gobierno.
3. **Elementos de correlación:** dirección IP, campos de cuenta/recuperación, número de teléfono, identificadores del dispositivo, cookies, browser fingerprint, zona horaria, instrumento de pago, dirección de envío, estilo de escritura, grafo de transacciones, presencia física y cámaras.
4. **Capacidad y tiempo:** el tracking comercial pasivo es distinto de un observador dirigido capaz de obtener una orden judicial contra proveedores, incautar endpoints u observar ambos extremos de una conexión.
5. **Coste del fallo:** vergüenza, suspensión de cuentas, perjuicio al cliente, pérdida financiera, peligro físico o exposición legal.

Después, selecciona los controles sostenibles mínimos. Un plan complicado que se elude habitualmente es más débil que un plan sencillo utilizado de forma constante.

## Tabla rápida de decisiones

| Necesidad | Punto de partida razonable | Lo que **no** resuelve |
|---|---|---|
| Ocultar los metadatos de navegación al ISP/red local | VPN reputada o Tor Browser | Cuentas, cookies, device fingerprint, compromiso del endpoint |
| Mayor anonimato web | Tor Browser; Tails para una sesión amnésica | Correlación global del tráfico, divulgaciones personales, observación física |
| Trabajo persistente compartimentado | Whonix o Qubes-Whonix; qubes/perfiles separados | Compromiso del hypervisor/host, vinculación de comportamientos entre identidades |
| Egress rápido de red team autorizado | Jump host proporcionado por el cliente o VPS/VPN específico del engagement | Atribución al proveedor/cliente; obligaciones de scope y políticas de cloud |
| Reducir la exposición del número de tarjeta al comerciante | Tarjeta virtual del emisor o wallet tokenizada | Conocimiento del emisor/red, envío, datos de cuenta y dispositivo |
| Minimizar los datos de pago en el punto de venta | Efectivo obtenido legalmente cuando se acepte | CCTV, recibos, rastro de retirada, límites de efectivo |
| Mejorar la privacidad de criptomonedas en cadenas públicas | Wallet/node propio, direcciones nuevas, coin control, Tor, PayJoin compatible | Exchange/KYC, registros de contrapartes, análisis permanente de la cadena |
| Confidencialidad predeterminada del importe/receptor/emisor on-chain | Monero con contextos de wallet separados y privacidad de red | Registros de adquisición/off-ramp, compromiso del endpoint, datos del comerciante/envío |

## Reglas básicas

- **Separa los contextos antes de iniciar la actividad.** Intentar establecer la separación después de que las cuentas, dispositivos y pagos ya se hayan vinculado rara vez deshace el historial.
- **No te personalices hasta convertirte en único.** El browser fingerprinting puede correlacionar actividad incluso después de borrar las cookies o cambiar la IP; normalmente son preferibles las configuraciones estándar con conjuntos de anonimato más grandes.<sup>[[5]](#references)</sup>
- **Protege el endpoint.** El anonimato de red no puede salvar un dispositivo desbloqueado, infectado o incautado.
- **Cifra el contenido y minimiza los metadatos.** El cifrado end-to-end protege el contenido de los mensajes, pero no necesariamente quién se comunicó, cuándo, desde dónde o con qué dispositivo.
- **Trata a los proveedores como observadores.** Las VPN, los servicios de email, los hosts de cloud, los exchanges, los emisores de pagos y los alias forwarders ven partes distintas de la actividad.
- **Prefiere afirmaciones verificables.** Busca documentación de protocolos, software reproducible, auditorías públicas, detalles de retención e informes de transparencia, en lugar de marketing de “grado militar”.
- **Reevalúa periódicamente.** Los servicios, las leyes, los threat actors y los valores predeterminados cambian.

## Mapa de la sección centrada en el uso ofensivo

- [Catálogo de técnicas de acceso anónimo a Internet](anonymous-internet-access-techniques.md) — 48 familias de rutas de acceso con ventajas, desventajas, pasos de despliegue/emulación, detección, exposición de captura y monitorización de descubrimiento en el lado del controlador.
- [Catálogo de técnicas de pagos anónimos](anonymous-payment-techniques.md) — 48 familias de pagos con ventajas, desventajas, workflows legales, detección, exposición de captura y monitorización de compromisos.
- [Nodos de campo autorizados resistentes a la captura](capture-resilient-authorized-field-nodes.md) — rendezvous saliente estable, recuperación con dual-uplink, minimización de secretos, ejercicios de captura y monitorización de descubrimiento/compromiso para drops aprobados por el propietario.
- [Infraestructura ofensiva y evasión de atribución](offensive-infrastructure-and-attribution-evasion.md) — ORBs, relays multi-hop/residenciales, redirectors, fronting, fast flux, domain shadowing, web services e infraestructura de personas.
- [Acceso físico e inalámbrico encubierto](covert-physical-wireless-access.md) — ataques nearest-neighbor, acceso público, dispositivos de drop, backhaul celular y abuso de satélites.
- [Casos de estudio gubernamentales y de APT](government-and-apt-case-studies.md) — casos públicos reconstruidos y la telemetría que los expuso.
- [Tradecraft de ofuscación financiera](financial-obfuscation-tradecraft.md) — cómo funciona el layering de pagos, por qué falla y cómo lo siguen los investigadores.
- [Atribución, detección y contramedidas](attribution-detection-and-countermeasures.md) — un modelo de detección entre capas y lógica práctica de hunting.
- [Labs de emulación de adversarios autorizados](authorized-adversary-emulation-labs.md) — ejercicios reproducibles usando redes propias y datos sintéticos.

## Fundamentos del operador y guías de apoyo

- [Modelado de amenazas y separación de identidades](threat-modeling-and-identity-separation.md)
- [Privacidad de red y conectividad anónima](network-privacy-and-anonymous-connectivity.md)
- [Arquitecturas avanzadas de privacidad de red](advanced-network-privacy-architectures.md)
- [Sistemas operativos orientados a la privacidad](privacy-operating-systems.md)
- [Comunicaciones y compartición con preservación de la privacidad](privacy-preserving-communications-and-sharing.md)
- [Infraestructura autorizada de red team](authorized-red-team-infrastructure.md)
- [Pagos digitales privados](private-digital-payments.md)
- [Privacidad de las criptomonedas](cryptocurrency-privacy.md)
- [Protocolos de pago con preservación de la privacidad](privacy-preserving-payment-protocols.md)
- [Pruebas de privacidad reproducibles](reproducible-privacy-testing.md)
- [Playbooks de privacidad operativa](operational-privacy-playbooks.md)

## Índice de guías y verificación

| Técnica | Guía de despliegue | Prueba de verificación/fallo |
|---|---|---|
| Todas las familias de técnicas de acceso a Internet | [Catálogo de técnicas de acceso anónimo a Internet](anonymous-internet-access-techniques.md) | Detección por técnica más [labs reproducibles](authorized-adversary-emulation-labs.md) |
| Todas las familias de técnicas de pago | [Catálogo de técnicas de pagos anónimos](anonymous-payment-techniques.md) | Detección por técnica más [lab de pagos sintéticos](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph) |
| Nodo de campo físico aprobado por el propietario | [Nodos de campo autorizados resistentes a la captura](capture-resilient-authorized-field-nodes.md) | Ejercicio de captura, monitorización de estado off-device y runbook de descubrimiento sospechado |
| ORBs, relays residenciales, fronting, fast flux y dead drops | [Infraestructura ofensiva y evasión de atribución](offensive-infrastructure-and-attribution-evasion.md) | [Labs de emulación propios](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) |
| Wi-Fi nearest-neighbor, drops, rutas celulares y satelitales | [Acceso físico e inalámbrico encubierto](covert-physical-wireless-access.md) | [Lab de wireless pivot propio](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) |
| Infraestructura entre capas y atribución del operador | [Atribución, detección y contramedidas](attribution-detection-and-countermeasures.md) | [Plantilla de informe del ejercicio](authorized-adversary-emulation-labs.md#exercise-report-template) |
| Peel chains, mixers, chain hopping, nominees y conversión OTC | [Tradecraft de ofuscación financiera](financial-obfuscation-tradecraft.md) | [Grafo de transacciones sintético](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph) |
| Compartimentación de identidad/browser | [Modelado de amenazas y separación de identidades](threat-modeling-and-identity-separation.md) | [Pruebas de browser y OS](reproducible-privacy-testing.md#browser-compartment-test) |
| VPN, Tor, Wi-Fi de invitados, travel router, celular | [Privacidad de red y conectividad anónima](network-privacy-and-anonymous-connectivity.md) | [Prueba de ruta de red](reproducible-privacy-testing.md#network-path-test) |
| Relays divididos, OHTTP, namespaces, bridges, onions, I2P | [Arquitecturas avanzadas de privacidad de red](advanced-network-privacy-architectures.md) | [Pruebas de Tor/onion y rutas](reproducible-privacy-testing.md#tor-and-onion-service-test) |
| Tails, Whonix y Qubes | [Sistemas operativos orientados a la privacidad](privacy-operating-systems.md) | [Prueba de aislamiento del OS](reproducible-privacy-testing.md#operating-system-isolation-test) |
| Signal, SimpleX, Briar, OnionShare y archivos cifrados | [Comunicaciones y compartición con preservación de la privacidad](privacy-preserving-communications-and-sharing.md) | [Pruebas de comunicaciones/archivos](reproducible-privacy-testing.md#communications-metadata-test) |
| Egress/drops de red team autorizados | [Infraestructura autorizada de red team](authorized-red-team-infrastructure.md) | [Ejercicio de accountability](reproducible-privacy-testing.md#authorized-red-team-accountability-drill) |
| Efectivo, prepago y tarjetas virtuales | [Pagos digitales privados](private-digital-payments.md) | [Prueba de privacidad de pagos](reproducible-privacy-testing.md#payment-privacy-test) |
| Bitcoin, PayJoin/CoinJoin, Lightning y Monero | [Privacidad de las criptomonedas](cryptocurrency-privacy.md) | [Prueba de privacidad de pagos](reproducible-privacy-testing.md#payment-privacy-test) |
| Silent Payments, Zcash, Taler y e-cash federado | [Protocolos de pago con preservación de la privacidad](privacy-preserving-payment-protocols.md) | [Prueba de privacidad de pagos](reproducible-privacy-testing.md#payment-privacy-test) |

## References

- [1] [Autodefensa de la vigilancia de EFF — Tu plan de seguridad](https://ssd.eff.org/module/your-security-plan)
- [2] [Código de EE. UU., 18 USC §1030 — Fraude y actividades relacionadas en conexión con ordenadores](https://uscode.house.gov/view.xhtml?req=title:18%20section:1030%20edition:prelim)
- [3] [Computer Misuse Act 1990 del Reino Unido, sección 1](https://www.legislation.gov.uk/ukpga/1990/18/section/1)
- [4] [EUR-Lex — Directiva 2013/40/UE sobre ataques contra sistemas de información](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32013L0040)
- [5] [W3C — Mitigación del browser fingerprinting en especificaciones web](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [MITRE ATT&CK — Acquire Infrastructure (T1583) y Compromise Infrastructure (T1584)](https://attack.mitre.org/techniques/T1584/)
- [7] [MITRE ATT&CK — Proxy (T1090)](https://attack.mitre.org/techniques/T1090/)
{{#include ../banners/hacktricks-training.md}}
