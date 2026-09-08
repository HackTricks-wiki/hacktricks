# Atribución, Detección y Contramedidas

{{#include ../banners/hacktricks-training.md}}

La infraestructura de evasión de atribución está diseñada para que los indicadores individuales sean desechables. Los defensores deben preservar la evidencia sin procesar, modelar las relaciones y buscar comportamientos que sobrevivan a un cambio de IP, dominio o persona.

## Jerarquía de evidencia

| Evidencia | Útil para | Principal salvedad |
|---|---|---|
| IP/ASN/geolocalización de origen | localizar la salida visible y el proveedor | la salida puede ser un relay, NAT o una víctima; la geolocalización es aproximada |
| DNS pasivo/registro | historial de infraestructura y co-hosting | la privacidad/redacción y el hosting compartido generan lagunas |
| Huella de certificado/TLS/HTTP | agrupar despliegues repetidos | el software común y la imitación generan falsos positivos |
| Temporización del flujo y forma de los bytes | vincular etapas del relay y beacons recurrentes | las CDN/NAT y la visibilidad limitada reducen la certeza |
| Proceso/identidad del endpoint | explicar por qué ocurrió una conexión | no está presente en edge/IoT; el atacante puede usar herramientas nativas |
| Auditoría de Cloud/CDN/API | identificar el tenant y el control de la infraestructura | la retención y el acceso legal/del proveedor varían |
| Pago/cuenta/dispositivo | conectar la adquisición con una persona/entidad | deben considerarse los nominees, el compromiso y los dispositivos compartidos |
| Implant/configuración incautados | revelar claves, peers, controladores y vínculos de compilación | la integridad de la recopilación y el momento de la incautación son importantes |
| Evidencia humana/física | conectar el evento digital con un lugar/operador | es intrusiva, depende de la jurisdicción y requiere un manejo estricto |

Ninguna fila por sí sola debería sustentar una atribución estatal con alta confianza. Utiliza hipótesis contrapuestas e indica qué observación falsaría cada una.

## Telemetría mínima

1. **DNS:** cliente, consulta, tipo, respuestas, TTL, código de respuesta, resolver y marca de tiempo.
2. **Flujo de red:** origen/destino/puerto, inicio/fin, paquetes/bytes, flags TCP y ubicación del sensor.
3. **TLS/HTTP:** SNI cuando sea visible, certificado, protocolo negociado, huella del cliente/servidor, método, categoría de authority/path, estado y cantidad de bytes. Protege las URL completas sensibles.
4. **Identidad:** resultado de autenticación, factor/certificado/dispositivo, origen, aplicación, ID de sesión y decisión de riesgo.
5. **Endpoint:** proceso iniciador, padre, usuario, firma/hash del binario y destino.
6. **Dispositivo edge/de red:** diferencia de configuración, inicio de sesión del administrador, integridad de procesos/archivos/firmware, interfaz y logs de flujo.
7. **Cloud/SaaS/CDN:** actor, tenant/proyecto, acción de API, origen, objeto/recurso, token y resultado.
8. **Wireless/NAC:** estación, indicador de MAC aleatoria, AP, señal, identidad/certificado EAP, VLAN/IP asignadas y postura.

Sincroniza los relojes, conserva las zonas horarias originales, documenta los límites de NAT/proxy y conserva suficiente historial para superar la vida útil de un nodo ORB de 31 días.

## Construir un grafo de atribución

Representa las observaciones como nodos y aristas tipados:
```text
[persona]--created-->[cloud account]--deployed-->[VPS]
|                       |                     |
recovery               login-from             TLS fingerprint
|                       |                     |
[email]                [access relay]-------->[redirector]--seen-by-->[target]
```
Los nodos útiles incluyen IP, prefijo, ASN, dominio, cuenta DNS, certificado/clave, fingerprint similar a JA3/JA4, gramática HTTP, hash de archivo/configuración, tenant cloud, API token, correo electrónico, persona, instrumento de pago y dispositivo físico. Cada arista necesita `first_seen`, `last_seen`, sensor/fuente, confianza e indicar si es observada o inferida.

La densidad del grafo por sí sola es engañosa: una CDN o una autoridad certificadora conecta muchos actores no relacionados. Asigna mayor peso a las relaciones poco comunes controladas por el operador—misma cuenta API, clave SSH, allowlist de origen, cuerpo de respuesta único o protocolo de control—que al hosting común.

## ORB y búsqueda de routers comprometidos

### Desde una salida observada

1. Determina si la dirección corresponde a hosting, una red residencial, móvil, educativa o empresarial; no descartes las fuentes residenciales.
2. Obtén DNS histórico, servicios/certificados, puertos abiertos y comportamiento observado de escaneo/explotación durante un período acotado.
3. Busca pares que compartan fingerprints de servicio poco comunes, destinos de control, material de certificados o tiempos de rotación.
4. Clasifica las funciones probables: acceso, tránsito, salida/staging o administración.
5. Comprueba si varios clusters de intrusión no relacionados utilizaron el mismo pool; la multitenencia debilita la atribución directa al actor, pero refuerza la hipótesis de ORB.
6. Rastrea nuevos nodos que coincidan con el perfil de función después de que desaparezcan las IP antiguas.

### En el propietario de la red

- Genera alertas sobre nuevos sistemas de administración expuestos a Internet y autenticación predeterminada/legacy.
- Envía los cambios de configuración del router/firewall/VPN y la autenticación de administradores fuera del dispositivo.
- Establece una línea base de las conexiones salientes desde infraestructura que normalmente inicia pocas sesiones.
- Detecta nuevos procesos de proxy/listener, túneles, tareas programadas, cambios de firmware y DNS inesperado.
- Sustituye los dispositivos al final de su vida útil; un reinicio que elimina malware volátil no soluciona la exposición.
- Restringe la administración a un plano de administración autenticado y a fuentes conocidas.

Mandiant recomienda rastrear la infraestructura ORB como una entidad en evolución, porque el bloqueo de IP de corta duración no captura la topología ni el ciclo de vida.<sup>[[1]](#references)</sup>

## Análisis de fast-flux y dynamic-DNS

Agrega por dominio registrado y una ventana deslizante. Una puntuación práctica puede combinar:
```text
score =
2 * low_median_ttl
+ 2 * unique_answer_count
+ 2 * unique_asn_count
+ geographic_dispersion
+ nxdomain_or_answer_churn
+ first_seen_recently
+ suspicious_process_or_follow_on
```
Investiga los dominios utilizando varias características independientes, no un único umbral. Compara con un allow-model de CDN/anti-DDoS y comprueba la rotación de los authoritative name servers para distinguir entre single y double flux. Para las DGA, añade los picos de NXDOMAIN por cliente, la distribución de longitud y caracteres, las consultas sincronizadas entre hosts y el proceso que las genera. La guía actual de MITRE también enfatiza los cambios de alta frecuencia, los TTL bajos y la correlación entre procesos y red.<sup>[[2]](#references)</sup>

## Detección de Domain-fronting

Cuando el endpoint empresarial o un punto de inspección autorizado tenga ambas identidades, compara:
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
Aumenta la confianza cuando SNI y authority pertenecen a tenants no relacionados, el proceso no es un cliente aprobado, la sesión es periódica o de larga duración y el origen interno es poco frecuente. Un SNI vacío es una característica que debe registrarse, no algo automáticamente malicioso. ECH puede ocultar SNI en la red, por lo que los logs del endpoint, DNS y del proveedor/CDN adquieren mayor importancia. MITRE documenta tanto las variantes con discrepancias como las variantes con SNI vacío.<sup>[[3]](#references)</sup>

## Detección de secuencias de resolvers dead-drop

El comportamiento de alta señal es una secuencia, no un dominio bloqueado:
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
Busca en toda la flota rutas de objetos idénticas, hashes de respuestas, identificadores de API y destinos posteriores. Conserva el contenido obtenido porque el actor puede editarlo o eliminarlo. Restringe las API de servicios innecesarias y exige que las aplicaciones aprobadas utilicen proxies empresariales, pero ten en cuenta las herramientas de desarrollo y la automatización. MITRE incluye GitHub, foros, documentos y servicios sociales/web en procedimientos reales.<sup>[[4]](#references)</sup>

## Clustering de redirectors y deployments reutilizables

Aunque los dominios y las direcciones cambien, los operadores suelen volver a desplegar la misma automatización. Agrupa basándote en combinaciones de:

- campos de certificados/reutilización de claves y momento de emisión;
- versión de TLS/orden de cifrados y extensiones, y comportamiento del servidor;
- código de estado HTTP, orden de cabeceras, comportamiento de caché, icono/cuerpo y página de error idénticos;
- pares de puertos inusuales y cadenas de redirección;
- patrón del proveedor DNS/servidor de nombres y programación del TTL;
- momento del deployment, disponibilidad y ventana de mantenimiento;
- exposición del origen de back-end o listas de permitidos idénticas.

Una sola página genérica de Nginx es una evidencia débil. Varias coincidencias independientes poco comunes, junto con continuidad temporal, pueden justificar una hipótesis de clúster de infraestructura.

## Detección de proxies residenciales y sesiones imposibles

Mantén la identidad de la sesión por encima de la capa IP. Marca combinaciones como:

- una sesión/huella de dispositivo cambia de países/ASN más rápido de lo que permite un viaje;
- una IP de consumidor cambia en cada solicitud mientras las cookies y la identidad TLS/navegador permanecen fijas;
- el dispositivo local declarado tiene latencia/zona horaria/idioma incompatibles con la salida;
- una dirección alterna entre poblaciones de cuentas no relacionadas o muestra comportamiento de proxy backconnect;
- una sesión privilegiada aparece desde un acceso residencial sin el certificado de dispositivo de la organización.

Carrier NAT, herramientas de accesibilidad, VPN corporativas y viajes producen anomalías benignas. Exige autenticación step-up o una investigación en lugar de bloquear irreversiblemente basándote únicamente en etiquetas de “proxy residencial”.

## Detección de dispositivos inalámbricos y encubiertos

Relaciona RADIUS/NAC con el AP y el contexto físico:

1. encuentra las primeras combinaciones observadas cuenta–dispositivo–AP;
2. identifica las credenciales utilizadas sin un certificado EAP/postura gestionados;
3. compara las sesiones simultáneas y la presencia en la tarjeta de acceso/edificio;
4. inspecciona señales inusualmente débiles/periféricas y el movimiento entre AP;
5. busca en los endpoints gestionados cercanos escaneo inalámbrico, un bridge/NAT de interfaz recién habilitado, adaptadores virtuales o túneles;
6. inventaría la actividad nueva de puertos de switch, DHCP, red USB y PoE;
7. realiza un barrido RF/físico autorizado cuando las evidencias lo respalden.

Esto detecta tanto una ruta de vecino más cercano al estilo APT28 como un dispositivo colocado durante un ejercicio. La aleatorización de MAC no debe tratarse como identidad ni como prueba de culpabilidad.

## Detección de atribución financiera

- Conserva la cadena, el token, la dirección, la transacción y los identificadores de bloque exactos.
- Sigue el valor a través de change, peel chains, fan-out/in, mixers, bridges y depósitos en servicios, etiquetando las heurísticas.
- Correlaciona el momento, el importe menos las comisiones, el evento del contrato, la liquidez y el retiro en la cadena de destino.
- Obtén o conserva legalmente los registros de exchanges, bridges, comerciantes, cuentas, dispositivos y entregas.
- Comprueba las entidades/direcciones sancionadas actuales y sus derivados conforme al programa aplicable; no dependas de una lista estática antigua.
- Trata el uso de protocolos de privacidad como un dato del contexto de riesgo, no como una prueba de conducta ilícita.

Las señales de alerta de FATF son explícitamente contextuales: el patrón inusual, el importe/frecuencia, la geografía, el origen de los fondos y los servicios que mejoran el anonimato adquieren significado conjuntamente.<sup>[[5]](#references)</sup>

## Deception y canaries

Los defensores pueden crear señales de alta confianza sin intentar desanonimizar a usuarios comunes:

- credenciales o documentos únicos que nunca deberían salir de un sistema;
- endpoints administrativos falsos y recursos compartidos señuelo;
- nombres DNS instrumentados integrados únicamente en artefactos controlados;
- claves cloud canary sin uso legítimo;
- una identidad Wi-Fi señuelo que ningún dispositivo gestionado posea.

Define el alcance y gobierna la deception cuidadosamente. Un canary debe identificar el uso indebido de un activo propio del defensor, no recopilar tráfico no relacionado de terceros.

## Prioridades de las contramedidas

1. Elimina routers, VPN y appliances expuestos a Internet que no tengan soporte.
2. Exige MFA resistente al phishing y certificados vinculados al dispositivo, incluido el acceso interno/inalámbrico.
3. Centraliza logs suficientemente inmutables de identidad, endpoints, DNS, flujos, proxies, cloud y dispositivos de red.
4. Restringe la gestión y la salida; inventaría cada servicio accesible externamente.
5. Monitoriza DNS, Certificate Transparency y la configuración cloud para detectar activos no autorizados.
6. Conserva visibilidad del proceso a la red y a nivel de objeto en SaaS.
7. Practica investigaciones entre capas y la coordinación con proveedores vecinos.
8. Rastrea clústeres de infraestructura y comportamientos, no solo listas de bloqueo de IP.

## Disciplina analítica

Utiliza lenguaje de confianza:

- **Observado:** el registro del sensor/proveedor muestra directamente la relación.
- **Fuertemente respaldado:** varias observaciones independientes la favorecen frente a las alternativas.
- **Evaluado:** inferencia basada en supuestos y evidencias declarados.
- **Desconocido:** la falta de visibilidad impide llegar a una conclusión.

Mantén siempre al menos dos hipótesis: infraestructura operada por el actor frente a un intermediario comprometido/compartido; un actor frente a un servicio multi-tenant; evasión deliberada frente a un comportamiento legítimo de privacidad/CDN. La capacidad de explicar la incertidumbre forma parte de una detección correcta.

## References

- [1] [Google Cloud/Mandiant — Actores de espionaje vinculados a China utilizan redes ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — DNS Fast Flux (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Indicadores de señales de alerta de activos virtuales](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — Actores de la RPC comprometen y mantienen acceso persistente](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — Orientación sobre visibilidad mejorada y hardening para infraestructura de comunicaciones](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
{{#include ../banners/hacktricks-training.md}}
