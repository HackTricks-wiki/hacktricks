# Atribución, detección y contramedidas

La infraestructura de evasión de atribución está diseñada para hacer que los indicadores individuales sean desechables. Los defensores deben conservar la evidencia sin procesar, modelar las relaciones y buscar comportamientos que sobrevivan a un cambio de IP, dominio o persona.

## Jerarquía de evidencia

| Evidencia | Útil para | Principal salvedad |
|---|---|---|
| IP/ASN/geolocalización de origen | localizar la salida visible y el proveedor | la salida puede ser un relay, NAT o una víctima; la geolocalización es aproximada |
| DNS pasivo/registro | historial de la infraestructura y co-hosting | la privacidad/redacción y el shared hosting generan brechas |
| Huella de certificado/TLS/HTTP | agrupar despliegues repetidos | el software común y la imitación generan falsos positivos |
| Temporización del flujo y forma de los bytes | vincular etapas de relay y beacons recurrentes | las CDN/NAT y la visibilidad limitada reducen la certeza |
| Proceso/identidad del endpoint | explicar por qué ocurrió una conexión | no está presente en edge/IoT; el atacante puede usar herramientas nativas |
| Auditoría de Cloud/CDN/API | identificar el tenant y el control de la infraestructura | la retención y el acceso legal/del proveedor varían |
| Pago/cuenta/dispositivo | conectar la adquisición con una persona/entidad | deben considerarse los testaferros, el compromiso y los dispositivos compartidos |
| Implant/configuración incautados | revelar claves, peers, controladores y vínculos de compilación | la integridad de la recopilación y el momento de la incautación son importantes |
| Evidencia humana/física | conectar el evento digital con un lugar/operador | es intrusiva, depende de la jurisdicción y requiere un manejo estricto |

Ninguna fila por sí sola debería respaldar una atribución estatal de alta confianza. Usa hipótesis contrapuestas e indica qué observación falsaría cada una.

## Telemetría mínima

1. **DNS:** cliente, consulta, tipo, respuestas, TTL, código de respuesta, resolver y marca de tiempo.
2. **Flujo de red:** origen/destino/puerto, inicio/fin, paquetes/bytes, flags TCP y ubicación del sensor.
3. **TLS/HTTP:** SNI cuando sea visible, certificado, protocolo negociado, huella del cliente/servidor, método, categoría de autoridad/ruta, estado y cantidad de bytes. Protege las URL completas sensibles.
4. **Identidad:** resultado de autenticación, factor/certificado/dispositivo, origen, aplicación, ID de sesión y decisión de riesgo.
5. **Endpoint:** proceso iniciador, proceso padre, usuario, firma/hash del binario y destino.
6. **Dispositivo edge/de red:** diferencia de configuración, inicio de sesión del administrador, integridad del proceso/archivo/firmware, interfaz y logs de flujo.
7. **Cloud/SaaS/CDN:** actor, tenant/proyecto, acción de API, origen, objeto/recurso, token y resultado.
8. **Wireless/NAC:** estación, indicador de MAC aleatoria, AP, señal, identidad/certificado EAP, VLAN/IP asignada y postura.

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

La densidad del grafo por sí sola es engañosa: una CDN o una autoridad certificadora conecta muchos actores no relacionados. Pondere más las relaciones poco frecuentes controladas por el operador—la misma cuenta API, clave SSH, origin allowlist, cuerpo de respuesta único o protocolo de control—que el hosting común.

## Caza de ORB y routers comprometidos

### Desde una salida observada

1. Determine si la dirección corresponde a hosting, una red residencial, móvil, educativa o empresarial; no descarte las fuentes residenciales.
2. Recopile DNS histórico, servicios/certificados, puertos abiertos y comportamiento de scan/exploitation observado durante un período acotado.
3. Busque pares que compartan fingerprints de servicio poco frecuentes, destinos de controller, material de certificado o tiempos de rotación.
4. Clasifique los roles probables: acceso, traversal, salida/staging o administración.
5. Compruebe si varios intrusion clusters no relacionados utilizaron el mismo pool; la multi-tenancy debilita la atribución directa del actor, pero refuerza la hipótesis de ORB.
6. Rastree nuevos nodos que coincidan con el perfil del rol después de que desaparezcan las IP antiguas.

### En el propietario de la red

- Genere alertas sobre nuevos sistemas de administración expuestos a Internet y autenticación predeterminada/legacy.
- Envíe fuera del dispositivo los cambios de configuración del router/firewall/VPN y las autenticaciones de administradores.
- Establezca una baseline de las conexiones salientes desde infraestructura que normalmente inicia pocas sesiones.
- Detecte nuevos procesos de proxy/listener, túneles, tareas programadas, cambios de firmware y DNS inesperado.
- Sustituya los dispositivos end-of-life; un reinicio que elimina malware volátil no corrige la exposición.
- Restrinja la administración a un plano de administración autenticado y a fuentes conocidas.

Mandiant recomienda rastrear la infraestructura ORB como una entidad en evolución, ya que el bloqueo de IP de corta duración no refleja la topología ni el ciclo de vida.<sup>[[1]](#references)</sup>

## Analítica de Fast-flux y dynamic-DNS

Agregue por dominio registrado y una ventana deslizante. Una puntuación práctica puede combinar:
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
Investiga los dominios mediante varias características independientes, no con un único umbral. Compara con un modelo de permitidos de CDN/anti-DDoS y comprueba la rotación de los servidores de nombres autoritativos para distinguir entre flux simple y doble. Para las DGA, añade ráfagas de NXDOMAIN por cliente, distribución de longitud y caracteres, consultas sincronizadas entre hosts y el proceso que las genera. La guía actual de MITRE también enfatiza los cambios de alta frecuencia, el TTL bajo y la correlación entre procesos y red.<sup>[[2]](#references)</sup>

## Domain-fronting detection

Cuando el endpoint empresarial o un punto de inspección autorizado tenga ambas identidades, compara:
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
Aumenta la confianza cuando SNI y authority pertenecen a tenants no relacionados, el proceso no es un cliente aprobado, la sesión es periódica o de larga duración y el origen interno es poco frecuente. Un SNI vacío es una característica que se debe registrar, no algo automáticamente malicioso. ECH puede ocultar SNI en el tráfico, por lo que los logs del endpoint, DNS y del proveedor/CDN adquieren mayor importancia. MITRE documenta tanto las variantes con SNI no coincidente como las variantes con SNI vacío.<sup>[[3]](#references)</sup>

## Detección de secuencias de resolvers dead-drop

El comportamiento de alta señal es una secuencia, no un dominio bloqueado:
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
Busca en toda la flota rutas de objetos, hashes de respuestas, identificadores de API y destinos posteriores idénticos. Conserva el contenido obtenido porque el actor puede editarlo o eliminarlo. Restringe las API de servicios innecesarias y exige que las aplicaciones aprobadas utilicen proxies empresariales, pero ten en cuenta las herramientas de desarrollo y la automatización. MITRE incluye GitHub, foros, documentos y servicios sociales/web en procedimientos reales.<sup>[[4]](#references)</sup>

## Agrupación de redirectors y despliegues reutilizables

Aunque cambien los dominios y las direcciones, los operadores suelen volver a desplegar la misma automatización. Agrupa según combinaciones de:

- campos de certificados/reutilización de claves y momento de emisión;
- versión de TLS/orden de cipher/extensiones y comportamiento del servidor;
- código de estado HTTP, orden de cabeceras, comportamiento de caché, icono/cuerpo y página de error idénticos;
- pares de puertos inusuales y cadenas de redirección;
- patrón de proveedor DNS/servidor de nombres y programación de TTL;
- momento del despliegue, tiempo de actividad y ventana de mantenimiento;
- exposición del origen back-end o allowlists idénticas.

Una única página genérica de Nginx es evidencia débil. Varias coincidencias independientes y poco frecuentes, junto con continuidad temporal, pueden justificar una hipótesis de clúster de infraestructura.

## Detección de proxies residenciales y sesiones imposibles

Mantén la identidad de la sesión por encima de la capa IP. Marca combinaciones como:

- la huella de una sesión/dispositivo cambia de países/ASNs más rápido de lo que permite un desplazamiento;
- una IP de consumidor cambia en cada solicitud mientras las cookies y la identidad TLS/navegador permanecen fijas;
- el dispositivo local declarado tiene una latencia/zona horaria/idioma incoherentes con la salida;
- una dirección alterna poblaciones de cuentas no relacionadas o muestra comportamiento de backconnect proxy;
- una sesión privilegiada aparece desde un acceso residencial sin el certificado de dispositivo de la organización.

Carrier NAT, herramientas de accesibilidad, VPNs corporativas y viajes producen anomalías benignas. Exige step-up authentication o una investigación en lugar de bloquear irreversiblemente basándote únicamente en etiquetas de “proxy residencial”.

## Detección de dispositivos wireless y encubiertos

Relaciona RADIUS/NAC con el AP y el contexto físico:

1. encuentra combinaciones cuenta–dispositivo–AP vistas por primera vez;
2. identifica credenciales utilizadas sin un certificado/postura EAP gestionado;
3. compara las sesiones simultáneas y la presencia en el edificio mediante badges;
4. inspecciona señales inusualmente débiles/periféricas y el movimiento entre APs;
5. busca en los endpoints gestionados cercanos wireless scanning, un bridge/NAT de interfaz recién habilitado, adaptadores virtuales o túneles;
6. inventaría la nueva actividad de switchport, DHCP, red USB y PoE;
7. realiza un barrido RF/físico autorizado cuando las evidencias lo justifiquen.

Esto detecta tanto una ruta de vecino más cercano al estilo APT28 como un dispositivo colocado durante un ejercicio. La aleatorización de MAC no debe tratarse como identidad ni como indicio de culpabilidad.

## Detección de atribución financiera

- Conserva la cadena, el token, la dirección, la transacción y los identificadores de bloque exactos.
- Sigue el valor a través de change, peel chains, fan-out/in, mixers, bridges y depósitos de servicios, etiquetando las heurísticas.
- Correlaciona el momento, el importe menos las comisiones, el evento del contrato, la liquidez y el retiro en la cadena de destino.
- Obtén o conserva legalmente registros de exchanges, bridges, merchants, cuentas, dispositivos y entregas.
- Comprueba las entidades/direcciones sancionadas actuales y sus derivados conforme al programa aplicable; no dependas de una lista estática antigua.
- Trata el uso de protocolos de privacidad como un factor del contexto de riesgo, no como prueba de una conducta indebida.

Las señales de alerta de FATF son explícitamente contextuales: el patrón inusual, el importe/frecuencia, la geografía, el origen de los fondos y los servicios que mejoran el anonimato adquieren significado en conjunto.<sup>[[5]](#references)</sup>

## Deception y canaries

Los defensores pueden crear señales de alta confianza sin intentar desanonimizar a usuarios comunes:

- credenciales o documentos únicos que nunca deberían salir de un sistema;
- endpoints administrativos falsos y shares señuelo;
- nombres DNS instrumentados incrustados únicamente en artefactos controlados;
- claves cloud canary sin uso legítimo;
- una identidad Wi-Fi señuelo que ningún dispositivo gestionado posee.

Define y gobierna cuidadosamente el alcance de la deception. Un canary debe identificar el uso indebido de un activo propio del defensor, no recopilar tráfico no relacionado de terceros.

## Prioridades de countermeasures

1. Elimina routers, VPNs y appliances expuestos a Internet que no tengan soporte.
2. Exige MFA resistente al phishing y certificados vinculados al dispositivo, incluido el acceso interno/wireless.
3. Centraliza logs suficientemente inmutables de identidad, endpoints, DNS, flujos, proxy, cloud y dispositivos de red.
4. Restringe la gestión y el egress; inventaría todos los servicios accesibles externamente.
5. Supervisa DNS, certificate transparency y la configuración cloud para detectar activos no autorizados.
6. Conserva visibilidad SaaS a nivel de proceso-red y objeto.
7. Practica investigaciones entre capas y la coordinación con proveedores vecinos.
8. Rastrea clústeres de infraestructura y comportamientos, no solo listas de bloqueo de IPs.

## Disciplina analítica

Usa lenguaje de confianza:

- **Observado:** el registro del sensor/proveedor muestra directamente la relación.
- **Fuertemente respaldado:** varias observaciones independientes la favorecen frente a las alternativas.
- **Evaluado:** inferencia basada en supuestos y evidencias declarados.
- **Desconocido:** la falta de visibilidad impide llegar a una conclusión.

Conserva siempre al menos dos hipótesis: infraestructura operada por el actor frente a un intermediario comprometido/compartido; un actor frente a un servicio multi-tenant; evasión deliberada frente a un comportamiento legítimo de privacidad/CDN. La capacidad de explicar la incertidumbre forma parte de una detección correcta.

## References

- [1] [Google Cloud/Mandiant — Los actores de espionaje vinculados a China utilizan redes ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — DNS Fast Flux (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Indicadores de señales de alerta de los Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — Actores de la RPC comprometen y mantienen acceso persistente](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — Orientación mejorada sobre visibilidad y hardening para la infraestructura de comunicaciones](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
