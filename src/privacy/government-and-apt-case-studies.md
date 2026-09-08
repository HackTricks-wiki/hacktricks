# Estudios de caso gubernamentales y de APT

Estos casos públicos muestran cómo se combinan distintas técnicas de privacidad en operaciones reales. Las etiquetas de atribución son las utilizadas por los investigadores o gobiernos citados; una dirección IP, una coincidencia de herramientas o una compatibilidad geopolítica por sí solas no constituyen una atribución concluyente.

## APT28: acceso Wi-Fi remoto mediante un vecino cercano

**Hallazgo público.** Volexity atribuyó una intrusión de 2022 a GruesomeLarch/APT28. Después de que el acceso a Internet con una credencial validada fuera detenido por MFA, el actor comprometió organizaciones cercanas al objetivo y accedió a la Wi-Fi empresarial del objetivo desde un host cercano con doble conexión de red. La ruta Wi-Fi aceptó la credencial sin el MFA requerido externamente.<sup>[[1]](#references)</sup>

**Efecto sobre la privacidad.** El acceso final se originó dentro del alcance físico de la radio y las organizaciones intermedias eran víctimas. La operación evitó desplazamientos y provocó que la geolocalización IP convencional apuntara a un vecino.

**Qué lo expuso.** La alerta del objetivo, la investigación del host/red, la actividad de las credenciales, la topología de las interfaces y la proximidad física tuvieron que analizarse como una sola cadena. El hecho anómalo no era simplemente una IP nueva; era una identidad legítima llegando a través de un contexto inusual de Wi-Fi/dispositivo mientras se comprometían sistemas cercanos.

**Lección defensiva.** Aplicar acceso respaldado por certificados/dispositivos a la Wi-Fi, correlacionar RADIUS con NAC/MDM y el contexto físico, e investigar la infraestructura vecina en lugar de asumir que el último salto es el operador.

## APT28: infraestructura criminal de Moobot reutilizada por el GRU

**Hallazgo público.** En febrero de 2024, el Departamento de Justicia de EE. UU. describió un botnet de cientos de routers Ubiquiti EdgeOS. Actores criminales habían instalado Moobot en routers que conservaban credenciales de administrador predeterminadas conocidas; posteriormente, la Unidad 26165 del GRU añadió scripts y archivos, convirtiendo un botnet criminal existente en una plataforma de espionaje utilizada para spearphishing y robo de credenciales.<sup>[[2]](#references)</sup>

**Efecto sobre la privacidad.** El GRU no construyó toda la infraestructura por sí mismo. Tomar prestada una flota ya comprometida colocó direcciones de hogares y pequeñas oficinas no relacionadas entre el actor y los objetivos, mezcló la actividad estatal con la actividad criminal y redujo los artefactos de registro específicos del actor.

**Qué lo expuso.** Los archivos de los routers, el comportamiento de control del malware y la información de routing que no incluía contenido respaldaron la investigación. La interrupción modificó temporalmente las reglas del firewall y eliminó archivos maliciosos, mientras que el DOJ advirtió que las credenciales predeterminadas sin cambios podían permitir una reinfección.

**Lección defensiva.** Sustituir los routers sin soporte, eliminar la administración expuesta a Internet, cambiar los valores predeterminados, aplicar parches, recopilar datos de configuración/flujo de los dispositivos perimetrales y buscar patrones de comportamiento de la flota. Una “IP residencial de EE. UU.” no es evidencia de que el operador sea estadounidense.

## Volt Typhoon: KV Botnet más living off the land

**Hallazgo público.** El DOJ y un aviso conjunto de CISA describieron que Volt Typhoon, patrocinado por el Estado de la RPC, utilizaba KV Botnet, compuesto principalmente por routers SOHO Cisco y NETGEAR obsoletos y comprometidos, para ocultar el origen de la RPC en actividades dirigidas contra infraestructura crítica. Dentro de las víctimas, el actor prefería cuentas válidas y herramientas de administración integradas; las agencias informaron de accesos que en algunos entornos duraron al menos cinco años.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
```text
PRC operator -> encrypted KV path -> compromised SOHO exit -> edge service
|
valid accounts + native tools
```
**Efecto sobre la privacidad.** La ruta similar a ORB ocultó el origen, mientras que el uso de herramientas legítimas del sistema redujo los binarios novedosos y las oportunidades de detección mediante signatures después del acceso. El ocultamiento de la red y del endpoint se reforzaron mutuamente.

**Qué lo expuso.** La estructura del router/controlador, la recopilación técnica autorizada por un tribunal, la actividad recurrente y el análisis entre víctimas fueron más importantes que un único IOC. Reiniciar un router eliminó el malware KV volátil en los casos descritos, pero no corrigió la exposición subyacente del dispositivo al encontrarse al final de su vida útil.

**Lección defensiva.** Sustituir los dispositivos edge EOL, centralizar los logs de autenticación y de dispositivos de red, establecer una línea base del comportamiento de los administradores, restringir la conectividad saliente y buscar secuencias de comportamiento entre las capas de identidad, endpoint y red.

## Redes ORB vinculadas a China: infrastructure as a service

**Hallazgo público.** Mandiant describió un ecosistema de redes ORB utilizado por múltiples actores de espionaje vinculados a China. Las redes provisionadas utilizaban nodos VPS alquilados; las redes no provisionadas utilizaban dispositivos IoT y routers comprometidos; las redes híbridas combinaban ambos. ORB3/SPACEHOP respaldaba actividad asociada con APT5/APT15. ORB2/FLORAHOX combinaba un servidor de administración, servidores alquilados, una capa Tor personalizada y dispositivos Cisco, ASUS y DrayTek comprometidos. Mandiant evaluó que algunas redes eran administradas de forma independiente y alquiladas a múltiples actores APT.<sup>[[5]](#references)</sup>

**Efecto sobre la privacidad.** La infraestructura se convirtió en un límite de servicio. Un operador podía obtener salidas geográficas/residenciales sin mantener la flota de víctimas, mientras que el uso compartido por muchos clientes debilitaba la atribución simple de actor a IP. La rápida rotación de la flota aceleraba la “extinción de IOC”.

**Qué lo expuso.** La topología de red, las imágenes clonadas de servidores, los puertos/servicios, las relaciones con los controladores, los implantes en routers y los patrones del ciclo de vida seguían siendo agrupables. Mandiant informó que algunas IP de nodos permanecieron en una ORB tan solo 31 días.

**Lección defensiva.** Rastrear una ORB como una entidad cambiante: roles de los nodos, fingerprints de servicios, relaciones upstream, comportamiento de scanning y ritmo de rotación. La expiración de un indicador IP debe actualizar el cluster, no borrar el caso.

## Sistema de espionaje global de la RPC: routers, enlaces de confianza y traffic mirroring

**Hallazgo público.** Un aviso multinacional de 2025 describió actividad que coincidía con nombres utilizados en informes comerciales, incluidos Salt Typhoon, OPERATOR PANDA, RedMike, UNC5807 y GhostEmperor. Las agencias informaron del uso de VPS alquilados y routers intermedios comprometidos para acceder a proveedores de telecomunicaciones y de red. Los actores pivotaban mediante enlaces de confianza entre proveedores y clientes, modificaban rutas, creaban túneles GRE/IPsec, utilizaban contenedores de dispositivos y habilitaban SPAN/RSPAN/ERSPAN o packet capture nativo para recopilar autenticación y tráfico de clientes.<sup>[[13]](#references)</sup>

**Efecto sobre la privacidad.** Un router comprometido es simultáneamente un relay, un punto de observación y un participante de confianza en la red. Las interconexiones privadas pueden eludir controles diseñados para Internet pública, mientras que el traffic mirroring recopila credenciales sin desplegar un agente en el endpoint.

**Qué lo expone.** Diffs de configuración, administración SNMP/SSH/web inesperada, nuevas rutas estáticas/túneles, sesiones de mirroring, contenedores Guest Shell, archivos PCAP, cambios en los destinos TACACS+/RADIUS y logs deshabilitados. El aviso enfatiza que algunos routers intermedios no formaban parte de una botnet pública previamente identificada, por lo que la ausencia de indicadores ORB conocidos no era exculpatoria.

**Lección defensiva.** Utilizar administración out-of-band, logs centralizados de configuración/autenticación, comprobaciones de integridad de runtime y de imágenes firmadas, restricciones sobre el egress de las interfaces de administración y alertas para cambios de rutas/mirroring/túneles/AAA. Ampliar el alcance de un compromiso sospechoso a través de los peers de confianza antes de realizar la eviction.

## UNC3886 RedPenguin: backdoors pasivos en routers de ISP

**Hallazgo público.** Mandiant atribuyó a UNC3886 backdoors personalizados derivados de TINYSHELL en routers Juniper MX al final de su vida útil. El conjunto incluía implants activos y pasivos, nombres que imitaban daemons legítimos, comportamiento de deshabilitación de logs, process injection en un proceso de confianza, capacidad de proxy SOCKS e infraestructura evaluada como nodos de staging ORB. Las variantes pasivas inspeccionaban paquetes mediante `libpcap` y solo se activaban después de un patrón mágico; una de ellas podía cambiar a un callback activo proporcionado en el trigger.<sup>[[14]](#references)</sup>

**Efecto sobre la privacidad.** Un implant pasivo no tiene un beacon periódico que permita descubrirlo. Comparte puertos/tráfico con un dispositivo de red real, se activa brevemente y puede retransmitir mediante una ORB en lugar de conectarse directamente a un controlador final.

**Qué lo expone.** El análisis de memoria, las diferencias entre el código almacenado en disco y el código en ejecución, los filtros inesperados de packet capture/comportamiento de sockets, los nombres de procesos/archivos que solo se aproximan a daemons legítimos, la administración mediante terminal servers, los logs ausentes y la relación en dos etapas entre los nodos de staging y un controlador backend.

**Lección defensiva.** Adquirir memoria además de evidencias del filesystem/configuración, comparar procesos/módulos con una imagen conocida como válida, monitorizar el uso de packet capture/socket filters, proteger los terminal servers de administración y sustituir el hardware de red EOL. Una búsqueda limpia de outbound beacons no garantiza que el sistema esté limpio.

## APT29: domain fronting mediante Tor

**Hallazgo público.** MITRE registra que APT29 utilizó el transporte conectable `meek` de Tor para realizar domain fronting del tráfico C2. El nombre TLS externo parecía ser un dominio permitido alojado en una CDN, mientras que el host HTTP interno seleccionaba la ruta real.<sup>[[6]](#references)</sup>

**Efecto sobre la privacidad.** Un observador que aplicara filtering podía ver un front/CDN común en lugar del destino interno, y bloquearlo podía provocar daños colaterales.

**Qué lo expone.** La CDN puede observar la discrepancia de routing, y un defensor con visibilidad del endpoint o de TLS obtenida legalmente puede correlacionar el proceso, la autoridad, la duración de la conexión, el patrón de bytes y la actividad posterior. Los cambios en las políticas del proveedor pueden deshabilitar la técnica.

**Lección defensiva.** No depender únicamente del allowlisting de SNI. Aplicar egress con conocimiento de la aplicación, comparar las identidades TLS y HTTP cuando sean visibles y asociar el evento de red con el proceso que lo inició.

## APT41 y otros dead-drop resolvers

**Hallazgo público.** MITRE documenta que APT41 utilizó sitios legítimos, incluidos GitHub, Pastebin, Microsoft TechNet, Cloudflare y foros comunitarios, para publicar o recuperar información de C2. Otras herramientas vinculadas a Estados también han utilizado publicaciones, documentos y redes sociales de forma similar.<sup>[[7]](#references)</sup>

**Efecto sobre la privacidad.** Un binario contiene un servicio/objeto legítimo en lugar de una dirección C2 estable. El objeto puede editarse para rotar la infraestructura, y la solicitud inicial se mezcla con tráfico TLS común.

**Qué lo expone.** El identificador del objeto o de la cuenta es estable; procesos poco frecuentes lo solicitan repetidamente; el contenido se decodifica; y después se produce una segunda conexión saliente. Los registros de la cuenta del proveedor y de la API pueden vincular la publicación con el operador.

**Lección defensiva.** Conservar las rutas completas del proxy/los object IDs y la process lineage del endpoint. Un evento a nivel de dominio como “conectado a GitHub” es demasiado impreciso.

## Turla: C2 mediante direcciones satelitales

**Hallazgo público.** Kaspersky informó que Turla abusaba de broadcasts descendentes no cifrados de antiguos servicios de Internet unidireccionales DVB-S. Un operador dentro de la cobertura satelital podía seleccionar la dirección de un suscriptor legítimo y recibir las respuestas transmitidas a ella, haciendo que el C2 pareciera estar alojado detrás de un proveedor satelital de otra región.<sup>[[8]](#references)</sup>

**Efecto sobre la privacidad.** La dirección aparente del servidor no identificaba al receptor, y los procesos convencionales de incautación del hosting/WHOIS eran menos útiles.

**Qué lo expone.** El actor aún necesitaba una ruta de solicitud saliente, el routing era asimétrico, el suscriptor legítimo no iniciaba el intercambio C2 y una investigación de RF/proveedor podía acotar la zona de recepción.

**Lección defensiva.** Tratar la geolocalización como una hipótesis más. Validar la simetría de la ruta, el RTT, la titularidad del routing y si el endpoint alegado podía producir realmente el servicio observado.

## Cyclops Blink y VPNFilter: dispositivos edge como cobertura duradera

**Hallazgo público.** Un aviso de NCSC/CISA/FBI/NSA de 2022 describió el malware modular Cyclops Blink de Sandworm en dispositivos WatchGuard, desplegado de forma persistente como una actualización de firmware y capaz de añadir módulos. Por separado, el DOJ describió la botnet VPNFilter anterior de APT28, compuesta por routers y dispositivos NAS, como capaz de recopilar inteligencia, realizar actividad destructiva y facilitar la misatribución.<sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>

**Efecto sobre la privacidad.** Los dispositivos edge están continuamente online, son de confianza como infraestructura y tienen una cobertura deficiente de EDR. La persistencia en el firmware puede sobrevivir a un reinicio normal y convertir el dispositivo de la víctima en un relay o punto de control.

**Qué lo expone.** La integridad del firmware, el protocolo del implant específico del proveedor, la exposición de administración inesperada, los cambios de configuración y los outbound beacons. Los dispositivos edge deben ser sujetos forenses, no plumbing transparente.

## DPRK: capas de identidad, red y finanzas

**Hallazgo público.** Los casos del DOJ describen a trabajadores de la DPRK obteniendo empleos remotos mediante material de identidad falso o robado y VPNs, recibiendo criptomonedas, dividiendo transferencias, intercambiando activos/chains, utilizando NFTs y mezclando los ingresos. Otros casos describen a traders OTC y empresas pantalla convirtiendo criptomonedas robadas en compras. Treasury y el FBI han vinculado públicamente los ingresos de Lazarus/TraderTraitor con mixers e identificado direcciones procedentes de grandes robos.<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup>

**Efecto sobre la privacidad.** Esto no es “una private coin”. Es una cadena multidominio: la persona y el acceso remoto ocultan la ubicación del trabajador; las criptomonedas mueven el valor; el layering rompe las narrativas transaccionales simples; y los traders OTC/empresas pantalla conectan con bienes y fiat.

**Qué lo expone.** Las anomalías del empleador/dispositivo, los facilitadores reutilizados, la continuidad temporal y de valor en la blockchain, los registros de exchanges/bridges, las direcciones sancionadas, la identidad de la cuenta y los registros de envíos/empresas vuelven a conectar la cadena.

**Lección defensiva.** Los equipos de contratación, IAM, endpoint, payroll, blockchain y sanctions necesitan un modelo de caso compartido. Puede encontrarse más información en [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md).

## Patrones entre casos

| Patrón | Ejemplos de APT | Adaptación del defensor |
|---|---|---|
| El exit es otra víctima | APT28/Moobot, Volt Typhoon/KV, ORBs | investigar y remediar el exit; no equipararlo con la ubicación del actor |
| Los controles difieren según el límite | APT28 nearest neighbor | proporcionar al acceso interno/wireless la misma garantía de identidad que al acceso desde Internet |
| Un servicio legítimo es una capa de routing | APT29, APT41 | conservar el contexto del objeto/ruta/proceso, no solo el dominio de destino |
| Los dispositivos edge carecen de telemetría | KV, Moobot, Cyclops Blink, ORBs | centralizar los logs de configuración/autenticación/flujo y verificar firmware/inventario |
| La infraestructura es compartida y de corta duración | ORBs vinculadas a China | agrupar el comportamiento/topología y rastrear los cambios de rol a lo largo del tiempo |
| Varias separaciones débiles se componen | Personas de la DPRK + VPN + crypto + OTC | relacionar las evidencias de identidad, dispositivo, red, pagos y presencia física |

## References

- [1] [Volexity — El ataque Nearest Neighbor](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [US DOJ — Disruption de la botnet de routers Moobot controlada por la GRU](https://www.justice.gov/archives/opa/pr/justice-department-conducts-court-authorized-disruption-botnet-controlled-russian)
- [3] [US DOJ — Disruption de la botnet KV de la RPC](https://www.justice.gov/archives/opa/pr/us-government-disrupts-botnet-peoples-republic-china-used-conceal-hacking-critical)
- [4] [CISA AA24-038A — Actores de la RPC comprometen y mantienen acceso persistente a infraestructura crítica de EE. UU.](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [5] [Google Cloud/Mandiant — Actores de espionaje vinculados a China utilizan redes ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [6] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [7] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [Kaspersky Securelist — Turla satelital](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [9] [CISA/NCSC/FBI/NSA — Aviso Cyclops Blink AA22-054A](https://www.cisa.gov/sites/default/files/publications/AA22-054A%20New%20Sandworm%20Malware%20Cyclops%20Blink%20Replaces%20VPN%20Filter.pdf)
- [10] [US DOJ — Disruption de VPNFilter de APT28](https://www.justice.gov/archives/opa/pr/justice-department-announces-actions-disrupt-advanced-persistent-threat-28-botnet-infected)
- [11] [US DOJ — Representante del Foreign Trade Bank de la DPRK acusado de conspiraciones de lavado de criptomonedas](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [12] [US Treasury — Sanciones contra Blender.io y fondos de Lazarus](https://home.treasury.gov/news/press-releases/jy0768)
- [13] [CISA AA25-239A — Contrarrestar el compromiso de redes de todo el mundo por actores patrocinados por el Estado chino](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [14] [Google Cloud/Mandiant — Ghost in the Router: UNC3886 ataca routers Juniper](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers)
