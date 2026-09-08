# Estudios de caso gubernamentales y de APT

{{#include ../banners/hacktricks-training.md}}

Estos casos públicos muestran cómo se combinan distintas técnicas de privacidad en operaciones reales. Las etiquetas de atribución son las utilizadas por los investigadores o gobiernos citados; una dirección IP, la coincidencia de herramientas o la afinidad geopolítica por sí solas no constituyen una atribución concluyente.

## APT28: acceso Wi-Fi remoto al vecino más cercano

**Hallazgo público.** Volexity atribuyó una intrusión de 2022 a GruesomeLarch/APT28. Después de que el acceso a Internet con una credencial validada fuera detenido por MFA, el actor comprometió organizaciones cercanas al objetivo y accedió a la red Wi-Fi empresarial del objetivo desde un host dual-homed cercano. La ruta Wi-Fi aceptó la credencial sin el MFA requerido externamente.<sup>[[1]](#references)</sup>

**Efecto sobre la privacidad.** El acceso final se originó desde el alcance físico de la radio y las organizaciones intermedias eran víctimas. La operación evitó desplazamientos y provocó que la geolocalización convencional basada en IP apuntara a un vecino.

**Qué lo dejó al descubierto.** La alerta del objetivo, la investigación del host/red, la actividad de las credenciales, la topología de las interfaces y la proximidad física tuvieron que analizarse como una sola cadena. El hecho anómalo no era simplemente una IP nueva; era una identidad legítima que llegaba a través de un contexto inusual de Wi-Fi/dispositivo mientras los sistemas cercanos estaban comprometidos.

**Lección defensiva.** Aplicar acceso respaldado por certificados/dispositivos a la red Wi-Fi, correlacionar RADIUS con NAC/MDM y el contexto físico, e investigar la infraestructura vecina en lugar de asumir que el último salto es el operador.

## APT28: infraestructura de Moobot criminal reutilizada por el GRU

**Hallazgo público.** En febrero de 2024, el Departamento de Justicia de EE. UU. describió una botnet de cientos de routers Ubiquiti EdgeOS. Actores criminales habían instalado Moobot en routers que conservaban credenciales de administrador predeterminadas conocidas; la Unidad 26165 del GRU añadió posteriormente scripts y archivos, convirtiendo una botnet criminal existente en una plataforma de espionaje utilizada para spearphishing y robo de credenciales.<sup>[[2]](#references)</sup>

**Efecto sobre la privacidad.** El GRU no construyó toda la infraestructura por sí mismo. Tomar prestada una flota ya comprometida colocó direcciones de hogares y pequeñas oficinas no relacionadas entre el actor y los objetivos, mezcló la actividad estatal con la actividad criminal y redujo los artefactos de registro específicos del actor.

**Qué lo dejó al descubierto.** Los archivos de los routers, el comportamiento de control del malware y la información de routing sin contenido respaldaron la investigación. La interrupción cambió temporalmente las reglas del firewall y eliminó archivos maliciosos, mientras que el DOJ advirtió que las credenciales predeterminadas sin modificar podían permitir una reinfección.

**Lección defensiva.** Sustituir los routers sin soporte, eliminar la administración expuesta a Internet, cambiar los valores predeterminados, aplicar parches, recopilar datos de configuración/flujo de los dispositivos perimetrales y buscar comportamiento de flota. Una “IP residencial de EE. UU.” no es evidencia de que el operador sea estadounidense.

## Volt Typhoon: KV Botnet más living off the land

**Hallazgo público.** El DOJ y un aviso conjunto de CISA describieron a Volt Typhoon, patrocinado por el Estado de la RPC, utilizando la KV Botnet, compuesta principalmente por routers SOHO Cisco y NETGEAR obsoletos comprometidos, para ocultar el origen de la RPC en actividades dirigidas contra infraestructura crítica. Dentro de las víctimas, el actor prefería cuentas válidas y herramientas de administración integradas; las agencias informaron de accesos que en algunos entornos duraron al menos cinco años.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
```text
PRC operator -> encrypted KV path -> compromised SOHO exit -> edge service
|
valid accounts + native tools
```
**Efecto sobre la privacidad.** La ruta similar a ORB ocultó el origen, mientras que living-off-the-land redujo los binarios novedosos y las oportunidades de detección mediante firmas después del acceso. El ocultamiento de la red y del endpoint se reforzaron mutuamente.

**Qué lo expuso.** La estructura del router/controlador, la recopilación técnica autorizada por un tribunal, la actividad recurrente y el análisis entre víctimas fueron más importantes que un único IOC. Reiniciar un router eliminó el malware KV volátil en los casos descritos, pero no corrigió la exposición subyacente del dispositivo, que ya estaba al final de su vida útil.

**Lección defensiva.** Sustituir los edge devices EOL, centralizar los logs de autenticación y de los dispositivos de red, establecer una línea base del comportamiento de los administradores, restringir la conectividad saliente y buscar secuencias de comportamiento entre las capas de identidad, endpoint y red.

## Redes ORB vinculadas a China: infraestructura como servicio

**Hallazgo público.** Mandiant describió un ecosistema de redes ORB utilizadas por múltiples actores de espionaje vinculados a China. Las redes provisioned utilizaban nodos VPS alquilados; las redes non-provisioned utilizaban IoT y routers comprometidos; y las redes híbridas combinaban ambos. ORB3/SPACEHOP respaldaba actividad asociada con APT5/APT15. ORB2/FLORAHOX combinaba un servidor de administración, servidores alquilados, una capa Tor personalizada y dispositivos Cisco, ASUS y DrayTek comprometidos. Mandiant evaluó que algunas redes eran administradas de forma independiente y alquiladas a múltiples actores APT.<sup>[[5]](#references)</sup>

**Efecto sobre la privacidad.** La infraestructura se convirtió en un límite de servicio. Un operador podía obtener salidas geográficas/residenciales sin mantener la flota de víctimas, mientras que muchos clientes compartiéndola debilitaban la asignación simple de actor a IP. La rápida rotación de la flota aceleraba la “extinción de IOC”.

**Qué lo expuso.** La topología de red, las imágenes de servidor clonadas, los puertos/servicios, las relaciones con los controladores, los implantes en routers y los patrones del ciclo de vida seguían pudiéndose agrupar. Mandiant informó que algunas IP de nodos permanecieron en una ORB tan solo 31 días.

**Lección defensiva.** Rastrear una ORB como una entidad cambiante: roles de los nodos, fingerprints de servicios, relaciones ascendentes, comportamiento de escaneo y ritmo de rotación. La expiración de un indicador IP debe actualizar el clúster, no borrar el caso.

## Sistema de espionaje global de la RPC: routers, enlaces de confianza y traffic mirroring

**Hallazgo público.** Un aviso multinacional de 2025 describió actividad que se solapaba con nombres de informes comerciales, incluidos Salt Typhoon, OPERATOR PANDA, RedMike, UNC5807 y GhostEmperor. Las agencias informaron del uso de VPS alquilados y routers intermedios comprometidos para alcanzar proveedores de telecomunicaciones y de redes. Los actores pivotaban mediante enlaces de confianza entre proveedores y clientes, modificaban rutas, construían túneles GRE/IPsec, utilizaban contenedores de dispositivos y habilitaban SPAN/RSPAN/ERSPAN o la captura nativa de paquetes para recopilar autenticación y tráfico de clientes.<sup>[[13]](#references)</sup>

**Efecto sobre la privacidad.** Un router comprometido es simultáneamente un relay, un punto de observación y un participante de confianza en la red. Las interconexiones privadas pueden eludir controles diseñados en torno a Internet público, mientras que el traffic mirroring recopila credenciales sin desplegar un agente en el endpoint.

**Qué lo expone.** Diferencias de configuración, administración SNMP/SSH/web inesperada, nuevas rutas estáticas/túneles, sesiones de mirroring, contenedores Guest Shell, archivos PCAP, cambios en los destinos TACACS+/RADIUS y logs deshabilitados. El aviso destaca que algunos routers intermedios no formaban parte de una botnet pública previamente identificada, por lo que la ausencia de indicadores ORB conocidos no era exculpatoria.

**Lección defensiva.** Utilizar administración out-of-band, logs centralizados de configuración/autenticación, comprobaciones de integridad de runtime y de imágenes firmadas, restricciones del egress de las interfaces de administración y alertas para cambios de rutas/mirroring/túneles/AAA. Ampliar el alcance de una sospecha de compromiso a través de los peers de confianza antes de realizar la expulsión.

## UNC3886 RedPenguin: backdoors pasivos en routers de ISP

**Hallazgo público.** Mandiant atribuyó a UNC3886 backdoors personalizados derivados de TINYSHELL en routers Juniper MX EOL. El conjunto incluía implantes activos y pasivos, nombres que imitaban daemons legítimos, comportamiento de desactivación de logs, process injection en un proceso de confianza, capacidad de proxy SOCKS e infraestructura evaluada como nodos de staging ORB. Las variantes pasivas inspeccionaban paquetes mediante `libpcap` y solo se activaban tras detectar un patrón mágico; una podía cambiar a un callback activo proporcionado en el trigger.<sup>[[14]](#references)</sup>

**Efecto sobre la privacidad.** Un implante pasivo no tiene un beacon periódico que permita descubrirlo. Comparte puertos/tráfico con un dispositivo de red real, se activa brevemente y puede retransmitir mediante una ORB en lugar de conectarse directamente a un controlador final.

**Qué lo expone.** El análisis de memoria, las diferencias entre el código en disco y el código en ejecución, los filtros de captura de paquetes o el comportamiento inesperado de sockets, los nombres de procesos/archivos que solo se aproximan a daemons legítimos, la administración mediante servidores de terminales, los logs ausentes y la relación en dos etapas entre los nodos de staging y un controlador backend.

**Lección defensiva.** Adquirir tanto la memoria como las pruebas del sistema de archivos/configuración, comparar los procesos/módulos con una imagen conocida como válida, monitorizar el uso de captura de paquetes/filtros de sockets, proteger los servidores de terminales de administración y sustituir el hardware de red EOL. Una búsqueda limpia de beacons salientes no garantiza que el sistema esté limpio.

## APT29: domain fronting con Tor

**Hallazgo público.** MITRE registra que APT29 utilizó el transporte conectable `meek` de Tor para realizar domain fronting del tráfico C2. El nombre TLS externo parecía ser un dominio permitido alojado en una CDN, mientras que el host HTTP interno seleccionaba la ruta real.<sup>[[6]](#references)</sup>

**Efecto sobre la privacidad.** Un observador que filtrara el tráfico podía ver un front/CDN común en lugar del destino interno, y bloquearlo podía causar daños colaterales.

**Qué lo expone.** La CDN puede observar la discrepancia de enrutamiento, y un defensor con visibilidad del endpoint o de TLS obtenida legalmente puede correlacionar el proceso, la autoridad, la duración de la conexión, el patrón de bytes y la actividad posterior. Los cambios en las políticas del proveedor pueden deshabilitar la técnica.

**Lección defensiva.** No depender únicamente de allowlisting de SNI. Aplicar egress con conocimiento de la aplicación, comparar las identidades TLS y HTTP cuando sean visibles y vincular el evento de red con el proceso que lo inició.

## APT41 y otros dead-drop resolvers

**Hallazgo público.** MITRE documenta que APT41 utilizó sitios legítimos, incluidos GitHub, Pastebin, Microsoft TechNet, Cloudflare y foros comunitarios, para publicar o recuperar información de C2. Otras herramientas vinculadas a Estados también han utilizado publicaciones, documentos y redes sociales de forma similar.<sup>[[7]](#references)</sup>

**Efecto sobre la privacidad.** Un binario contiene un servicio/objeto legítimo en lugar de una dirección C2 estable. El objeto puede editarse para rotar la infraestructura, y la solicitud inicial se mezcla con el tráfico TLS común.

**Qué lo expone.** El objeto o identificador de cuenta es estable; procesos poco frecuentes lo descargan repetidamente; el contenido se decodifica; y después se produce una segunda conexión saliente. Los registros de la cuenta del proveedor y de la API pueden vincular la publicación con el operador.

**Lección defensiva.** Conservar las rutas completas del proxy y los object IDs, así como la process lineage del endpoint. Un evento a nivel de dominio como “conectado a GitHub” es demasiado impreciso.

## Turla: C2 mediante direcciones de satélite

**Hallazgo público.** Kaspersky informó de que Turla abusaba de broadcasts descendentes no cifrados de servicios de Internet DVB-S unidireccionales antiguos. Un operador dentro de la huella del satélite podía seleccionar la dirección de un suscriptor legítimo y recibir las respuestas transmitidas a ella, haciendo que el C2 pareciera estar alojado detrás de un proveedor de satélite en otra región.<sup>[[8]](#references)</sup>

**Efecto sobre la privacidad.** La dirección aparente del servidor no identificaba al receptor, y los procesos convencionales de incautación del hosting/WHOIS eran menos útiles.

**Qué lo expone.** El actor aún necesitaba una ruta de solicitud saliente, el enrutamiento era asimétrico, el suscriptor legítimo no iniciaba el intercambio C2 y la investigación de RF/proveedor podía acotar la zona de recepción.

**Lección defensiva.** Tratar la geolocalización como una hipótesis. Validar la simetría de la ruta, el RTT, la titularidad del enrutamiento y si el supuesto endpoint podía producir realmente el servicio observado.

## Cyclops Blink y VPNFilter: edge devices como cobertura duradera

**Hallazgo público.** Un aviso de NCSC/CISA/FBI/NSA de 2022 describió el malware modular Cyclops Blink de Sandworm en dispositivos WatchGuard, desplegado persistentemente como una actualización de firmware y capaz de añadir módulos. Por separado, el DOJ describió la botnet VPNFilter anterior de APT28, formada por routers y dispositivos NAS, como capaz de realizar recopilación de inteligencia, actividad destructiva y misattribution.<sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>

**Efecto sobre la privacidad.** Los edge appliances están continuamente conectados, se consideran infraestructura de confianza y están poco cubiertos por EDR. La persistencia en el firmware puede sobrevivir a un reinicio normal y convertir el dispositivo de la víctima en un relay o punto de control.

**Qué lo expone.** La integridad del firmware, el protocolo del implante específico del proveedor, la exposición inesperada de la administración, los cambios de configuración y los beacons salientes. Los edge devices deben ser sujetos forenses, no plumbing transparente.

## DPRK: estratificación de identidad, red y finanzas

**Hallazgo público.** Los casos del DOJ describen a trabajadores de la DPRK obteniendo empleos remotos mediante material de identidad falso o robado y VPNs, recibiendo criptomonedas, dividiendo transferencias, intercambiando activos/cadenas, utilizando NFTs y mezclando fondos. Otros casos describen a traders OTC y empresas pantalla convirtiendo criptomonedas robadas en compras. Treasury y el FBI han vinculado públicamente fondos de Lazarus/TraderTraitor con mixers e identificado direcciones procedentes de robos importantes.<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup>

**Efecto sobre la privacidad.** Esto no es “una private coin”. Es una cadena multidominio: la persona y el acceso remoto ocultan la ubicación del trabajador; las criptomonedas mueven el valor; la estratificación rompe las narrativas transaccionales simples; y los traders OTC/empresas pantalla conectan con bienes y dinero fiat.

**Qué lo expone.** Las anomalías del empleador/dispositivo, los facilitadores reutilizados, la continuidad temporal y de valor en la blockchain, los registros de exchanges/bridges, las direcciones sancionadas y los registros de identidad de cuentas y de envíos/empresas vuelven a conectar la cadena.

**Lección defensiva.** Los equipos de contratación, IAM, endpoint, nóminas, blockchain y sanciones necesitan un modelo de caso compartido. Hay más detalles en [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md).

## Patrones entre casos

| Patrón | Ejemplos de APT | Adaptación del defensor |
|---|---|---|
| La salida es otra víctima | APT28/Moobot, Volt Typhoon/KV, ORBs | investigar y remediar la salida; no equipararla con la ubicación del actor |
| Los controles difieren según el límite | APT28 nearest neighbor | proporcionar al acceso interno/inalámbrico la misma garantía de identidad que al acceso desde Internet |
| El servicio legítimo es una capa de enrutamiento | APT29, APT41 | conservar el contexto de objeto/ruta/proceso, no solo el dominio de destino |
| Los edge devices carecen de telemetría | KV, Moobot, Cyclops Blink, ORBs | centralizar los logs de configuración/autenticación/flujo y verificar el firmware/inventario |
| La infraestructura es compartida y de corta duración | ORBs vinculadas a China | agrupar el comportamiento/topología y rastrear los cambios de rol a lo largo del tiempo |
| Varias separaciones débiles se combinan | Personas de la DPRK + VPN + criptomonedas + OTC | unir las pruebas de identidad, dispositivo, red, pagos y elementos físicos |

## References

- [1] [Volexity — El ataque Nearest Neighbor](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [US DOJ — Interrupción de la botnet de routers Moobot controlada por la GRU](https://www.justice.gov/archives/opa/pr/justice-department-conducts-court-authorized-disruption-botnet-controlled-russian)
- [3] [US DOJ — Interrupción de la botnet KV de la RPC](https://www.justice.gov/archives/opa/pr/us-government-disrupts-botnet-peoples-republic-china-used-conceal-hacking-critical)
- [4] [CISA AA24-038A — Actores de la RPC comprometen y mantienen acceso persistente a infraestructuras críticas de EE. UU.](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [5] [Google Cloud/Mandiant — Actores de espionaje vinculados a China utilizan redes ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [6] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [7] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [Kaspersky Securelist — Turla por satélite](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [9] [CISA/NCSC/FBI/NSA — Aviso Cyclops Blink AA22-054A](https://www.cisa.gov/sites/default/files/publications/AA22-054A%20New%20Sandworm%20Malware%20Cyclops%20Blink%20Replaces%20VPN%20Filter.pdf)
- [10] [US DOJ — Interrupción de VPNFilter de APT28](https://www.justice.gov/archives/opa/pr/justice-department-announces-actions-disrupt-advanced-persistent-threat-28-botnet-infected)
- [11] [US DOJ — Representante del Foreign Trade Bank de la DPRK acusado de conspiraciones de blanqueo de criptomonedas](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [12] [US Treasury — Sanciones contra Blender.io y fondos de Lazarus](https://home.treasury.gov/news/press-releases/jy0768)
- [13] [CISA AA25-239A — Contrarrestar el compromiso de redes en todo el mundo por parte de actores patrocinados por el Estado chino](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [14] [Google Cloud/Mandiant — Ghost in the Router: UNC3886 ataca routers Juniper](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers)
{{#include ../banners/hacktricks-training.md}}
