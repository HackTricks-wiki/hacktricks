# Red de Área Amplia de Baja Potencia

{{#include ../../banners/hacktricks-training.md}}

## Introducción

**Low-Power Wide Area Network** (LPWAN) es un grupo de tecnologías de red inalámbricas de baja potencia y área amplia diseñadas para **comunicaciones de largo alcance** a una baja tasa de bits.
Dependiendo de los parámetros de radio, la antena, la región regulatoria, el terreno y el duty cycle, las implementaciones de LPWAN pueden intercambiar rendimiento por una cobertura de varios kilómetros y una duración de batería de varios años. Considera las cifras de alcance y batería de los proveedores como objetivos de diseño, no como garantías.<sup>[[3]](#references)</sup>

Long Range (**LoRa**) es actualmente la physical layer de LPWAN más implementada y su especificación abierta de la capa MAC es **LoRaWAN**.

---

## LPWAN, LoRa y LoRaWAN

* LoRa – Physical layer de Chirp Spread Spectrum (CSS) desarrollada por Semtech (propietaria, pero documentada).
* LoRaWAN – Capa MAC/Network abierta mantenida por LoRa-Alliance. Las versiones 1.0.x y 1.1 son comunes en entornos reales.
* Arquitectura típica: *end-device → gateway (packet-forwarder) → network-server → application-server*.<sup>[[3]](#references)</sup>

> En LoRaWAN 1.1, el **modelo de seguridad** utiliza claves raíz de aplicación y de red AES-128 independientes para derivar session keys específicas de cada rol durante OTAA. Las implementaciones anteriores de 1.0.x normalmente utilizan una única AppKey para derivar las claves de sesión de red y aplicación, mientras que ABP aprovisiona directamente las claves de sesión. Por tanto, la capacidad obtenida de una clave filtrada depende de la versión de LoRaWAN y de qué clave haya quedado expuesta.<sup>[[3]](#references)</sup>

---

## Resumen de la superficie de ataque

| Capa | Debilidad | Impacto práctico |
|-------|----------|------------------|
| PHY | Jamming reactivo / selectivo | Pérdida de paquetes localizada; la efectividad depende del link budget, el timing, el ancho de banda y las restricciones regulatorias |
| MAC | Replay de joins y data-frames cuando se reutiliza el estado de nonce/counter | Desincronización del dispositivo, spoofing o injection si el servidor/dispositivo incumple las protecciones contra replay |
| Network-Server | Packet-forwarder inseguro, filtros MQTT/UDP débiles, firmware de gateway obsoleto | RCE en gateways → pivot hacia la red OT/IT |
| Application | AppKeys hard-coded o predecibles | Fuerza bruta/descifrado del tráfico, suplantación de sensores |

---

## Vulnerabilidades representativas de implementaciones

* **CVE-2024-29862** – Las versiones de ChirpStack Gateway Bridge anteriores a 4.0.11 y las versiones de MQTT Forwarder anteriores a 4.2.1 podían conectarse a un MQTT broker controlado por un atacante porque la validación del certificado del servidor TLS estaba deshabilitada. Esto podía exponer credenciales y tráfico del gateway; actualiza a las versiones corregidas.<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – CVE-2022-45227 describe un listado no autenticado del directorio `/lib/` que contenía un archivo de backup descargable; CVE-2022-45228 es un CSRF de baja severidad en la página de logout. Estos registros no establecen el impacto declarado sobre LG308, la sobrescritura de configuración, el tamaño de la población ni el estado de los parches de 2025.<sup>[[6]](#references)[[7]](#references)</sup>
* Una versión anterior de esta página describía un supuesto problema del Semtech UDP packet-forwarder como un **uplink diseñado de más de 255 bytes que provocaba un stack smash y RCE en gateways de referencia SX130x**, atribuido a una presentación de Black Hat Europe 2023 titulada “LoRa Exploitation Reloaded” y a un parche privado de octubre de 2023. Esos detalles específicos se conservan aquí como una línea de investigación, pero no se pudo corroborar ningún advisory, presentación o parche público coincidente. No consideres el problema una vulnerabilidad conocida sin obtener el producto/versión afectados y una fuente primaria verificable.

---

## Técnicas de ataque prácticas

### 1. Sniff & Decrypt traffic
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
Estos comandos conservan el flujo de trabajo original como **sintaxis ilustrativa**; la estructura del repositorio y los flags difieren entre proyectos/releases. La captura pasiva no revela una AppKey sólida. La adivinación offline solo es útil cuando la root key es lo suficientemente débil como para encontrarla y un intercambio de join capturado proporciona un valor que permite validar candidatos.<sup>[[2]](#references)[[3]](#references)</sup>

### 2. Probar la protección contra replay de OTAA y el estado de los nonces

1. En una red de pruebas autorizada, captura un **JoinRequest** legítimo.
2. Reproduce la misma solicitud y confirma que el network server rechaza el `DevNonce` reutilizado.
3. Reinicia o restablece el dispositivo de pruebas y repite la comprobación para detectar la pérdida del estado de los nonces. Un servidor conforme debe realizar un seguimiento de los nonces usados; reproducir un JoinRequest por sí solo no revela las session keys recién derivadas ni proporciona al atacante el control de una sesión.<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Degradación de Adaptive Data-Rate (ADR)

Un atacante que pueda autenticar comandos MAC de la capa de red —por ejemplo, después de comprometer la network session key aplicable o el network server— puede intentar forzar parámetros ineficientes de data-rate y aumentar el airtime. Un transmisor no autenticado cercano no puede emitir legítimamente comandos ADR simplemente conociendo la dirección de un dispositivo.<sup>[[3]](#references)</sup>

### 4. Jamming reactivo

Un jammer reactivo puede transmitir después de detectar un preámbulo LoRa e interrumpir selectivamente las tramas. La página anterior afirmaba que una configuración de HackRF/GNU Radio provocaba una interrupción total a **2 km con no más de 200 mW**, pero no se proporcionó ninguna fuente de medición que lo respaldara; conserva esas cifras solo como objetivo de reproducción, no como resultado esperado. La potencia de transmisión, el timing, el ancho de banda, los spreading factors afectados y el alcance necesarios dependen del entorno. Realiza pruebas únicamente dentro de una configuración autorizada y con RF contenida, y cumple las normas locales sobre el espectro.

---

## Herramientas ofensivas (2025)

| Tool | Purpose | Notes |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Crear/analizar/atacar tramas LoRaWAN, analizadores respaldados por DB, brute-forcer | Imagen de Docker; admite entrada UDP de Semtech<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Utility de Python de Trend Micro para hacer brute-force de OTAA, generar downlinks y descifrar payloads | Utility de investigación pública; verifica el hardware y las versiones del protocolo compatibles<sup>[[2]](#references)</sup> |
| **LoRAttack** | Framework de investigación para captura LoRaWAN multicanal, análisis de sesiones, derivación de claves y pruebas de replay | Descrito en una tesis de máster de 2024; obtén y verifica la implementación exacta antes de confiar en los flags del ejemplo<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | Bloques out-of-tree de GNU Radio para recepción de banda base LoRa o investigación de transceptores | Los proyectos difieren en compatibilidad con GNU Radio y conjunto de funcionalidades<sup>[[9]](#references)</sup> |

---

## Recomendaciones defensivas (checklist de pentester)

1. Da preferencia a **OTAA** y verifica que los dispositivos y servidores conserven el estado de los nonces requerido; monitoriza los joins duplicados rechazados.
2. Da preferencia a **LoRaWAN 1.1** cuando sea compatible, para que las funciones de red utilicen session keys distintas y un manejo actualizado de los nonces.<sup>[[3]](#references)</sup>
3. Almacena el frame-counter en memoria no volátil (**ABP**) o migra a OTAA.
4. Implementa un **secure element** adecuado (por ejemplo, ATECC608A en un diseño compatible) para reducir la exposición de las root keys en el almacenamiento de firmware habitual.
5. No expongas listeners UDP configurados del packet-forwarder (normalmente el puerto 1700) a redes no confiables; autentica/cifra el backhaul del gateway o restríngelo mediante una VPN.
6. Mantén los gateways con firmware compatible con el soporte del fabricante y confirma el modelo/versión exactos frente a los advisories aplicables.
7. Implementa **detección de anomalías de tráfico** (p. ej., el analizador de LAF): marca resets de contadores, joins duplicados y cambios repentinos de ADR.<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Descripción general de LoRaPWN de Trend Micro](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - especificación LoRaWAN L2 1.1](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - parámetros regionales de LoRaWAN 1.1 y sincronización de joins](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [Catálogo de tesis de CTU - Análisis de seguridad de protocolos LPWAN mediante tecnología SDR](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [Transceptor GNU Radio `gr-lora_sdr` de EPFL](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
