# Red de área amplia de baja potencia

{{#include ../../banners/hacktricks-training.md}}

## Introducción

**Low-Power Wide Area Network** (LPWAN) es un grupo de tecnologías inalámbricas de red de área amplia y baja potencia, diseñadas para **comunicaciones de largo alcance** a una velocidad de bits baja.
Según los parámetros de radio, la antena, la región regulatoria, el terreno y el ciclo de trabajo, las implementaciones de LPWAN pueden sacrificar rendimiento para obtener cobertura de varios kilómetros y una duración de batería de varios años. Considere las cifras de alcance y duración de batería de los proveedores como objetivos de diseño, no como garantías.<sup>[[3]](#references)</sup>

Long Range (**LoRa**) es actualmente la capa física de LPWAN más implementada, y su especificación abierta de capa MAC es **LoRaWAN**.

---

## LPWAN, LoRa y LoRaWAN

* LoRa – Capa física Chirp Spread Spectrum (CSS) desarrollada por Semtech (propietaria, pero documentada).
* LoRaWAN – Capa MAC/Network abierta mantenida por LoRa-Alliance. Las versiones 1.0.x y 1.1 son comunes en las implementaciones actuales.
* Arquitectura típica: *dispositivo final → gateway (packet-forwarder) → servidor de red → servidor de aplicaciones*.<sup>[[3]](#references)</sup>

> En LoRaWAN 1.1, el **modelo de seguridad** usa claves raíz de aplicación y de red AES-128 separadas para derivar claves de sesión específicas de cada función durante OTAA. Las implementaciones anteriores de la versión 1.0.x suelen usar una AppKey para derivar las claves de sesión de red y de aplicación, mientras que ABP aprovisiona directamente las claves de sesión. Por tanto, las capacidades que se obtienen de una clave filtrada dependen de la versión de LoRaWAN y de cuál sea la clave expuesta.<sup>[[3]](#references)</sup>

---

## Resumen de la superficie de ataque

| Capa | Vulnerabilidad | Impacto práctico |
|-------|----------|------------------|
| PHY | Jamming reactivo/selectivo | Pérdida localizada de paquetes; la eficacia depende del presupuesto de enlace, la temporización, el ancho de banda y las restricciones regulatorias |
| MAC | Reproducción de tramas de unión y de datos cuando se reutiliza el estado de nonce/contador | Desincronización de dispositivos, suplantación o inyección si el servidor/dispositivo no aplica las protecciones contra replay |
| Network-Server | packet-forwarder inseguro, filtros MQTT/UDP débiles, firmware de gateway desactualizado | RCE en gateways → pivot a la red OT/IT |
| Aplicación | AppKeys codificadas o predecibles | Fuerza bruta/descifrado del tráfico, suplantación de sensores |

---

## Vulnerabilidades representativas en implementaciones

* **CVE-2024-29862** – Las versiones de ChirpStack Gateway Bridge anteriores a la 4.0.11 y las versiones de MQTT Forwarder anteriores a la 4.2.1 podían conectarse a un broker MQTT controlado por un atacante porque la validación del certificado TLS del servidor estaba deshabilitada. Esto podía exponer credenciales y tráfico de gateway; actualice a las versiones corregidas.<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – CVE-2022-45227 describe un listado del directorio `/lib/` sin autenticación que contiene un archivo de copia de seguridad descargable; CVE-2022-45228 es una CSRF de baja gravedad en la página de cierre de sesión. Estos registros no confirman el impacto atribuido al LG308, la sobrescritura de configuración, el tamaño de la población afectada ni el estado de los parches en 2025.<sup>[[6]](#references)[[7]](#references)</sup>
* Una versión anterior de esta página describía un supuesto problema del packet-forwarder UDP de Semtech como **un uplink manipulado de más de 255 bytes que provocaba un stack smash y RCE en gateways de referencia SX130x**, atribuido a una presentación de Black Hat Europe 2023 titulada “LoRa Exploitation Reloaded” y a un parche privado de octubre de 2023. Estos detalles concretos se conservan aquí como pista de investigación, pero no se pudo corroborar ningún aviso público, presentación o parche coincidente. No considere el problema una vulnerabilidad conocida sin obtener el producto/versión afectado y una fuente primaria verificable.

---

## Técnicas prácticas de ataque

### 1. Sniff & Decrypt traffic

```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
    --freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```

Estos comandos conservan el flujo de trabajo original como **sintaxis ilustrativa**; la estructura del repositorio y las flags varían según el proyecto y la versión. La captura pasiva no revela una AppKey sólida. El guessing offline solo es útil si la clave raíz es lo bastante débil como para encontrarla y una comunicación de unión capturada proporciona un valor que permita validar candidatos.<sup>[[2]](#references)[[3]](#references)</sup>

### 2. Probar la protección contra replay de OTAA y el estado de nonce

1. En una red de pruebas autorizada, captura un **JoinRequest** legítimo.
2. Reproduce la misma solicitud y confirma que el servidor de red rechace el `DevNonce` reutilizado.
3. Reinicia o restablece el dispositivo de prueba y repite la comprobación para detectar si se pierde el estado de nonce. Un servidor que cumpla con la especificación debe llevar un registro de los nonces utilizados; reproducir un JoinRequest por sí solo no revela las claves de sesión recién derivadas ni permite al atacante controlar una sesión.<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Degradación de Adaptive Data-Rate (ADR)

Un atacante que pueda autenticar comandos MAC de la capa de red —por ejemplo, tras comprometer la clave de sesión de red correspondiente o el servidor de red— podría intentar forzar parámetros de tasa de datos ineficientes y aumentar el tiempo en el aire. Un transmisor cercano sin autenticar no puede emitir legítimamente comandos ADR con solo conocer la dirección de un dispositivo.<sup>[[3]](#references)</sup>

### 4. Jamming reactivo

Un jammer reactivo puede transmitir tras detectar un preámbulo LoRa e interrumpir selectivamente las tramas. La página anterior afirmaba que una configuración de HackRF/GNU Radio provocó una interrupción total a **2 km con no más de 200 mW**, pero no se proporcionó ninguna fuente que respaldara esa medición; conserva esas cifras solo como objetivo de reproducción, no como resultado esperado. La potencia de transmisión, la temporización, el ancho de banda, los factores de dispersión afectados y el alcance necesarios dependen del entorno. Haz pruebas solo en una configuración autorizada y con contención de RF, y cumple las normas locales sobre el espectro.

---

## Herramientas ofensivas (2025)

| Herramienta | Propósito | Notas |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Crear y analizar tramas LoRaWAN, atacarlas, usar analizadores con base de datos y hacer brute force | Imagen de Docker; admite entrada UDP de Semtech<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Utilidad de Python de Trend Micro para hacer brute force de OTAA, generar downlinks y descifrar payloads | Utilidad de investigación pública; verifica el hardware y las versiones del protocolo compatibles<sup>[[2]](#references)</sup> |
| **LoRAttack** | Framework de investigación para captura LoRaWAN multicanal, análisis de sesiones, derivación de claves y pruebas de replay | Descrito en una tesis de máster de 2024; obtén y verifica la implementación exacta antes de confiar en las flags del ejemplo<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | Bloques out-of-tree de GNU Radio para recepción de banda base LoRa o investigación de transceptores | Los proyectos varían en compatibilidad con GNU Radio y en el conjunto de funciones<sup>[[9]](#references)</sup> |

---

## Recomendaciones defensivas (lista de verificación de pentester)

1. Prioriza **OTAA** y verifica que los dispositivos y servidores conserven el estado de nonce requerido; supervisa los intentos de unión duplicados rechazados.
2. Prioriza **LoRaWAN 1.1** cuando sea compatible, para que las funciones de red utilicen claves de sesión distintas y una gestión de nonce actualizada.<sup>[[3]](#references)</sup>
3. Almacena el contador de tramas en memoria no volátil (**ABP**) o migra a OTAA.
4. Implementa un **secure element** adecuado (por ejemplo, ATECC608A en un diseño compatible) para reducir la exposición de las claves raíz en el almacenamiento habitual del firmware.
5. No expongas a redes no confiables los listeners UDP configurados del packet-forwarder (comúnmente el puerto 1700); autentica y cifra el backhaul del gateway o restríngelo mediante una VPN.
6. Mantén los gateways con firmware compatible con el soporte del fabricante y verifica que el modelo y la versión exactos estén cubiertos por los avisos aplicables.
7. Implementa **detección de anomalías de tráfico** (p. ej., el analizador LAF): marca los reinicios de contador, las uniones duplicadas y los cambios repentinos de ADR.<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Resumen de LoRaPWN de Trend Micro](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - Especificación LoRaWAN L2 1.1](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - Parámetros regionales de LoRaWAN 1.1 y sincronización de unión](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [Catálogo de tesis de CTU - Análisis de seguridad de protocolos LPWAN mediante tecnología SDR](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [Transceptor GNU Radio `gr-lora_sdr` de EPFL](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
