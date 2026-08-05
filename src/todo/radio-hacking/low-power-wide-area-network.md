# Red de área amplia de bajo consumo

{{#include ../../banners/hacktricks-training.md}}

## Introducción

**Low-Power Wide Area Network** (LPWAN) es un grupo de tecnologías inalámbricas de red de área amplia y bajo consumo, diseñadas para **comunicaciones de largo alcance** a una velocidad de bits baja.
Pueden alcanzar más de **seis millas** y sus **baterías** pueden durar hasta **20 años**.

Long Range (**LoRa**) es actualmente la capa física LPWAN más implementada y su especificación abierta de la capa MAC es **LoRaWAN**.

---

## LPWAN, LoRa y LoRaWAN

* LoRa – Capa física Chirp Spread Spectrum (CSS) desarrollada por Semtech (propietaria, pero documentada).
* LoRaWAN – Capa MAC/Network abierta mantenida por LoRa-Alliance. Las versiones 1.0.x y 1.1 son comunes en entornos reales.
* Arquitectura típica: *end-device → gateway (packet-forwarder) → network-server → application-server*.

> El **modelo de seguridad** depende de dos claves raíz AES-128 (AppKey/NwkKey) que derivan claves de sesión durante el procedimiento de *join* (OTAA) o están codificadas de forma fija (ABP). Si alguna clave sufre un leak, el atacante obtiene capacidad total de lectura/escritura sobre el tráfico correspondiente.

---

## Resumen de la superficie de ataque

| Capa | Debilidad | Impacto práctico |
|-------|----------|------------------|
| PHY | Jamming reactivo / selectivo | Pérdida del 100 % de los paquetes demostrada con un único SDR y una salida inferior a 1 W |
| MAC | Replay de Join-Accept y tramas de datos (reutilización de nonce, rollover del contador ABP) | Suplantación de dispositivos, inyección de mensajes, DoS |
| Network-Server | packet-forwarder inseguro, filtros MQTT/UDP débiles, firmware de gateway obsoleto | RCE en gateways → pivotaje hacia la red OT/IT |
| Application | AppKeys codificadas de forma fija o predecibles | Fuerza bruta/descifrado del tráfico, suplantación de sensores |

---

## Vulnerabilidades recientes (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge & mqtt-forwarder* aceptaban paquetes TCP que eludían las reglas del firewall con estado en gateways Kerlink, permitiendo la exposición de la interfaz de gestión remota. Corregido en 4.0.11 / 4.2.1, respectivamente .
* **Serie Dragino LG01/LG308** – Múltiples CVE de 2022-2024 (por ejemplo, 2022-45227 directory traversal, 2022-45228 CSRF) todavía se observaban sin parchear en 2025; permitían un firmware dump no autenticado o sobrescribir la configuración en miles de gateways públicos .
* Desbordamiento de *packet-forwarder UDP* de Semtech (advisory no publicado, parcheado en 2023-10): un uplink manipulado de más de 255 B activaba un stack-smash ‑> RCE en gateways de referencia SX130x (descubierto por Black Hat EU 2023, “LoRa Exploitation Reloaded”).

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
### 2. Join-replay OTAA (reutilización de DevNonce)

1. Captura un **JoinRequest** legítimo.
2. Retransmítelo inmediatamente (o incrementa el RSSI) antes de que el dispositivo original vuelva a transmitir.
3. El network-server asigna un nuevo DevAddr y nuevas session keys, mientras el dispositivo objetivo continúa con la sesión antigua → el atacante controla la sesión vacante y puede inyectar uplinks falsificados.

### 3. Degradación del Adaptive Data-Rate (ADR)

Fuerza SF12/125 kHz para aumentar el airtime → agota el duty-cycle del gateway (denial-of-service), manteniendo bajo el impacto en la batería del atacante (solo envía comandos MAC a nivel de red).

### 4. Jamming reactivo

*HackRF One*, ejecutando un flowgraph de GNU Radio, activa un chirp de banda ancha cada vez que detecta un preámbulo; bloquea todos los spreading factors con ≤200 mW de TX; se midió una interrupción total a una distancia de 2 km.

---

## Herramientas ofensivas (2025)

| Herramienta | Propósito | Notas |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Crear/analizar/atacar frames de LoRaWAN, analizadores respaldados por DB, brute-forcer | Imagen de Docker, compatible con entrada UDP de Semtech |
| **LoRaPWN** | Utilidad Python de Trend Micro para brute-force de OTAA, generar downlinks y descifrar payloads | Demo publicada en 2023, independiente del SDR |
| **LoRAttack** | Sniffer multicanal + replay con USRP; exporta PCAP/LoRaTap | Buena integración con Wireshark |
| **gr-lora / gr-lorawan** | Bloques OOT de GNU Radio para TX/RX de banda base | Base para ataques personalizados |

---

## Recomendaciones defensivas (checklist de pentester)

1. Prefiere dispositivos **OTAA** con DevNonce realmente aleatorio; supervisa los duplicados.
2. Aplica **LoRaWAN 1.1**: contadores de frames de 32 bits, FNwkSIntKey / SNwkSIntKey distintos.
3. Almacena el contador de frames en memoria no volátil (**ABP**) o migra a OTAA.
4. Implementa un **secure-element** (ATECC608A/SX1262-TRX-SE) para proteger las root keys contra la extracción del firmware.
5. Deshabilita los puertos UDP remotos del packet-forwarder (1700/1701) o restríngeos mediante WireGuard/VPN.
6. Mantén los gateways actualizados; Kerlink/Dragino proporcionan imágenes parcheadas en 2024.
7. Implementa **detección de anomalías de tráfico** (por ejemplo, el analizador de LAF); marca los reinicios de contadores, los joins duplicados y los cambios repentinos de ADR.<sup>[[1]](#references)</sup>



## Referencias

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Descripción general de Trend Micro LoRaPWN](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)

{{#include ../../banners/hacktricks-training.md}}
