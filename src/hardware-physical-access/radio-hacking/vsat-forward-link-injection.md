# Inyección de señal en el enlace de bajada VSAT

{{#include ../../banners/hacktricks-training.md}}

Un terminal VSAT normalmente trata la señal de bajada del satélite como tráfico proveniente del hub del operador. En un sistema DVB-RCS, ese enlace de bajada puede transportar tanto paquetes IP de usuario como mensajes de control del módem. Si el receptor no autentica un mensaje antes de procesarlo, una señal inyectada localmente puede cruzar el límite de confianza entre la radio y el plano de control. Esto es **inyección del enlace de bajada en el terminal**, no una transmisión de subida al satélite ni una interceptación pasiva del enlace de bajada. El resultado demostrado depende de la implementación del protocolo y de la autenticación de mensajes del módem, no solo de DVB-RCS.<sup>[[1]](#references)[[2]](#references)</sup>

## Pruebas en un laboratorio con RF contenida

Usa un terminal propio, su firmware y un SDR conectado a la entrada de recepción del módem mediante la atenuación adecuada, o una configuración de RF blindada. No transmitas por un canal satelital activo. Primero, registra la portadora de inicio configurada en el terminal, la tasa de símbolos y el ID de población; estos datos ayudan a adquirir el enlace de bajada.<sup>[[1]](#references)[[3]](#references)</sup> La cadena de adquisición DVB-RCS utiliza la Network Information Table (NIT) para localizar la RCS Map Table (RMT) y, después, la Program Association Table (PAT) y la Program Map Table (PMT) para localizar los flujos de señalización del enlace de bajada. El terminal puede resintonizar varias portadoras de flujo de transporte antes de llegar al flujo de datos.<sup>[[3]](#references)</sup>

1. Decodifica o reconstruye el flujo de transporte de inicio del objetivo e inspecciona su NIT, RMT, ID de servicio, ID de paquete (PID) y gestión de referencias de reloj. Compara el estándar con el parser y los registros del objetivo; un orden o unos descriptores específicos del proveedor pueden hacer que no se acepte un flujo que, de otro modo, sería válido.
2. En el transmisor del laboratorio, encapsula una sonda UDP inocua como `UDP/IP → MPE → MPEG-TS → DVB-S2 I/Q` y envíala mediante una salida SDR a la ruta de recepción aislada. Mantén el Program Clock Reference (PCR) del flujo de transporte coherente con la tasa de bytes; de lo contrario, el módem podría perder la sincronización antes de procesar la sonda.
3. Confirma tanto el **bloqueo del demodulador** como la recepción de la sonda en un endpoint interno propio. El bloqueo solo demuestra que la capa física aceptó la forma de onda. Después, comprueba si la *señalización* de administración o actualización sin autenticar está expuesta, sin instalar una imagen ni cambiar la configuración del servicio.

El caso publicado del MDM2200 utilizó un módulo de origen de GNU Radio para DVB-RCS/MPE/MPEG-TS y `gr-dtv` para la modulación DVB-S2. El módem requería detalles de inicialización específicos del objetivo: una SDT antes de la PAT/PMT, un descriptor de contenido RCS con el ID de tabla `0x3E` y un byte privado de RMT de `0x01` para su modo GSE/4CPM. No des por hecho que esos valores funcionen en otro terminal.<sup>[[1]](#references)</sup> Los investigadores también observaron que los paquetes MPE multicast llegaban a los módems receptores en su configuración, por lo que el objetivo no se limitaba a una dirección MAC unicast conocida.<sup>[[1]](#references)</sup> Otro análisis encontró señalización de control y actualización de software sin protección en el sistema estudiado, pero ese hallazgo debe verificarse en cada implementación.<sup>[[2]](#references)</sup>

Un túnel IPsec o VPN para el tráfico de usuario no autentica la señalización DVB-RCS anterior ni el parser de actualización propio del módem. En una evaluación autorizada, distingue entre la protección criptográfica de **la IP de usuario**, **el control del enlace de bajada** y el tráfico de **mantenimiento/recuperación**, en vez de considerar que un túnel de usuario seguro demuestra que la inyección por radio está bloqueada.<sup>[[1]](#references)[[2]](#references)</sup>

Para una inspección inicial de I/Q, consulta [análisis de señales de radio](../hardware-hacking/radio.md). Para inspeccionar el firmware y el parser desde la placa, consulta [análisis de firmware](../firmware-analysis/). Vuelve a la [página general de Radio Hacking](./) para ver otras interfaces.

## References

- [1] [Bisping et al. - Ataques de inyección de señales inalámbricas contra módems satelitales VSAT (USENIX Security 2024)](https://www.usenix.org/system/files/usenixsecurity24-bisping.pdf)
- [2] [Willbold et al. - VSAsTer: Descubriendo problemas de seguridad inherentes a las prácticas actuales de los sistemas VSAT (WiSec 2024)](https://www.lenders.ch/publications/conferences/wisec24.pdf)
- [3] [ETSI EN 301 790 - Canal de interacción DVB para sistemas de distribución por satélite](https://www.etsi.org/deliver/etsi_en/301700_301799/301790/01.04.01_40/en_301790v010401o.pdf)
{{#include ../../banners/hacktricks-training.md}}
