# Información en impresoras

{{#include ../../banners/hacktricks-training.md}}

Una impresora con credenciales LDAP guardadas puede exponerlas si se cambia la configuración del servidor y luego se autentica en un endpoint malicioso.<sup>[[2]](#references)</sup> El resultado depende del método de bind: un simple bind sin protección revela la contraseña, mientras que un bind de desafío-respuesta SASL no la revela en texto plano.<sup>[[8]](#references)</sup> Consulta [LDAP authentication and transport security](../../network-services-pentesting/pentesting-ldap.md#cleartext-credentials-and-tls-downgrade-risks).

Además, varias impresoras contienen **registros con nombres de usuario** o incluso pueden **descargar todos los nombres de usuario** del Domain Controller.

Toda esta **información sensible** y la frecuente **falta de seguridad** hacen que las impresoras sean muy interesantes para los atacantes.

Algunos blogs introductorios sobre el tema:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Configuración de la impresora

- **Ubicación**: La lista de servidores LDAP suele encontrarse en la interfaz web (p. ej., *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Comportamiento**: Muchos servidores web integrados permiten modificar los servidores LDAP **sin volver a introducir las credenciales** (función de usabilidad → riesgo de seguridad).
- **Explotación**: Redirige la dirección del servidor LDAP a un host controlado por el atacante y usa el botón *Test Connection* / *Address Book Sync* para forzar a la impresora a hacer bind contigo.

---

## Captura de credenciales

### Método 1 – Netcat Listener

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

Un `BindRequest` simple puede exponer el DN de enlace y la contraseña en el flujo BER, incluso si el servidor rechaza el inicio de sesión posteriormente. Una búsqueda anónima o una negociación SASL por sí solas no exponen esa contraseña almacenada.<sup>[[8]](#references)</sup>

Un listener `nc` sin cifrar en 636/3269 ve un handshake TLS, no un enlace LDAP. LDAPS requiere un endpoint compatible con TLS. La validación de certificados por sí sola no evita el pass-back si la impresora acepta un cambio de hostname y el nuevo endpoint tiene un certificado válido para ese hostname; el cliente también debe restringir qué servidor está autorizado a recibir la credencial almacenada.<sup>[[8]](#references)</sup>

### Método 2 – Servidor LDAP Rogue completo (recomendado)

Es posible que una impresora requiera una respuesta LDAP válida antes de intentar un enlace.<sup>[[10]](#references)</sup> Un servidor LDAP completo puede gestionar ese intercambio preliminar, pero no puede hacer que un cliente que tiene fijado un mecanismo SASL sólido o el servidor TLS previsto revele su contraseña.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # use a base DN compatible with the printer lookup

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

Considera una consulta como evidencia de una conexión, no como prueba de que se haya divulgado una contraseña. Una contraseña solo queda expuesta si el cliente envía un bind con la contraseña en texto plano; comprueba el mecanismo de bind real y el estado de TLS.<sup>[[8]](#references)</sup>

> 💡 Responder incluye servicios de autenticación LDAP y SMB rogue. Un bind LDAP simple puede exponer la contraseña configurada, mientras que la autenticación NTLM produce material de desafío-respuesta; no describas ambos resultados como si fueran una contraseña en texto claro.

### Selección del mecanismo SASL

Algunos clientes LDAP de impresoras eligen entre los mecanismos que anuncia un servidor LDAP.<sup>[[8]](#references)[[10]](#references)</sup> Las investigaciones demostraron que un cliente dispuesto a aceptar un mecanismo SASL en texto plano anunciado podía enviar una contraseña, mientras que su negociación NTLM habitual solo habría proporcionado datos de desafío-respuesta.<sup>[[9]](#references)[[10]](#references)</sup> Se trata de un **fallo en la política del cliente**, no de una propiedad de todos los binds SASL: un cliente que exija un mecanismo más seguro o fije el servidor TLS previsto debería fallar de forma segura.<sup>[[8]](#references)</sup> OpenLDAP deshabilita de forma predeterminada los mecanismos SASL que admiten texto plano, por lo que un daemon estándar no demuestra que este comportamiento exista en una impresora.<sup>[[11]](#references)</sup>

---

## Vulnerabilidades recientes de Pass-Back (2024-2025)

Pass-back *no* es un problema teórico: los proveedores siguen publicando avisos en 2024/2025 que describen exactamente esta clase de ataque.

### Xerox VersaLink – CVE-2024-12510 y CVE-2024-12511

El firmware ≤ 57.69.91 de las MFP Xerox VersaLink C70xx permitía que un administrador autenticado (o cualquiera si se mantenían las credenciales predeterminadas) pudiera:

* **CVE-2024-12510 – Pass-back LDAP**: cambiar la dirección del servidor LDAP y activar una consulta, haciendo que el dispositivo filtrara las credenciales de Windows configuradas al host controlado por el atacante.
* **CVE-2024-12511 – Pass-back SMB/FTP**: el mismo problema mediante destinos de *scan-to-folder*, filtrando credenciales NetNTLMv2 o FTP en texto claro.<sup>[[2]](#references)</sup>

Un listener sencillo, como:

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

o un servidor SMB malicioso (`impacket-smbserver`) bastan para recolectar las credenciales.  

### Canon imageRUNNER / imageCLASS – Aviso del 20 de mayo de 2025

Canon confirmó una debilidad de **SMTP/LDAP pass-back** en decenas de líneas de productos Laser y MFP. Un atacante con acceso de administrador puede modificar la configuración del servidor y recuperar las credenciales almacenadas de LDAP **o** SMTP (muchas organizaciones usan una cuenta privilegiada para permitir el escaneo a correo).<sup>[[3]](#references)</sup>

La guía del proveedor recomienda explícitamente:

1. Actualizar al firmware corregido en cuanto esté disponible.
2. Usar contraseñas de administrador seguras y únicas.
3. Evitar cuentas privilegiadas de AD para la integración de impresoras.

---

### Dispositivos Brother y variantes OEM – acceso de administrador derivado del número de serie a credenciales de servicio

Una divulgación coordinada de 2025 demostró una cadena especialmente útil en dispositivos Brother afectados; algunas partes del conjunto de vulnerabilidades también afectan a modelos OEM, así que verifica el modelo exacto en el aviso de su proveedor. Un atacante sin autenticar puede obtener el número de serie del dispositivo mediante HTTP/HTTPS/IPP en firmware vulnerable, aunque los números de serie también pueden estar disponibles a través de protocolos de gestión como SNMP o PJL. Si nunca se cambió la contraseña de fábrica, el número de serie permite determinar de forma unívoca la contraseña de administrador. Tras autenticarse, la vulnerabilidad independiente de pass-back CVE-2024-51984 expone en texto plano las contraseñas configuradas para servicios externos, como LDAP o FTP, convirtiendo el acceso de gestión de impresoras en credenciales de red reutilizables. El firmware corrige la divulgación de contraseñas de servicio, pero los dispositivos fabricados anteriormente aún requieren que el operador reemplace la contraseña inicial de administrador derivada del número de serie.<sup>[[6]](#references)</sup>

Metasploit incluye actualmente un módulo auxiliar que descubre el número de serie mediante HTTP, SNMP o PJL, genera la posible contraseña inicial y, opcionalmente, la verifica en la consola web. `DiscoverSerialVia=AUTO` prueba las rutas de descubrimiento compatibles; proporciona `TargetSerial` en su lugar si el inventario de activos ya contiene el número de serie.<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

Usa el resultado únicamente para validar activos autorizados. Que la contraseña funcione depende del modelo exacto y, sobre todo, de si ya se cambió la contraseña de administrador de fábrica.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Herramientas automatizadas de enumeración / explotación

| Herramienta | Propósito | Ejemplo |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Abuso de PostScript/PJL/PCL, acceso al sistema de archivos, comprobación de credenciales predeterminadas, *descubrimiento SNMP*; consulta [evaluación de PJL](../../network-services-pentesting/9100-pjl.md) | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Obtener configuraciones (incluidas libretas de direcciones y credenciales LDAP) mediante HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Ejecutar servicios de autenticación maliciosos y capturar/relay NetNTLM desde callbacks SMB | `sudo responder -I eth0 -v` |
| **Módulo auxiliar de Brother de Metasploit** | Detectar un número de serie, derivar la posible contraseña de administrador de fábrica y verificar el acceso a la consola web | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Endurecimiento y detección

1. **Aplicar parches / actualizar el firmware** de las MFP de inmediato (consulta los boletines PSIRT del proveedor).
2. **Reemplazar las contraseñas de administrador de fábrica**: el firmware por sí solo no elimina las contraseñas iniciales derivadas del número de serie de los dispositivos Brother/OEM afectados que ya se fabricaron.<sup>[[6]](#references)</sup>
3. **Cuentas de servicio con privilegios mínimos**: nunca uses Domain Admin para LDAP/SMB/SMTP; limita su alcance a OU de *solo lectura*.
4. **Restringir el acceso de administración**: coloca las interfaces web/IPP/SNMP de la impresora en una VLAN de administración o detrás de una ACL/VPN.
5. **Limitar el tráfico saliente de la impresora**: permite que cada dispositivo se comunique únicamente con los destinos previstos de DC/LDAP, correo, DNS/NTP, impresión y archivos de escaneo. El pass-back requiere un callback a un endpoint elegido por el atacante.
6. **Deshabilitar los protocolos que no se usen**: FTP, Telnet, raw-9100 y cifrados SSL antiguos.
7. **Habilitar el registro de auditoría**: algunos dispositivos pueden enviar por syslog los errores de LDAP/SMTP; correlaciona los binds inesperados.
8. **Supervisar los destinos de autenticación**: genera alertas cuando una impresora inicia conexiones LDAP, SMB, SMTP o FTP a un host fuera de su lista de permitidos, especialmente justo después de un inicio de sesión de administración o un cambio de configuración.
9. **Usar SNMPv3 o deshabilitar SNMP**: la comunidad `public` suele filtrar información del dispositivo y del número de serie.

---



---



## References

- [1] [Es solo una impresora… ¿Qué es lo peor que podría pasar?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Impresora multifunción Xerox Versalink C7025: vulnerabilidades de ataque pass-back (corregidas)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Mitigación/remediación de vulnerabilidades para impresoras de producción, impresoras multifunción para oficinas/pequeñas oficinas e impresoras láser](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Obtención de credenciales de dominio a través de una impresora con Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Explotación de impresoras multifunción durante una prueba de penetración](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Múltiples dispositivos Brother: múltiples vulnerabilidades (CORREGIDAS)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: módulo de bypass de autenticación de administrador predeterminada de Brother](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
- [8] [RFC 4513: métodos de autenticación y mecanismos de seguridad LDAP](https://datatracker.ietf.org/doc/html/rfc4513)
- [9] [Servidor Docker LDAP passback](https://github.com/cybertrinchera/ldap-passback-docker)
- [10] [Ataque LDAP pass back – ACCEIS](https://www.acceis.fr/ldap-pass-back-attack/)
- [11] [slapd-config(5): propiedades de seguridad SASL](https://man7.org/linux/man-pages/man5/slapd-config.5.html)
{{#include ../../banners/hacktricks-training.md}}
