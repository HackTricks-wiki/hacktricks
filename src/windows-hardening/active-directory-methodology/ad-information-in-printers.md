# Información en impresoras

{{#include ../../banners/hacktricks-training.md}}

Hay varios blogs en Internet que **destacan los peligros de dejar las impresoras configuradas con LDAP y con credenciales de inicio de sesión predeterminadas/débiles**.  \
Esto se debe a que un atacante podría **engañar a la impresora para que se autentique contra un servidor LDAP malicioso** (normalmente basta con `nc -vv -l -p 389` o `slapd -d 2`) y capturar las **credenciales de la impresora en texto claro**.

Además, varias impresoras contienen **logs con nombres de usuario** o incluso podrían ser capaces de **descargar todos los nombres de usuario** del Domain Controller.

Toda esta **información sensible** y la frecuente **falta de seguridad** hacen que las impresoras sean muy interesantes para los atacantes.

Algunos blogs introductorios sobre el tema:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Configuración de la impresora

- **Ubicación**: La lista de servidores LDAP suele encontrarse en la interfaz web (p. ej., *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Comportamiento**: Muchos servidores web integrados permiten modificar los servidores LDAP **sin volver a introducir las credenciales** (función de usabilidad → riesgo de seguridad).
- **Explotación**: Redirige la dirección del servidor LDAP a un host controlado por el atacante y utiliza el botón *Test Connection* / *Address Book Sync* para forzar a la impresora a realizar un bind contigo.

---

## Captura de credenciales

### Method 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```
Los MFP pequeños/antiguos pueden enviar un *simple-bind* cuyo DN de bind y contraseña son visibles en el flujo BER sin procesar. Los dispositivos modernos normalmente realizan primero una consulta anónima y después intentan el bind, por lo que los resultados varían.<sup>[[1]](#references)</sup>

Un listener `nc` simple en 636/3269 solo recibe texto cifrado TLS; probar LDAPS requiere un endpoint LDAP compatible con TLS, y la redirección debería fallar cuando el dispositivo valida correctamente el certificado del servidor.

### Method 2 – Servidor LDAP Rogue completo (recomendado)

Debido a que muchos dispositivos realizan una búsqueda anónima *antes* de autenticarse, poner en marcha un daemon LDAP real produce resultados mucho más fiables:<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Cuando la impresora realice la consulta, verás las credenciales en texto claro en la salida de depuración.

> 💡  Responder incluye servicios de autenticación LDAP y SMB rogue. Un bind LDAP simple puede exponer la contraseña configurada, mientras que la autenticación NTLM produce material de challenge-response; no describas ambos resultados como una contraseña en texto claro.

---

## Vulnerabilidades recientes de Pass-Back (2024-2025)

Pass-back *no* es un problema teórico: los proveedores siguen publicando avisos en 2024/2025 que describen exactamente esta clase de ataque.

### Xerox VersaLink – CVE-2024-12510 y CVE-2024-12511

El firmware ≤ 57.69.91 de las MFP Xerox VersaLink C70xx permitía a un administrador autenticado (o a cualquiera cuando se mantienen las credenciales predeterminadas):

* **CVE-2024-12510 – LDAP pass-back**: cambiar la dirección del servidor LDAP y activar una consulta, provocando que el dispositivo haga leak de las credenciales de Windows al host controlado por el atacante.
* **CVE-2024-12511 – SMB/FTP pass-back**: problema idéntico mediante destinos de *scan-to-folder*, haciendo leak de credenciales NetNTLMv2 o credenciales FTP en texto claro.<sup>[[2]](#references)</sup>

Un listener simple, como:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
o un servidor SMB malicioso (`impacket-smbserver`) es suficiente para recolectar las credenciales.

### Canon imageRUNNER / imageCLASS – Aviso del 20 de mayo de 2025

Canon confirmó una debilidad de **SMTP/LDAP pass-back** en docenas de líneas de productos Laser y MFP. Un atacante con acceso de administrador puede modificar la configuración del servidor y recuperar las credenciales almacenadas de LDAP **o** SMTP (muchas organizaciones utilizan una cuenta privilegiada para permitir el escaneo a correo electrónico).<sup>[[3]](#references)</sup>

La guía del proveedor recomienda explícitamente:

1. Actualizar al firmware corregido tan pronto como esté disponible.
2. Utilizar contraseñas de administrador únicas y seguras.
3. Evitar cuentas privilegiadas de AD para la integración de impresoras.

---

### Dispositivos Brother y variantes OEM – acceso de administrador derivado del número de serie a credenciales de servicio

Una divulgación coordinada de 2025 demostró una cadena especialmente útil en dispositivos Brother afectados; partes del conjunto de vulnerabilidades también afectan a modelos OEM, por lo que se debe verificar el modelo exacto con el aviso de seguridad del proveedor. Un atacante no autenticado puede obtener el número de serie del dispositivo mediante HTTP/HTTPS/IPP en firmware vulnerable, mientras que los números de serie también pueden estar disponibles mediante protocolos de gestión como SNMP o PJL. Si la contraseña de fábrica nunca se cambió, el número de serie determina de forma determinista la contraseña del administrador. Después de autenticarse, la vulnerabilidad independiente de pass-back CVE-2024-51984 expone en texto plano las contraseñas de servicios externos configurados, como LDAP o FTP, convirtiendo el acceso a la gestión de la impresora en credenciales de red reutilizables. El firmware corrige la divulgación de contraseñas de servicio, pero los dispositivos fabricados anteriormente todavía requieren que el operador reemplace la contraseña inicial del administrador derivada del número de serie.<sup>[[6]](#references)</sup>

La versión actual de Metasploit incluye un módulo auxiliar que descubre el número de serie mediante HTTP, SNMP o PJL, genera la contraseña inicial candidata y, opcionalmente, la verifica en la consola web. `DiscoverSerialVia=AUTO` prueba las rutas de descubrimiento compatibles; proporciona `TargetSerial` en su lugar cuando el inventario de activos ya contiene el número de serie.<sup>[[7]](#references)</sup>
```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```
Utiliza el resultado únicamente para validar activos autorizados. Que la contraseña funcione depende del modelo exacto y, fundamentalmente, de si la contraseña de administrador de fábrica ya se ha cambiado.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Herramientas automatizadas de enumeración / explotación

| Herramienta | Propósito | Ejemplo |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Abuso de PostScript/PJL/PCL, acceso al sistema de archivos, comprobación de credenciales predeterminadas, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Recopilación de configuración (incluidas libretas de direcciones y credenciales LDAP) mediante HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Ejecutar servicios de autenticación rogue y capturar/relay NetNTLM de callbacks SMB | `sudo responder -I eth0 -v` |
| **Módulo auxiliar de Brother de Metasploit** | Descubrir un número de serie, derivar la contraseña candidata de administrador de fábrica y verificar el acceso a la consola web | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Hardening y detección

1. **Aplicar parches / actualizar el firmware** de las MFP puntualmente (consultar los boletines PSIRT del proveedor).
2. **Sustituir las contraseñas de administrador de fábrica**: el firmware por sí solo no elimina las contraseñas iniciales derivadas del número de serie de dispositivos Brother/OEM afectados fabricados anteriormente.<sup>[[6]](#references)</sup>
3. **Cuentas de servicio con privilegios mínimos**: nunca utilizar Domain Admin para LDAP/SMB/SMTP; restringirlas a ámbitos de OU de *solo lectura*.
4. **Restringir el acceso de gestión**: colocar las interfaces web/IPP/SNMP de la impresora en una VLAN de gestión o detrás de una ACL/VPN.
5. **Limitar el tráfico de salida de la impresora**: permitir que cada dispositivo se comunique únicamente con los destinos esperados de DC/LDAP, correo, DNS/NTP, impresión y archivos de escaneo. Pass-back requiere un callback a un endpoint seleccionado por el atacante.
6. **Deshabilitar protocolos no utilizados**: FTP, Telnet, raw-9100 y cifrados SSL antiguos.
7. **Activar el registro de auditoría**: algunos dispositivos pueden enviar por syslog los fallos de LDAP/SMTP; correlacionar los binds inesperados.
8. **Monitorizar los destinos de autenticación**: alertar cuando una impresora inicia conexiones LDAP, SMB, SMTP o FTP a un host fuera de su allowlist, especialmente justo después de un inicio de sesión de gestión o un cambio de configuración.
9. **SNMPv3 o deshabilitar SNMP**: la comunidad `public` a menudo leaks información del dispositivo y del número de serie.

---



---

## References

- [1] [Es solo una impresora... ¿Qué es lo peor que podría pasar?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Impresora multifunción Xerox Versalink C7025: vulnerabilidades de ataque Pass-Back (corregidas)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [Mitigación / remediación de la vulnerabilidad CP2025-004 para impresoras de producción, impresoras multifunción de oficina/pequeña oficina e impresoras láser](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Obtención de credenciales de dominio mediante una impresora con Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Explotación de impresoras multifunción durante un pentesting](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Varios dispositivos Brother: múltiples vulnerabilidades (CORREGIDAS)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: módulo de bypass de autenticación del administrador predeterminado de Brother](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
