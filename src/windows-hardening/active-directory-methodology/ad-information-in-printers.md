# Información en impresoras

{{#include ../../banners/hacktricks-training.md}}

Hay varios blogs en Internet que **destacan los peligros de dejar impresoras configuradas con LDAP y credenciales de inicio de sesión predeterminadas/débiles**.  \
Esto se debe a que un atacante podría **engañar a la impresora para que se autentique contra un servidor LDAP malicioso** (normalmente basta con `nc -vv -l -p 389` o `slapd -d 2`) y capturar las **credenciales de la impresora en texto claro**.

Además, muchas impresoras contienen **registros con nombres de usuario** o incluso pueden **descargar todos los nombres de usuario** del Domain Controller.

Toda esta **información confidencial** y la habitual **falta de seguridad** hacen que las impresoras sean muy interesantes para los atacantes.

Algunos blogs introductorios sobre el tema:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Configuración de la impresora

- **Ubicación**: La lista de servidores LDAP suele encontrarse en la interfaz web (p. ej., *Red ➜ Configuración de LDAP ➜ Configurar LDAP*).
- **Comportamiento**: Muchos servidores web integrados permiten modificar los servidores LDAP **sin volver a introducir las credenciales** (función de usabilidad → riesgo de seguridad).
- **Explotación**: Redirige la dirección del servidor LDAP a un host controlado por el atacante y usa el botón *Probar conexión* / *Sincronizar libreta de direcciones* para forzar a la impresora a hacer bind contigo.

---

## Captura de credenciales

### Método 1 – Listener de Netcat

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

Los MFP pequeños/antiguos pueden enviar un *simple-bind* simple cuyo bind DN y contraseña son visibles en el flujo BER sin procesar. Los dispositivos modernos suelen realizar primero una consulta anónima y luego intentar el bind, por lo que los resultados varían.<sup>[[1]](#references)</sup>

Un listener `nc` simple en 636/3269 solo recibe texto cifrado TLS; para probar LDAPS se necesita un endpoint LDAP compatible con TLS, y la redirección debería fallar cuando el dispositivo valida correctamente el certificado del servidor.

### Método 2 – Servidor LDAP rogue completo (recomendado)

Como muchos dispositivos realizan una búsqueda anónima *antes* de autenticarse, poner en marcha un daemon LDAP real ofrece resultados mucho más fiables:<sup>[[1]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

Cuando la impresora realice la consulta, verás las credenciales en texto claro en la salida de depuración.

> 💡 Responder incluye servicios de autenticación LDAP y SMB rogue. Un simple LDAP bind puede exponer la contraseña configurada, mientras que la autenticación NTLM produce material de challenge-response; no describas ambos resultados como una contraseña en texto claro.

---

## Vulnerabilidades recientes de Pass-Back (2024-2025)

Pass-back *no* es un problema teórico: los proveedores siguen publicando avisos en 2024/2025 que describen exactamente esta clase de ataque.

### Xerox VersaLink – CVE-2024-12510 y CVE-2024-12511

El firmware ≤ 57.69.91 de las MFP Xerox VersaLink C70xx permitía que un administrador autenticado (o cualquiera si se conservaban las credenciales predeterminadas):

* **CVE-2024-12510 – LDAP pass-back**: cambiar la dirección del servidor LDAP y activar una consulta, lo que provoca que el dispositivo filtre las credenciales de Windows configuradas al host controlado por el atacante.
* **CVE-2024-12511 – SMB/FTP pass-back**: el mismo problema mediante destinos de *scan-to-folder*, que filtran credenciales NetNTLMv2 o credenciales FTP en texto claro.<sup>[[2]](#references)</sup>

Un listener simple como:

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

o un servidor SMB malicioso (`impacket-smbserver`) basta para recopilar las credenciales.  

### Canon imageRUNNER / imageCLASS – Aviso del 20 de mayo de 2025

Canon confirmó una vulnerabilidad de **SMTP/LDAP pass-back** en decenas de líneas de productos Laser y MFP. Un atacante con acceso de administrador puede modificar la configuración del servidor y recuperar las credenciales almacenadas de LDAP **o** SMTP (muchas organizaciones usan una cuenta privilegiada para permitir el escaneo a correo).<sup>[[3]](#references)</sup>

Las recomendaciones del proveedor indican explícitamente:

1. Actualizar al firmware parcheado en cuanto esté disponible.
2. Usar contraseñas de administrador sólidas y únicas.
3. Evitar cuentas privilegiadas de AD para la integración de impresoras.

---

### Dispositivos Brother y variantes OEM: acceso de administrador derivado del número de serie a credenciales de servicios

Una divulgación coordinada de 2025 demostró una cadena especialmente útil en dispositivos Brother afectados; algunas partes del conjunto de vulnerabilidades también afectan a modelos OEM, por lo que hay que verificar el modelo exacto con el aviso del proveedor correspondiente. Un atacante no autenticado puede obtener el número de serie del dispositivo mediante HTTP/HTTPS/IPP en firmware vulnerable; los números de serie también pueden estar disponibles a través de protocolos de administración como SNMP o PJL. Si nunca se cambió la contraseña de fábrica, el número de serie permite determinar de forma inequívoca la contraseña de administrador. Tras autenticarse, la vulnerabilidad independiente de pass-back CVE-2024-51984 expone en texto plano las contraseñas configuradas de servicios externos, como LDAP o FTP, convirtiendo el acceso de administración de la impresora en credenciales de red reutilizables. El firmware corrige la divulgación de contraseñas de servicios, pero los dispositivos fabricados anteriormente aún requieren que el operador cambie la contraseña de administrador inicial derivada del número de serie.<sup>[[6]](#references)</sup>

La versión actual de Metasploit incluye un módulo auxiliar que descubre el número de serie mediante HTTP, SNMP o PJL, genera la posible contraseña inicial y, opcionalmente, la verifica en la consola web. `DiscoverSerialVia=AUTO` prueba las rutas de descubrimiento compatibles; se debe proporcionar `TargetSerial` en su lugar si el inventario de activos ya incluye el número de serie.<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

Usa el resultado únicamente para validar activos autorizados. Que la contraseña funcione depende del modelo exacto y, fundamentalmente, de si ya se cambió la contraseña de administrador de fábrica.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Herramientas automatizadas de enumeración / explotación

| Herramienta | Propósito | Ejemplo |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Abuso de PostScript/PJL/PCL, acceso al sistema de archivos, comprobación de credenciales predeterminadas, *descubrimiento SNMP* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Recopilación de configuración (incluidas libretas de direcciones y credenciales LDAP) mediante HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Ejecutar servicios de autenticación falsos y capturar/reenviar NetNTLM de conexiones SMB de retorno | `sudo responder -I eth0 -v` |
| **Módulo auxiliar de Brother para Metasploit** | Descubrir un número de serie, derivar la posible contraseña de administrador de fábrica y verificar el acceso a la consola web | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Fortalecimiento y detección

1. **Aplicar parches / actualizar el firmware** de las MFP cuanto antes (consultar los boletines PSIRT del proveedor).
2. **Cambiar las contraseñas de administrador de fábrica**: el firmware por sí solo no elimina las contraseñas iniciales derivadas del número de serie en dispositivos Brother/OEM afectados que ya se fabricaron.<sup>[[6]](#references)</sup>
3. **Cuentas de servicio con privilegios mínimos**: nunca usar Domain Admin para LDAP/SMB/SMTP; limitar el alcance a OU de *solo lectura*.
4. **Restringir el acceso de administración**: colocar las interfaces web/IPP/SNMP de la impresora en una VLAN de administración o detrás de una ACL/VPN.
5. **Limitar el tráfico saliente de la impresora**: permitir que cada dispositivo se conecte únicamente a los destinos esperados de DC/LDAP, correo, DNS/NTP, impresión y archivos de escaneo. Pass-back requiere un callback a un endpoint elegido por el atacante.
6. **Deshabilitar los protocolos no utilizados**: FTP, Telnet, raw-9100 y cifrados SSL antiguos.
7. **Habilitar el registro de auditoría**: algunos dispositivos pueden enviar por syslog los errores de LDAP/SMTP; correlacionar las vinculaciones inesperadas.
8. **Supervisar los destinos de autenticación**: alertar cuando una impresora inicie conexiones LDAP, SMB, SMTP o FTP a un host fuera de su lista de permitidos, especialmente justo después de un inicio de sesión de administración o de un cambio de configuración.
9. **Usar SNMPv3 o deshabilitar SNMP**: la comunidad `public` suele filtrar información del dispositivo y del número de serie.

---



---

## References

- [1] [Es solo una impresora… ¿Qué es lo peor que podría pasar?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Impresora multifunción Xerox Versalink C7025: vulnerabilidades de ataque Pass-Back (corregidas)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Mitigación/remediación de vulnerabilidades para impresoras de producción, impresoras multifunción de oficina/pequeña oficina e impresoras láser](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Obtención de credenciales de dominio mediante una impresora con Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Explotación de impresoras multifunción durante una prueba de penetración](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Varios dispositivos Brother: múltiples vulnerabilidades (CORREGIDAS)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: módulo para omitir la autenticación de administrador predeterminada de Brother](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
