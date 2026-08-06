# Información en impresoras

{{#include ../../banners/hacktricks-training.md}}

Hay varios blogs en Internet que **destacan los peligros de dejar las impresoras configuradas con LDAP con credenciales de inicio de sesión predeterminadas/débiles**.  \
Esto se debe a que un atacante podría **engañar a la impresora para que se autentique contra un servidor LDAP rogue** (normalmente basta con un `nc -vv -l -p 389` o `slapd -d 2`) y capturar las **credenciales de la impresora en texto plano**.

Además, varias impresoras contienen **registros con nombres de usuario** o incluso podrían ser capaces de **descargar todos los nombres de usuario** del Domain Controller.

Toda esta **información sensible** y la habitual **falta de seguridad** hacen que las impresoras sean muy interesantes para los atacantes.

Algunos blogs introductorios sobre el tema:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Configuración de la impresora

- **Ubicación**: La lista de servidores LDAP suele encontrarse en la interfaz web (p. ej., *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Comportamiento**: Muchos servidores web integrados permiten modificar los servidores LDAP **sin volver a introducir las credenciales** (función de usabilidad → riesgo de seguridad).
- **Exploit**: Redirige la dirección del servidor LDAP a un host controlado por el atacante y utiliza el botón *Test Connection* / *Address Book Sync* para forzar a la impresora a realizar un bind contigo.

---

## Captura de credenciales

### Method 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
Los MFP pequeños/antiguos pueden enviar un *simple-bind* simple en texto claro que netcat puede capturar. Los dispositivos modernos normalmente realizan primero una consulta anónima y después intentan el bind, por lo que los resultados varían.<sup>[[1]](#references)</sup>

### Método 2 – Full Rogue LDAP server (recomendado)

Debido a que muchos dispositivos realizan una búsqueda anónima *antes* de autenticarse, montar un daemon LDAP real produce resultados mucho más fiables:<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Cuando la impresora realice su consulta, verás las credenciales en texto claro en la salida de depuración.

> 💡  También puedes usar `impacket/examples/ldapd.py` (Python rogue LDAP) o `Responder -w -r -f` para harvest hashes NTLMv2 mediante LDAP/SMB.

---

## Vulnerabilidades recientes de Pass-Back (2024-2025)

Pass-back *no* es un problema teórico: los vendors siguen publicando advisories en 2024/2025 que describen exactamente esta clase de ataque.

### Xerox VersaLink – CVE-2024-12510 y CVE-2024-12511

El firmware ≤ 57.69.91 de las MFP Xerox VersaLink C70xx permitía a un admin autenticado (o a cualquiera cuando se mantienen las credenciales predeterminadas):

* **CVE-2024-12510 – LDAP pass-back**: cambiar la dirección del servidor LDAP y activar una consulta, haciendo que el dispositivo haga leak de las credenciales de Windows configuradas al host controlado por el atacante.
* **CVE-2024-12511 – SMB/FTP pass-back**: problema idéntico mediante destinos de *scan-to-folder*, haciendo leak de credenciales NetNTLMv2 o credenciales FTP en texto claro.<sup>[[2]](#references)</sup>

Un listener sencillo como:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
o un rogue SMB server (`impacket-smbserver`) es suficiente para harvest las credenciales.

### Canon imageRUNNER / imageCLASS – Advisory 20 May 2025

Canon confirmó una debilidad de **SMTP/LDAP pass-back** en docenas de líneas de productos Laser y MFP. Un atacante con acceso de administrador puede modificar la configuración del servidor y recuperar las credenciales almacenadas para LDAP **o** SMTP (muchas organizaciones utilizan una cuenta privilegiada para permitir scan-to-mail).<sup>[[3]](#references)</sup>

La guía del proveedor recomienda explícitamente:

1. Actualizar al firmware parcheado en cuanto esté disponible.
2. Utilizar contraseñas de administrador fuertes y únicas.
3. Evitar cuentas privilegiadas de AD para la integración de la impresora.

---

## Herramientas automatizadas de enumeración / explotación

| Tool | Propósito | Ejemplo |
|------|-----------|---------|
| **PRET** (Printer Exploitation Toolkit) | Abuso de PostScript/PJL/PCL, acceso al sistema de archivos, comprobación de default-creds, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Recolección de la configuración (incluidas libretas de direcciones y credenciales LDAP) mediante HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Captura y relay de hashes NetNTLM desde SMB/FTP pass-back | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | Servicio LDAP rogue ligero para recibir binds en clear-text | `python ldapd.py -debug` |

---

## Hardening y detección

1. **Aplicar parches / actualizar el firmware** de las MFP promptly (consultar los boletines PSIRT del proveedor).
2. **Least-Privilege Service Accounts**: nunca utilizar Domain Admin para LDAP/SMB/SMTP; restringirlas a ámbitos de OU *read-only*.
3. **Restringir el acceso de administración**: colocar las interfaces web/IPP/SNMP de las impresoras en una VLAN de administración o detrás de una ACL/VPN.
4. **Deshabilitar protocolos no utilizados**: FTP, Telnet, raw-9100 y cifrados SSL antiguos.
5. **Habilitar Audit Logging**: algunos dispositivos pueden registrar mediante syslog los fallos de LDAP/SMTP; correlacionar binds inesperados.
6. **Monitorizar binds LDAP en clear-text** procedentes de fuentes inusuales (normalmente, las impresoras solo deberían comunicarse con los DC).
7. **SNMPv3 o deshabilitar SNMP**: la community `public` a menudo hace leak de la configuración del dispositivo y LDAP.

---

## Referencias

- [1] [Es solo una impresora... ¿Qué es lo peor que podría pasar?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Impresora multifunción Xerox Versalink C7025: vulnerabilidades de ataques pass-back (corregidas)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [Mitigación/remediación de la vulnerabilidad CP2025-004 para impresoras de producción, impresoras multifunción de oficina/pequeña oficina e impresoras láser](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Obtención de credenciales de dominio mediante una impresora con Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Explotación de impresoras multifunción durante un pentesting](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

{{#include ../../banners/hacktricks-training.md}}
