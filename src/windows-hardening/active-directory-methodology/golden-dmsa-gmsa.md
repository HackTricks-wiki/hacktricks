# Ataque Golden gMSA/dMSA (Derivación Offline de Contraseñas de Managed Service Accounts)

{{#include ../../banners/hacktricks-training.md}}

## Descripción general

Las Windows Managed Service Accounts son principals de dominio diseñados para ejecutar servicios sin que un administrador gestione una contraseña de larga duración:

1. **gMSA** (group Managed Service Account) puede ser utilizada por los equipos autorizados mediante `msDS-GroupMSAMembership` / `PrincipalsAllowedToRetrieveManagedPassword`.
2. **dMSA** (delegated Managed Service Account) se introdujo en **Windows Server 2025**. Vincula la autenticación normal a identidades de máquina autorizadas y puede reemplazar una cuenta de servicio heredada mediante un flujo de migración.

No confundas **Golden dMSA** con **BadSuccessor**. Golden dMSA requiere el compromiso del material de la clave raíz de KDS y deriva las claves de las cuentas administradas; [BadSuccessor](badsuccessor-dmsa-migration-abuse.md), en cambio, abusa del control de un objeto dMSA y de sus atributos de migración.

Un DC no almacena una contraseña en texto claro generada de forma independiente para cada gMSA. Deriva la contraseña de la cuenta a partir de una **clave raíz de KDS**, una clave de Group Key Distribution Protocol (GKDI) indexada por tiempo y el SID de la cuenta. Los objetos de clave raíz son objetos `msKds-ProvRootKey` debajo de `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,...`; el valor sensible es `msKds-RootKeyData`. `msDS-ManagedPasswordId` **no es un GUID**: es un identificador de clave binario que contiene el GUID de la clave raíz de KDS, los índices `L0`/`L1`/`L2` de GKDI y metadatos del dominio/bosque. El DC aplica el KDF con la etiqueta `GMSA PASSWORD` y el SID binario como contexto, y después expone un `MSDS-MANAGEDPASSWORD_BLOB` únicamente a principals autorizados a recuperar la contraseña de una gMSA.<sup>[[2]](#references)</sup>

Una dMSA normalmente difiere a nivel operativo: su secreto debe permanecer en el DC y el KDC emite credenciales a una máquina autorizada. Sin embargo, las dMSA reutilizan la derivación de contraseñas subyacente de KDS/GKDI. Golden dMSA reconstruye ese secreto directamente y, por tanto, evita el flujo previsto vinculado a la máquina y Credential Guard en el host del servicio.<sup>[[1]](#references)</sup>

## Ataque Golden gMSA / Golden dMSA

Después de extraer una clave raíz de KDS, un atacante puede derivar las contraseñas de las cuentas vinculadas a esa clave sin leer `msDS-ManagedPassword`. Esto evita la ACL de recuperación de contraseñas por cuenta y resiste las rotaciones normales de contraseñas administradas mientras la clave raíz comprometida siga en uso. Para las gMSA, el `msDS-ManagedPasswordId` legible normalmente proporciona el identificador de clave exacto. Para las dMSA restringidas mediante ACL, Golden dMSA reduce el identificador faltante a solo **1.024 candidatos**.<sup>[[1]](#references)[[2]](#references)</sup>

### Prerrequisitos

* El objeto de clave raíz de KDS relevante, normalmente obtenido con derechos de Enterprise Admin / Domain Admin del bosque raíz, `SYSTEM` en un DC o desde una base de datos o backup expuesto del DC.<sup>[[1]](#references)[[2]](#references)</sup>
* El SID de la cuenta objetivo, el dominio DNS, el nombre del bosque y `sAMAccountName`.<sup>[[1]](#references)[[2]](#references)</sup>
* Para el cálculo directo de una gMSA, su `msDS-ManagedPasswordId` codificado en base64; para Golden dMSA, este valor puede adivinarse.<sup>[[1]](#references)[[2]](#references)</sup>
* Un host Windows x64 con .NET Framework 4.7.2 para [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA).<sup>[[3]](#references)</sup>

### Fase 1 - Extraer la clave raíz de KDS

`GoldenDMSA` y [`GoldenGMSA`](https://github.com/Semperis/GoldenGMSA) exportan los campos del objeto de clave raíz como un blob base64. Sin un argumento de dominio, las herramientas consultan el bosque raíz y requieren acceso privilegiado adecuado al directorio. Con el argumento de dominio/bosque, `SYSTEM` en un DC puede consultar la réplica local del naming-context de Configuration de ese DC.<sup>[[1]](#references)[[2]](#references)</sup>
```cmd
:: GoldenDMSA: Enterprise Admin, or SYSTEM on a DC with --domain
GoldendMSA.exe kds
GoldendMSA.exe kds -g KDS_ROOT_KEY_GUID
GoldendMSA.exe kds --domain child.example.local

:: GoldenGMSA equivalents
GoldenGMSA.exe kdsinfo
GoldenGMSA.exe kdsinfo --guid KDS_ROOT_KEY_GUID
```
Registra tanto el GUID de la root key como el blob de la root key en base64. Una exportación de las colmenas `SECURITY`/`SYSTEM` del registro no es por sí sola la KDS root key: el material autorizado se encuentra en la partición de configuración de AD.<sup>[[1]](#references)[[2]](#references)</sup>

### Fase 2 - Enumerar objetos gMSA / dMSA

Para los gMSA, obtén `sAMAccountName`, `objectSid` y el `msDS-ManagedPasswordId` binario. Este último normalmente se puede leer incluso cuando el caller no tiene permitido recuperar `msDS-ManagedPassword`.<sup>[[2]](#references)</sup>
```powershell
Get-ADServiceAccount -Filter * -Properties objectSid,msDS-ManagedPasswordId |
Select-Object sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo --domain example.local
```
La ACL predeterminada de un dMSA puede impedir la enumeración LDAP con pocos privilegios. `GoldenDMSA info` puede consultar LDAP o enumerar RIDs candidatos y resolver los SIDs mediante `LsaLookupSids` a través de `\PIPE\lsarpc`, y luego distinguir los dMSAs de las cuentas de equipo y los gMSAs.<sup>[[1]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe info -d example.local -m ldap
GoldendMSA.exe info -d example.local -m brute -u alice -p PASSWORD -o EXAMPLE -r 5000
```
### Fase 3 - Reconstruir o adivinar `msDS-ManagedPasswordId`

El identificador de clave incluye `L0Index`, `L1Index` y `L2Index`, no una marca de tiempo de creación de la cuenta seguida de bits aleatorios. Semperis descubrió que la ruta de generación de contraseñas no consume el `L0Index` candidato, mientras que `L1Index` y `L2Index` están limitados a los valores `0..31`. Por lo tanto, un atacante que conozca el GUID de la root key, el dominio, el forest y el SID puede construir los `32 * 32 = 1,024` identificadores candidatos.<sup>[[1]](#references)</sup>
```cmd
:: Write 1,024 base64 ManagedPasswordId candidates to KDS_ROOT_KEY_GUID.txt
GoldendMSA.exe wordlist -s DMSA_SID -d example.local -f example.local -k KDS_ROOT_KEY_GUID

:: Derive and validate candidates; -t caches the successful TGT
GoldendMSA.exe bruteforce -s DMSA_SID -i KDS_ROOT_KEY_GUID -k KDS_ROOT_KEY_BASE64 -d example.local -u svc_dmsa$ -t
```
Las derivaciones se realizan offline, pero identificar el candidato válido normalmente requiere intentos de autenticación. Esto puede producir una ráfaga de preautenticaciones Kerberos fallidas o validaciones NTLM antes de encontrar la clave válida. Para las claves Kerberos AES, el salt de la cuenta administrada utilizado por la herramienta es `UPPERCASE.DNS.DOMAIN` + `host` + el UPN de la cuenta en minúsculas, sin el `$` final (por ejemplo, `EXAMPLE.LOCALhostsvc_dmsa.example.local`).<sup>[[1]](#references)</sup>

### Fase 4 - Calcular y usar la contraseña

Si se conoce el identificador exacto, calcula el búfer de contraseña de 256 bytes y conviértelo en material NTLM/AES. El valor base64 mostrado por estas herramientas es el búfer de contraseña codificado, **no el propio `MSDS-MANAGEDPASSWORD_BLOB` de LDAP**.<sup>[[2]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe compute -s ACCOUNT_SID -k KDS_ROOT_KEY_BASE64 -d example.local -m MANAGED_PASSWORD_ID_BASE64
GoldendMSA.exe convert -d example.local -u svc_account$ -p BASE64_PASSWORD

GoldenGMSA.exe compute --sid ACCOUNT_SID --kdskey KDS_ROOT_KEY_BASE64 --pwdid MANAGED_PASSWORD_ID_BASE64
```
El resultado NTLM puede utilizarse donde se acepte NTLM; la clave AES puede utilizarse para overpass-the-hash / solicitudes de TGT cuando la cuenta administrada solo admite AES. Esto proporciona los privilegios, SPN, configuración de delegación y acceso a recursos de la cuenta de servicio administrada comprometida, sin añadir la máquina del atacante a `PrincipalsAllowedToRetrieveManagedPassword`.<sup>[[1]](#references)[[2]](#references)</sup>

### Abuso de la partición Configuration entre dominios

Los objetos de la clave raíz de KDS se encuentran en el contexto de nomenclatura Configuration del bosque, que se replica en los DC de los dominios secundarios. En consecuencia, `SYSTEM` en un DC de un dominio secundario puede leer el material KDS de la raíz del bosque desde la réplica local del DC secundario, aunque los Domain Admins del dominio secundario no puedan leer el objeto directamente desde un DC de la raíz del bosque. Si el atacante también puede leer `msDS-ManagedPasswordId` de una gMSA del dominio principal, GoldenGMSA puede calcular la contraseña de esa cuenta principal; el filtrado de SID no impide este ataque criptográfico.<sup>[[5]](#references)</sup>
```cmd
:: Run as SYSTEM on a child.example.local DC
GoldenGMSA.exe kdsinfo --forest child.example.local

:: Query target metadata in the parent, then combine both inputs
GoldenGMSA.exe gmsainfo --domain example.local
GoldenGMSA.exe compute --sid PARENT_GMSA_SID --domain example.local --forest child.example.local
```
## Detección, Contención y Recuperación

* Configure una SACL en el contenedor **Master Root Keys**, heredada por los objetos `msKds-ProvRootKey`, para lecturas exitosas de `msKds-RootKeyData`. Con la auditoría de acceso al servicio de directorio habilitada, una extracción online genera el evento de seguridad **4662**; investigue los sujetos que no sean DC esperados u operadores de Tier-0. Audite también los cambios en estas SACL y en las ACL de los objetos de root key.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>
* Un ataque de hijo a padre lee el objeto KDS desde la réplica local del DC hijo comprometido, por lo que el dominio raíz del forest podría no observar esa lectura. En el dominio padre, audite las lecturas exitosas de `msDS-ManagedPasswordId` (GUID de esquema `0e78295a-c6d3-0a40-b491-d62251ffa0a6`) en objetos `msDS-GroupManagedServiceAccount` e investigue las lecturas realizadas por principals de otro dominio.<sup>[[5]](#references)</sup>
* Correlacione el acceso a objetos KDS con logons inusuales de managed accounts y ráfagas de fallos de Kerberos/NTLM para service accounts con sufijo `$`. El cálculo offline posterior al robo previo de una base de datos o backup no es visible para un DC activo.<sup>[[1]](#references)[[3]](#references)</sup>
* La rotación ordinaria de contraseñas no es suficiente después de la exposición de una root key. El procedimiento de recuperación actual de Microsoft crea una nueva KDS root key, reinicia KDS en todos los DC relevantes y mueve las cuentas afectadas a esa key. Si se desconoce el alcance o el momento de la exposición y esperar a un roll seguro es inaceptable, reemplace cada gMSA que haya utilizado la key comprometida; si se conoce el alcance, Microsoft documenta un flujo de trabajo de authoritative-restore para forzar un rolling seguro. Valide el GUID de la nueva key en `msDS-ManagedPasswordId` antes de eliminar la key antigua.<sup>[[4]](#references)</sup>
* Considere el acceso a la base de datos y los backups de los DC, la replicación de la partición Configuration y la administración de KDS root keys como Tier-0. Reducir `ManagedPasswordIntervalInDays` limita algunas ventanas de recuperación, pero no revoca una root key ya comprometida.<sup>[[4]](#references)</sup>

## Herramientas

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) - enumeración de dMSA/gMSA, generación de identificadores, validación de 1.024 candidatos, cálculo de contraseñas y conversión NTLM/AES.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) - enumeración de gMSA/KDS y cálculo de contraseñas online, offline y cross-domain.<sup>[[2]](#references)</sup>
* [`Rubeus`](https://github.com/GhostPack/Rubeus) y [`Impacket`](https://github.com/fortra/impacket) - use o valide las claves NTLM/AES derivadas en pruebas autorizadas.



## References

- [1] [Golden dMSA - bypass de autenticación para Managed Service Accounts delegadas](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [Ataques de gMSA en Active Directory](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Repositorio de GitHub de Semperis/GoldenDMSA](https://github.com/Semperis/GoldenDMSA)
- [4] [Microsoft - Cómo recuperarse de un ataque Golden gMSA](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/recover-from-golden-gmsa-attack)
- [5] [SID filter como límite de seguridad entre dominios? Parte 5 - Ataque de trust Golden gMSA](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
{{#include ../../banners/hacktricks-training.md}}
