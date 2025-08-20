# Abusando de ACLs/ACEs de Active Directory

{{#include ../../../banners/hacktricks-training.md}}

## Resumen

Las Delegated Managed Service Accounts (**dMSAs**) son un nuevo tipo de principal de AD introducido con **Windows Server 2025**. Están diseñadas para reemplazar cuentas de servicio heredadas al permitir una “migración” de un clic que copia automáticamente los Service Principal Names (SPNs), membresías de grupo, configuraciones de delegación e incluso claves criptográficas de la cuenta antigua a la nueva dMSA, proporcionando a las aplicaciones una transición sin problemas y eliminando el riesgo de Kerberoasting.

Investigadores de Akamai encontraron que un solo atributo — **`msDS‑ManagedAccountPrecededByLink`** — indica al KDC qué cuenta heredada “sucede” a una dMSA. Si un atacante puede escribir ese atributo (y alternar **`msDS‑DelegatedMSAState` → 2**), el KDC generará felizmente un PAC que **hereda cada SID de la víctima elegida**, permitiendo efectivamente que la dMSA se haga pasar por cualquier usuario, incluidos los Administradores de Dominio.

## ¿Qué es exactamente una dMSA?

* Construida sobre la tecnología **gMSA** pero almacenada como la nueva clase de AD **`msDS‑DelegatedManagedServiceAccount`**.
* Soporta una **migración optativa**: llamar a `Start‑ADServiceAccountMigration` vincula la dMSA a la cuenta heredada, otorga a la cuenta heredada acceso de escritura a `msDS‑GroupMSAMembership`, y cambia `msDS‑DelegatedMSAState` = 1.
* Después de `Complete‑ADServiceAccountMigration`, la cuenta reemplazada se desactiva y la dMSA se vuelve completamente funcional; cualquier host que anteriormente usó la cuenta heredada está automáticamente autorizado para obtener la contraseña de la dMSA.
* Durante la autenticación, el KDC incrusta una pista **KERB‑SUPERSEDED‑BY‑USER** para que los clientes de Windows 11/24H2 reintenten de manera transparente con la dMSA.

## Requisitos para atacar
1. **Al menos un Windows Server 2025 DC** para que existan la clase LDAP de dMSA y la lógica del KDC.
2. **Cualquier derecho de creación de objetos o escritura de atributos en una OU** (cualquier OU) – por ejemplo, `Create msDS‑DelegatedManagedServiceAccount` o simplemente **Create All Child Objects**. Akamai encontró que el 91 % de los inquilinos del mundo real otorgan tales permisos “benignos” de OU a no administradores.
3. Capacidad para ejecutar herramientas (PowerShell/Rubeus) desde cualquier host unido al dominio para solicitar tickets de Kerberos.
*No se requiere control sobre el usuario víctima; el ataque nunca toca la cuenta objetivo directamente.*

## Paso a paso: BadSuccessor*escalada de privilegios

1. **Localiza o crea una dMSA que controles**
```bash
New‑ADServiceAccount Attacker_dMSA `
‑DNSHostName ad.lab `
‑Path "OU=temp,DC=lab,DC=local"
```

Dado que creaste el objeto dentro de una OU a la que puedes escribir, automáticamente posees todos sus atributos.

2. **Simula una “migración completada” en dos escrituras LDAP**:
- Establece `msDS‑ManagedAccountPrecededByLink = DN` de cualquier víctima (por ejemplo, `CN=Administrator,CN=Users,DC=lab,DC=local`).
- Establece `msDS‑DelegatedMSAState = 2` (migración completada).

Herramientas como **Set‑ADComputer, ldapmodify**, o incluso **ADSI Edit** funcionan; no se necesitan derechos de administrador de dominio.

3. **Solicita un TGT para la dMSA** — Rubeus soporta la bandera `/dmsa`:

```bash
Rubeus.exe asktgs /targetuser:attacker_dmsa$ /service:krbtgt/aka.test /dmsa /opsec /nowrap /ptt /ticket:<Machine TGT>
```

El PAC devuelto ahora contiene el SID 500 (Administrador) más los grupos de Administradores de Dominio/Administradores Empresariales.

## Reunir todas las contraseñas de los usuarios

Durante migraciones legítimas, el KDC debe permitir que la nueva dMSA descifre **tickets emitidos a la cuenta antigua antes de la transición**. Para evitar romper sesiones activas, coloca tanto las claves actuales como las anteriores dentro de un nuevo blob ASN.1 llamado **`KERB‑DMSA‑KEY‑PACKAGE`**.

Debido a que nuestra migración falsa afirma que la dMSA sucede a la víctima, el KDC copia diligentemente la clave RC4‑HMAC de la víctima en la lista de **claves anteriores** – incluso si la dMSA nunca tuvo una contraseña “anterior”. Esa clave RC4 no está salada, por lo que es efectivamente el hash NT de la víctima, otorgando al atacante capacidad de **cracking offline o “pass‑the‑hash”**.

Por lo tanto, vincular masivamente miles de usuarios permite a un atacante volcar hashes “a gran escala”, convirtiendo **BadSuccessor en un primitivo tanto de escalada de privilegios como de compromiso de credenciales**.

## Herramientas

- [https://github.com/akamai/BadSuccessor](https://github.com/akamai/BadSuccessor)
- [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)

## Referencias

- [https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)

{{#include ../../../banners/hacktricks-training.md}}
