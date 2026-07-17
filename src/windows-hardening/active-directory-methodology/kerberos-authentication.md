# Autenticación Kerberos

{{#include ../../banners/hacktricks-training.md}}

**Consulta el increíble post de:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR para atacantes
- Kerberos es el protocolo de autenticación predeterminado de AD; la mayoría de las cadenas de movimiento lateral interactuarán con él.
- Piensa en **tres fases operativas**:
- **AS-REQ / AS-REP** → usar una contraseña/hash/certificado para obtener un **TGT**. Aquí tienen lugar **AS-REP roasting**, **over-pass-the-hash / pass-the-key** y **PKINIT**.
- **TGS-REQ / TGS-REP** → usar un TGT para obtener **tickets de servicio**. Aquí son relevantes **Kerberoasting**, **S4U abuse**, **delegation abuse** y la mayoría de las técnicas de **ticket-forging**.
- **AP-REQ / AP-REP** → presentar el ticket al servicio. Aquí ocurren **pass-the-ticket** y el movimiento lateral específico del servicio.
- Para cheatsheets prácticas (AS-REP/Kerberoasting, falsificación de tickets, delegation abuse, etc.), consulta:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Usa esta página como índice general / de **“qué ha cambiado recientemente”** y, después, accede a las páginas específicas sobre [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) o [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Notas de ataque recientes (2024-2026)
- **El hardening de RC4 cambió los valores predeterminados, no Kerberos en sí**: el hardening moderno de los DC se centra en los **tipos de cifrado asumidos de forma predeterminada** para las cuentas que no establecen explícitamente `msDS-SupportedEncryptionTypes`. Tras el despliegue de 2026, esas cuentas utilizan cada vez más AES-only de forma predeterminada en DC con los parches aplicados, por lo que las suposiciones ciegas de Kerberoast con `/rc4` fallan con más frecuencia. Sin embargo, las cuentas de servicio con RC4 habilitado explícitamente siguen siendo objetivos excelentes para el cracking offline.
- **La aplicación de la validación PAC es importante para los forged tickets**: el hardening de las firmas PAC de 2024 implica que los abusos de tipo **golden/diamond/sapphire/extraSID** necesitan datos PAC más realistas y el contexto de firma correcto. Los dominios sin parches o los dominios que mantienen despliegues en modo de compatibilidad/auditoría siguen siendo objetivos más vulnerables.
- **Kerberos basado en certificados cambió dos veces**:
- El **strong certificate binding** (cronología de KB5014754) hace que los mappings descuidados entre certificados y cuentas sean menos fiables en entornos completamente enforced.
- **CVE-2025-26647** añadió otra capa de hardening en torno a los mappings de certificados **altSecID / SKI**. Si los DC no tienen los parches aplicados, siguen en modo de auditoría o evitan explícitamente la validación de NTAuth, el abuso posterior de pass-the-certificate / shadow-credential sigue siendo más práctico.
- **El delegation abuse entre dominios/forests sigue muy activo**: Windows admite flujos modernos de **S4U2Self/S4U2Proxy** entre realms, por lo que los atributos de delegación modificables en otro dominio siguen siendo valiosos. El obstáculo suele ser la fidelidad de las herramientas y los detalles de trust/policy, no la compatibilidad del protocolo.
- **El RBCD recursivo en múltiples dominios es importante operativamente**: en forests con 3 o más dominios, **S4U2Self/S4U2Proxy** puede realizarse de forma recursiva a través de referrals de trust, y el abuso **SPN-less** puede requerir un salto final de **`S4U2Self+U2U`**, además de un manejo de tickets dependiente de RC4. Consulta [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).
- **Windows Server 2025 introdujo una nueva superficie de ataque adyacente a Kerberos** mediante la lógica de migración de **dMSA**. Si observas derechos delegados sobre OUs u objetos de cuentas de servicio en un dominio de 2025, consulta la [página de BadSuccessor](acl-persistence-abuse/BadSuccessor.md) específica en lugar de tratarlo como “otro gMSA más”.

## Comprobaciones rápidas del operador en dominios modernos

Antes de elegir una ruta de ataque contra Kerberos, responde rápidamente a cuatro preguntas:

1. **¿Qué cuentas siguen siendo compatibles con RC4?**
2. **¿Qué usuarios no requieren pre-auth?**
3. **¿Qué objetos exponen delegation abuse?**
4. **¿Qué partes del dominio son lo bastante nuevas como para aplicar el hardening reciente?**
```powershell
# 1) Service accounts explicitly pinned to RC4 / legacy etypes
Get-ADObject -LDAPFilter '(|(msDS-SupportedEncryptionTypes=4)(msDS-SupportedEncryptionTypes=12))' \
-Properties samAccountName,servicePrincipalName,msDS-SupportedEncryptionTypes

# 2) Service accounts with no explicit etype config
#    (these increasingly inherit AES-only defaults on patched 2026 DCs)
Get-ADObject -LDAPFilter '(&(servicePrincipalName=*)(!(msDS-SupportedEncryptionTypes=*)))' \
-Properties samAccountName,servicePrincipalName

# 3) AS-REP roastable users
Get-ADUser -LDAPFilter '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' \
-Properties userAccountControl

# 4) Delegation hot spots
Get-ADComputer -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' \
-Properties msDS-AllowedToActOnBehalfOfOtherIdentity
Get-ADObject -LDAPFilter '(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216))' \
-Properties samAccountName,servicePrincipalName,userAccountControl

# 5) DC-side RC4 hardening / compatibility clues
Get-WinEvent -LogName System | Where-Object {
$_.ProviderName -eq 'Microsoft-Windows-Kerberos-Key-Distribution-Center' -and $_.Id -in 201..209
}
```
Interpretación práctica:
- Si las cuentas **SPN interesantes son explícitamente compatibles con RC4**, Kerberoasting sigue siendo barato y rápido.
- Si la mayoría de las cuentas de servicio **no tienen una configuración de etype explícita**, espera un comportamiento **solo AES** en los DCs actualizados de 2026 y planifica un cracking offline más lento o una ruta diferente.
- Si hay **RBCD / KCD / unconstrained delegation**, S4U suele ser mejor que la fuerza bruta.
- Si se utiliza **certificate auth**, recuerda que un fallo en la ruta PKINIT **no siempre significa que el certificado sea inútil**; en muchos entornos, el mismo certificado sigue funcionando para el abuso de **Schannel/LDAPS** (consulta [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Errores comunes de Kerberos que cambian el plan de ataque
- **`KDC_ERR_ETYPE_NOTSUPP`** → La cuenta objetivo / el DC no utilizará el tipo de cifrado solicitado. Deja de reintentarlo usando únicamente RC4; proporciona **claves AES** o solicita material de roast **AES**.
- **`KRB_AP_ERR_MODIFIED`** → Probablemente tienes la **clave de servicio incorrecta**, el **SPN incorrecto** o un ticket falsificado que no coincide con la cuenta de servicio que realmente lo está descifrando.
- **`KRB_AP_ERR_SKEW`** → Tu hora es incorrecta. Sincronízala con el DC antes de depurar cualquier otra cosa.
- **`KDC_ERR_BADOPTION`** durante los flujos de S4U / delegation → con frecuencia significa **usuarios sensibles/no delegables**, el modelo de delegation incorrecto o que intentas utilizar **classic KCD** cuando solo **RBCD** aceptaría un ticket S4U2Self no reenviable.

## Referencias
- [Microsoft Learn - Detectar y corregir el uso de RC4 en Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Últimas directrices de hardening de Windows y fechas clave](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
