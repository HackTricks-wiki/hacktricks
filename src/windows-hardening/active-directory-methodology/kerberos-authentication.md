# Autenticación Kerberos

{{#include ../../banners/hacktricks-training.md}}

Para una explicación a nivel de protocolo de los intercambios resumidos a continuación, consulta el artículo de Kerberos de Tarlogic.<sup>[[3]](#references)</sup>

## TL;DR para atacantes
- Kerberos es el protocolo de autenticación predeterminado de AD; la mayoría de las cadenas de movimiento lateral interactuarán con él.
- Piensa en **tres fases operativas**:<sup>[[3]](#references)</sup>
- **AS-REQ / AS-REP** → usa una contraseña/hash/certificado para obtener un **TGT**. Aquí es donde entran **AS-REP roasting**, **over-pass-the-hash / pass-the-key** y **PKINIT**.
- **TGS-REQ / TGS-REP** → usa un TGT para obtener **tickets de servicio**. Aquí es donde **Kerberoasting**, el abuso de **S4U**, el **abuso de delegación** y la mayoría de las técnicas de **ticket-forging** se vuelven relevantes.
- **AP-REQ / AP-REP** → presenta el ticket al servicio. Aquí es donde ocurren **pass-the-ticket** y el movimiento lateral específico del servicio.
- Para cheatsheets prácticas (AS-REP/Kerberoasting, falsificación de tickets, abuso de delegación, etc.), consulta:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Usa esta página como índice general / de **“qué ha cambiado recientemente”** y luego consulta las páginas específicas de [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) o [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Notas de ataques recientes (2024-2026)
- **El hardening de RC4 cambió los valores predeterminados, no Kerberos en sí**: el hardening moderno de los DC se centra en los **tipos de cifrado asumidos por defecto** para las cuentas que **no** establecen explícitamente `msDS-SupportedEncryptionTypes`. Tras el despliegue de 2026, esas cuentas utilizan cada vez más **solo AES** de forma predeterminada en DC parcheados, por lo que las suposiciones ciegas de Kerberoast con `/rc4` fallan con mayor frecuencia. Sin embargo, las **cuentas de servicio con RC4 habilitado explícitamente siguen siendo objetivos excelentes para el crack offline**.<sup>[[1]](#references)</sup>
- **La aplicación de la validación de PAC es importante para los tickets falsificados**: el hardening de las firmas PAC de 2024 implica que los abusos de tipo **golden/diamond/sapphire/extraSID** necesitan datos PAC más realistas y el contexto de firma correcto. Los dominios sin parches o aquellos que permanecen en implementaciones de compatibilidad/auditoría siguen siendo objetivos más vulnerables.<sup>[[2]](#references)</sup>
- **Kerberos basado en certificados cambió dos veces**:
- El **strong certificate binding** (cronología de KB5014754) hace que las asignaciones descuidadas de certificado a cuenta sean menos fiables en entornos con enforcement completo.
- **CVE-2025-26647** añadió otra capa de hardening en torno a las asignaciones de `altSecurityIdentities` que utilizan el Subject Key Identifier de un certificado. Por tanto, el nivel de parcheado, el estado de enforcement o auditoría y la configuración explícita de las asignaciones son importantes al evaluar pass-the-certificate y rutas relacionadas basadas en certificados.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup> Para PKINIT, el KDC también valida la cadena del certificado y comprueba que el emisor sea de confianza mediante el almacén NTAuth.<sup>[[8]](#references)</sup>
- **El abuso de delegación entre dominios o bosques sigue muy activo**: Windows admite flujos modernos de **S4U2Self/S4U2Proxy** entre realms, por lo que los atributos de delegación modificables en otro dominio siguen siendo valiosos. El obstáculo suele estar en la fidelidad del tooling y en los detalles de confianza/políticas, no en la compatibilidad del protocolo.
- **La RBCD recursiva entre múltiples dominios es importante desde el punto de vista operativo**: en bosques con 3 o más dominios, **S4U2Self/S4U2Proxy** puede recorrer referencias de confianza de forma recursiva, y el abuso **SPN-less** puede requerir un salto final **`S4U2Self+U2U`**, además del manejo de tickets dependiente de RC4. Consulta [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[4]](#references)</sup>
- **Windows Server 2025 introdujo las Managed Service Accounts delegadas (dMSAs)** y su lógica de migración. Si observas derechos delegados sobre OUs u objetos de cuentas de servicio en un dominio de 2025, consulta la [página de BadSuccessor](acl-persistence-abuse/BadSuccessor.md) específica en lugar de tratarlo como “otra gMSA más”.<sup>[[7]](#references)</sup>

## Comprobaciones operativas rápidas en dominios modernos

Antes de elegir una ruta de ataque de Kerberos, responde rápidamente a cuatro preguntas:

1. **¿Qué cuentas siguen siendo compatibles con RC4?**
2. **¿Qué usuarios no requieren pre-auth?**
3. **¿Qué objetos exponen oportunidades de abuso de delegación?**
4. **¿Qué partes del dominio son lo bastante recientes como para aplicar el hardening más reciente?**
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
- Si la mayoría de las cuentas de servicio **no tienen una configuración explícita de etype**, espera un comportamiento **solo AES** en los DC actualizados de 2026 y planifica un cracking offline más lento u otra vía.
- Si está presente **RBCD / KCD / unconstrained delegation**, S4U suele ser mejor que el brute-force.
- Si se utiliza **certificate auth**, recuerda que un fallo en la ruta PKINIT **no siempre significa que el certificado sea inútil**; en muchos entornos, el mismo certificado sigue funcionando para abusar de **Schannel/LDAPS** (consulta [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Errores comunes de Kerberos que cambian el plan de ataque
- **`KDC_ERR_ETYPE_NOTSUPP`** → La cuenta objetivo / el DC no utilizará el tipo de cifrado solicitado. Deja de reintentar usando únicamente RC4; proporciona **claves AES** o solicita material de roast **AES**.
- **`KRB_AP_ERR_MODIFIED`** → Probablemente tienes la **clave de servicio incorrecta**, el **SPN incorrecto** o un ticket falsificado que no coincide con la cuenta de servicio que realmente lo está descifrando.
- **`KRB_AP_ERR_SKEW`** → Tu hora es incorrecta. Sincronízala con el DC antes de depurar cualquier otra cosa.
- **`KDC_ERR_BADOPTION`** durante flujos S4U / delegation → suele significar **usuarios sensibles/no delegables**, el modelo de delegation incorrecto o que intentas utilizar **classic KCD** cuando solo **RBCD** aceptaría un ticket S4U2Self no forwardable.

## References
- [1] [Microsoft Learn - Detectar y corregir el uso de RC4 en Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - Últimas directrices de hardening de Windows y fechas clave](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I): ¿Cómo funciona Kerberos? – Teoría](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Explotación de RBCD en entornos Cross-Domain y Cross-Forest: Parte 2](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)
- [5] [Microsoft Support - Cambios en la autenticación basada en certificados de KB5014754](https://support.microsoft.com/help/5014754)
- [6] [Microsoft - CVE-2025-26647 Vulnerabilidad de mapeo de certificados de Kerberos](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-26647)
- [7] [Microsoft Learn - Descripción general de las cuentas de servicio administradas delegadas](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [8] [Microsoft Learn - Requisitos de los certificados de smart card y validación del KDC](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration)
{{#include ../../banners/hacktricks-training.md}}
