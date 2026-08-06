# Autenticación Kerberos

{{#include ../../banners/hacktricks-training.md}}

**Consulta el increíble post de:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)<sup>[[3]](#references)</sup>

## TL;DR para atacantes
- Kerberos es el protocolo de autenticación predeterminado de AD; la mayoría de las cadenas de movimiento lateral interactuarán con él.
- Piensa en **tres fases del operador**:<sup>[[3]](#references)</sup>
- **AS-REQ / AS-REP** → usa una password/hash/certificate para obtener un **TGT**. Aquí tienen lugar **AS-REP roasting**, **over-pass-the-hash / pass-the-key** y **PKINIT**.
- **TGS-REQ / TGS-REP** → usa un TGT para obtener **service tickets**. Aquí resultan relevantes **Kerberoasting**, **S4U abuse**, **delegation abuse** y la mayoría de las técnicas de **ticket-forging**.
- **AP-REQ / AP-REP** → presenta el ticket al servicio. Aquí ocurren **pass-the-ticket** y el movimiento lateral específico del servicio.
- Para cheatsheets prácticas (AS-REP/Kerberoasting, ticket forgery, delegation abuse, etc.), consulta:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Usa esta página como índice de **visión general / “qué ha cambiado recientemente”** y luego consulta las páginas dedicadas a [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) o [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Notas recientes de attack (2024-2026)
- **El hardening de RC4 cambió los valores predeterminados, no Kerberos en sí**: el hardening moderno de los DC se centra en los **tipos de cifrado predeterminados asumidos** para las cuentas que no establecen explícitamente `msDS-SupportedEncryptionTypes`. Tras el despliegue de 2026, esas cuentas utilizan cada vez más **AES-only** de forma predeterminada en DC parcheados, por lo que las suposiciones ciegas de Kerberoast con `/rc4` fallan con mayor frecuencia. Sin embargo, las **service accounts con RC4 habilitado explícitamente siguen siendo excelentes objetivos para el crack offline**.<sup>[[1]](#references)</sup>
- **El enforcement de la validación PAC es importante para los forged tickets**: el hardening de las firmas PAC de 2024 implica que los abusos de tipo **golden/diamond/sapphire/extraSID** necesitan datos PAC más realistas y el contexto de firma correcto. Los dominios sin parchear o aquellos que mantienen despliegues en modo de compatibilidad/auditoría siguen siendo objetivos más débiles.<sup>[[2]](#references)</sup>
- **Kerberos basado en certificates cambió dos veces**:<sup>[[2]](#references)</sup>
- El **Strong certificate binding** (cronología de KB5014754) hace que los mappings descuidados entre certificates y cuentas sean menos fiables en entornos completamente enforced.
- **CVE-2025-26647** añadió otra capa de hardening en torno a los **mappings de certificates altSecID / SKI**. Si los DC no están parcheados, todavía están auditando o evitan explícitamente la validación de NTAuth, el abuso posterior de pass-the-certificate / shadow-credential sigue siendo más práctico.
- **El delegation abuse entre dominios / forests sigue muy activo**: Windows admite flujos modernos de **S4U2Self/S4U2Proxy** entre realms, por lo que los atributos de delegation modificables en otro dominio siguen siendo valiosos. El obstáculo suele estar en la fidelidad del tooling y en los detalles de trust/policy, no en la compatibilidad del protocolo.
- **El RBCD recursivo en múltiples dominios es importante operativamente**: en forests con 3 o más dominios, **S4U2Self/S4U2Proxy** puede recorrer referrals de trust, y el abuso **SPN-less** puede requerir un salto final **`S4U2Self+U2U`**, además de un manejo de tickets dependiente de RC4. Consulta [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[4]](#references)</sup>
- **Windows Server 2025 introdujo una nueva attack surface adyacente a Kerberos** mediante la lógica de migración de **dMSA**. Si observas delegated rights sobre OUs u objetos de service accounts en un dominio de 2025, consulta la [página de BadSuccessor](acl-persistence-abuse/BadSuccessor.md) dedicada en lugar de tratarlo como “otro gMSA más”.

## Comprobaciones rápidas del operador en dominios modernos

Antes de elegir una vía de attack de Kerberos, responde rápidamente a cuatro preguntas:

1. **¿Qué cuentas siguen siendo compatibles con RC4?**
2. **¿Qué usuarios no requieren pre-auth?**
3. **¿Qué objetos exponen delegation abuse?**
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
- Si la mayoría de las cuentas de servicio **no tienen una configuración de etype explícita**, espera un comportamiento **solo AES** en los DCs actualizados de 2026 y prepárate para un cracking offline más lento o para utilizar otra vía.
- Si existe **RBCD / KCD / unconstrained delegation**, S4U suele ser mejor que el brute-force.
- Si se utiliza **certificate auth**, recuerda que un fallo en la vía PKINIT **no siempre significa que el certificado sea inútil**; en muchos entornos, el mismo certificado sigue funcionando para abusar de **Schannel/LDAPS** (consulta [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Errores comunes de Kerberos que cambian el plan de ataque
- **`KDC_ERR_ETYPE_NOTSUPP`** → La cuenta objetivo o el DC no utilizarán el tipo de cifrado solicitado. Deja de reintentar usando únicamente RC4; proporciona **claves AES** o solicita material de roast **AES**.
- **`KRB_AP_ERR_MODIFIED`** → Probablemente tienes la **clave de servicio incorrecta**, el **SPN incorrecto** o un ticket falsificado que no coincide con la cuenta de servicio que realmente lo está descifrando.
- **`KRB_AP_ERR_SKEW`** → Tu hora es incorrecta. Sincronízala con el DC antes de depurar cualquier otra cosa.
- **`KDC_ERR_BADOPTION`** durante flujos de S4U / delegation → normalmente significa **usuarios sensibles/no delegables**, el modelo de delegation incorrecto o que estás intentando usar **classic KCD** cuando solo **RBCD** aceptaría un ticket S4U2Self no forwardable.

## Referencias
- [1] [Microsoft Learn - Detectar y corregir el uso de RC4 en Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - Últimas directrices de hardening de Windows y fechas clave](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I): ¿Cómo funciona Kerberos? – Teoría](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Explotación de RBCD en entornos Cross-Domain y Cross-Forest: Parte 2](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)

{{#include ../../banners/hacktricks-training.md}}
