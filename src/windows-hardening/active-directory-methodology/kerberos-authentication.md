# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**Consulta la increíble publicación de:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR para attackers
- Kerberos es el protocolo de auth por defecto de AD; la mayoría de las cadenas de lateral-movement lo tocarán.
- Piensa en **tres fases del operador**:
- **AS-REQ / AS-REP** → password/hash/certificate para obtener un **TGT**. Aquí es donde viven **AS-REP roasting**, **over-pass-the-hash / pass-the-key**, y **PKINIT**.
- **TGS-REQ / TGS-REP** → usa un TGT para obtener **service tickets**. Aquí es donde se vuelven relevantes **Kerberoasting**, **S4U abuse**, **delegation abuse**, y la mayor parte del **ticket-forging tradecraft**.
- **AP-REQ / AP-REP** → presenta el ticket al servicio. Aquí es donde ocurre **pass-the-ticket** y el lateral movement específico del servicio.
- Para cheatsheets prácticas (AS-REP/Kerberoasting, ticket forgery, delegation abuse, etc.) mira:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Usa esta página como el índice de **overview / “qué cambió recientemente”**, y luego salta a las páginas dedicadas de [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md), o [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Fresh attack notes (2024-2026)
- **El hardening de RC4 cambió los defaults, no Kerberos en sí** – el hardening moderno de DC se centra en los **default assumed encryption types** para cuentas que **no** establecen explícitamente `msDS-SupportedEncryptionTypes`. Después del rollout de 2026, esas cuentas pasan cada vez más a **AES-only** en DCs parcheados, así que las suposiciones ciegas de `/rc4` para Kerberoast fallan más a menudo. Sin embargo, las service accounts **habilitadas explícitamente para RC4 siguen siendo excelentes objetivos de crack offline**.
- **La enforcement de validación PAC importa para forged tickets** – el hardening de la firma PAC de 2024 significa que los abusos tipo **golden/diamond/sapphire/extraSID** necesitan datos PAC más realistas y el contexto de firma correcto. Los dominios sin parchear o los dominios dejados en despliegues de compatibilidad/audit siguen siendo objetivos más débiles.
- **Certificate-based Kerberos cambió dos veces**:
- **Strong certificate binding** (cronología de KB5014754) hace que las mappings torpes de certificate-to-account sean menos fiables en entornos completamente enforced.
- **CVE-2025-26647** añadió otra capa de hardening alrededor de las mappings de certificates **altSecID / SKI**. Si los DCs no están parcheados, siguen en auditing, o están saltándose explícitamente la validación NTAuth, el abuso posterior de pass-the-certificate / shadow-credential sigue siendo más práctico.
- **El abuso de delegation cross-domain / cross-forest sigue muy vivo** – Windows soporta flujos modernos cross-realm **S4U2Self/S4U2Proxy**, así que los atributos de delegation escribibles en otro dominio siguen teniendo valor. El bloqueo suele ser la fidelidad de las herramientas y los detalles de trust/policy, no el soporte del protocolo.
- **Windows Server 2025 introdujo nueva superficie de ataque adyacente a Kerberos** mediante lógica de migración **dMSA**. Si ves derechos delegados sobre OUs u objetos de service-account en un dominio 2025, revisa la página dedicada de [BadSuccessor](acl-persistence-abuse/BadSuccessor.md) en lugar de tratarlo como “solo otro gMSA”.

## Fast operator checks in modern domains

Antes de elegir una ruta de ataque Kerberos, responde rápidamente cuatro preguntas:

1. **¿Qué cuentas siguen siendo RC4-friendly?**
2. **¿Qué usuarios no requieren pre-auth?**
3. **¿Qué objetos exponen delegation abuse?**
4. **¿Qué partes del dominio son lo bastante nuevas como para imponer el hardening reciente?**
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
- Si las cuentas de **SPN** interesantes son explícitamente compatibles con RC4, **Kerberoasting** sigue siendo barato y rápido.
- Si la mayoría de las cuentas de servicio no tienen **configuración explícita de etype**, espera comportamiento **solo AES** en DCs actualizados de 2026 y planifica un cracking offline más lento o una ruta diferente.
- Si hay **RBCD / KCD / unconstrained delegation**, **S4U** a menudo supera el brute-force.
- Si la **autenticación por certificado** está en juego, recuerda que una ruta **PKINIT** fallida no siempre significa que el certificado sea inútil; en muchos entornos, el mismo certificado sigue funcionando para abuso de **Schannel/LDAPS** (ver [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Errores comunes de Kerberos que cambian el plan de ataque
- **`KDC_ERR_ETYPE_NOTSUPP`** → La cuenta objetivo / DC no usará el tipo de cifrado que solicitaste. Deja de reintentar solo con RC4; proporciona **AES keys** o solicita material de roasting **AES** en su lugar.
- **`KRB_AP_ERR_MODIFIED`** → Probablemente tienes la **clave de servicio incorrecta**, el **SPN incorrecto**, o un ticket forjado que no coincide con la cuenta de servicio que realmente lo está descifrando.
- **`KRB_AP_ERR_SKEW`** → Tu hora está desincronizada. Sincronízate con el DC antes de depurar cualquier otra cosa.
- **`KDC_ERR_BADOPTION`** durante flujos de S4U / delegation → con frecuencia significa **usuarios sensibles/no delegables**, el modelo de delegation incorrecto, o que estás intentando hacer **classic KCD** donde solo **RBCD** aceptaría un ticket **S4U2Self** no reenviable.

## Referencias
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Latest Windows hardening guidance and key dates](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
