# Autenticazione Kerberos

{{#include ../../banners/hacktricks-training.md}}

Per una panoramica a livello di protocollo degli scambi riassunti di seguito, consulta l'articolo di Tarlogic su Kerberos.<sup>[[3]](#references)</sup>

## TL;DR per gli attacker
- Kerberos è il protocollo di autenticazione AD predefinito; la maggior parte delle catene di lateral movement lo coinvolge.
- Pensa in **tre fasi operative**:<sup>[[3]](#references)</sup>
- **AS-REQ / AS-REP** → password/hash/certificate per ottenere un **TGT**. È qui che entrano in gioco **AS-REP roasting**, **over-pass-the-hash / pass-the-key** e **PKINIT**.
- **TGS-REQ / TGS-REP** → usa un TGT per ottenere **service tickets**. È qui che diventano rilevanti **Kerberoasting**, **S4U abuse**, **delegation abuse** e la maggior parte delle tecniche di **ticket-forging**.
- **AP-REQ / AP-REP** → presenta il ticket al servizio. È qui che avvengono **pass-the-ticket** e il lateral movement specifico del servizio.
- Per cheatsheet pratici (AS-REP/Kerberoasting, ticket forgery, delegation abuse, ecc.) consulta:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Usa questa pagina come indice di **panoramica / “cosa è cambiato di recente”**, poi passa alle pagine dedicate per [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) o [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Note recenti sugli attacchi (2024-2026)
- **L'hardening di RC4 ha modificato i valori predefiniti, non Kerberos in sé** – l'hardening moderno dei DC si concentra sui **tipi di crittografia predefiniti** per gli account che non impostano esplicitamente `msDS-SupportedEncryptionTypes`. Dopo il rollout del 2026, questi account utilizzano sempre più spesso **solo AES** come valore predefinito sui DC patchati, quindi le ipotesi di Kerberoast basate ciecamente su `/rc4` falliscono più frequentemente. Tuttavia, gli account di servizio con RC4 **abilitato esplicitamente** restano ottimi target per l'offline cracking.<sup>[[1]](#references)</sup>
- **L'enforcement della validazione PAC è importante per i forged tickets** – l'hardening delle firme PAC del 2024 significa che gli abusi di tipo **golden/diamond/sapphire/extraSID** richiedono dati PAC più realistici e il contesto di firma corretto. I domini non patchati o lasciati in deployment di compatibilità/audit restano target più vulnerabili.<sup>[[2]](#references)</sup>
- **Il Kerberos basato su certificate è cambiato due volte**:
- Il **strong certificate binding** (timeline di KB5014754) rende meno affidabili le mappature certificate-to-account superficiali negli ambienti completamente sottoposti a enforcement.
- **CVE-2025-26647** ha aggiunto un ulteriore livello di hardening alle mappature `altSecurityIdentities` che utilizzano il Subject Key Identifier di un certificate. Il livello delle patch, lo stato di enforcement o audit e la configurazione della mappatura esplicita sono quindi importanti per valutare pass-the-certificate e i percorsi correlati basati su certificate.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup> Per PKINIT, il KDC valida anche il percorso del certificate e verifica che l'issuer sia trusted tramite lo store NTAuth.<sup>[[8]](#references)</sup>
- **L'abuse della delegation cross-domain / cross-forest è ancora molto attuale** – Windows supporta i moderni flussi **S4U2Self/S4U2Proxy** cross-realm, quindi gli attributi di delegation scrivibili in un altro dominio restano preziosi. Il limite è solitamente la fedeltà dei tool e i dettagli di trust/policy, non il supporto del protocollo.
- **La RBCD ricorsiva su più domini è importante dal punto di vista operativo** – nelle forest con 3 o più domini, **S4U2Self/S4U2Proxy** può ricorrere attraverso i trust referral e l'abuse **SPN-less** può richiedere un hop finale **`S4U2Self+U2U`** oltre alla gestione dei ticket dipendente da RC4. Consulta [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[4]](#references)</sup>
- **Windows Server 2025 ha introdotto i Managed Service Accounts delegati (dMSA)** e la relativa logica di migrazione. Se rilevi diritti delegati su OU o oggetti service-account in un dominio 2025, consulta la [pagina BadSuccessor dedicata](acl-persistence-abuse/BadSuccessor.md) invece di trattarlo come “un altro gMSA”.<sup>[[7]](#references)</sup>

## Verifiche rapide per gli operatori nei domini moderni

Prima di scegliere un percorso di attacco Kerberos, rispondi rapidamente a quattro domande:

1. **Quali account sono ancora compatibili con RC4?**
2. **Quali utenti non richiedono la pre-auth?**
3. **Quali oggetti espongono possibilità di delegation abuse?**
4. **Quali parti del dominio sono abbastanza recenti da applicare l'hardening più recente?**
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
Interpretazione pratica:
- Se gli account **SPN interessanti sono esplicitamente compatibili con RC4**, Kerberoasting rimane economico e veloce.
- Se la maggior parte degli account di servizio non ha una **configurazione etype esplicita**, aspettati un comportamento **solo AES** sui DC 2026 aggiornati e pianifica un cracking offline più lento o un percorso diverso.
- Se sono presenti **RBCD / KCD / unconstrained delegation**, S4U spesso è preferibile al brute-force.
- Se è in uso la **certificate auth**, ricorda che un percorso PKINIT fallito non significa **sempre** che il certificato sia inutilizzabile; in molti ambienti lo stesso certificato funziona ancora per l'abuso di **Schannel/LDAPS** (vedi [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Common Kerberos errors that change the attack plan
- **`KDC_ERR_ETYPE_NOTSUPP`** → L'account target / DC non utilizzerà il tipo di cifratura richiesto. Smetti di riprovare usando solo RC4; fornisci **chiavi AES** o richiedi invece materiale di roast **AES**.
- **`KRB_AP_ERR_MODIFIED`** → Probabilmente hai la **chiave di servizio errata**, lo **SPN errato** o un ticket contraffatto che non corrisponde all'account di servizio che lo sta effettivamente decrittando.
- **`KRB_AP_ERR_SKEW`** → L'orario non è sincronizzato. Sincronizza con il DC prima di eseguire qualsiasi altra attività di debugging.
- **`KDC_ERR_BADOPTION`** durante i flussi S4U / delegation → spesso indica **utenti sensibili/non delegabili**, il modello di delegation errato o che stai tentando di usare la **classic KCD** dove solo **RBCD** accetterebbe un ticket S4U2Self non-forwardable.

## References
- [1] [Microsoft Learn - Rilevare e correggere l'uso di RC4 in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - Indicazioni più recenti sull'hardening di Windows e date chiave](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I): Come funziona Kerberos? – Teoria](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Sfruttare RBCD in ambienti Cross-Domain e Cross-Forest: Parte 2](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)
- [5] [Microsoft Support - Modifiche all'autenticazione basata su certificati KB5014754](https://support.microsoft.com/help/5014754)
- [6] [Microsoft - Vulnerabilità di mapping dei certificati Kerberos CVE-2025-26647](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-26647)
- [7] [Microsoft Learn - Panoramica degli account di servizio gestiti delegati](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [8] [Microsoft Learn - Requisiti dei certificati per smart card e validazione KDC](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration)
{{#include ../../banners/hacktricks-training.md}}
