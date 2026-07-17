# Autenticazione Kerberos

{{#include ../../banners/hacktricks-training.md}}

**Consulta l'incredibile post su:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR per gli attacker
- Kerberos è il protocollo di autenticazione predefinito di AD; la maggior parte delle catene di lateral-movement lo coinvolge.
- Pensa in **tre fasi operative**:
- **AS-REQ / AS-REP** → password/hash/certificate per ottenere un **TGT**. È qui che entrano in gioco **AS-REP roasting**, **over-pass-the-hash / pass-the-key** e **PKINIT**.
- **TGS-REQ / TGS-REP** → usa un TGT per ottenere **service ticket**. È qui che diventano rilevanti **Kerberoasting**, **S4U abuse**, **delegation abuse** e la maggior parte delle tecniche di **ticket-forging**.
- **AP-REQ / AP-REP** → presenta il ticket al servizio. È qui che avvengono **pass-the-ticket** e il lateral-movement specifico del servizio.
- Per cheatsheet pratici (AS-REP/Kerberoasting, ticket forgery, delegation abuse, ecc.) consulta:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Usa questa pagina come indice di **overview / “cosa è cambiato di recente”**, quindi passa alle pagine dedicate per [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) o [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Note recenti sugli attacchi (2024-2026)
- **L'hardening di RC4 ha modificato i valori predefiniti, non Kerberos in sé** – il moderno hardening dei DC si concentra sui **default assumed encryption types** per gli account che non impostano esplicitamente `msDS-SupportedEncryptionTypes`. Dopo il rollout del 2026, su DC patchati questi account utilizzano sempre più spesso AES-only come valore predefinito, quindi le ipotesi basate ciecamente su `/rc4` durante il Kerberoast falliscono più frequentemente. Tuttavia, gli account di servizio con RC4 **esplicitamente** abilitato rimangono ottimi target per l'offline-cracking.
- **L'enforcement della validazione PAC è importante per i forged ticket** – l'hardening delle firme PAC del 2024 fa sì che gli abusi **golden/diamond/sapphire/extraSID-style** richiedano dati PAC più realistici e il corretto contesto di firma. I domini non patchati o lasciati in configurazioni di compatibilità/audit rimangono target più vulnerabili.
- **Il Kerberos basato su certificate è cambiato due volte**:
- Il **Strong certificate binding** (timeline di KB5014754) rende meno affidabili le mappature certificate-to-account poco rigorose negli ambienti completamente sottoposti a enforcement.
- **CVE-2025-26647** ha aggiunto un ulteriore livello di hardening intorno alle mappature certificate **altSecID / SKI**. Se i DC non sono patchati, sono ancora in modalità auditing o bypassano esplicitamente la validazione NTAuth, gli abusi successivi di pass-the-certificate / shadow-credential rimangono più pratici.
- **Il delegation abuse cross-domain / cross-forest è ancora molto attuale** – Windows supporta moderni flussi **S4U2Self/S4U2Proxy** cross-realm, quindi gli attributi di delegation modificabili in un altro dominio rimangono preziosi. Il limite è solitamente la fedeltà del tooling e i dettagli di trust/policy, non il supporto del protocollo.
- **La RBCD ricorsiva multi-domain è importante a livello operativo** – nelle forest con 3 o più domini, **S4U2Self/S4U2Proxy** può ricorrere attraverso i trust referral e l'abuso **SPN-less** può richiedere un hop finale **`S4U2Self+U2U`** oltre alla gestione dei ticket dipendente da RC4. Consulta [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).
- **Windows Server 2025 ha introdotto una nuova attack surface adiacente a Kerberos** tramite la logica di migrazione **dMSA**. Se rilevi diritti delegati su OU o oggetti service-account in un dominio 2025, consulta la [pagina BadSuccessor](acl-persistence-abuse/BadSuccessor.md) dedicata invece di considerarlo “solo un altro gMSA”.

## Verifiche rapide per gli operatori nei domini moderni

Prima di scegliere un percorso di attacco Kerberos, rispondi rapidamente a quattro domande:

1. **Quali account sono ancora compatibili con RC4?**
2. **Quali utenti non richiedono la pre-autenticazione?**
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
- Se gli account SPN **interessanti sono esplicitamente compatibili con RC4**, il Kerberoasting rimane economico e rapido.
- Se la maggior parte degli account di servizio **non ha una configurazione esplicita dell'etype**, sui DC aggiornati del 2026 aspettati un comportamento **solo AES** e pianifica un cracking offline più lento o un percorso diverso.
- Se sono presenti **RBCD / KCD / unconstrained delegation**, S4U spesso è preferibile al brute-force.
- Se è in uso l'**autenticazione tramite certificati**, ricorda che un percorso PKINIT fallito **non significa sempre** che il certificato sia inutilizzabile; in molti ambienti lo stesso certificato funziona ancora per abusi di **Schannel/LDAPS** (vedi [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Errori Kerberos comuni che modificano il piano di attacco
- **`KDC_ERR_ETYPE_NOTSUPP`** → L'account target / DC non utilizzerà il tipo di crittografia richiesto. Smetti di riprovare usando solo RC4; fornisci **chiavi AES** o richiedi materiale di roast **AES**.
- **`KRB_AP_ERR_MODIFIED`** → Probabilmente hai la **chiave di servizio errata**, lo **SPN errato** o un ticket contraffatto che non corrisponde all'account di servizio che lo sta effettivamente decrittando.
- **`KRB_AP_ERR_SKEW`** → L'orario non è corretto. Sincronizzati con il DC prima di eseguire qualsiasi altro troubleshooting.
- **`KDC_ERR_BADOPTION`** durante i flussi S4U / delegation → spesso indica **utenti sensibili/non delegabili**, il modello di delegation errato oppure che stai tentando di usare la **classic KCD** quando solo **RBCD** accetterebbe un ticket S4U2Self non forwardable.

## Riferimenti
- [Microsoft Learn - Rilevare e correggere l'uso di RC4 in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Indicazioni più recenti sull'hardening di Windows e date principali](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
