# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**Controlla il fantastico post di:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR per attackers
- Kerberos è il protocollo di autenticazione AD predefinito; la maggior parte delle catene di lateral movement lo toccherà.
- Pensa in **tre fasi operative**:
- **AS-REQ / AS-REP** → password/hash/certificato per ottenere un **TGT**. Qui vivono **AS-REP roasting**, **over-pass-the-hash / pass-the-key**, e **PKINIT**.
- **TGS-REQ / TGS-REP** → usa un TGT per ottenere **service tickets**. Qui diventano rilevanti **Kerberoasting**, **S4U abuse**, **delegation abuse**, e la maggior parte del **ticket-forging tradecraft**.
- **AP-REQ / AP-REP** → presenta il ticket al servizio. Qui avvengono **pass-the-ticket** e il lateral movement specifico del servizio.
- Per cheatsheet pratici (AS-REP/Kerberoasting, ticket forgery, delegation abuse, ecc.) vedi:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Usa questa pagina come indice di **panoramica / “cosa è cambiato di recente”**, poi passa alle pagine dedicate per [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md), oppure [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Note rapide di attacco (2024-2026)
- **Il rafforzamento RC4 ha cambiato i default, non Kerberos stesso** – l'hardening moderno dei DC si concentra sui **tipi di cifratura assunti di default** per gli account che non impostano esplicitamente `msDS-SupportedEncryptionTypes`. Dopo il rollout del 2026, quegli account defaultano sempre più a **AES-only** su DC patchati, quindi le assunzioni cieche `/rc4` per Kerberoast falliscono più spesso. Tuttavia, gli **service account esplicitamente abilitati a RC4** restano ottimi target offline crack.
- **L'enforcement della validazione PAC conta per i ticket forgiati** – l'hardening della firma PAC del 2024 significa che gli abusi **golden/diamond/sapphire/extraSID-style** richiedono dati PAC più realistici e il corretto contesto di firma. I domini non patchati o lasciati in deploy di compatibilità/audit restano target più deboli.
- **Il Kerberos basato su certificati è cambiato due volte**:
- **Il strong certificate binding** (timeline KB5014754) rende le mappature certificate-to-account fatte in modo approssimativo meno affidabili in ambienti pienamente enforced.
- **CVE-2025-26647** ha aggiunto un altro livello di hardening attorno alle mappature certificato **altSecID / SKI**. Se i DC non sono patchati, sono ancora in auditing, o stanno esplicitamente bypassando la validazione NTAuth, il pass-the-certificate / shadow-credential follow-on abuse resta più pratico.
- **L'abuse della delegation cross-domain / cross-forest è ancora molto vivo** – Windows supporta i moderni flussi cross-realm **S4U2Self/S4U2Proxy**, quindi gli attributi di delegation scrivibili in un altro dominio sono ancora preziosi. Il blocco è di solito la fedeltà del tooling e i dettagli di trust/policy, non il supporto del protocollo.
- **Windows Server 2025 ha introdotto nuova superficie d'attacco adiacente a Kerberos** tramite la logica di migrazione **dMSA**. Se vedi diritti delegati su OU o oggetti service-account in un dominio 2025, controlla la pagina dedicata [BadSuccessor page](acl-persistence-abuse/BadSuccessor.md) invece di trattarlo come “solo un altro gMSA”.

## Controlli rapidi per operator in domini moderni

Prima di scegliere un percorso di attacco Kerberos, rispondi rapidamente a quattro domande:

1. **Quali account sono ancora RC4-friendly?**
2. **Quali utenti non richiedono pre-auth?**
3. **Quali oggetti espongono delegation abuse?**
4. **Quali parti del dominio sono abbastanza nuove da imporre l'hardening recente?**
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
- Se gli account SPN **interessanti** sono esplicitamente compatibili con RC4, il Kerberoasting resta economico e veloce.
- Se la maggior parte degli account di servizio non ha **nessuna configurazione esplicita dell'etype**, aspettati un comportamento **solo AES** sui DC 2026 aggiornati e pianifica un cracking offline più lento o un percorso diverso.
- Se è presente **RBCD / KCD / unconstrained delegation**, spesso S4U batte il brute-force.
- Se è in gioco l'**autenticazione certificate**, ricorda che un percorso PKINIT fallito non significa **sempre** che il certificato sia inutile; in molti ambienti lo stesso certificato funziona ancora per abuso **Schannel/LDAPS** (vedi [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Errori Kerberos comuni che cambiano il piano d'attacco
- **`KDC_ERR_ETYPE_NOTSUPP`** → L'account target / DC non userà il tipo di crittografia richiesto. Smetti di riprovare solo con RC4; fornisci chiavi **AES** o richiedi invece materiale da roast **AES**.
- **`KRB_AP_ERR_MODIFIED`** → Probabilmente hai la **chiave di servizio sbagliata**, lo **SPN sbagliato**, oppure un ticket forgiato che non corrisponde all'account di servizio che lo sta effettivamente decifrando.
- **`KRB_AP_ERR_SKEW`** → L'orario non è corretto. Sincronizzati con il DC prima di fare altro debug.
- **`KDC_ERR_BADOPTION`** durante i flussi S4U / delegation → spesso significa **utenti sensibili/non delegabili**, il modello di delegation sbagliato, oppure che stai cercando di fare **classic KCD** dove solo **RBCD** accetterebbe un ticket S4U2Self non forwardable.

## Riferimenti
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Latest Windows hardening guidance and key dates](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
