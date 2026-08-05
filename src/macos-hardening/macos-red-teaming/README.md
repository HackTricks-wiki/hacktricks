# Red Teaming su macOS

{{#include ../../banners/hacktricks-training.md}}


## Abusing gli MDM

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Se riesci a **compromettere le credenziali di admin** per accedere alla management platform, puoi **potenzialmente compromettere tutti i computer** distribuendo il tuo malware sulle macchine.

Per il red teaming negli ambienti MacOS è altamente consigliato avere una certa comprensione di come funzionano gli MDM:


{{#ref}}
macos-mdm/
{{#endref}}

### Usare MDM come C2

Un MDM avrà i permessi per installare, interrogare o rimuovere profili, installare applicazioni, creare account admin locali, impostare la password del firmware, modificare la chiave FileVault...

Per eseguire un tuo MDM devi avere **il tuo CSR firmato da un vendor**, che potresti provare a ottenere tramite [**https://mdmcert.download/**](https://mdmcert.download/). Per eseguire il tuo MDM per dispositivi Apple puoi usare [**MicroMDM**](https://github.com/micromdm/micromdm).

Tuttavia, per installare un'applicazione su un dispositivo enrolled, questa deve comunque essere firmata da un developer account... tuttavia, durante l'enrolment MDM il **dispositivo aggiunge il certificato SSL dell'MDM come CA trusted**, quindi ora puoi firmare qualsiasi cosa.<sup>[[4]](#references)</sup>

Per fare l'enrolment del dispositivo in un MDM è necessario installare un file **`mobileconfig`** come root, che può essere distribuito tramite un file **pkg** (puoi comprimerlo in zip e, quando viene scaricato da Safari, verrà decompresso).

L'**agent Mythic Orthrus** usa questa tecnica.

### Abusing JAMF PRO

JAMF può eseguire **custom scripts** (script sviluppati dal sysadmin), **native payloads** (creazione di account locali, impostazione della password EFI, monitoraggio di file/processi...) e **MDM** (configurazioni dei dispositivi, certificati dei dispositivi...).<sup>[[5]](#references)</sup>

#### JAMF self-enrolment

Visita una pagina come `https://<company-name>.jamfcloud.com/enroll/` per verificare se hanno abilitato il **self-enrolment**. In tal caso potrebbe **chiedere delle credenziali per accedere**.

Puoi usare lo script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) per eseguire un attacco di password spraying.

Inoltre, dopo aver trovato credenziali valide, potresti riuscire a eseguire il brute-force di altri username tramite il seguente form:

![Abusing JAMF PRO - JAMF self-enrolment: Inoltre, dopo aver trovato credenziali valide, potresti riuscire a eseguire il brute-force di altri username tramite il seguente form](<../../images/image (107).png>)

#### Autenticazione del dispositivo JAMF

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Il binario **`jamf`** conteneva il segreto per aprire il keychain che, al momento della scoperta, era **condiviso tra tutti** ed era: **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
Inoltre, jamf **persiste** come **LaunchDaemon** in **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### JAMF Device Takeover

L'**URL** del **JSS** (Jamf Software Server) utilizzato da **`jamf`** si trova in **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Questo file contiene fondamentalmente l'URL:
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://subdomain-company.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
Quindi, un attaccante potrebbe distribuire un pacchetto malevolo (`pkg`) che **sovrascrive questo file** durante l'installazione, impostando l'**URL su un listener Mythic C2 di un agent Typhon**, così da poter abusare di JAMF come C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Impersonation

Per **impersonare la comunicazione** tra un dispositivo e JAMF sono necessari:

- L'**UUID** del dispositivo: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- Il **keychain JAMF** da: `/Library/Application\ Support/Jamf/JAMF.keychain`, che contiene il certificato del dispositivo

Con queste informazioni, **crea una VM** con l'**UUID** hardware **rubato** e con **SIP disabilitato**, copia il **keychain JAMF**, fai **hook** sull'**agent** Jamf e sottrai le sue informazioni.

#### Furto di secrets

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Potresti anche monitorare il percorso `/Library/Application Support/Jamf/tmp/` per gli **script custom** che gli admin potrebbero voler eseguire tramite Jamf, poiché vengono **posizionati qui, eseguiti e rimossi**. Questi script **potrebbero contenere credenziali**.

Tuttavia, le **credenziali** potrebbero essere passate a questi script come **parametri**, quindi dovresti monitorare `ps aux | grep -i jamf` (anche senza essere root).

Lo script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) può ascoltare l'aggiunta di nuovi file e i nuovi argomenti dei processi.

### Accesso remoto a macOS

E anche riguardo ai **protocolli** di rete "speciali" di **MacOS**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

In alcune occasioni troverai che il **computer MacOS è connesso a un AD**. In questo scenario dovresti provare a fare l'**enumeration** dell'Active Directory come sei abituato a fare. Trova qualche **aiuto** nelle pagine seguenti:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Alcuni **tool locali per MacOS** che potrebbero esserti utili includono `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Inoltre, sono disponibili alcuni tool preparati per MacOS per enumerare automaticamente l'AD e interagire con kerberos:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound è un'estensione del tool di auditing Bloodhound che consente di raccogliere e importare le relazioni di Active Directory dagli host MacOS.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost è un progetto Objective-C progettato per interagire con le API Heimdal krb5 su macOS. L'obiettivo del progetto è consentire security testing più efficace su Kerberos nei dispositivi macOS utilizzando API native, senza richiedere framework o packages aggiuntivi sul target.
- [**Orchard**](https://github.com/its-a-feature/Orchard): tool JavaScript for Automation (JXA) per eseguire l'enumerazione di Active Directory.

### Informazioni sul dominio
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Utenti

I tre tipi di utenti macOS sono:

- **Utenti locali** — Gestiti dal servizio OpenDirectory locale, non sono connessi in alcun modo ad Active Directory.
- **Utenti di rete** — Utenti Active Directory volatili che richiedono una connessione al server DC per autenticarsi.
- **Utenti mobili** — Utenti Active Directory con un backup locale delle proprie credenziali e dei propri file.

Le informazioni locali su utenti e gruppi sono archiviate nella cartella _/var/db/dslocal/nodes/Default._\
Ad esempio, le informazioni sull'utente chiamato _mark_ sono archiviate in _/var/db/dslocal/nodes/Default/users/mark.plist_ e quelle sul gruppo _admin_ si trovano in _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Oltre a utilizzare gli archi HasSession e AdminTo, **MacHound aggiunge tre nuovi archi** al database Bloodhound:<sup>[[2]](#references)</sup>

- **CanSSH** - entità autorizzata a utilizzare SSH sull'host
- **CanVNC** - entità autorizzata a utilizzare VNC sull'host
- **CanAE** - entità autorizzata a eseguire script AppleEvent sull'host
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Maggiori informazioni in [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Computer$ password

Ottieni le password usando:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
È possibile accedere alla password di **`Computer$`** all'interno del portachiavi System.

### Over-Pass-The-Hash

Ottieni un TGT per un utente e un servizio specifici:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Una volta ottenuto il TGT, è possibile iniettarlo nella sessione corrente con:
```bash
bifrost --action asktgt --username test_lab_admin \
--hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
--enctype aes256 --domain test.lab.local
```
### Kerberoasting
```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
--username [user] --hash [hash] --enctype [enctype]
```
Con i service ticket ottenuti è possibile provare ad accedere alle condivisioni su altri computer:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Accesso al Keychain

Il Keychain contiene molto probabilmente informazioni sensibili che, se vi si accedesse senza generare un prompt, potrebbero aiutare a portare avanti un esercizio di red teaming:


{{#ref}}
macos-keychain.md
{{#endref}}

## Servizi esterni

Il Red Teaming su macOS è diverso dal normale Red Teaming su Windows, poiché solitamente **macOS è integrato direttamente con diverse piattaforme esterne**. Una configurazione comune di macOS consiste nell'accedere al computer utilizzando **credenziali sincronizzate con OneLogin e accedere a diversi servizi esterni** (come github, aws...) tramite OneLogin.

## Tecniche varie di Red Team

### Safari

Quando un file viene scaricato in Safari, se è un file "sicuro", viene **aperto automaticamente**. Ad esempio, se **scaricate uno zip**, questo verrà decompresso automaticamente:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Riferimenti

- [1] [Gone Apple Pickin': Red Teaming MacOS Environments in 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Introducing MacHound: A Solution to macOS Active Directory Based Attacks](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domain Enumeration Commands (dscl / net / ldapsearch equivalents)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Come to the Dark Side, We Have Apples: Turning macOS Management Evil](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
