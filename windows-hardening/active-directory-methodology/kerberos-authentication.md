# Autenticação Kerberos

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

**Esta informação foi extraída do post:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## Kerberos (I): Como funciona o Kerberos? - Teoria

20 - MAR - 2019 - ELOY PÉREZ

O objetivo desta série de posts é esclarecer como o Kerberos funciona, mais do que apenas apresentar os ataques. Isso ocorre porque, em muitas ocasiões, não está claro por que algumas técnicas funcionam ou não. Ter esse conhecimento permite saber quando usar qualquer um desses ataques em um pentest.

Portanto, após uma longa jornada de mergulho na documentação e vários posts sobre o assunto, tentamos escrever neste post todos os detalhes importantes que um auditor deve conhecer para entender como aproveitar o protocolo Kerberos.

Neste primeiro post, apenas a funcionalidade básica será discutida. Em posts posteriores, veremos como realizar os ataques e como funcionam os aspectos mais complexos, como a delegação.

Se você tiver alguma dúvida sobre o tópico que não está bem explicado, não tenha medo de deixar um comentário ou fazer uma pergunta sobre ele. Agora, sobre o tópico.

### O que é Kerberos?

Em primeiro lugar, o Kerberos é um protocolo de autenticação, não de autorização. Em outras palavras, permite identificar cada usuário, que fornece uma senha secreta, no entanto, não valida a quais recursos ou serviços esse usuário pode acessar.

O Kerberos é usado no Active Directory. Nesta plataforma, o Kerberos fornece informações sobre os privilégios de cada usuário, mas é responsabilidade de cada serviço determinar se o usuário tem acesso aos seus recursos.

### Itens do Kerberos

Nesta seção, vários componentes do ambiente Kerberos serão estudados.

**Camada de transporte**

O Kerberos usa UDP ou TCP como protocolo de transporte, que envia dados em texto claro. Devido a isso, o Kerberos é responsável por fornecer criptografia.

As portas usadas pelo Kerberos são UDP/88 e TCP/88, que devem ser ouvidas no KDC (explicado na próxima seção).

**Agentes**

Vários agentes trabalham juntos para fornecer autenticação no Kerberos. Estes são os seguintes:

* **Cliente ou usuário** que deseja acessar o serviço.
* **AP** (Application Server) que oferece o serviço exigido pelo usuário.
* **KDC** (Key Distribution Center), o principal serviço do Kerberos, responsável por emitir os ingressos, instalado no DC (Domain Controller). É suportado pelo **AS** (Authentication Service), que emite os TGTs.

**Chaves de criptografia**

Existem várias estruturas manipuladas pelo Kerberos, como ingressos. Muitas dessas estruturas são criptografadas ou assinadas para evitar que sejam adulteradas por terceiros. Essas chaves são as seguintes:

* **Chave KDC ou krbtgt** que é derivada do hash NTLM da conta krbtgt.
* **Chave do usuário** que é derivada do hash NTLM do usuário.
* **Chave do serviço** que é derivada do hash NTLM do proprietário do serviço, que pode ser uma conta de usuário ou computador.
* **Chave de sessão** que é negociada entre o usuário e o KDC.
* **Chave de sessão de serviço** a ser usada entre o usuário e o serviço.

**Ingressos**

As principais estruturas manipuladas pelo Kerberos são os ingressos. Esses ingressos são entregues aos usuários para serem usados por eles para executar várias ações no reino Kerberos. Existem 2 tipos:

* O **TGS** (Ticket Granting Service) é o ingresso que o usuário pode usar para autenticar-se em um serviço. É criptografado com a chave do serviço.
* O **TGT** (Ticket Granting Ticket) é o ingresso apresentado ao KDC para solicitar TGSs. É criptografado com a chave do KDC.

**PAC**

O **PAC** (Privilege Attribute Certificate) é uma estrutura incluída em quase todos os ingressos. Esta estrutura contém os privilégios do usuário e é assinada com a chave do KDC.

É possível que os serviços verifiquem o PAC comunicando-se com o KDC, embora isso não aconteça com frequência. No entanto, a verificação do PAC consiste apenas em verificar sua assinatura, sem inspecionar se os privilégios dentro do PAC estão corretos.

Além disso, um cliente pode evitar a inclusão do PAC dentro do ingresso especificando-o no campo _KERB-PA-PAC-REQUEST_ da solicitação de ingresso.

**Mensagens**

O Kerberos usa diferentes tipos de mensagens. Os mais interessantes são os seguintes:

* **KRB\_AS\_REQ**: Usado para solicitar o TGT ao KDC.
* **KRB\_AS\_REP**: Usado para entregar o TGT pelo KDC.
* **KRB\_TGS\_REQ**: Usado para solicitar o TGS ao KDC, usando o TGT.
* **KRB\_TGS\_REP**: Usado para entregar o TGS pelo KDC.
* **KRB\_AP\_REQ**: Usado para autenticar um usuário em um serviço, usando o TGS.
* **KRB\_AP\_REP**: (Opcional) Usado pelo serviço para se identificar contra o usuário.
* **KRB\_ERROR**: Mensagem para comunicar condições de erro.

Além disso, mesmo que não faça parte do Kerberos, mas do NRPC, o AP opcionalmente poderia usar a mensagem **KERB\_VERIFY\_PAC\_REQUEST** para enviar ao KDC a assinatura do PAC e verificar se está correta.

Abaixo é mostrado um resumo da sequência de mensagens para realizar a autenticação

![Resumo das mensagens do Kerberos](<../../.gitbook/assets/image (174) (1).png>)

### Processo de autenticação

Nesta seção, a sequência de mensagens para realizar a autenticação será estudada, começando de um usuário sem ingressos, até ser autenticado no serviço desejado.

**KRB\_AS\_REQ**

Em primeiro lugar, o usuário deve obter um TGT do KDC. Para conseguir isso, um KRB\_AS\_REQ deve ser enviado:

![Esquema de mensagem KRB\_AS\_REQ](<../../.gitbook/assets/image (175) (1).png>)

_KRB\_AS\_REQ_ tem, entre outros, os seguintes campos:

* Um **timestamp** criptografado com a chave do cliente, para autenticar o usuário e evitar ataques de replay
* **Nome de usuário** do usuário autenticado
* O **SPN** do serviço associado à conta **krbtgt**
* Um **Nonce** gerado pelo usuário

Nota: o timestamp criptografado é necessário apenas se o usuário exigir pré-autenticação, o que é comum, exceto se a flag [_DONT\_REQ\_PREAUTH_](https://support.microsoft.com/en-us/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro) \_\_ estiver definida na conta do usuário.

**KRB\_AS\_REP**

Após receber a solicitação, o KDC verifica a identidade do usuário descriptografando o timestamp. Se a mensagem estiver correta, ele deve responder com um _KRB\_AS\_REP_:

![Esquema de mensagem KRB\_AS\_REP](<../../.gitbook/assets/image (176) (1).png>)

_KRB\_AS\_REP_ inclui as seguintes informações:

* **Nome de usuário**
* **TGT**, que inclui:
  * **Nome de usuário**
  * **Chave de sessão**
  * **Data de expiração** do TGT
  * **PAC** com privilégios do usuário, assinado pelo KDC
* Alguns **dados criptografados** com a chave do usuário, que incluem:
  * **Chave de sessão**
  * **Data de expiração** do TGT
  * **Nonce** do usuário, para evitar ataques de replay

Uma vez concluído, o usuário já possui o TGT, que pode ser usado para solicitar TGSs e, posteriormente, acessar os serviços.

**KRB\_TGS\_REQ**

Para solicitar um TGS, uma mensagem _KRB\_TGS\_REQ_ deve ser enviada ao KDC:

![Esquema de mensagem KRB\_TGS\_REQ](<../../.gitbook/assets/image (177).png>)

_KRB\_TGS\_REQ_ inclui:

* **Dados criptografados** com a chave de sessão:
  * **Nome de usuário**
  * **Timestamp**
* **TGT**
* **SPN** do serviço solicitado
* **Nonce** gerado pelo usuário

**KRB\_TGS\_REP**

Após receber a mensagem _KRB\_TGS\_REQ_, o KDC retorna um TGS dentro de _KRB\_TGS\_REP_:

![Esquema de mensagem KRB\_TGS\_REP](<../../.gitbook/assets/image (178) (1).png>)

_KRB\_TGS\_REP_ inclui:

* **Nome de usuário**
* **TGS**, que contém:
  * **Chave de sessão do serviço**
  * **Nome de usuário**
  * **Data de expiração** do TGS
  * **PAC** com privilégios do usuário, assinado pelo KDC
* **Dados criptografados** com a chave de sessão:
  * **Chave de sessão do serviço**
  * **Data de expiração** do TGS
  * **Nonce** do usuário, para evitar ataques de replay

**KRB\_AP\_REQ**

Para finalizar, se tudo correu bem, o usuário já possui um TGS válido para interagir com o serviço. Para usá-lo, o usuário deve enviar uma mensagem _KRB\_AP\_REQ_ para o AP:

![Esquema de mensagem KRB\_AP\_REQ](<../../.gitbook/assets/image (179) (1).png>)

_KRB\_AP\_REQ_ inclui:

* **TGS**
* **Dados criptografados** com a chave de sessão do serviço:
  * **Nome de usuário**
  * **Timestamp**, para evitar ataques de replay

Depois disso, se os privilégios do usuário estiverem corretos, ele poderá acessar o serviço. Se for o caso, o AP verificará o PAC em relação ao KDC. E também, se a autenticação mútua for necessária, ele responderá ao usuário com uma mensagem _KRB\_AP\_REP_.

### Referências

* Kerberos v5 RFC: [https://tools.ietf.org/html/rfc4120](https://tools.ietf.org/html/rfc4120)
* \[MS-KILE\] – Extensão Kerberos: [https://msdn.microsoft.com/en-us/library/cc233855.aspx](https://msdn.microsoft.com/en-us/library/cc233855.aspx)
* \[MS-APDS\] – Suporte de Domínio do Protocolo de Autenticação: [https://msdn.microsoft.com/en-us/library/cc223948.aspx](https://msdn.microsoft.com/en-us/library/cc223948.aspx)
* Mimikatz e Ataques Kerberos do Active Directory: [https://adsecurity.org/?p=556](https://adsecurity.org/?p=556)
* Explicando como se eu tivesse 5 anos: Kerberos: [https://www.roguelynn.com/words/explain-like-im-5-kerberos/](https://www.roguelynn.com/words/explain-like-im-5-kerberos/)
* Kerberos e KRBTGT: [https://adsecurity.org/?p=483](https://adsecurity.org/?p=483)
* Mastering Windows Network Forensics and Investigation, 2ª Edição. Autores: S. Anson, S. Bunting, R. Johnson e S. Pearson. Editorial Sibex.
* Active Directory, 5ª Edição. Autores: B. Desmond, J. Richards, R. Allen e A.G. Lowe-Norris
* Service Principal Names: [https://msdn.microsoft.com/en-us/library/ms677949(v=vs.85).aspx](https://msdn.microsoft.com/en-us/library/ms677949\(v=vs.85\).aspx)
* Níveis funcionais do Active Directory: [https://technet.microsoft.com/en-us/library/dbf0cdec-d72f-4ba3-bc7a-46410e02abb0](https://technet.microsoft.com/en-us/library/dbf0cdec-d72f-4ba3-bc7a-46410e02abb0)
* OverPass The Hash – Blog Gentilkiwi: [https://blog.gentilkiwi.com/securite/mimikatz/overpass-the-hash](https://blog.gentilkiwi.com/securite/mimikatz/overpass-the-hash)
* Pass The Ticket – Blog Gentilkiwi: [https://blog.gentilkiwi.com/securite/mimikatz/pass-the-ticket-kerberos](https://blog.gentilkiwi.com/secur
