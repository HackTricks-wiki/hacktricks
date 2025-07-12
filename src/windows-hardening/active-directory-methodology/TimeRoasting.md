# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

timeRoasting, a principal causa é o mecanismo de autenticação desatualizado deixado pela Microsoft em sua extensão para servidores NTP, conhecido como MS-SNTP. Nesse mecanismo, os clientes podem usar diretamente o Identificador Relativo (RID) de qualquer conta de computador, e o controlador de domínio usará o hash NTLM da conta de computador (gerado pelo MD4) como a chave para gerar o **Código de Autenticação de Mensagem (MAC)** do pacote de resposta.

Os atacantes podem explorar esse mecanismo para obter valores de hash equivalentes de contas de computador arbitrárias sem autenticação. Claramente, podemos usar ferramentas como Hashcat para força bruta.

O mecanismo específico pode ser visualizado na seção 3.1.5.1 "Comportamento da Solicitação de Autenticação" da [documentação oficial do Windows para o protocolo MS-SNTP](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf).

No documento, a seção 3.1.5.1 cobre o Comportamento da Solicitação de Autenticação.
![](../../images/Pasted%20image%2020250709114508.png)
Pode-se ver que quando o elemento ADM ExtendedAuthenticatorSupported é definido como `false`, o formato Markdown original é mantido.

> Citado no artigo original：
>> Se o elemento ADM ExtendedAuthenticatorSupported for falso, o cliente DEVE construir uma mensagem de Solicitação NTP do Cliente. O comprimento da mensagem de Solicitação NTP do Cliente é de 68 bytes. O cliente define o campo Autenticador da mensagem de Solicitação NTP do Cliente conforme descrito na seção 2.2.1, escrevendo os 31 bits menos significativos do valor RID nos 31 bits menos significativos do subcampo Identificador da Chave do autenticador, e então escrevendo o valor do Seletor de Chave no bit mais significativo do subcampo Identificador da Chave.

Na seção 4 do documento Exemplos de Protocolo ponto 3

> Citado no artigo original：
>> 3. Após receber a solicitação, o servidor verifica se o tamanho da mensagem recebida é de 68 bytes. Se não for, o servidor descarta a solicitação (se o tamanho da mensagem não for igual a 48 bytes) ou a trata como uma solicitação não autenticada (se o tamanho da mensagem for 48 bytes). Supondo que o tamanho da mensagem recebida seja de 68 bytes, o servidor extrai o RID da mensagem recebida. O servidor o utiliza para chamar o método NetrLogonComputeServerDigest (conforme especificado na seção 3.5.4.8.2 do [MS-NRPC]) para calcular os checksums criptográficos e selecionar o checksum criptográfico com base no bit mais significativo do subcampo Identificador da Chave da mensagem recebida, conforme especificado na seção 3.2.5. O servidor então envia uma resposta ao cliente, definindo o campo Identificador da Chave como 0 e o campo Crypto-Checksum como o checksum criptográfico calculado.

De acordo com a descrição no documento oficial da Microsoft acima, os usuários não precisam de nenhuma autenticação; eles apenas precisam preencher o RID para iniciar uma solicitação e, em seguida, podem obter o checksum criptográfico. O checksum criptográfico é explicado na seção 3.2.5.1.1 do documento.

> Citado no artigo original：
>> O servidor recupera o RID dos 31 bits menos significativos do subcampo Identificador da Chave do campo Autenticador da mensagem de Solicitação NTP do Cliente. O servidor usa o método NetrLogonComputeServerDigest (conforme especificado na seção 3.5.4.8.2 do [MS-NRPC]) para calcular checksums criptográficos com os seguintes parâmetros de entrada:
>>>![](../../images/Pasted%20image%2020250709115757.png)

O checksum criptográfico é calculado usando MD5, e o processo específico pode ser consultado no conteúdo do documento. Isso nos dá a oportunidade de realizar um ataque de roasting.

## como atacar

Citar para https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-roasting-timeroasting/

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Scripts de Timeroasting de Tom Tervoort
```
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
{{#include ../../banners/hacktricks-training.md}}
