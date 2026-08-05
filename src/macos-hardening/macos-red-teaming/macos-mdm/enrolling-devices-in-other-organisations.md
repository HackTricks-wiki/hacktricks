# Inscrição de Dispositivos em Outras Organizações

{{#include ../../../banners/hacktricks-training.md}}

## Introdução

Como [**comentado anteriormente**](#what-is-mdm-mobile-device-management)**,** para tentar inscrever um dispositivo em uma organização, **é necessário apenas um número de série pertencente a essa organização**. Depois que o dispositivo é inscrito, várias organizações instalam dados confidenciais no novo dispositivo: certificados, aplicações, senhas de WiFi, configurações de VPN [e assim por diante](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Portanto, isso pode ser um ponto de entrada perigoso para attackers se o processo de inscrição não estiver devidamente protegido.

**A seguir, há um resumo da pesquisa [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Consulte-a para obter mais detalhes técnicos!**<sup>[[1]](#references)</sup>

## Visão Geral da Análise dos Binários de DEP e MDM

Esta pesquisa analisa os binários associados ao Device Enrollment Program (DEP) e ao Mobile Device Management (MDM) no macOS. Os principais componentes incluem:

- **`mdmclient`**: Comunica-se com servidores MDM e aciona check-ins do DEP nas versões do macOS anteriores à 10.13.4.
- **`profiles`**: Gerencia Configuration Profiles e aciona check-ins do DEP nas versões 10.13.4 e posteriores do macOS.
- **`cloudconfigurationd`**: Gerencia as comunicações com a API do DEP e recupera os perfis de inscrição de dispositivos.

Os check-ins do DEP utilizam as funções `CPFetchActivationRecord` e `CPGetActivationRecord` do framework privado Configuration Profiles para obter o Activation Record, com `CPFetchActivationRecord` coordenando-se com `cloudconfigurationd` por meio de XPC.<sup>[[1]](#references)</sup>

## Engenharia Reversa do Protocolo Tesla e do Esquema Absinthe

O check-in do DEP envolve o envio, pelo `cloudconfigurationd`, de um payload JSON criptografado e assinado para _iprofiles.apple.com/macProfile_. O payload inclui o número de série do dispositivo e a ação "RequestProfileConfiguration". O esquema de criptografia utilizado é chamado internamente de "Absinthe". Desvendar esse esquema é complexo e envolve várias etapas, o que levou à exploração de métodos alternativos para inserir números de série arbitrários na solicitação do Activation Record.<sup>[[1]](#references)</sup>

## Proxy de Solicitações do DEP

As tentativas de interceptar e modificar solicitações do DEP para _iprofiles.apple.com_ usando ferramentas como Charles Proxy foram dificultadas pela criptografia do payload e pelas medidas de segurança SSL/TLS. No entanto, habilitar a configuração `MCCloudConfigAcceptAnyHTTPSCertificate` permite contornar a validação do certificado do servidor, embora a natureza criptografada do payload ainda impeça a modificação do número de série sem a chave de descriptografia.<sup>[[1]](#references)</sup>

## Instrumentação de Binários do Sistema que Interagem com o DEP

A instrumentação de binários do sistema, como `cloudconfigurationd`, exige a desativação do System Integrity Protection (SIP) no macOS. Com o SIP desativado, ferramentas como o LLDB podem ser usadas para anexar-se a processos do sistema e potencialmente modificar o número de série utilizado nas interações com a API do DEP. Este método é preferível, pois evita as complexidades relacionadas a entitlements e assinatura de código.

**Explorando a Instrumentação de Binários:**
Modificar o payload da solicitação do DEP antes da serialização JSON em `cloudconfigurationd` mostrou-se eficaz. O processo envolveu:

1. Anexar o LLDB ao `cloudconfigurationd`.
2. Localizar o ponto em que o número de série do sistema é obtido.
3. Injetar um número de série arbitrário na memória antes que o payload seja criptografado e enviado.

Este método permitiu recuperar perfis DEP completos para números de série arbitrários, demonstrando uma possível vulnerabilidade.<sup>[[1]](#references)</sup>

### Automatizando a Instrumentação com Python

O processo de exploração foi automatizado usando Python com a API do LLDB, tornando viável injetar números de série arbitrários programaticamente e recuperar os perfis DEP correspondentes.<sup>[[1]](#references)</sup>

### Possíveis Impactos das Vulnerabilidades de DEP e MDM

A pesquisa destacou preocupações significativas de segurança:

1. **Divulgação de Informações**: Ao fornecer um número de série registrado no DEP, é possível recuperar informações organizacionais confidenciais contidas no perfil DEP.<sup>[[1]](#references)</sup>

## Referências

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
