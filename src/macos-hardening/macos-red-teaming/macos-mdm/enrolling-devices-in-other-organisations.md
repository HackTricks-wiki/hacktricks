# Inscrição de Dispositivos em Outras Organizações

{{#include ../../../banners/hacktricks-training.md}}

## Introdução

Como [**comentado anteriormente**](./#what-is-mdm-mobile-device-management)**,** para tentar inscrever um dispositivo em uma organização **apenas um Número de Série pertencente a essa Organização é necessário**. Uma vez que o dispositivo está inscrito, várias organizações instalarão dados sensíveis no novo dispositivo: certificados, aplicativos, senhas de WiFi, configurações de VPN [e assim por diante](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Portanto, isso pode ser um ponto de entrada perigoso para atacantes se o processo de inscrição não estiver corretamente protegido.

**A seguir está um resumo da pesquisa [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Confira para mais detalhes técnicos!**

## Visão Geral da Análise Binária do DEP e MDM

Esta pesquisa investiga os binários associados ao Programa de Inscrição de Dispositivos (DEP) e à Gestão de Dispositivos Móveis (MDM) no macOS. Os componentes principais incluem:

- **`mdmclient`**: Comunica-se com servidores MDM e aciona check-ins do DEP em versões do macOS anteriores a 10.13.4.
- **`profiles`**: Gerencia Perfis de Configuração e aciona check-ins do DEP em versões do macOS 10.13.4 e posteriores.
- **`cloudconfigurationd`**: Gerencia comunicações da API do DEP e recupera perfis de Inscrição de Dispositivos.

Os check-ins do DEP utilizam as funções `CPFetchActivationRecord` e `CPGetActivationRecord` do framework privado de Perfis de Configuração para buscar o Registro de Ativação, com `CPFetchActivationRecord` coordenando com `cloudconfigurationd` através do XPC.

## Engenharia Reversa do Protocolo Tesla e do Esquema Absinthe

O check-in do DEP envolve `cloudconfigurationd` enviando um payload JSON assinado e criptografado para _iprofiles.apple.com/macProfile_. O payload inclui o número de série do dispositivo e a ação "RequestProfileConfiguration". O esquema de criptografia utilizado é referido internamente como "Absinthe". Desvendar esse esquema é complexo e envolve várias etapas, o que levou à exploração de métodos alternativos para inserir números de série arbitrários na solicitação do Registro de Ativação.

## Interceptando Solicitações do DEP

Tentativas de interceptar e modificar solicitações do DEP para _iprofiles.apple.com_ usando ferramentas como Charles Proxy foram dificultadas pela criptografia do payload e medidas de segurança SSL/TLS. No entanto, habilitar a configuração `MCCloudConfigAcceptAnyHTTPSCertificate` permite contornar a validação do certificado do servidor, embora a natureza criptografada do payload ainda impeça a modificação do número de série sem a chave de descriptografia.

## Instrumentando Binários do Sistema que Interagem com o DEP

Instrumentar binários do sistema como `cloudconfigurationd` requer desativar a Proteção de Integridade do Sistema (SIP) no macOS. Com o SIP desativado, ferramentas como LLDB podem ser usadas para anexar-se a processos do sistema e potencialmente modificar o número de série usado nas interações da API do DEP. Este método é preferível, pois evita as complexidades de direitos e assinatura de código.

**Explorando a Instrumentação Binária:**
Modificar o payload da solicitação do DEP antes da serialização JSON em `cloudconfigurationd` provou ser eficaz. O processo envolveu:

1. Anexar o LLDB a `cloudconfigurationd`.
2. Localizar o ponto onde o número de série do sistema é buscado.
3. Injetar um número de série arbitrário na memória antes que o payload seja criptografado e enviado.

Esse método permitiu recuperar perfis completos do DEP para números de série arbitrários, demonstrando uma vulnerabilidade potencial.

### Automatizando a Instrumentação com Python

O processo de exploração foi automatizado usando Python com a API do LLDB, tornando viável injetar programaticamente números de série arbitrários e recuperar os perfis do DEP correspondentes.

### Impactos Potenciais das Vulnerabilidades do DEP e MDM

A pesquisa destacou preocupações significativas de segurança:

1. **Divulgação de Informações**: Ao fornecer um número de série registrado no DEP, informações organizacionais sensíveis contidas no perfil do DEP podem ser recuperadas.

{{#include ../../../banners/hacktricks-training.md}}
