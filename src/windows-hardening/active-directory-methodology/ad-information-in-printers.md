# Informações em Impressoras

{{#include ../../banners/hacktricks-training.md}}

Há vários blogs na Internet que **destacam os perigos de deixar impressoras configuradas com LDAP e credenciais de logon padrão/fracas**.  \
Isso ocorre porque um invasor pode **enganar a impressora para que ela se autentique em um servidor LDAP malicioso** (normalmente, um `nc -vv -l -p 389` ou `slapd -d 2` é suficiente) e capturar as **credenciais da impressora em texto claro**.

Além disso, várias impressoras contêm **logs com nomes de usuário** ou podem até **baixar todos os nomes de usuário** do Domain Controller.

Todas essas **informações confidenciais** e a comum **falta de segurança** tornam as impressoras muito interessantes para invasores.

Alguns blogs introdutórios sobre o assunto:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Configuração da Impressora

- **Localização**: A lista de servidores LDAP geralmente fica na interface web (por exemplo, *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Comportamento**: Muitos servidores web incorporados permitem modificar os servidores LDAP **sem inserir novamente as credenciais** (recurso de usabilidade → risco de segurança).
- **Exploração**: Redirecione o endereço do servidor LDAP para um host controlado pelo invasor e use o botão *Test Connection* / *Address Book Sync* para forçar a impressora a fazer bind com você.

---

## Captura de Credenciais

### Método 1 – Listener Netcat

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

MFPs pequenos/antigos podem enviar um *simple-bind* simples, cujo DN de bind e senha ficam visíveis no fluxo BER bruto. Dispositivos modernos geralmente fazem primeiro uma consulta anônima e, em seguida, tentam o bind, então os resultados variam.<sup>[[1]](#references)</sup>

Um listener `nc` simples na porta 636/3269 recebe apenas o texto cifrado TLS; testar LDAPS requer um endpoint LDAP compatível com TLS, e o redirecionamento deve falhar quando o dispositivo valida corretamente o certificado do servidor.

### Método 2 – Servidor LDAP rogue completo (recomendado)

Como muitos dispositivos fazem uma busca anônima *antes* de se autenticar, iniciar um daemon LDAP real oferece resultados muito mais confiáveis:<sup>[[1]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

Quando a impressora realizar a consulta, você verá as credenciais em texto claro na saída de depuração.

> 💡  O Responder inclui serviços rogue de autenticação LDAP e SMB. Um bind LDAP simples pode expor a senha configurada, enquanto a autenticação NTLM produz material de desafio-resposta; não descreva ambos os resultados como uma senha em texto claro.

---

## Vulnerabilidades recentes de Pass-Back (2024-2025)

Pass-back *não* é um problema teórico – os fornecedores continuam publicando alertas em 2024/2025 que descrevem exatamente essa classe de ataque.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

O firmware ≤ 57.69.91 dos MFPs Xerox VersaLink C70xx permitia que um administrador autenticado (ou qualquer pessoa, quando as credenciais padrão permanecessem em uso) pudesse:

* **CVE-2024-12510 – Pass-back LDAP**: alterar o endereço do servidor LDAP e acionar uma consulta, fazendo com que o dispositivo vazasse as credenciais Windows configuradas para o host controlado pelo atacante.
* **CVE-2024-12511 – Pass-back SMB/FTP**: o mesmo problema via destinos *scan-to-folder*, vazando credenciais NetNTLMv2 ou FTP em texto claro.<sup>[[2]](#references)</sup>

Um listener simples, como:

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

ou um servidor SMB malicioso (`impacket-smbserver`) é suficiente para coletar as credenciais.  

### Canon imageRUNNER / imageCLASS – comunicado de segurança de 20 de maio de 2025

A Canon confirmou uma vulnerabilidade de **SMTP/LDAP pass-back** em dezenas de linhas de produtos Laser e MFP. Um invasor com acesso de administrador pode modificar a configuração do servidor e recuperar as credenciais armazenadas de LDAP **ou** SMTP (muitas organizações usam uma conta privilegiada para permitir a digitalização para e-mail).<sup>[[3]](#references)</sup>

As orientações do fornecedor recomendam explicitamente:

1. Atualizar para o firmware corrigido assim que estiver disponível.
2. Usar senhas de administrador fortes e exclusivas.
3. Evitar contas privilegiadas do AD na integração com impressoras.

---

### Dispositivos Brother e variantes OEM – acesso de administrador derivado do número de série e acesso a credenciais de serviços

Uma divulgação coordenada em 2025 demonstrou uma cadeia especialmente útil em dispositivos Brother afetados; partes do conjunto de vulnerabilidades também afetam modelos OEM, portanto, verifique o modelo exato no comunicado de segurança do fornecedor. Um invasor não autenticado pode obter o número de série do dispositivo por HTTP/HTTPS/IPP em firmware vulnerável, enquanto os números de série também podem estar disponíveis por meio de protocolos de gerenciamento, como SNMP ou PJL. Se a senha de fábrica nunca foi alterada, o número de série determina a senha de administrador. Após a autenticação, a falha independente de pass-back CVE-2024-51984 expõe em texto simples as senhas configuradas para serviços externos, como LDAP ou FTP, transformando o acesso ao gerenciamento da impressora em credenciais de rede reutilizáveis. O firmware corrige a divulgação de senhas de serviços, mas dispositivos fabricados anteriormente ainda exigem que o operador substitua a senha inicial de administrador derivada do número de série.<sup>[[6]](#references)</sup>

A versão atual do Metasploit inclui um módulo auxiliar que descobre o número de série por HTTP, SNMP ou PJL, gera a possível senha inicial e, opcionalmente, verifica-a no console web. `DiscoverSerialVia=AUTO` tenta os métodos de descoberta compatíveis; forneça `TargetSerial` quando o inventário de ativos já incluir o número de série.<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

Use o resultado apenas para validar ativos autorizados. O funcionamento da senha depende do modelo exato e, principalmente, de a senha de administrador de fábrica já ter sido alterada.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Ferramentas automatizadas de enumeração / exploração

| Ferramenta | Finalidade | Exemplo |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Abuso de PostScript/PJL/PCL, acesso ao sistema de arquivos, verificação de credenciais padrão, *descoberta SNMP* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Coleta de configurações (incluindo catálogos de endereços e credenciais LDAP) via HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Executar serviços de autenticação maliciosos e capturar/encaminhar NetNTLM de callbacks SMB | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Descobrir um número de série, derivar a possível senha de administrador de fábrica e verificar o acesso ao console web | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Fortalecimento e detecção

1. **Aplicar patches / atualizar o firmware** das MFPs prontamente (verifique os boletins PSIRT dos fornecedores).
2. **Substituir as senhas de administrador de fábrica** – o firmware, por si só, não remove as senhas iniciais derivadas do número de série em dispositivos Brother/OEM afetados fabricados anteriormente.<sup>[[6]](#references)</sup>
3. **Contas de serviço com privilégio mínimo** – nunca use Domain Admin para LDAP/SMB/SMTP; restrinja o escopo a OUs *somente leitura*.
4. **Restringir o acesso de gerenciamento** – coloque as interfaces web/IPP/SNMP das impressoras em uma VLAN de gerenciamento ou atrás de uma ACL/VPN.
5. **Restringir o tráfego de saída das impressoras** – permita que cada dispositivo se conecte apenas aos destinos esperados de DC/LDAP, e-mail, DNS/NTP, impressão e arquivos de digitalização. Pass-back exige um callback para um endpoint escolhido pelo atacante.
6. **Desativar protocolos não utilizados** – FTP, Telnet, raw-9100 e cifras SSL antigas.
7. **Ativar o registro de auditoria** – alguns dispositivos podem registrar falhas LDAP/SMTP via syslog; correlacione binds inesperados.
8. **Monitorar os destinos de autenticação** – gere alertas quando uma impressora iniciar conexões LDAP, SMB, SMTP ou FTP com um host fora da lista de permissões, especialmente logo após um login de gerenciamento ou uma alteração de configuração.
9. **Usar SNMPv3 ou desativar o SNMP** – a community `public` costuma causar leak de informações sobre o dispositivo e o número de série.

---



---

## References

- [1] [É só uma impressora… Qual é a pior coisa que poderia acontecer?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Impressora multifuncional Xerox Versalink C7025: vulnerabilidades de ataque Pass-Back (corrigidas)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Mitigação/Remediação de vulnerabilidade para impressoras de produção, impressoras multifuncionais de escritório/escritório doméstico e impressoras a laser](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Obtendo credenciais de domínio por meio de uma impressora com Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Explorando impressoras multifuncionais durante um trabalho de pentest](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Vários dispositivos Brother: várias vulnerabilidades (CORRIGIDAS)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: módulo de bypass da autenticação de administrador padrão da Brother](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
