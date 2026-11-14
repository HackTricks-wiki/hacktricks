# Informações em Impressoras

{{#include ../../banners/hacktricks-training.md}}

Uma impressora com credenciais LDAP salvas pode expô-las se a configuração do servidor for alterada e ela, em seguida, autenticar-se em um endpoint malicioso.<sup>[[2]](#references)</sup> O resultado depende do método de bind: um simple bind desprotegido revela a senha, enquanto um bind SASL de desafio-resposta não a revela em texto simples.<sup>[[8]](#references)</sup> Consulte [autenticação LDAP e segurança de transporte](../../network-services-pentesting/pentesting-ldap.md#cleartext-credentials-and-tls-downgrade-risks).

Além disso, várias impressoras contêm **logs com nomes de usuário** ou podem até **baixar todos os nomes de usuário** do Controlador de Domínio.

Todas essas **informações confidenciais** e a **falta de segurança** comum tornam as impressoras muito interessantes para atacantes.

Alguns blogs introdutórios sobre o tema:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Configuração da Impressora

- **Localização**: A lista de servidores LDAP geralmente fica na interface web (por exemplo, *Rede ➜ Configuração LDAP ➜ Configurar LDAP*).
- **Comportamento**: Muitos servidores web incorporados permitem modificar o servidor LDAP **sem inserir novamente as credenciais** (recurso de usabilidade → risco de segurança).
- **Exploração**: Redirecione o endereço do servidor LDAP para um host controlado pelo atacante e use o botão *Test Connection* / *Address Book Sync* para forçar a impressora a fazer bind com você.

---

## Captura de Credenciais

### Método 1 – Listener Netcat

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

Uma BindRequest simples pode expor o bind DN e a password no fluxo BER, mesmo que o servidor rejeite o login posteriormente. Uma consulta anónima ou apenas a negociação SASL não expõe essa password armazenada.<sup>[[8]](#references)</sup>

Um listener `nc` simples na porta 636/3269 vê um handshake TLS, não um bind LDAP. LDAPS requer um endpoint compatível com TLS. A validação do certificado, por si só, não impede o pass-back se a impressora aceitar a alteração do hostname e o novo endpoint tiver um certificado válido para esse hostname; o cliente também tem de restringir quais servidores estão autorizados a receber a credencial armazenada.<sup>[[8]](#references)</sup>

### Method 2 – Full Rogue LDAP server (recommended)

Uma impressora pode exigir uma resposta LDAP válida antes de tentar um bind.<sup>[[10]](#references)</sup> Um servidor LDAP completo pode lidar com essa troca preliminar, mas não pode fazer um cliente que esteja vinculado a um mecanismo SASL forte ou ao servidor TLS pretendido revelar a sua password.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # use a base DN compatible with the printer lookup

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

Trate uma consulta como evidência de uma conexão, não como prova de divulgação de senha. Uma senha só é exposta se o cliente enviar um bind com senha em texto simples; verifique o mecanismo de bind real e o estado do TLS.<sup>[[8]](#references)</sup>

> 💡  O Responder inclui serviços rogue de autenticação LDAP e SMB. Um bind LDAP simples pode expor a senha configurada, enquanto a autenticação NTLM produz material challenge-response; não descreva os dois resultados como uma senha em texto claro.

### Seleção de mecanismo SASL

Alguns clientes LDAP de impressoras escolhem entre os mecanismos anunciados por um servidor LDAP.<sup>[[8]](#references)[[10]](#references)</sup> Pesquisas mostraram que um cliente disposto a aceitar um mecanismo SASL anunciado que permite texto simples poderia enviar uma senha, enquanto sua negociação NTLM usual produziria apenas dados challenge-response.<sup>[[9]](#references)[[10]](#references)</sup> Isso é uma **falha na política do cliente**, não uma propriedade de todos os binds SASL: em vez disso, um cliente que exija um mecanismo mais forte ou fixe o servidor TLS pretendido deve falhar de forma segura.<sup>[[8]](#references)</sup> O OpenLDAP desativa por padrão os mecanismos SASL que permitem texto simples, portanto, um daemon padrão não comprova que esse comportamento exista em uma impressora.<sup>[[11]](#references)</sup>

---

## Vulnerabilidades recentes de Pass-Back (2024-2025)

Pass-back *não* é uma questão teórica: os fornecedores continuam publicando avisos em 2024/2025 que descrevem exatamente essa classe de ataque.

### Xerox VersaLink – CVE-2024-12510 e CVE-2024-12511

O firmware ≤ 57.69.91 das MFPs Xerox VersaLink C70xx permitia que um administrador autenticado (ou qualquer pessoa, quando as credenciais padrão permaneciam em uso):

* **CVE-2024-12510 – LDAP pass-back**: alterasse o endereço do servidor LDAP e acionasse uma consulta, fazendo com que o dispositivo vazasse as credenciais do Windows configuradas para o host controlado pelo atacante.
* **CVE-2024-12511 – SMB/FTP pass-back**: o mesmo problema por meio dos destinos de *scan-to-folder*, vazando credenciais NetNTLMv2 ou FTP em texto claro.<sup>[[2]](#references)</sup>

Um listener simples, como:

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

ou um servidor SMB malicioso (`impacket-smbserver`) é suficiente para coletar as credenciais.  

### Canon imageRUNNER / imageCLASS – Comunicado de 20 de maio de 2025

A Canon confirmou uma vulnerabilidade de **SMTP/LDAP pass-back** em dezenas de linhas de produtos Laser e MFP. Um atacante com acesso de administrador pode modificar a configuração do servidor e recuperar as credenciais armazenadas de LDAP **ou** SMTP (muitas organizações usam uma conta privilegiada para permitir o envio de digitalizações por e-mail).<sup>[[3]](#references)</sup>

As orientações do fornecedor recomendam explicitamente:

1. Atualizar para o firmware corrigido assim que estiver disponível.
2. Usar senhas de administrador fortes e exclusivas.
3. Evitar contas privilegiadas do AD para a integração com impressoras.

---

### Dispositivos Brother e variantes OEM – acesso de administrador derivado do número de série e credenciais de serviço

Uma divulgação coordenada em 2025 demonstrou uma cadeia especialmente útil em dispositivos Brother afetados; partes do conjunto de vulnerabilidades também afetam modelos OEM, portanto, verifique o modelo exato no comunicado do fornecedor. Um atacante não autenticado pode obter o número de série do dispositivo por HTTP/HTTPS/IPP em firmware vulnerável, enquanto os números de série também podem estar disponíveis por meio de protocolos de gerenciamento como SNMP ou PJL. Se a senha de fábrica nunca tiver sido alterada, o número de série determina a senha de administrador. Após se autenticar, a vulnerabilidade separada de pass-back CVE-2024-51984 expõe em texto simples senhas configuradas para serviços externos, como LDAP ou FTP, transformando o acesso de gerenciamento da impressora em credenciais de rede reutilizáveis. O firmware corrige a divulgação de senhas de serviço, mas dispositivos fabricados anteriormente ainda exigem que o operador substitua a senha inicial de administrador derivada do número de série.<sup>[[6]](#references)</sup>

A versão atual do Metasploit inclui um módulo auxiliary que descobre o número de série por HTTP, SNMP ou PJL, gera a senha inicial candidata e, opcionalmente, verifica-a no console web. `DiscoverSerialVia=AUTO` tenta os métodos de descoberta compatíveis; forneça `TargetSerial` quando o inventário de ativos já contiver o número de série.<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

Use o resultado apenas para validar ativos autorizados. Se a senha funcionar depende do modelo exato e, principalmente, de a senha de administrador de fábrica já ter sido alterada.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Ferramentas de Enumeração / Exploração Automatizadas

| Ferramenta | Finalidade | Exemplo |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Abuso de PostScript/PJL/PCL, acesso ao sistema de arquivos, verificação de default-creds, *descoberta SNMP*; consulte [avaliação de PJL](../../network-services-pentesting/9100-pjl.md) | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Coletar configurações (incluindo agendas de endereços e credenciais LDAP) via HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Executar serviços de autenticação maliciosos e capturar/encaminhar NetNTLM de callbacks SMB | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Descobrir um número de série, derivar a possível senha de administrador de fábrica e verificar o acesso ao console Web | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Hardening e Detecção

1. **Aplicar patches/atualizações de firmware** às MFPs prontamente (consulte os boletins PSIRT do fornecedor).
2. **Substituir as senhas de administrador de fábrica** – o firmware, por si só, não remove as senhas iniciais derivadas do número de série em dispositivos Brother/OEM afetados fabricados anteriormente.<sup>[[6]](#references)</sup>
3. **Contas de serviço com privilégios mínimos** – nunca use Domain Admin para LDAP/SMB/SMTP; restrinja o acesso a escopos de OU *somente leitura*.
4. **Restringir o acesso de gerenciamento** – coloque as interfaces Web/IPP/SNMP da impressora em uma VLAN de gerenciamento ou atrás de uma ACL/VPN.
5. **Restringir o tráfego de saída da impressora** – permita que cada dispositivo se conecte apenas aos destinos esperados de DC/LDAP, e-mail, DNS/NTP, impressão e arquivos de digitalização. O Pass-Back exige um callback a um endpoint escolhido pelo atacante.
6. **Desativar protocolos não utilizados** – FTP, Telnet, raw-9100 e cifras SSL antigas.
7. **Ativar o registro de auditoria** – alguns dispositivos podem enviar falhas de LDAP/SMTP ao syslog; correlacione binds inesperados.
8. **Monitorar destinos de autenticação** – alerte quando uma impressora iniciar conexões LDAP, SMB, SMTP ou FTP com um host fora da lista de permissões, especialmente logo após um login de gerenciamento ou uma alteração de configuração.
9. **Usar SNMPv3 ou desativar SNMP** – a community `public` frequentemente expõe informações do dispositivo e do número de série.

---



---



## References

- [1] [É só uma impressora… O que de pior poderia acontecer?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Impressora multifuncional Xerox Versalink C7025: vulnerabilidades de ataque Pass-Back (corrigidas)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Mitigação/Remediação de vulnerabilidades para impressoras de produção, impressoras multifuncionais para escritório/pequenos escritórios e impressoras a laser](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Obtenção de credenciais de domínio por meio de uma impressora com Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Explorando impressoras multifuncionais durante um teste de penetração](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Vários dispositivos Brother: várias vulnerabilidades (CORRIGIDAS)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: módulo de bypass da autenticação de administrador padrão Brother](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
- [8] [RFC 4513 – métodos de autenticação LDAP e mecanismos de segurança](https://datatracker.ietf.org/doc/html/rfc4513)
- [9] [Servidor Docker LDAP passback](https://github.com/cybertrinchera/ldap-passback-docker)
- [10] [Ataque LDAP pass back – ACCEIS](https://www.acceis.fr/ldap-pass-back-attack/)
- [11] [slapd-config(5) – propriedades de segurança SASL](https://man7.org/linux/man-pages/man5/slapd-config.5.html)
{{#include ../../banners/hacktricks-training.md}}
