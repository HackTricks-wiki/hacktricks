# FISSURE - The RF Framework

{{#include ../../banners/hacktricks-training.md}}

**Compreensão e engenharia reversa de sinais baseada em SDR e independente de frequência**

FISSURE é um framework open source de RF e engenharia reversa, projetado para todos os níveis de habilidade, com recursos para detecção e classificação de sinais, descoberta de protocolos, execução de ataques, manipulação de IQ, análise de vulnerabilidades, automação e AI/ML. O framework foi criado para promover a integração rápida de módulos de software, rádios, protocolos, dados de sinais, scripts, fluxogramas, material de referência e ferramentas de terceiros. FISSURE facilita os fluxos de trabalho, mantendo o software em um só lugar e permitindo que as equipes comecem a trabalhar rapidamente, compartilhando a mesma configuração de referência comprovada para distribuições Linux específicas.<sup>[[1]](#references)[[2]](#references)</sup>

O framework e as ferramentas incluídas no FISSURE foram projetados para detectar energia RF, caracterizar sinais, coletar e analisar amostras, desenvolver técnicas de transmissão ou injeção e criar payloads ou mensagens personalizados. FISSURE também fornece informações sobre protocolos e sinais para identificação, criação de pacotes e fuzzing, além de arquivos e listas de reprodução para simulação e teste de tráfego.<sup>[[1]](#references)[[2]](#references)</sup>

A base de código Python e a interface gráfica ajudam iniciantes a aprender sobre RF e ferramentas de engenharia reversa. Educadores podem usar as lições integradas, enquanto desenvolvedores e pesquisadores podem integrar seus próprios módulos e fluxos de trabalho. As versões atuais também oferecem suporte a nós de sensores distribuídos, integração com TAK, fluxos de trabalho de geolocalização e implantações do Apptainer específicas para cada função.<sup>[[1]](#references)[[3]](#references)</sup>

**Informações adicionais**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Primeiros passos

**Compatíveis**

A versão atual do FISSURE usa a branch **`Python3`** para o desenvolvimento ativo com PyQt5 e GNU Radio 3.8 ou 3.10. A branch obsoleta **`Python2_maint-3.7`** continua disponível para sistemas operacionais antigos e ferramentas de terceiros que exigem GNU Radio 3.7. Os nomes anteriores das branches `Python3_maint-3.8` e `Python3_maint-3.10` são históricos; a seleção da versão de manutenção do GNU Radio agora é feita a partir da branch `Python3`.<sup>[[1]](#references)[[3]](#references)</sup>

| Sistema operacional | Branch do FISSURE | Branch padrão do GNU Radio |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | use a supported Linux version | use the matching version |

**Em desenvolvimento (beta)**

Esses sistemas operacionais ainda estão em versão beta. Eles estão em desenvolvimento e sabe-se que vários recursos estão ausentes. Os itens do instalador podem entrar em conflito com programas existentes ou falhar na instalação enquanto o status não for removido.

| Sistema operacional | Branch do FISSURE | Branch padrão do GNU Radio |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

Algumas ferramentas de terceiros não funcionam em todos os sistemas operacionais. Consulte a documentação atual de [Known Conflicts and Third-Party Software](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts) antes de instalar.<sup>[[3]](#references)</sup>

**Instalação**

```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```

A etapa do submódulo baixa os módulos out-of-tree do GNU Radio usados pelo FISSURE e é necessária ao instalar esses módulos. O instalador também instala as dependências PyQt ausentes, necessárias para iniciar suas GUIs de instalação.<sup>[[3]](#references)</sup>

Em seguida, selecione a opção que melhor corresponde ao seu sistema operacional (ela deve ser detectada automaticamente se o seu sistema operacional corresponder a uma opção).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Recomenda-se instalar o FISSURE em um sistema operacional limpo para evitar conflitos existentes. Selecione todas as caixas de seleção recomendadas (botão Default) para evitar erros ao usar as diversas ferramentas do FISSURE. Durante a instalação, haverá várias solicitações, principalmente para pedir permissões elevadas e nomes de usuário. Se um item tiver uma seção "Verify" no final, o instalador executará o comando a seguir e destacará a caixa de seleção do item em verde ou vermelho, dependendo da ocorrência de erros no comando. Os itens marcados sem uma seção "Verify" permanecerão pretos após a instalação.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Uso**

Abra um terminal e digite:

```
fissure
```

Consulte o menu Ajuda do FISSURE para mais detalhes sobre o uso.

## Detalhes

**Componentes**

* Dashboard
* Central Hub (HIPRFISR)
* Identificação de Sinais Alvo (TSI)
* Descoberta de Protocolos (PD)
* Executor de Flow Graph e Scripts (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Recursos**

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Detector de Sinais**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Manipulação de IQ**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Busca de Sinais**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Reconhecimento de Padrões**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Ataques**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Listas de Reprodução de Sinais**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Galeria de Imagens**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Criação de Pacotes**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Integração com Scapy**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Calculadora de CRC**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Registro de Logs**_            |

**Hardware**

Os seguintes hardwares têm diferentes níveis de integração no FISSURE:<sup>[[1]](#references)[[3]](#references)</sup>

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
* HackRF
* RTL2832U
* Adaptadores 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR
* SDRplay: RSPduo, RSPdx, RSPdx R2

## Lições

O FISSURE inclui vários guias úteis para você se familiarizar com diferentes tecnologias e técnicas. Muitos incluem etapas para usar diversas ferramentas integradas ao FISSURE.

* [Lição 1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lição 2: Dissectors Lua](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lição 3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lição 4: Placas ESP](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lição 5: Rastreamento de Radiossondas](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lição 6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lição 7: Tipos de Dados](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lição 8: Blocos GNU Radio Personalizados](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lição 9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lição 10: Exames de Rádio Amador](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lição 11: Ferramentas Wi-Fi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)
* [Lição 12: Criando USBs Inicializáveis](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [Lição 13: Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [Lição 14: Ventiladores de Teto](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## Roteiro

* [ ] Adicionar mais tipos de hardware, protocolos RF, parâmetros de sinal e ferramentas de análise
* [ ] Oferecer suporte a mais sistemas operacionais
* [ ] Desenvolver material didático sobre o FISSURE (ataques RF, Wi-Fi, GNU Radio, PyQt etc.)
* [ ] Criar um condicionador de sinais, extrator de características e classificador de sinais com técnicas de IA/ML selecionáveis
* [ ] Implementar mecanismos de demodulação recursiva para produzir um bitstream a partir de sinais desconhecidos
* [ ] Migrar os principais componentes do FISSURE para um esquema genérico de implantação de nós sensores

## Contribuição

Sugestões para melhorar o FISSURE são muito bem-vindas. Deixe um comentário na página [Discussions](https://github.com/ainfosec/FISSURE/discussions) ou no servidor Discord se tiver alguma ideia sobre os seguintes tópicos:

* Sugestões de novos recursos e alterações de design
* Ferramentas de software com etapas de instalação
* Novas lições ou material adicional para lições existentes
* Protocolos RF de interesse
* Mais tipos de hardware e SDR para integração
* Scripts de análise de IQ em Python
* Correções e melhorias de instalação

As contribuições para melhorar o FISSURE são essenciais para acelerar seu desenvolvimento. Agradecemos muito todas as contribuições. Se quiser contribuir com código, faça um fork do repositório e crie um pull request:

1. Faça um fork do projeto
2. Crie sua branch de recurso (`git checkout -b feature/AmazingFeature`)
3. Faça commit das suas alterações (`git commit -m 'Add some AmazingFeature'`)
4. Envie para a branch (`git push origin feature/AmazingFeature`)
5. Abra um pull request

Também são bem-vindos [Issues](https://github.com/ainfosec/FISSURE/issues) para chamar a atenção para bugs.

## Colaboração

Entre em contato com a equipe de Desenvolvimento de Negócios da Assured Information Security, Inc. (AIS) para propor e formalizar oportunidades de colaboração com o FISSURE — seja dedicando tempo à integração do seu software, contando com os profissionais talentosos da AIS para desenvolver soluções para seus desafios técnicos ou integrando o FISSURE a outras plataformas/aplicações.

## Licença

GPL-3.0

Para ver os detalhes da licença, consulte o arquivo LICENSE.

## Contato

Entre no servidor Discord: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Siga no Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Desenvolvimento de Negócios - Assured Information Security, Inc. - bd@ainfosec.com

## Créditos

Reconhecemos e agradecemos a estes desenvolvedores:

[Créditos](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Agradecimentos

Agradecimentos especiais ao Dr. Samuel Mantravadi e a Joseph Reith por suas contribuições a este projeto.

## References

- [1] [FISSURE - The RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [Documentação do FISSURE - Instalação](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
