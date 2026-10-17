# Rastreamento de instruções ARM CoreSight via SWO

{{#include ../../banners/hacktricks-training.md}}

Uma [porta de depuração SWD/JTAG](jtag.md) acessível pode ser usada para habilitar um rastreamento de execução Cortex-M em tempo real, sem instrumentação do firmware. Isso requer um MCU com ETM e TPIU, uma rota SWO exposta, uma cópia exata do firmware para decodificação e um analisador lógico rápido o suficiente para a taxa de bits SWO selecionada. Ao contrário das [medições de canal lateral de potência ou EM](side_channel_analysis.md), ETM é um rastreamento de depuração; registrar ambos pode alinhar o leak observado com o código executado. Esse mesmo alinhamento pode ajudar a sincronizar a [fault injection](fault_injection_attacks.md).<sup>[[1]](#references)</sup>

ETM emite eventos de fluxo de controle comprimidos, em vez de bytes de instrução. Um decodificador reconstrói a execução usando a imagem de firmware correspondente. ITM transporta instrumentação de software, enquanto TPIU enquadra as fontes de rastreamento e conduz a saída serial-wire. Antes de aplicar quaisquer valores de registradores, verifique os componentes CoreSight e a multiplexação de pinos do alvo no manual de referência: o exemplo abaixo é para um STM32F401, não uma configuração universal de Cortex-M.<sup>[[1]](#references)</sup>

## Localizar a saída de rastreamento

No STM32F401, o SWO assíncrono usa PB3. No controlador pesquisado, PB3 estava conectado ao resistor R15, fornecendo um ponto de teste acessível. Quando o encapsulamento ou a conexão está oculto, configure temporariamente o pino candidato compatível com SWO como GPIO e alterne seu estado por meio de gravações de memória via SWD. Teste os pontos da placa para encontrar a forma de onda correspondente e, em seguida, restaure a configuração do pino de rastreamento. Conecte o analisador com um terra comum e uma tensão lógica compatível.<sup>[[1]](#references)</sup>

## Habilitar TPIU e ETM com OpenOCD

Os comandos a seguir devem ser incluídos em uma configuração do OpenOCD após selecionar o adaptador apropriado e `target/stm32f4x.cfg`. `setbits` preserva os bits não relacionados nos registradores de controle, enquanto `mww` sobrescreve a palavra inteira. Primeiro, o TPIU direciona o rastreamento assíncrono; em seguida, o ETM é desbloqueado, configurado no modo de programação, recebe o ID de origem de rastreamento `1` e é iniciado. Esses valores seguem a configuração STM32F401 funcional do autor; portanto, adapte-os ao mapa de registradores e à árvore de clock do alvo.<sup>[[1]](#references)[[2]](#references)</sup>

<details>
<summary>Configuração dos registradores de rastreamento do STM32F401 no OpenOCD</summary>

```tcl
proc setbits {addr mask} {
    mem2array value 32 $addr 1
    set value(0) [expr {$value(0) | $mask}]
    array2mem value 32 $addr 1
}
init
reset halt
setbits 0xe0042004 0x20       ;# DBGMCU_CR: trace I/O, async SWO
setbits 0xe000edfc 0x1000000  ;# DEMCR: TRCENA
mww 0xe0040004 1              ;# TPIU_CPSR: port size
mww 0xe0040010 3              ;# TPIU_ACPR: 16 MHz / (3 + 1) = 4 Mbaud
mww 0xe00400f0 2              ;# TPIU_SPPR: async UART framing
mww 0xe0040304 0x102          ;# TPIU_FFCR: formatter
mww 0xe0041fb0 0xC5ACCE55     ;# ETM_LAR: unlock
mww 0xe0041000 0x00201d0e     ;# ETM_CR: programming mode
mww 0xe0041200 1              ;# ETM_TRACEIDR: source ID 1
mww 0xe0041008 0x0000406F     ;# ETM_TER: trigger event
mww 0xe0041020 0x0000006F     ;# ETM_TEE: trace-enable event
mww 0xe0041024 0x00000001     ;# ETM_TSSR: start trace
mww 0xe0041000 0x0000191E     ;# ETM_CR: leave programming mode
```

</details>

A taxa de SWO é `HCLK / (TPIU_ACPR + 1)`. Com HCLK de 16 MHz e `ACPR=3`, capture a 4 Mbaud. No PulseView, coloque o decodificador ETM acima de um decodificador UART no canal do analisador SWO, configure o UART para a taxa real do sinal e use o ID de origem ETM configurado acima. O exemplo usou amostragem de 24 MHz (seis amostras por bit), um trigger na borda de descida e captura com 25% de pré-trigger. Após a configuração, pare/reinicie o target, arme a captura e então execute `resume`; verifique a sincronização do ETM e um caminho de PC plausível em relação ao firmware, em vez de confiar apenas em uma saída que pareça decodificada.<sup>[[1]](#references)</sup>

## Recuperar-se de alterações de clock e pin-mux

Duas ações independentes do firmware podem interromper um trace válido. Uma alteração de PLL aumenta HCLK e, portanto, a taxa de baud do SWO enquanto `ACPR` permanece fixo; a camada UART então recupera bytes incorretos e o replay do ETM se torna um absurdo. Inspecione a configuração de RCC/PLL em [firmware analysis](../firmware-analysis/) e, no exemplo do STM32F401, carregue a imagem Cortex-M em `0x08000000` e importe seu SVD no Ghidra para que as escritas nos registradores de clock tenham nomes. Defina um breakpoint de hardware em uma instrução Thumb de dois bytes *após* a inicialização do clock. No exemplo, `bp 0x080001fa 2 hw` seguido de `resume` para após a configuração da PLL; enquanto estiver parado, `mww 0xe0040010 31` define o novo divisor. Calcule e configure a nova taxa do UART, arme a captura e então execute `resume` novamente. Isso captura o caminho após a transição; não recupera a transição perdida.<sup>[[1]](#references)</sup>

Separadamente, o firmware pode remapear o pad SWO para outro periférico. No exemplo, a configuração de função alternativa do GPIO mudou PB3 para I2C2 SDA, então nenhuma configuração do decodificador poderia restaurar o trace nesse fio. Encontre a inicialização relevante do GPIO no firmware e, em seguida, substitua os pontos de chamada por NOPs Thumb do mesmo tamanho (`0xBF00` por meia palavra) ou pare o core e restaure a configuração do pino compatível com trace via SWD. Ambas as abordagens podem desativar o periférico deslocado; uma restauração em tempo de execução também pode ser sobrescrita novamente pelo firmware. Ao restaurar o pino em tempo de execução, configure o divisor do SWO para o HCLK atual.<sup>[[1]](#references)</sup>

## References

- [1] [Seguindo as instruções: tracing ARM ao vivo com ETM, ITM e TPIU](https://voidstarsec.com/blog/arm-tracing-etm-itm)
- [2] [wrongbaud/etm-examples: configuração de ETM/TPIU do STM32F4 no OpenOCD](https://github.com/wrongbaud/etm-examples/blob/main/openocd-configs/prescaler.cfg)
{{#include ../../banners/hacktricks-training.md}}
