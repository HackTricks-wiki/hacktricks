# Traçage d’instructions ARM CoreSight via SWO

{{#include ../../banners/hacktricks-training.md}}

Un [port de débogage SWD/JTAG](jtag.md) accessible peut servir à activer une trace d’exécution Cortex-M en direct, sans instrumentation du firmware. Cela nécessite un MCU doté d’ETM et de TPIU, une ligne SWO accessible, une copie exacte du firmware pour le décodage et un analyseur logique suffisamment rapide pour le débit binaire SWO sélectionné. Contrairement aux mesures par canal auxiliaire [de puissance ou électromagnétiques](side_channel_analysis.md), l’ETM est une trace de débogage ; leur enregistrement simultané permet d’aligner les fuites observées sur le code exécuté. Le même alignement peut aider à synchroniser l’[injection de fautes](fault_injection_attacks.md).<sup>[[1]](#references)</sup>

L’ETM émet des événements de flux de contrôle compressés plutôt que des octets d’instructions. Un décodeur reconstitue l’exécution à partir de l’image du firmware correspondante. L’ITM transporte l’instrumentation logicielle, tandis que le TPIU encapsule les sources de trace et pilote la sortie série. Avant d’appliquer des valeurs de registre, vérifiez les composants CoreSight de la cible et le multiplexage des broches dans son manuel de référence : l’exemple ci-dessous concerne un STM32F401 et ne constitue pas une configuration universelle pour Cortex-M.<sup>[[1]](#references)</sup>

## Repérer la sortie de trace

Sur le STM32F401, le SWO asynchrone utilise PB3. Sur le contrôleur étudié, PB3 était connecté à la résistance R15, qui fournissait un point de test accessible. Lorsque le boîtier ou le réseau est caché, configurez temporairement la broche candidate compatible SWO en GPIO et faites-la basculer au moyen d’écritures mémoire via SWD. Sondez les points de la carte pour repérer la forme d’onde correspondante, puis rétablissez la configuration de la broche de trace. Connectez l’analyseur avec une masse commune et une tension logique compatible.<sup>[[1]](#references)</sup>

## Activer le TPIU et l’ETM avec OpenOCD

Les commandes suivantes doivent figurer dans une configuration OpenOCD, après sélection de l’adaptateur approprié et de `target/stm32f4x.cfg`. `setbits` préserve les bits non concernés des registres de contrôle, tandis que `mww` écrase le mot entier. Le TPIU achemine d’abord la trace asynchrone ; l’ETM est ensuite déverrouillé, configuré en mode programmation, associé à l’identifiant de source de trace `1`, puis démarré. Ces valeurs correspondent à la configuration STM32F401 fonctionnelle de l’auteur ; adaptez-les donc à la cartographie des registres et à l’arbre d’horloge de la cible.<sup>[[1]](#references)[[2]](#references)</sup>

<details>
<summary>Configuration des registres de trace STM32F401 dans OpenOCD</summary>

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

Le débit SWO est de `HCLK / (TPIU_ACPR + 1)`. Avec un HCLK de 16 MHz et `ACPR=3`, capturez à 4 Mbaud. Dans PulseView, placez le décodeur ETM au-dessus d’un décodeur UART sur le canal d’analyse SWO, réglez l’UART sur le débit réel du signal et utilisez l’ID de source ETM configuré précédemment. L’exemple utilisait un échantillonnage à 24 MHz (six échantillons par bit), un déclenchement sur front descendant et une capture avec 25 % de pré-déclenchement. Après la configuration, arrêtez/réinitialisez la cible, armez la capture, puis faites `resume` ; vérifiez la synchronisation ETM et la cohérence du parcours PC avec le firmware, au lieu de vous fier uniquement à une sortie qui semble décodée.<sup>[[1]](#references)</sup>

## Récupérer après des changements d’horloge et de multiplexage des broches

Deux actions indépendantes du firmware peuvent interrompre une trace valide. Un changement de PLL augmente le HCLK et donc le débit SWO, tandis que `ACPR` reste fixe ; la couche UART récupère alors des octets incorrects et la relecture ETM devient incohérente. Examinez la configuration RCC/PLL dans [firmware analysis](../firmware-analysis/) et, pour l’exemple STM32F401, chargez l’image Cortex-M à `0x08000000` et importez son SVD dans Ghidra afin que les écritures dans les registres d’horloge soient nommées. Définissez un point d’arrêt matériel sur une instruction Thumb de deux octets *après* l’initialisation de l’horloge. Dans l’exemple, `bp 0x080001fa 2 hw` suivi de `resume` s’arrête après la configuration du PLL ; pendant que le processeur est arrêté, `mww 0xe0040010 31` définit le nouveau diviseur. Calculez et définissez le nouveau débit UART, armez la capture, puis faites à nouveau `resume`. Cela capture le parcours après la transition, mais ne récupère pas la transition manquée.<sup>[[1]](#references)</sup>

Par ailleurs, le firmware peut remapper la broche SWO vers un autre périphérique. Dans l’exemple, la configuration de la fonction alternative GPIO a basculé PB3 vers SDA d’I2C2 ; aucun réglage du décodeur ne pouvait donc rétablir la trace sur ce fil. Repérez l’initialisation GPIO concernée dans le firmware, puis remplacez ses points d’appel par des NOP Thumb de taille correspondante (`0xBF00` par demi-mot) ou arrêtez le cœur et rétablissez via SWD une configuration de broche compatible avec la trace. Ces deux méthodes peuvent désactiver le périphérique déplacé ; une restauration à l’exécution peut également être écrasée à nouveau par le firmware. Lors de la restauration de la broche à l’exécution, réglez le diviseur SWO en fonction du HCLK actuel.<sup>[[1]](#references)</sup>

## References

- [1] [Suivre les instructions : traçage ARM en direct avec ETM, ITM et TPIU](https://voidstarsec.com/blog/arm-tracing-etm-itm)
- [2] [wrongbaud/etm-examples : configuration STM32F4 OpenOCD ETM/TPIU](https://github.com/wrongbaud/etm-examples/blob/main/openocd-configs/prescaler.cfg)
{{#include ../../banners/hacktricks-training.md}}
