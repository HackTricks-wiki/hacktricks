# Forensics de Android

{{#include ../banners/hacktricks-training.md}}

## Dispositivo bloqueado

Prefira métodos de aquisição que preservem o estado do dispositivo e documente cada ação. Se o dispositivo estiver bloqueado, as opções disponíveis dependem do modelo, da versão do Android, do nível de patch e de o acesso ter sido configurado antes da apreensão. A NIST recomenda escolher um método de acordo com o dispositivo e a autoridade responsável pelo exame.<sup>[[1]](#references)</sup>

- Verifique se a depuração USB estava habilitada e se a estação de trabalho de aquisição já está autorizada. O acesso ADB normalmente exige que o usuário desbloqueie o dispositivo e confirme a chave RSA da estação de trabalho.<sup>[[3]](#references)</sup>
- Considere se o acesso biométrico continua disponível de acordo com as regras legais e processuais aplicáveis.
- Um **smudge attack** pode revelar um padrão gráfico de desbloqueio a partir de resíduos na tela, embora toques posteriores e a limpeza reduzam sua confiabilidade.<sup>[[2]](#references)</sup>
- Use ferramentas comerciais ou de pesquisa para bypass de bloqueio somente quando elas oferecerem suporte explícito ao dispositivo e à build exatos do software.

## Aquisição de dados

Em dispositivos mais antigos, um [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) legado pode produzir um arquivo `.backup` que o Android Backup Extractor consegue desempacotar:<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
Não presuma que isso abranja todos os aplicativos. O ADB marca o comando como obsoleto, e o Android 12 exclui dados de aplicativos direcionados ao nível de API 31 ou posterior, a menos que o aplicativo seja depurável.<sup>[[4]](#references)</sup>

### Acesso root ou depuração física

Com acesso root a um dispositivo em execução, primeiro faça um inventário das partições e montagens; os comandos abaixo não se aplicam diretamente a uma aquisição física via JTAG. O dispositivo de bloco correto depende do hardware, portanto, não presuma que seja sempre `mmcblk0`. Crie uma imagem apenas da origem verificada em um armazenamento separado:<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
Faça o hash do resultado e registre o comando exato, os identificadores do dispositivo, o horário e quaisquer alterações feitas durante a aquisição.<sup>[[1]](#references)</sup>

### Memória

O LiME pode adquirir memória física do Linux e de alguns dispositivos Android, mas seu módulo de kernel deve ser compilado para o kernel de destino e carregado com privilégios suficientes. A assinatura de módulos, o kernel lockdown e as proteções modernas do Android podem impedir seu carregamento.<sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Diretrizes para perícia forense em dispositivos móveis](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Ataques Smudge em telas sensíveis ao toque de smartphones](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Restrição de backup do ADB no Android 12](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Extrator de memória do Linux (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Extrator de backup do Android](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
