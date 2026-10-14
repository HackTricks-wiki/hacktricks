# Forense Android

{{#include ../../banners/hacktricks-training.md}}

## Dispositivo bloqueado

Prefira métodos de aquisição que preservem o estado do dispositivo e documente cada ação. Se o dispositivo estiver bloqueado, as opções disponíveis dependem do modelo, da versão do Android, do nível de patch e de o acesso ter sido configurado antes da apreensão. O NIST recomenda escolher um método de acordo com o dispositivo e a autorização para o exame.<sup>[[1]](#references)</sup>

- Verifique se a depuração USB estava ativada e se a estação de trabalho de aquisição já está autorizada. O acesso via ADB normalmente exige que o usuário desbloqueie o dispositivo e confirme a chave RSA da estação de trabalho.<sup>[[3]](#references)</sup>
- Considere se o acesso biométrico continua disponível de acordo com as regras legais e processuais aplicáveis.
- Um **smudge attack** pode revelar um padrão gráfico de desbloqueio a partir dos resíduos na tela, embora toques posteriores e a limpeza reduzam sua confiabilidade.<sup>[[2]](#references)</sup>
- Quando ferramentas autorizadas forem compatíveis com o dispositivo e a versão exata do software, elas podem tentar recuperar ou fazer brute force de PINs, senhas ou padrões. A verificação de credenciais com suporte de hardware, os atrasos entre tentativas e as políticas de apagamento tornam esse processo muito específico para cada dispositivo; portanto, não use uma técnica ou resultado de iPhone como evidência de que há suporte para um dispositivo Android.<sup>[[1]](#references)</sup>

## Aquisição de dados

Em dispositivos mais antigos, um [ADB backup](../../mobile-pentesting/android-app-pentesting/adb-commands.md#legacy-adb-backup) legado pode gerar um arquivo `.backup` que o Android Backup Extractor consegue descompactar:<sup>[[6]](#references)</sup>

```bash
java -jar abe.jar unpack file.backup file.tar
```

Não presuma que isso capture todos os aplicativos. O ADB marca o comando como obsoleto, e o Android 12 exclui dados de aplicativos que visam o nível de API 31 ou posterior, a menos que o aplicativo seja depurável.<sup>[[4]](#references)</sup>

### Acesso root ou depuração física

Com acesso root em um dispositivo ativo, primeiro faça o inventário das partições e montagens; os comandos abaixo não se aplicam diretamente a uma aquisição física por JTAG. O dispositivo de bloco correto depende do hardware, portanto, não presuma que seja sempre `mmcblk0`. Crie uma imagem apenas da origem verificada para um armazenamento separado:<sup>[[1]](#references)</sup>

Uma aquisição JTAG, por sua vez, usa a interface de acesso de teste de hardware do dispositivo e equipamento de aquisição compatível para ler a memória acessível. O pinout, o suporte ao chipset, o estado do dispositivo e a distinção entre alvos voláteis e não voláteis variam de acordo com o dispositivo; documente o caminho de hardware e use um procedimento validado para esse modelo.<sup>[[1]](#references)</sup>

```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```

Por exemplo, se o inventário de partições confirmar que `/dev/block/mmcblk0` é o dispositivo flash inteiro e o destino tiver espaço suficiente, o comando de aquisição original passa a ser:<sup>[[1]](#references)</sup>

```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```

Aqui, `df /data` ajuda a associar `/data` ao sistema de arquivos montado; não deve ser tratado como prova de que `mmcblk0` é a origem correta do dispositivo inteiro nem de que `4096` é o único tamanho de bloco válido para `dd`.

Calcule o hash do resultado e registre o comando exato, os identificadores do dispositivo, o horário e quaisquer alterações feitas durante a aquisição.<sup>[[1]](#references)</sup>

### Memória

O LiME pode adquirir a memória física de dispositivos Linux e de alguns dispositivos Android, mas seu módulo de kernel deve ser compilado para o kernel de destino e carregado com privilégios suficientes. A assinatura de módulos, o bloqueio do kernel e as proteções modernas do Android podem impedir seu carregamento.<sup>[[5]](#references)</sup>

O fluxo de trabalho Android do projeto envia o módulo correspondente usando ADB, encaminha uma porta TCP, carrega o módulo a partir de um root shell e captura o fluxo no host de análise:<sup>[[5]](#references)</sup>

```bash
adb push lime.ko /sdcard/lime.ko
adb forward tcp:4444 tcp:4444
adb shell
su
insmod /sdcard/lime.ko "path=tcp:4444 format=lime"
```

```bash
nc localhost 4444 > ram.lime
```

LiME pode, em vez disso, gravar no armazenamento do dispositivo com `path=/sdcard/ram.lime`, mas isso altera o armazenamento do dispositivo e exige espaço livre suficiente. Registre esse efeito colateral e calcule o hash da imagem adquirida.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Diretrizes para perícia em dispositivos móveis](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Ataques Smudge em telas sensíveis ao toque de smartphones](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Restrição do backup do ADB no Android 12](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Extrator de memória Linux (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Extrator de backup do Android](https://sourceforge.net/projects/adbextractor/)
{{#include ../../banners/hacktricks-training.md}}
