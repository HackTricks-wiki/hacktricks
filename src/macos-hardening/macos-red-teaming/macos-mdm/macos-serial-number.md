# Número de série do macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informações básicas

Não presuma que todo Mac tenha um número de série decodificável de 12 caracteres. O formato antigo da Apple codificava informações de fabricação e configuração, mas a Apple começou a introduzir números de série randomizados em novos produtos em 2021. O formato randomizado não expõe detalhes de fabricação ou configuração.<sup>[[1]](#references)</sup>

### Formato legado de 12 caracteres

Para muitos dispositivos fabricados de 2010 até a transição para o formato randomizado, o formato de 12 caracteres ainda pode fornecer informações úteis para inventário:<sup>[[3]](#references)</sup>

- Os caracteres 1–3 identificam o local de fabricação.
- Os caracteres 4–5 codificam o semestre e a semana de produção.
- Os caracteres 6–8 distinguem unidades produzidas no mesmo local e período.
- Os caracteres 9–12 identificam o modelo ou código de configuração.

Por exemplo, `C02L13ECF8J2` segue essa estrutura legada. Os mapeamentos de fábricas mantidos pela comunidade incluem prefixos como `FC`, `F`, `XA`, `XB`, `QP` e `G8` para locais nos Estados Unidos; `RN` para o México; `CK` para Cork; `VM` para uma unidade da Foxconn na República Tcheca; `SG` ou `E` para Singapura; `MB` para a Malásia; `PT` ou `CY` para a Coreia; e `EE`, `QT` ou `UV` para Taiwan. Vários prefixos — incluindo `FK`, `F1`, `F2`, `W8`, `DL`, `DM`, `DN`, `YM`, `7J`, `1C`, `4H`, `WQ`, `F7`, `C0`, `C3` e `C7` — foram associados a instalações na China; `RM` foi associado a dispositivos recondicionados.<sup>[[3]](#references)</sup>

Os códigos de data do quarto caractere vão de `C` (primeiro semestre de 2010) a `Z` (segundo semestre de 2019), com a sequência reutilizada posteriormente. Para o quinto caractere, os dígitos `1`–`9` representam as semanas 1–9, enquanto as letras `C`–`Y`, excluindo as vogais e `S`, representam as semanas 10–27; some 26 quando o quarto caractere indicar o segundo semestre de um ano.<sup>[[3]](#references)</sup>

Esses mapeamentos são úteis para a triagem de dispositivos legados, mas não constituem uma prova definitiva de origem, idade ou autenticidade. Confirme o resultado por meio dos dados de inventário da Apple.

Para uma identificação confiável, obtenha o número de série do dispositivo e use a consulta de cobertura ou de especificações técnicas da Apple, em vez de tentar inferir o modelo a partir das posições dos caracteres.<sup>[[2]](#references)</sup>

### Obter o número de série

A interface gráfica o exibe em **menu Apple > Sobre Este Mac**.<sup>[[2]](#references)</sup> Em um shell, qualquer um dos comandos a seguir lê o número de série da plataforma:
```bash
system_profiler SPHardwareDataType | awk -F ': ' '/Serial Number/ {print $2}'
ioreg -rd1 -c IOPlatformExpertDevice | awk -F '"' '/IOPlatformSerialNumber/ {print $4}'
```
Trate um número de série como um identificador, não como um autenticador: confirme o dispositivo por meio do fluxo de inventário relevante da Apple ou do MDM antes de tomar decisões de inscrição ou propriedade.

## References

- [1] [MacRumors - Apple inicia a transição para números de série aleatorizados](https://www.macrumors.com/2021/05/05/purple-iphone-12-randomized-serial-number/)
- [2] [Apple Support - Encontre o nome do modelo e o número de série do seu Mac](https://support.apple.com/en-us/102767)
- [3] [Beetstech - Decodifique o significado por trás de um número de série da Apple](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)
{{#include ../../../banners/hacktricks-training.md}}
