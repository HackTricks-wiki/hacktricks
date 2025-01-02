# macOS Serial Number

{{#include ../../../banners/hacktricks-training.md}}

## Informações Básicas

Dispositivos Apple pós-2010 têm números de série consistindo de **12 caracteres alfanuméricos**, cada segmento transmitindo informações específicas:

- **Primeiros 3 Caracteres**: Indicam a **localização de fabricação**.
- **Caracteres 4 e 5**: Denotam o **ano e a semana de fabricação**.
- **Caracteres 6 a 8**: Servem como um **identificador único** para cada dispositivo.
- **Últimos 4 Caracteres**: Especificam o **número do modelo**.

Por exemplo, o número de série **C02L13ECF8J2** segue essa estrutura.

### **Locais de Fabricação (Primeiros 3 Caracteres)**

Certos códigos representam fábricas específicas:

- **FC, F, XA/XB/QP/G8**: Vários locais nos EUA.
- **RN**: México.
- **CK**: Cork, Irlanda.
- **VM**: Foxconn, República Tcheca.
- **SG/E**: Cingapura.
- **MB**: Malásia.
- **PT/CY**: Coreia.
- **EE/QT/UV**: Taiwan.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: Diferentes locais na China.
- **C0, C3, C7**: Cidades específicas na China.
- **RM**: Dispositivos recondicionados.

### **Ano de Fabricação (4º Caractere)**

Este caractere varia de 'C' (representando a primeira metade de 2010) a 'Z' (segunda metade de 2019), com diferentes letras indicando diferentes períodos de meio ano.

### **Semana de Fabricação (5º Caractere)**

Dígitos 1-9 correspondem às semanas 1-9. Letras C-Y (excluindo vogais e 'S') representam as semanas 10-27. Para a segunda metade do ano, 26 é adicionado a esse número.

{{#include ../../../banners/hacktricks-training.md}}
