# Número de série do macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informações básicas

Os dispositivos Apple lançados após 2010 têm números de série compostos por **12 caracteres alfanuméricos**, e cada segmento transmite informações específicas:

- **Primeiros 3 caracteres**: Indicam o **local de fabricação**.
- **Caracteres 4 e 5**: Indicam o **ano e a semana de fabricação**.
- **Caracteres 6 a 8**: Servem como um **identificador único** para cada dispositivo.
- **Últimos 4 caracteres**: Especificam o **número do modelo**.

Por exemplo, o número de série **C02L13ECF8J2** segue essa estrutura.

### **Locais de fabricação (primeiros 3 caracteres)**

Alguns códigos representam fábricas específicas:

- **FC, F, XA/XB/QP/G8**: Vários locais nos EUA.
- **RN**: México.
- **CK**: Cork, Irlanda.
- **VM**: Foxconn, República Tcheca.
- **SG/E**: Singapura.
- **MB**: Malásia.
- **PT/CY**: Coreia.
- **EE/QT/UV**: Taiwan.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: Diferentes locais na China.
- **C0, C3, C7**: Cidades específicas na China.
- **RM**: Dispositivos recondicionados.

### **Ano de fabricação (4º caractere)**

Esse caractere varia de 'C' (representando a primeira metade de 2010) a 'Z' (segunda metade de 2019), com letras diferentes indicando diferentes períodos de seis meses.

### **Semana de fabricação (5º caractere)**

Os dígitos de 1 a 9 correspondem às semanas 1 a 9. As letras de C a Y (excluindo as vogais e o 'S') representam as semanas 10 a 27. Para a segunda metade do ano, 26 é adicionado a esse número.

{{#include ../../../banners/hacktricks-training.md}}
