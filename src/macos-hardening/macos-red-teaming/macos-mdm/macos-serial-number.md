# macOS Serial Number

{{#include ../../../banners/hacktricks-training.md}}

## Información Básica

Los dispositivos de Apple posteriores a 2010 tienen números de serie que constan de **12 caracteres alfanuméricos**, cada segmento transmite información específica:

- **Primeros 3 Caracteres**: Indican la **ubicación de fabricación**.
- **Caracteres 4 y 5**: Denotan el **año y la semana de fabricación**.
- **Caracteres 6 a 8**: Sirven como un **identificador único** para cada dispositivo.
- **Últimos 4 Caracteres**: Especifican el **número de modelo**.

Por ejemplo, el número de serie **C02L13ECF8J2** sigue esta estructura.

### **Ubicaciones de Fabricación (Primeros 3 Caracteres)**

Ciertos códigos representan fábricas específicas:

- **FC, F, XA/XB/QP/G8**: Varias ubicaciones en EE. UU.
- **RN**: México.
- **CK**: Cork, Irlanda.
- **VM**: Foxconn, República Checa.
- **SG/E**: Singapur.
- **MB**: Malasia.
- **PT/CY**: Corea.
- **EE/QT/UV**: Taiwán.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: Diferentes ubicaciones en China.
- **C0, C3, C7**: Ciudades específicas en China.
- **RM**: Dispositivos reacondicionados.

### **Año de Fabricación (4to Carácter)**

Este carácter varía de 'C' (representando la primera mitad de 2010) a 'Z' (segunda mitad de 2019), con diferentes letras que indican diferentes períodos de medio año.

### **Semana de Fabricación (5to Carácter)**

Los dígitos 1-9 corresponden a las semanas 1-9. Las letras C-Y (excluyendo vocales y 'S') representan las semanas 10-27. Para la segunda mitad del año, se añade 26 a este número.

{{#include ../../../banners/hacktricks-training.md}}
