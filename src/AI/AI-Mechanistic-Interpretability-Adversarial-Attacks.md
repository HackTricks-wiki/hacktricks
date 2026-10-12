# Ataques adversariais guiados por interpretabilidade mecanística

{{#include ../banners/hacktricks-training.md}}

## Superposição como superfície de ataque

Um espaço de ativação subparametrizado pode codificar mais características semânticas do que tem dimensões, atribuindo características a vetores não ortogonais. Consequentemente, uma característica ativada também se projeta sobre outras direções de características. O treinamento pode compensar combinações observadas na distribuição, mas uma combinação incomum de características válidas pode se somar construtivamente na direção de uma característica-alvo ausente da entrada.<sup>[[1]](#references)[[2]](#references)</sup>

Para vetores de características `v_i ∈ R^D`, ativações `a_i` e alvo `t`, a seguinte magnitude é útil para encontrar combinações candidatas:<sup>[[1]](#references)</sup>

```text
I_t = Σ_i≠t |a_i (v_i · v_t) / ||v_t|| |
candidate condition: I_t > max(a)
```

Isso é apenas uma heurística de triagem. Um exploit precisa preservar os sinais e as magnitudes e avaliar o decoder real, por exemplo, `h_hat[t] = ReLU(b_t + Σ_i a_i(v_i · v_t))` em um decoder linear com pesos compartilhados. Termos negativos podem cancelar o ataque, enquanto o bias do decoder, as normas dos vetores de características, os limiares de ativação e o gating da ReLU podem impedir que um grande score de cosseno absoluto produza a ativação-alvo.<sup>[[1]](#references)</sup>

## Fluxo de trabalho de ataque white-box

Uma avaliação prática pode usar um gargalo do modelo, um sparse autoencoder (SAE) ou outro dicionário de características interpretável. O objetivo não é apenas alterar a classe final: é fazer com que a reconstrução introduza uma característica interna escolhida que não estava ativa antes da compressão. O fluxo de trabalho proposto é:<sup>[[1]](#references)</sup>

1. **Recuperar direções de características:** extraia os vetores relevantes do encoder/decoder, remova características mortas e associe direções ativas a conceitos usando amostras de ativação máxima ou análise de circuitos de características.
2. **Classificar a interferência:** normalize uma cópia dos vetores, calcule sua matriz de similaridade por cosseno, zere a diagonal e examine os vizinhos fora da diagonal mais próximos do alvo. Recalcule os candidatos usando as magnitudes reais de ativação e os produtos escalares brutos com sinal.
3. **Garantir coativação:** mantenha um pequeno conjunto de características com contribuição positiva que possam ser ativadas na mesma camada ou no fluxo residual. Prefira combinações raras ou ausentes nos dados de treinamento; combinações comuns e correlacionadas têm maior probabilidade de terem sido compensadas durante o treinamento.
4. **Sintetizar a entrada:** combine exemplos do conjunto de dados ou padrões que maximizem a ativação dos contribuintes selecionados. Para um detector linear de pixels limitados, defina um pixel como alto para um peso positivo e baixo para um peso negativo e, em seguida, sobreponha os padrões resultantes. Preservar manualmente a estrutura dentro da distribuição e o **espaço negativo** inibitório pode suprimir características não relacionadas.
5. **Verificar o mecanismo:** registre as ativações antes da compressão, as coordenadas comprimidas, as ativações reconstruídas e a saída downstream em uma única passagem forward. Um teste bem-sucedido mostra que o alvo está inativo antes da reconstrução, mas ativo depois, e que a alteração prevista desaparece quando os contribuintes são removidos por ablação.

A triagem mínima a seguir classifica os contribuintes para um decoder com pesos compartilhados cujas **linhas** são vetores de características (transponha primeiro se as características estiverem nas colunas). Use os pesos brutos para o score com sinal e os pesos normalizados apenas para a classificação por cosseno.<sup>[[1]](#references)</sup>

```python
import numpy as np

norm = np.linalg.norm(W_dec, axis=1, keepdims=True)
unit = W_dec / np.clip(norm, 1e-12, None)
cosine = unit @ unit.T
np.fill_diagonal(cosine, 0.0)

target = 42
signed = activations * (W_dec @ W_dec[target])
signed[target] = -np.inf
order = np.argsort(signed)[::-1]
print([(int(i), float(signed[i]), float(cosine[i, target]))
       for i in order[:20] if signed[i] > 0])
```

Não infira explorabilidade apenas com base na similaridade do cosseno. Teste o decoder completo, incluindo seu bias e sua não linearidade, confirme que os contribuidores podem realmente ocorrer juntos e compare com combinações correspondentes da distribuição. Direções semelhantes podem codificar uma relação semântica legítima, em vez de interferência explorável de empacotamento.<sup>[[1]](#references)</sup>

## Ataque demonstrado em modelo de brinquedo

A prova de conceito usou um classificador MNIST deliberadamente interpretável com dois ramos. Um vetor de características esparso de 128 dimensões era classificado diretamente em um ramo e comprimido em um espaço de superposição bidimensional no outro; o mesmo classificador processava tanto as características originais quanto as reconstruídas.<sup>[[1]](#references)</sup>

```text
h       = ReLU(MLP(x))
z       = W_enc h
h_hat   = ReLU(W_enc^T z + b)
y_plain = C(h)
y_super = C(h_hat)
```

Duas direções de features associadas a formas semelhantes a 3/0 envolviam geometricamente direções de classe 5. Somar suas imagens de ativação máxima fez com que as features contribuidoras fossem as mais fortes antes da compressão, mas a reconstrução ativou várias features de classe 5, e o ramo de superposição previu 5. Uma entrada desenhada à mão usando apenas valores mínimos/máximos de pixels reproduziu o efeito, mostrando que, neste cenário de brinquedo, não eram necessárias perturbações de pixels otimizadas por gradiente exato.<sup>[[1]](#references)</sup>

## Triagem geométrica em modelos maiores

O artigo também examinou o SAE Gemma Scope `layer 20 / width 65k / average L0 20`. Multiplicou a matriz de decodificadores normalizada por unidade pela sua transposta, zerou a diagonal, ordenou os vizinhos de cada feature e calculou a média por posição no ranking. A similaridade média de cosseno dos vizinhos mais próximos foi `0.49`, enquanto a similaridade média do 27º vizinho foi `0.25`; geometricamente, quatro dessas direções poderiam corresponder à projeção de um alvo unitário. Esses valores identificam apenas candidatos — não mostram que quatro features adequadas possam ser ativadas em conjunto nem que o alvo ultrapasse o limiar do decodificador.<sup>[[1]](#references)</sup>

## Escopo e limitações

Esta é uma técnica em fase de pesquisa **white-box**, não um ataque demonstrado contra uma CNN implantada ou um LLM de fronteira. Ela exige superposição, direções não ortogonais úteis, acesso interpretável a features internas, ativação controlável das features contribuidoras e que elas sejam reunidas na mesma camada durante uma única passagem forward.<sup>[[1]](#references)</sup>

MLPs de imagem tornam a composição de features especialmente direta. Um transformer é mais difícil porque a atenção precisa reunir as ativações das features escolhidas no mesmo fluxo residual; o artigo não mostra como forçar isso para uma combinação fora da distribuição. Portanto, as alegações sobre manipular direções comportamentais ou de recusa, sistemas físicos de visão ou modelos de fronteira continuam sendo hipóteses.<sup>[[1]](#references)</sup>

## References

- [1] [Wilkinson e Anley — Uma investigação preliminar sobre ataques adversariais interpretáveis por meio da interferência de features em superposição (PDF)](https://www.nccgroup.com/media/kahclmxj/interpretable-adversarial-attacks-in-superpos_.pdf)
- [2] [NCC Group — Ataques adversariais interpretáveis em superposição](https://www.nccgroup.com/research/interpretable-adversarial-attacks-in-superposition/)
{{#include ../banners/hacktricks-training.md}}
