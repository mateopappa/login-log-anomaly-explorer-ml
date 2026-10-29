# Login-log anomaly explorer

Brief para un revisor. 29 oct 2026. Datos sintéticos.

Prototipo de Mateo Pappalardo para un bootcamp de Proofpoint. Detecta actividad sospechosa en logins sintéticos y deja que un investigador acotado arme un veredicto con evidencia. El objetivo principal es conseguir trabajo: mostrar un producto medible, no un chatbot.

Repositorio: https://github.com/mateopappa/login-log-anomaly-explorer-ml

Las dos corridas en vivo de esta nota están en la base local. Todavía no están en `main`.

## La frase que hay que creer

La aguja la metimos nosotros. En el escenario fácil las reglas y el modelo se ven muy bien. En el borde la regla deja de cerrar, y el investigador puede equivocarse igual. El agente no detecta. La métrica es la corrida puntuada, no un dossier suelto.

## Para qué existe

Es un trabajo de dos semanas. La consigna pide un sistema chico, integrado y medible:

1. Generador reproducible, con la verdad aparte.
2. Ingestión y persistencia validadas.
3. Detector de reglas interpretable.
4. Detector de ML evaluado por separado.
5. Investigación con herramientas de solo lectura.
6. Evaluación, tests y una demo reproducible.

Reglas y ML no se mezclan en un score híbrido.

Mateo lo está usando como pieza de contratación. Lo que quiere que se vea es que cumple la consigna, que el software está armado como un producto, y que dice el límite antes de que se lo pregunten.

## Qué no es

No es un detector de producción ni un SOC real. No hay usuarios reales, ni logs de clientes, ni remediación. El deploy de QA está escrito y apagado. Redpanda, Prometheus y Grafana existen como perfil opcional de Compose. No hay Kubernetes.

Streamlit sigue en el repo como demo secundaria. La consola que se presenta es React.

## Consigna y dónde está

| Pedido | Dónde vive | Estado |
| --- | --- | --- |
| Generador determinista, con verdad aparte | `simulation/`, seed grabado | Hecho |
| Ingestión y persistencia validadas | FastAPI + Postgres | Hecho |
| Detector de reglas interpretable | `detection/rules.py` | Hecho |
| ML supervisado, evaluado aparte | Random Forest, umbral 0.5 | Hecho |
| Investigación con tools de solo lectura | Haiku o mock, revisor en código | Hecho |
| Evaluación, tests, demo reproducible | pytest, CI, Scores | Hecho |
| Score híbrido reglas + ML | Fuera de la consigna | No se hizo |
| Ambiente de producción | Hook de Render, vars sin setear | Escrito, apagado |

## Arquitectura

Tres entradas llegan a la misma cola de casos. La etiqueta de ground truth se reconstruye solo al puntuar. Ni el detector ni las herramientas del investigador la ven.

| Capa | Qué hace | Qué no hace |
| --- | --- | --- |
| Generador | Seed + escenario. Eventos observables y etiquetas por separado. | No publica la etiqueta al runtime. |
| Reglas | Fuerza bruta, password spray, viaje imposible. Umbrales explícitos. | No lee el score del modelo. |
| Random Forest | Features causales. Marca un evento si la probabilidad pasa 0.5. | No fusiona su score con la regla. |
| Correlación | Une regla y ML solo si el event id coincide con exactamente una alerta. | Si no hay match, o hay más de uno, el caso queda `ml_only`. |
| Cola | El analista ve `rule_medium` y `ml_untriaged`. `rule_high` se queda con la regla. | `ml_untriaged` es un lugar en la cola, no un veredicto. |
| Investigador | Lee el dossier. Tools de solo lectura, tope de 10 pasos y 8 llamadas. | No detecta, no ejecuta SQL ni código, no ve la etiqueta. |
| Revisor | Código determinista. Mira citas, presupuesto y política. | No es otro modelo y no ve ground truth. |
| Evaluación | Precisión, recall, F1, y el veredicto contra la etiqueta reconstruida. | No vuelve al investigador. |

Entradas:

- Lote, a partir de un seed.
- Replay en vivo: `advance` sobre un escenario fijo.
- Cinco sitios (`acme-hq`, `acme-latam`, `acme-emea`, `northwind`, `contoso-jp`) vía Redpanda.

El worker de los sitios sigue investigando con el mock. Haiku solo arranca desde el botón del dossier. CI no tiene la API key.

La ventana del detector es 2 horas de tiempo simulado. La cola del analista no. Un caso solo de ML se queda hasta que una regla cubre ese mismo evento.

## F1 de las dos corridas en vivo

Misma semilla 42, 1500 eventos cada una. Score local del 29 oct 2026. No es el experimento offline.

| Corrida | Reglas F1 | ML F1 | Dossiers | Correctos | Incorrectos | Inconclusos | Sin investigar |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Mixed campaigns | 0.931 | 0.904 | 11 | 6 | 0 | 5 | 0 |
| Boundary lab | 0.000 | 0.553 | 66 | 34 | 4 | 28 | 0 |

Haiku investigó toda la cola de cada corrida. La etiqueta se unió después.

- Common: `sim-829c80864be8`, `live-eval-d880fcca5628`
- Boundary: `sim-09c09a172d00`, `live-eval-fb8125e0868c`

## El dossier para abrir

`case-f68131f0a388a84173f89779`

Boundary lab. Caso `rule_backed`, prioridad `rule_medium`, sospecha de password spray. Haiku dijo malicioso: una IP, unos 30 fallos, unas 30 cuentas, sin éxito visto. La etiqueta reconstruida dice benigno. Cero eventos maliciosos en el caso. El revisor marca `needs_review` porque hay citas fuera del input.

IP `10.154.22.26`. Es el señuelo de NAT compartida. La regla lo nombró, el modelo se solapa, el agente coincidió, y los tres se equivocaron.

## El otro número, para no mezclarlo

`reports/experiment.json` es otro ensayo: otro tamaño, otro plan, modelo entrenado en otras semillas. No es la corrida en vivo. Está citado en el README.

| Conjunto offline | Reglas F1 | ML F1 | Lectura |
| --- | ---: | ---: | --- |
| Nominal | 0.964 | 0.990 | Optimista: las campañas están sobre el umbral de la regla |
| Con señuelos benignos | 0.79 | 0.78 | Cae la precisión de los dos |
| Stress de borde | 0.01 | 0.70 | La regla se cae. No es un atacante distinto |

## Ingeniería

Python con tipos, FastAPI, PostgreSQL, scikit-learn, React, pytest. Los PR a `main` son obligatorios. Los checks que bloquean son `test` y `frontend`. La imagen de la API se publica al pushear a `main`. El deploy de QA no corre hasta que existan las variables. Los tests de CI no llaman a Anthropic.

## Qué mirar

- Scores: las dos tarjetas Common y Boundary, y el dossier de arriba.
- Present: ocho láminas encima del tablero. `N` muestra el texto para decir.
- Pipeline, si hace falta ver los cinco sitios. No investigar la pila en vivo.

Preguntas útiles: quién cierra cuando regla y modelo no coinciden, cómo se cuenta un inconcluso, y qué no puede entrar nunca a las herramientas del investigador.

## Límites

Los datos son sintéticos. El F1 alto del escenario fácil es optimista porque las campañas están sentadas sobre el umbral de la regla. Boundary lab es el borde de esa regla, no un cambio de atacante. El revisor no es otro modelo. Una investigación suelta no es una métrica. No hay producción.
