# Cómo el pipeline emula a un analista senior

Este documento es pedagógico. Explica, fase por fase, cómo el pipeline reproduce
el razonamiento que un analista de seguridad experimentado aplica cuando abre el
portátil por la mañana — no solo *ejecutar y reportar*, sino **decidir**.

La idea central: un junior lanza herramientas; un senior **elige dónde mirar,
lee la política con matices, planifica, y descarta lo que no merece reporte**.
Esas cuatro decisiones son exactamente las cuatro capas nuevas del pipeline.

```
  Un humano senior…                        …y el agente que lo emula
  ─────────────────────────────────────    ──────────────────────────────
  "¿Con qué programa gano más hoy?"     →  program_selector_agent   (Fase -1)
  "¿Qué me deja y qué me prohíbe?"      →  policy_parser_agent      (Fase 0)
  "¿Por dónde ataco este activo?"       →  attack_planner_agent     (Fase 2)
  "¿Esto merece que escriba un reporte?"→  reportability_agent      (Fase 6)
```

Todo respeta las reglas duras del repo: nada fuera de scope, tokens solo por
entorno, nada intrusivo por defecto, logging siempre, envío en dry-run, y
**deny-by-default** ante cualquier ambigüedad.

---

## Fase -1 · Elegir programa — `program_selector_agent`

**Lo que hace un humano:** mira su cartera de programas y sopesa, casi de forma
inconsciente, varias señales: ¿paga bien?, ¿triaje rápido o me van a tener un
mes esperando?, ¿el scope es grande y variado?, ¿está muy explotado por otros?,
¿encaja con lo que sé hacer?, ¿lo toqué hace poco?, ¿tengo ya cosas abiertas ahí?

**Cómo lo emula el pipeline** (`core/scoring.py`, sin LLM): calcula 7 criterios,
cada uno normalizado a `0..1` y **ponderado por `config/scoring.yaml`**:

| Criterio | Señal | Dirección |
|----------|-------|-----------|
| `bounty` | bounty activo + mediana histórica de `bounty_amount` | más = mejor |
| `triage_speed` | mediana de días `submitted → triaged` | más rápido = mejor |
| `scope` | nº de activos in-scope + variedad de tipos | más = mejor |
| `competition` | saturación subjetiva 0..1 (editable a mano) | menos = mejor |
| `skill_fit` | solape del scope con tu `skill_set` | más = mejor |
| `freshness` | días desde tu última sesión (superficie sin tocar) | más = oportunidad |
| `saturation` | días desde tu último finding **abierto** ahí, vs umbral | menos abierto reciente = mejor |

El resultado es una tabla ordenada con score 0–100, un **TOP 3 explicado** y una
recomendación explícita *"empieza hoy por X"*.

Reglas duras que lo hacen fiable:
- **Nunca** recomienda un programa `enabled: false` (queda fuera del ranking).
- Un programa **sin histórico** se marca `sin histórico, decisión por política`
  y se prioriza según lo permisiva que sea su política parseada.
- **Empate →** gana el de menos días desde la última sesión (continuidad).

```bash
python scripts/rank_programs.py --top 3
# → workspace/plans/programs_ranking_<YYYYMMDD>.md
```

---

## Fase 0 · Leer la política — `policy_parser_agent`

**Lo que hace un humano:** lee la policy y traduce prosa en reglas: *"puedo
automatizar, pero nada de DoS; no aceptan missing headers ni self-XSS; el mínimo
es medium; hay que mandar PoC en inglés; y ojo, dicen 'contact before testing'."*

**Cómo lo emula el pipeline** (`core/policy.py`, heurísticas por secciones, no
regex ingenua):

1. **Segmenta** el Markdown detectando líneas de encabezado (`#`, negrita,
   `Etiqueta:`, MAYÚSCULAS) y las clasifica a secciones canónicas: *In Scope /
   Out of Scope / Excluded / Prohibited / Rules of Engagement / Reporting /
   Rewards / Response Targets*.
2. Lee cada campo **solo de las secciones que lo gobiernan** (p. ej.
   `allowed_testing` nunca sale de "Out of Scope").
3. Cada dato extraído lleva su **`source_quote`** — la cita literal — para que
   toda decisión posterior sea auditable.

Campos: `allowed_testing`, `prohibited_actions`, `excluded_vuln_classes`,
`severity_floor`, `bounty_eligibility_rules`, `report_requirements`,
`rate_limits_declarados`, `window_de_testing`, `red_flags`.

Sesgo de seguridad correcto: **liberal** detectando prohibiciones y exclusiones
(el lado seguro), **estricto** detectando lo permitido (si no lo dice
explícitamente, no se asume; queda vacío y se marca `needs_manual_review`).

```bash
python scripts/parse_policy.py --program acme
# → workspace/scope/acme.policy.json  (+ .policy.md legible + fila en policies.csv)
```

---

## Fase 2 · Planificar el ataque — `attack_planner_agent`

**Lo que hace un humano:** antes de abrir Burp, decide un orden. Para una web
piensa en IDOR, authz, inyección, SSRF… primero los de más ROI; deja los "quick
wins" de 10 minutos y reserva bloques largos para lo profundo; y **tacha** lo que
la política excluye o prohíbe.

**Cómo lo emula el pipeline** (`core/planner.py`):

1. Clasifica el activo: `web_app` / `api` / `mobile` / `cloud` / `ip_red`.
2. Carga la checklist correspondiente de `config/checklists/` (WSTG, API Top 10,
   MASVS, cloud, red). Cada ítem es
   `{id, nombre, categoria, tiempo_estimado, herramienta, criterio_exito, prioridad_base}`.
3. **Filtra** lo que caiga en `excluded_vuln_classes` o en una categoría
   `prohibited_actions`. Si la política es "solo manual", quita también las
   herramientas automatizadas y lo dice.
4. Ordena por ROI (probabilidad × severidad típica × elegibilidad de bounty,
   codificado en `prioridad_base` y modulado por el bounty del asset y el
   `severity_floor`).
5. Marca **quick win** (≤10 min) vs **deep dive** (≥60 min) y da herramienta +
   criterio de éxito por check.

Regla dura: **solo planifica sobre activos validados por `scope_agent`**. Sin
ALLOW, se niega.

```bash
python scripts/plan_attack.py --program acme --asset app.acme.com
# → workspace/recon/acme/<session>/plan_app.acme.com.md  (+ fila en plans.csv)
```

---

## Fase 6 · Decidir si merece reporte — `reportability_agent`

**Lo que hace un humano:** encuentra algo y, **antes de gastar una hora
redactando**, se pregunta: *¿está en scope?, ¿aceptan submissions en este
activo?, ¿es una clase excluida?, ¿llega al mínimo de severidad?, ¿ya lo
reporté?* Si algo falla, lo descarta y sigue.

**Cómo lo emula el pipeline** (`core/reportability.py`): una **escalera de
decisión ordenada** — gana la primera regla que aplica, así el veredicto es
determinista y auditable:

| # | Condición | Veredicto |
|---|-----------|-----------|
| 1 | asset fuera de scope | `not_reportable_scope` |
| 2 | `eligible_for_submission = false` | `not_reportable_submission` |
| 3 | clase en `excluded_vuln_classes` | `not_reportable_excluded` |
| 4 | severidad < `severity_floor` | `not_reportable_severity` |
| 5 | `max_severity` del asset < severidad | `report_later_low_return` |
| 6 | `eligible_for_bounty = false` | `reportable_no_bounty` |
| 7 | `dedup_hash` ya enviado | `already_reported` |
| 8 | pasa todo | `report_now` (+ prioridad) |

La contención de scope **reutiliza `core.scope`** (las exclusiones ganan, un
wildcard nunca cubre su apex) y la comparación de severidad reutiliza
`core.severity`: cero lógica duplicada. Cada veredicto incluye la **cita textual**
de la política en la que se apoyó.

Reglas duras: **nunca invoca a `reporter_agent`** (solo lo *sugiere*); si falta
información crítica devuelve `needs_manual_review` en vez de adivinar;
deny-by-default ante ambigüedad.

```bash
python scripts/reportability.py --finding 42
python scripts/reportability.py --program acme --all-open
```

---

## Cómo encaja todo (las 12 fases)

```
 -1 selección → 0 política → 1 sync → 2 plan → 3 recon → 4 vuln
    → 5 triage → 6 reportability → 7 reporte(dry-run) → 8 cierre
```

Las fases **-1, 0 y 6 son análisis puro** (no tocan la red) y se pueden encadenar
con seguridad. Las fases **2–4 son activas** y pasan siempre por el gate de
`scope_agent`. El envío del reporte (fase 7) es **dry-run** y requiere tu "sí".

## Pruébalo sin tocar la red

`scripts/simulate_session.py` ejecuta las cuatro capas sobre 3 programas
ficticios (uno permisivo, uno restrictivo "solo manual", uno sin histórico), un
scope con wildcards/URLs/IPs y 5 findings de distintas severidades — todo en
`workspace/plans/_simulation/`, sin contaminar `data/*.csv` reales:

```bash
python scripts/simulate_session.py
```

Verás el ranking, tres políticas parseadas, dos planes priorizados y cinco
veredictos de reportabilidad que recorren distintas ramas de la escalera
(reporte, excluido por política, por debajo del mínimo, ya reportado y fuera de
scope). Es la mejor forma de entender el pipeline en 10 segundos.
