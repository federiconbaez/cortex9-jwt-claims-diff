# jwt-claims-diff

Prueba diferencial de la validación semántica de claims y header JWT (`exp`, `nbf`, `iat`, `aud`, `iss`, `crit`, `typ`, `alg`, duplicados y forma del token) en tres crates de Rust: `jsonwebtoken` 11.1.0, `jwt-simple` 0.15.0 y `josekit` 0.10.3, cada uno en modo default y en modo estricto.

Differential test of JWT claim and header validation in three Rust crates (`jsonwebtoken`, `jwt-simple`, `josekit`), each in a default and a strict mode.

> **ES** primero · **EN** abajo. Nivel de verificación: **B** (ver abajo).

---

## ES

### Qué hay

| Pieza | Qué hace |
|---|---|
| `src/cases.rs` | 43 casos armados desde JSON crudo, con el veredicto esperado por modo (aceptar, rechazar o abierto) y la sección del RFC. |
| `src/verifiers.rs` | Envoltorios de los tres crates. **Default**: la llamada mínima de cada crate. **Estricto**: `iss` y `aud` esperados, `exp`/`iss`/`aud` requeridos, leeway 60 s y `typ: JWT`, sólo con las opciones propias del crate. |
| `src/bin/jwt-claims-diff.rs` | Corre la matriz y escribe `results/matrix.csv`, `details.csv` (mensaje de error) y `summary.json`. |
| `tests/corpus.rs` | Control positivo (token válido aceptado por todos), control negativo (firma alterada rechazada por todos), forma del corpus. |

Si un crate no puede expresar una política del modo estricto (por ejemplo, josekit no tiene leeway), el caso se marca `n/c` y no se puntúa.

### Medición

Prerregistrada en [`PREREGISTRO.md`](PREREGISTRO.md). Repetida en un clon limpio con la matriz idéntica; el CI la vuelve a correr y falla si un veredicto cambia.

```sh
cargo run --release --bin jwt-claims-diff -- --csv results/matrix.csv --details results/details.csv --json results/summary.json
```

43 casos; 25 divergen entre crates o modos.

| Crate / modo | Coincide con lo esperado | Aceptaciones indebidas | Rechazos espurios | n/c |
|---|---|---|---|---|
| jsonwebtoken / default | 20/22 | — | E05, T02 | — |
| jsonwebtoken / estricto | 37/39 | **C01**, C02 | — | T01 |
| jwt-simple / default | 20/22 | C02, **G04** | — | — |
| jwt-simple / estricto | 38/39 | C02 | — | E06 |
| josekit / default | 21/22 | C02 | — | — |
| josekit / estricto | 33/34 | C02 | — | E02, E03, E06, N02, A06, T01 |

Hallazgos:
- **jsonwebtoken ignora `crit`.** En modo estricto acepta C01, un header con `"crit":["x-cx9"]`, una extensión que no entiende. RFC 7515 4.1.11 dice que en ese caso el JWS es inválido. jwt-simple y josekit lo rechazan. En modo default el rechazo de jsonwebtoken se debe a `aud` (ver abajo), no a `crit`.
- **jwt-simple acepta un header que es un array JSON** (G04, `["HS256"]`) en modo default, con firma válida. En modo estricto lo rechaza porque falta `typ`. Los otros dos lo rechazan como JSON inválido.
- **C02 (`crit: []`) lo aceptan los tres.** Ojo: RFC 7515 4.1.11 prohíbe el array vacío al *productor*, y el receptor sólo *puede* rechazarlo. Nuestro esperado (rechazar) quedó más estricto que el RFC. Se mantiene como estaba prerregistrado, pero aceptar C02 no viola un MUST.
- **jsonwebtoken en modo default rechaza todo token que tenga `aud`** si no se configuró una audiencia (`InvalidAudience`). RFC 7519 4.1.3 lo permite. Eso explica sus dos rechazos espurios (E05 y T02 llevan `aud`) y deja sin poder medir la hipótesis de `nbf` en default: N01 se rechaza por `aud`, no por `nbf`. Un `aud` numérico (A05) sí lo acepta en default.
- jwt-simple en modo default acepta un `exp` vencido hace 10 minutos (E02, no puntuado): su tolerancia por defecto es de 15 minutos. RFC 7519 4.1.4 habla de un leeway de «no más de unos pocos minutos».
- josekit no tiene leeway, ni chequeo de `typ`, ni forma de exigir `exp` o `aud`. En estricto acepta un token sin `aud` (A06, n/c). jwt-simple no puede exigir `exp` (E06, n/c).
- Duplicados: los tres rechazan D01 (`exp` duplicado con el último vencido) y D03 (`alg` duplicado). En D02 josekit default se queda con el último `iss`, que RFC 7519 4 permite.
- jsonwebtoken en estricto acepta un `iat` dos horas en el futuro y un `iat` string (I01, I02, no puntuados).

### Tests

`cargo test`: 5/5. Ningún test se saltea.

### Qué prueba y qué no "aceptado por todos / rechazado por todos" en los controles

- **Prueba**: los envoltorios de los 3 crates, en los 2 modos, verifican la firma y aceptan un token válido. El control negativo (firma alterada) lo rechazan los 6, así que los veredictos de la matriz no se deben a un envoltorio que acepta todo.
- **No prueba**:
  - Que los crates rechacen otras alteraciones: hay un solo control negativo.
  - Nada sobre confusión de algoritmos con claves asimétricas: solo HS256 y una clave.
  - Nada sobre el compromiso de la clave: quien tiene el secreto HS256 firma tokens válidos.
  - Nada sobre el replay de un token válido: `jti` no se chequea.
- **El corpus y los veredictos esperados son nuestros**: 43 casos, con nuestra lectura de los RFC.

### Nivel de verificación

**B**: el mecanismo está medido, es determinista entre dos corridas y tiene controles positivo y negativo. No es B+ porque no hay línea base que superar, y no es C porque no se probó contra servicios reales.

### Límites

- Sólo HS256 y una clave. No prueba confusión de algoritmos con claves asimétricas.
- El esperado es nuestra lectura de los RFC; cada caso lleva la sección. Dos etiquetas se corrigieron después de la primera corrida (commit `fix(cases)`), sin cambiar veredictos.
- El tiempo es el reloj real, con márgenes de 30 s o más respecto de cada borde.
- «Default» es la llamada mínima que elegimos para cada crate. Otra configuración puede dar otros resultados.

### Fuentes leídas

- RFC 7519 (secciones 2, 4, 4.1.3, 4.1.4), RFC 7515 (secciones 4 y 4.1.11), RFC 8725 (secciones 3.8, 3.9 y 3.11): `https://www.rfc-editor.org/rfc/rfc75xx.txt`.
- Código de `jsonwebtoken` 11.1.0 (`src/validation.rs`), `jwt-simple` 0.15.0 (`src/common.rs`, `src/claims.rs`) y `josekit` 0.10.3 (`src/jwt/jwt_payload_validator.rs`).
- API de crates.io para las versiones: `https://crates.io/api/v1/crates/<nombre>`.

---

## EN

### What is here

43 cases built from raw JSON, each with an expected verdict per mode and the RFC section; wrappers for the three crates in a default mode (the crate's minimal call) and a strict mode (expected iss and aud, required claims, 60 s leeway, `typ: JWT`, using only the crate's own options); a binary that writes the matrix. Policies a crate cannot express are marked `n/c` and not scored.

### Measurement

Pre-registered; re-run in a clean clone with an identical matrix; CI re-runs it and fails on any verdict change. 43 cases, 25 divergent. Scores are in the table above.

Findings: **jsonwebtoken ignores `crit`** (accepts an unknown critical extension in strict mode; RFC 7515 4.1.11 makes that JWS invalid). **jwt-simple accepts a header that is a JSON array** in default mode. All three accept `crit: []`, which RFC 7515 only forbids to producers (recipients MAY reject), so our expected verdict there was stricter than the RFC. jsonwebtoken's default mode rejects any token carrying `aud` when no audience is configured, which explains its two spurious rejections and confounds the default-mode `nbf` hypothesis. jwt-simple tolerates a 10-minute-old `exp` by default (15-minute tolerance). josekit has no leeway, no `typ` check and cannot require `exp` or `aud`.

### What "accepted by all / rejected by all" in the controls proves and what it doesn't

- **It proves** that the wrappers of the 3 crates in both modes verify the signature and accept a valid token, and that all 6 reject an altered signature, so the matrix verdicts do not come from an accept-all wrapper.
- **It doesn't cover**:
  - other alterations (there is a single negative control);
  - algorithm confusion with asymmetric keys (HS256 and one key only);
  - key compromise;
  - replay of a valid token (`jti` not checked).
- **The 43 cases and their expected verdicts are ours.**

### Verification level

**B**: mechanism measured, deterministic across two runs, positive and negative controls. Not B+ (no baseline), not C (no real services).

### Limits

HS256 only; expected verdicts are our reading of the RFCs; two rule labels were corrected after the first run without changing verdicts; wall-clock time with ≥ 30 s margins; "default" is our choice of minimal call.

## License

Apache-2.0.
