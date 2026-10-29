# Prerregistro de la medición / Measurement pre-registration

Escrito y commiteado antes de correr la matriz. / Written and committed before running the matrix.

**Divulgación / disclosure:** antes de este commit sólo se corrieron los tests de controles (`cargo test`). Ahí se vio que jsonwebtoken rechaza en modo default todo token con `aud` (`InvalidAudience`); por eso V01 quedó abierto en default (RFC 7519 4.1.3 permite rechazar si el verificador no se identifica con el `aud`). Ningún otro caso se corrió. / Only the control tests were run before this commit; that showed jsonwebtoken rejects any token with `aud` in default mode, so V01 is unscored in default mode. No other case was run.

Comando / command:

```sh
cargo run --release --bin jwt-claims-diff -- --csv results/matrix.csv --details results/details.csv --json results/summary.json
```

Dos corridas; la segunda en un clon limpio. Se compara la matriz (veredictos, no mensajes). / Two runs, the second in a clean clone; the verdict matrix must be identical.

Qué se reporta / what is reported, por crate y modo:
- coincidencias con el esperado / matches with the expected verdict, sobre los casos puntuados;
- **aceptaciones indebidas** (esperado rechazar, el crate acepta) / undue acceptances;
- rechazos espurios (esperado aceptar, el crate rechaza) / spurious rejections;
- n/c: casos estrictos cuya política el crate no puede expresar (no puntuados);
- casos abiertos aceptados (sin puntuar) / unscored cases accepted;
- casos con divergencia entre crates o modos / divergent cases.

Hipótesis sin número / hypotheses without a number: esperamos diferencias en `crit` (C01–C03), en `nbf` en modo default (jsonwebtoken no lo valida por defecto según su `Validation::new`), en exp vencido hace 10 min en default (jwt-simple tolera 15 min por defecto según su código) y en claims duplicados (D01–D03). No se fija un número esperado.

Criterio de aceptación del build / build acceptance: ≥ 30 casos puntuados contra los 3 crates en los 2 modos, tabla de aceptaciones indebidas, matriz determinista entre las dos corridas.

Límites conocidos / known limits: sólo HS256; el tiempo es el reloj real con márgenes ≥ 30 s respecto de cada borde; los esperados son nuestra lectura de los RFC y se listan con la sección.
