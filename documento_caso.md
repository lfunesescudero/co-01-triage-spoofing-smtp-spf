
La política SPF publicada por target.com autoriza únicamente a los servidores de pphosted.com y pardot.com. La IP de origen real (`45.77.160.39`) no pertenece a ninguno de los dos rangos autorizados. **Resultado: SPF fail.**

Se constató además que el `.eml` no contenía cabeceras `Authentication-Results` ni `Received-SPF`, dado que el servidor receptor (Postfix, sin configuración adicional visible en los headers) no ejecutó verificación de autenticación al momento de la entrega. Esto se documenta como hallazgo adicional: ausencia de controles de autenticación de correo en el punto de entrega, que permitió el paso del mensaje sin fricción.

### Consulta de indicadores en VirusTotal

| Indicador | Tipo | Resultado |
|---|---|---|
| 45.77.160.39 | IP de origen | 0/89 (sin detección) |
| tomtomsports.tech/wp-content/plugins/signup.html | URL de captura de datos | 1/90 (alphaMountain.ai: suspicious) |

La ausencia de detección extendida es consistente con la antigüedad de la muestra (diciembre 2017): la IP corresponde a hosting genérico de uso transitorio, y el dominio malicioso probablemente fue dado de baja y reasignado con posterioridad al ataque. La ausencia de detección actual no contradice la evidencia de spoofing y SPF fail obtenida por análisis directo, contemporáneo al hecho.

Se identificaron adicionalmente dos URLs correspondientes a recursos gráficos de plantilla (`gallery.mailchimp.com`), indicando que el correo fue construido sobre una plantilla de Mailchimp, herramienta legítima de email marketing, para incrementar la fidelidad visual del engaño.

---

## Bloque 3 — Criterio de Tuning / Hardening

**Veredicto de triage:** Verdadero positivo. Severidad media.

Justificación de severidad: el vector no compromete credenciales corporativas ni sistemas internos de forma directa. Sin embargo, explota un pretexto de oferta laboral con alta fidelidad de marca (plantilla profesional, imitación de identidad visual de Target) para capturar datos personales de la víctima mediante formulario externo.

**Recomendaciones de hardening derivadas del análisis:**

- Implementar verificación activa de SPF/DKIM/DMARC en el punto de entrega (MTA), dado que la muestra evidenció ausencia total de estas verificaciones al momento de la recepción. Sin este control, un mensaje con SPF fail es entregado igualmente al usuario final.
- Aplicar política DMARC con `p=reject` o `p=quarantine` sobre dominios corporativos, forzando el rechazo o cuarentena automática de mensajes que fallen SPF/DKIM en nombre del dominio propio.
- Incorporar consulta automatizada de reputación (IP + URL) como paso estándar de triage, dado que redujo el tiempo de verificación de indicadores de minutos a segundos sin intervención manual.

---

## Automatización (Python)

Script `parse_eml.py`: parsea el archivo `.eml` (módulo `email`, stdlib), extrae la IP de origen real de la cadena `Received` mediante expresión regular, recorre el cuerpo multipart (`.walk()`) para extraer el contenido HTML, identifica URLs mediante regex con clasificación automática (recurso de plantilla conocido vs. posible IOC), y consulta la API v3 de VirusTotal (IP y URL, esta última codificada en base64 urlsafe) para obtener veredicto de reputación en tiempo real. La API key se gestiona mediante variable de entorno, nunca embebida en el código fuente.

---

## Mapeo NIST CSF

| Función | Categoría | Acción documentada |
|---|---|---|
| **Identify** | ID.RA (Risk Assessment) | Identificación de vector de phishing con suplantación de marca corporativa |
| **Detect** | DE.AE (Anomalies and Events) | Detección de spoofing mediante análisis de cabeceras SMTP y verificación SPF |
| **Detect** | DE.CM (Security Continuous Monitoring) | Consulta de indicadores (IP, URL) contra fuente de reputación externa |
| **Respond** | RS.AN (Analysis) | Triage documentado con veredicto de verdadero/falso positivo y severidad justificada |
| **Recover** | RC.IM (Improvements) | Recomendación de hardening: activación de verificación SPF/DKIM/DMARC en el MTA y política DMARC de rechazo |
