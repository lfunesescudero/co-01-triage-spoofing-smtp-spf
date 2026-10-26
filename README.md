# CO-01 — Triage de Phishing: Verificación de Spoofing vía Cabeceras SMTP y Política SPF

Análisis de una muestra real de phishing dirigido con suplantación de la marca Target. Verificación de spoofing mediante análisis de cadena `Received` y validación de política SPF del dominio real. Automatización en Python para extracción de indicadores y consulta a la API de VirusTotal.

**Análisis completo:** [documento_caso.md](documento_caso.md)

**Stack:** Python (email, re, requests, base64) · dig · VirusTotal API v3

**Veredicto:** Verdadero positivo, severidad media

**Hallazgos clave:**
- Spoofing confirmado por reconstrucción de la cadena `Received`
- SPF fail verificado contra la política real de target.com
- Ausencia de verificación SPF/DKIM/DMARC en el punto de entrega original
- Script de automatización con extracción de IOCs y consulta de reputación en tiempo real

El script parse_eml.py espera el archivo .eml de muestra en la misma carpeta. La muestra no se versiona.
