
from email import message_from_file

RUTA_EML = "2017-12-01-phishing-email-spoofing-Target-full-example.eml"

with open(RUTA_EML) as f:
    msg = message_from_file(f)

print("From:", msg["From"])
print("Subject:", msg["Subject"])
print("\nCadena Received:")
for received in msg.get_all("Received"):
    print("-", received.replace("\n", " ").strip())

import re

patron_ip = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
primer_received = msg.get_all("Received")[-1]
ip_atacante = re.findall(patron_ip, primer_received)
print("\nIP de origen (atacante):", ip_atacante[0])

cuerpo_html = ""
for parte in msg.walk():
    if parte.get_content_type() == "text/html":
        cuerpo_html = parte.get_payload(decode=True).decode(errors="ignore")

print("\nLargo del cuerpo HTML extraído:", len(cuerpo_html), "caracteres")

patron_url = r'https?://[^\s"\'<>]+'
urls = re.findall(patron_url, cuerpo_html)
urls_unicas = sorted(set(urls))

dominios_confiables = ["mailchimp.com", "gallery.mailchimp.com"]

print("\nURLs encontradas en el cuerpo:")
for url in urls_unicas:
    es_recurso_confiable = any(dominio in url for dominio in dominios_confiables)
    etiqueta = "[recurso de plantilla]" if es_recurso_confiable else "[** POSIBLE IOC **]"
    print(f"- {etiqueta} {url}")


import os
api_key = os.environ.get("VT_API_KEY")

import requests

ip_atacante_limpia = ip_atacante[0]
url_api = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_atacante_limpia}"
headers = {"x-apikey": api_key}

respuesta = requests.get(url_api, headers=headers)
print("\nCódigo de respuesta HTTP:", respuesta.status_code)

datos = respuesta.json()
stats = datos["data"]["attributes"]["last_analysis_stats"]

print("\nResultado VirusTotal para", ip_atacante_limpia)
print("Maliciosos:", stats["malicious"])
print("Sospechosos:", stats["suspicious"])
print("Limpios:", stats["harmless"])

import base64

url_a_consultar = "http://www.tomtomsports.tech/wp-content/plugins/signup.html"
url_codificada = base64.urlsafe_b64encode(url_a_consultar.encode()).decode().strip("=")

url_api_url = f"https://www.virustotal.com/api/v3/urls/{url_codificada}"
respuesta_url = requests.get(url_api_url, headers=headers)

if respuesta_url.status_code == 200:
    datos_url = respuesta_url.json()
    stats_url = datos_url["data"]["attributes"]["last_analysis_stats"]
    print("\nResultado VirusTotal para la URL maliciosa:")
    print("Maliciosos:", stats_url["malicious"])
    print("Sospechosos:", stats_url["suspicious"])
    print("Limpios:", stats_url["harmless"])
else:
    print("\nCódigo de respuesta para la URL:", respuesta_url.status_code)
