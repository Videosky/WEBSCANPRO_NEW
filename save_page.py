import requests
from urllib.parse import urlparse

# Ask user (or define) the target URL
url = input(" enter a website )").strip()

# Extract domain name from the URL
parsed_url = urlparse(url)
domain_name = parsed_url.netloc.replace("www.", "")  # remove 'www.'
file_name = f"{domain_name}.html"

# Send HTTP GET request
response = requests.get(url)

# Save HTML content with the dynamic filename
with open(file_name, "w", encoding="utf-8") as file:
    file.write(response.text)

print(f"✅ HTML content saved to {file_name}")
