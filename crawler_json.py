import requests
import json
from bs4 import BeautifulSoup
import os
from urllib.parse import urljoin

def scrape_forms(url, base_url="http://localhost:8080/"):
    """Scrape DVWA forms for JSON output."""
    print(f"🔍 Scraping forms from: {url}")
    
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching URL: {e}")
        return []

    soup = BeautifulSoup(response.text, 'html.parser')
    data_list = []

    for form in soup.find_all("form"):
        action = form.get("action", "")
        full_action = urljoin(base_url, action)
        method = form.get("method", "GET").upper()

        for inp in form.find_all("input"):
            data_list.append({
                "url": url,
                "method": method,
                "param_name": inp.get("name", ""),
                "input_type": inp.get("type", "text"),
                "default_value": inp.get("value", ""),
                "form_action": full_action
            })
    return data_list

def save_json(data, filename="metadata.json"):
    """Save scraped data as JSON."""
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    print(f"✅ JSON file created: {filename}")

if __name__ == "__main__":
    print("Files will be saved in:", os.getcwd())
    TARGET_URL = "http://localhost:8080/login.php"
    scraped_data = scrape_forms(TARGET_URL)
    print(f"📊 Found {len(scraped_data)} form input fields.")
    save_json(scraped_data)
