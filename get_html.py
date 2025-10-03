import requests

# URL of the target page
url = "https://www.geeksforgeeks.org/"  # <-- Replace with your target URL

try:
    # Send GET request
    response = requests.get(url)
    response.raise_for_status()  # Raise exception for HTTP errors

    # Save HTML content to a file
    with open("page.html", "w", encoding="utf-8") as file:
        file.write(response.text)

    print("HTML content saved successfully to page.html")

except requests.exceptions.RequestException as e:
    print(f"Error fetching the page: {e}")
