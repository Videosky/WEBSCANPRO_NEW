import requests

def check_dvwa():
    url = "http://localhost:8080/login.php"  # DVWA login page
    try:
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200 and "DVWA" in response.text:
            print("✅ DVWA is running and accessible at:", url)
        else:
            print("⚠️ DVWA responded, but content does not match expected page.")
            print("Status code:", response.status_code)
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to DVWA. Make sure the Docker container is running.")
    except Exception as e:
        print("❌ Error:", e)

if __name__ == "__main__":
    check_dvwa()
