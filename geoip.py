import requests

def get_ip_info(ip):
    """
    Looks up IP geolocation info using a free public API.
    Only works for public IP addresses. Local IPs (192.x, 10.x, etc.) will return "Local Network".
    """
    # Checking for common local IP ranges
    if ip.startswith(("192.168.", "10.", "172.16.", "127.0.")):
        return "Local Network (Internal)"
    
    try:
        # Use ip-api's free endpoint (limit 45 requests/min)
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = r.json()
        if data['status'] == 'success':
            return f"{data['city']}, {data['country']}"
    except Exception:
        pass
    return "Unknown/Private"
