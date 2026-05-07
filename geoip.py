import requests
import socket

_PRIVATE = ("192.168.", "10.", "172.16.", "127.", "169.254.", "::1", "fe80")

# Unified cache: ip -> full api response dict
_api_cache   = {}
_host_cache  = {}


def _is_private(ip: str) -> bool:
    return ip.startswith(_PRIVATE)


def _fetch(ip: str):
    """Single API call that populates _api_cache with full response."""
    if ip in _api_cache:
        return
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,city,country,lat,lon",
            timeout=3,
        )
        data = r.json()
        if data.get("status") == "success":
            _api_cache[ip] = data
            return
    except Exception:
        pass
    _api_cache[ip] = {}


def get_ip_info(ip: str) -> str:
    """Returns 'City, Country' string (cached). Used in IP Intelligence panel."""
    if _is_private(ip):
        return "Local Network (Internal)"
    _fetch(ip)
    d = _api_cache.get(ip, {})
    return f"{d.get('city','?')}, {d.get('country','?')}" if d else "Unknown / Private"


def get_ip_coords(ip: str):
    """Improvement #18 — returns (lat, lon) for world map pins, or None."""
    if _is_private(ip):
        return None
    _fetch(ip)
    d = _api_cache.get(ip, {})
    if d and "lat" in d and "lon" in d:
        return (d["lat"], d["lon"])
    return None


def get_hostname(ip: str) -> str:
    """Improvement #5 — reverse DNS via socket (cached)."""
    if ip in _host_cache:
        return _host_cache[ip]
    if _is_private(ip):
        _host_cache[ip] = ip
        return ip
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        _host_cache[ip] = hostname
        return hostname
    except Exception:
        _host_cache[ip] = ip
        return ip
