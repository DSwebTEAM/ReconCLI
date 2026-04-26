"""engines/recon/geoip.py — IP/domain geolocation."""

from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn
from core.validator   import require_host, resolve
from core.errors      import NetworkError, DNSError


class GeoIP(BaseModule):
    name        = "recon/geoip"
    description = "Geolocate an IP or domain"

    def __init__(self):
        self.options = {"TARGET": Option(required=True, description="IP or hostname")}
        super().__init__()

    def run(self):
        requests = self.need_package("requests")
        target   = require_host(self.opt("TARGET"))
        ip       = resolve(target)
        info(f"Resolved {target} → {ip}\n")

        try:
            resp = requests.get(
                f"http://ip-api.com/json/{ip}"
                f"?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query",
                timeout=self._timeout
            )
            data = resp.json()
        except Exception as e:
            raise NetworkError(f"Geolocation request failed: {e}")

        if data.get("status") != "success":
            warn(f"Geolocation failed: {data.get('message','unknown')}")
            return

        fields = [
            ("IP",       data.get("query")),
            ("Country",  data.get("country")),
            ("Region",   data.get("regionName")),
            ("City",     data.get("city")),
            ("ZIP",      data.get("zip")),
            ("Lat/Lon",  f"{data.get('lat')}, {data.get('lon')}"),
            ("Timezone", data.get("timezone")),
            ("ISP",      data.get("isp")),
            ("Org",      data.get("org")),
            ("AS",       data.get("as")),
        ]
        for label, value in fields:
            if value:
                print(color(f"  {label:<12}: ", "dark") + color(str(value), "cyan"))
                self.note(label, str(value))
        print()
        success("Geolocation complete.")
