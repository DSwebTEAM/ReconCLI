"""engines/recon/whois.py"""
from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, section
from core.validator   import require_host


class WhoisLookup(BaseModule):
    name        = "recon/whois"
    description = "Domain registration and IP ownership info"

    def __init__(self):
        self.options = {"TARGET": Option(required=True, description="Domain or IP")}
        super().__init__()

    def run(self):
        target = require_host(self.opt("TARGET"))
        whois  = self.need_package("whois", "python-whois")

        info(f"Querying WHOIS for {target}...\n")
        try:
            w = whois.whois(target)
            fields = [
                ("Domain",      w.domain_name),
                ("Registrar",   w.registrar),
                ("Created",     w.creation_date),
                ("Expires",     w.expiration_date),
                ("Updated",     w.updated_date),
                ("Status",      w.status),
                ("Name Servers",w.name_servers),
                ("Org",         w.org),
                ("Country",     w.country),
                ("Emails",      w.emails),
            ]
            for label, value in fields:
                if value:
                    if isinstance(value, list):
                        value = value[0]
                    print(color(f"  {label:<16}: ", "dark") + color(str(value), "cyan"))
                    self.note(label, str(value))
            print()
            success("WHOIS complete.")
        except Exception as e:
            warn(f"WHOIS failed: {e}")
