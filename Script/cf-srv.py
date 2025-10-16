#!/usr/bin/env python3
import urllib.request
import json
import sys
import os

# Natter notification script arguments
protocol, private_ip, private_port, public_ip, public_port = sys.argv[1:6]

def load_config():
    """从JSON文件加载配置"""
    # 可能的配置文件路径
    config_paths = [
        os.path.join(os.getcwd(), "cloudflare.json"),
        os.path.join(os.getenv('APPDATA', ''), "NatterGUI", "cloudflare.json")
    ]

    config = None
    for config_path in config_paths:
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                print(f"Loaded configuration from: {config_path}")
                break
            except Exception as e:
                print(f"Error loading config from {config_path}: {e}")

    if config is None:
        raise FileNotFoundError("Could not find cloudflare.json in any of the expected locations")

    # 从配置中获取值，如果不存在则使用默认值
    cf_srv_service = config.get("service", "_mc")
    cf_domain = config.get("domain", "example.com")
    cf_auth_email = config.get("auth_email", "admin@example.com")
    cf_auth_key = config.get("auth_key", "07d47f2a106b267c3cf8fc1a640ebb2a485bc")

    return cf_srv_service, cf_domain, cf_auth_email, cf_auth_key

def main():
    # 加载配置
    cf_srv_service, cf_domain, cf_auth_email, cf_auth_key = load_config()

    cf = CloudFlareDNS(cf_auth_email, cf_auth_key)

    print(f"Setting {cf_domain} A record to {public_ip}...")
    cf.set_a_record(cf_domain, public_ip)

    print(f"Setting {cf_domain} SRV record to {protocol} port {public_port}...")
    cf.set_srv_record(cf_domain, public_port, service=cf_srv_service, protocol=f"_{protocol}")


class CloudFlareDNS:
    def __init__(self, auth_email, auth_key):
        self.opener = urllib.request.build_opener()
        self.opener.addheaders = [
            ("X-Auth-Email",    auth_email),
            ("X-Auth-Key",      auth_key),
            ("Content-Type",    "application/json")
        ]

    def set_a_record(self, name, ipaddr):
        zone_id = self._find_zone_id(name)
        if not zone_id:
            raise ValueError("%s is not on CloudFlare" % name)
        rec_id = self._find_a_record(zone_id, name)
        if not rec_id:
            rec_id = self._create_a_record(zone_id, name, ipaddr)
        else:
            rec_id = self._update_a_record(zone_id, rec_id, name, ipaddr)
        return rec_id

    def set_srv_record(self, name, port, service="_natter", protocol="_tcp"):
        zone_id = self._find_zone_id(name)
        if not zone_id:
            raise ValueError("%s is not on CloudFlare" % name)
        rec_id = self._find_srv_record(zone_id, name, service, protocol)
        if not rec_id:
            rec_id = self._create_srv_record(zone_id, name, service,
                                             protocol, port, name)
        else:
            rec_id = self._update_srv_record(zone_id, rec_id, name, service,
                                             protocol, port, name)
        return rec_id

    def _url_req(self, url, data=None, method=None):
        data_bin = None
        if data is not None:
            data_bin = json.dumps(data).encode()
        req = urllib.request.Request(url, data=data_bin, method=method)
        try:
            with self.opener.open(req, timeout=10) as res:
                ret = json.load(res)
        except urllib.error.HTTPError as e:
            ret = json.load(e)
        if "errors" not in ret:
            raise RuntimeError(ret)
        if not ret.get("success"):
            raise RuntimeError(ret["errors"])
        return ret

    def _find_zone_id(self, name):
        name = name.lower()
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones"
        )
        for zone_data in data["result"]:
            zone_name = zone_data["name"]
            if name == zone_name or name.endswith("." + zone_name):
                zone_id = zone_data["id"]
                return zone_id
        return None

    def _find_a_record(self, zone_id, name):
        name = name.lower()
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        )
        for rec_data in data["result"]:
            if rec_data["type"] == "A" and rec_data["name"] == name:
                rec_id = rec_data["id"]
                return rec_id
        return None

    def _create_a_record(self, zone_id, name, ipaddr, proxied=False, ttl=120):
        name = name.lower()
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
            data={
                "content":  ipaddr,
                "name":     name,
                "proxied":  proxied,
                "type":     "A",
                "ttl":      ttl
            },
            method="POST"
        )
        return data["result"]["id"]

    def _update_a_record(self, zone_id, rec_id, name, ipaddr, proxied=False, ttl=120):
        name = name.lower()
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rec_id}",
            data={
                "content":  ipaddr,
                "name":     name,
                "proxied":  proxied,
                "type":     "A",
                "ttl":      ttl
            },
            method="PUT"
        )
        return data["result"]["id"]

    def _find_srv_record(self, zone_id, name, service, protocol):
        name = name.lower()
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        )
        for rec_data in data["result"]:
            if rec_data["type"] == "SRV" and rec_data["name"] == f"{service}.{protocol}.{name}":
                rec_id = rec_data["id"]
                return rec_id
        return None

    def _create_srv_record(self, zone_id, name, service, protocol, port, target,
                           priority=1, weight=10, ttl=120):
        name = name.lower()
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
            data={
                "data": {
                    "port":     port,
                    "priority": priority,
                    "target":   target,
                    "weight":   weight
                },
                "name":     f"{service}.{protocol}.{name}",
                "proxied":  False,
                "type":     "SRV",
                "ttl":      ttl
            },
            method="POST"
        )
        return data["result"]["id"]

    def _update_srv_record(self, zone_id, rec_id, name, service, protocol, port, target,
                           priority=1, weight=10, ttl=120):
        name = name.lower()
        data = self._url_req(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rec_id}",
            data={
                "data": {
                    "port":     port,
                    "priority": priority,
                    "target":   target,
                    "weight":   weight
                },
                "name":     f"{service}.{protocol}.{name}",
                "proxied":  False,
                "type":     "SRV",
                "ttl":      ttl
            },
            method="PUT"
        )
        return data["result"]["id"]


if __name__ == "__main__":
    main()