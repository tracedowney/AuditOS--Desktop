from __future__ import annotations

import psutil


def run():
    items = []
    findings = []

    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    for name, addr_list in addrs.items():
        stat = stats.get(name)
        item = {
            "name": name,
            "is_up": bool(stat.isup) if stat else False,
            "speed": getattr(stat, "speed", 0) if stat else 0,
            "mtu": getattr(stat, "mtu", 0) if stat else 0,
            "addresses": [],
        }

        for addr in addr_list:
            item["addresses"].append({
                "family": str(addr.family),
                "address": addr.address,
                "netmask": addr.netmask,
                "broadcast": addr.broadcast,
            })

        items.append(item)

        if stat and stat.isup:
            findings.append({
                "severity": "low",
                "category": "network_interfaces",
                "detail": f"Active network interface: {name}",
            })

    return {
        "component": "network_interfaces",
        "items": items,
        "findings": findings,
        "error": "",
    }
