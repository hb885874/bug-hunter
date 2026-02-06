import re
from collections import defaultdict
from urllib.parse import urlparse, parse_qs


def normalize_hosts(outputs):
    hosts = set()
    for out in outputs:
        for line in out.splitlines():
            line = line.strip().lower()
            if line and not line.startswith("#"):
                hosts.add(line)
    return "\n".join(sorted(hosts))


def cluster_hosts(hosts: str):
    clusters = defaultdict(list)

    for host in hosts.splitlines():
        if host.startswith(("api.", "graphql.", "rest.")):
            clusters["api"].append(host)
        elif host.startswith(("dev.", "test.", "staging.", "qa.")):
            clusters["dev"].append(host)
        elif host.startswith(("auth.", "login.", "sso.", "id.")):
            clusters["auth"].append(host)
        elif host.startswith(("www.",)):
            clusters["prod"].append(host)
        else:
            clusters["misc"].append(host)

    return dict(clusters)


def extract_live_urls(httpx_output: str):
    urls = []
    for line in httpx_output.splitlines():
        if line.startswith("http"):
            urls.append(line.split()[0])
    return urls


def extract_tech_fingerprints(httpx_output: str):
    tech = defaultdict(set)

    for line in httpx_output.splitlines():
        if "[" in line and "]" in line:
            url = line.split()[0]
            match = re.search(r"\[(.*?)\]", line)
            if match:
                for t in match.group(1).split(","):
                    tech[url].add(t.strip())

    return {k: sorted(v) for k, v in tech.items()}


def extract_katana_params(katana_output: str):
    params = defaultdict(set)

    for line in katana_output.splitlines():
        try:
            parsed = urlparse(line.strip())
            for p in parse_qs(parsed.query):
                params[p].add(parsed.path)
        except Exception:
            continue

    return {k: sorted(v) for k, v in params.items()}
