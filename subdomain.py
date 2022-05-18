#!/usr/bin/python3

import ipaddress
import requests
import socket
import ssl
import sys


def get_domains_from_ct(domain):
    domains = []
    r = requests.get(f"https://crt.sh/?q={domain}&output=json")
    if not r.ok:
        print(f"Error getting CT entries: {r.status_code}")
        return domains
    for entry in r.json():
        if not entry["common_name"].endswith(domain):
            continue
        domains.append(entry["common_name"])
    return set(domains)


def resolve_domain(domain):
    ips = []
    try:
        response = socket.getaddrinfo(domain, None)
    except socket.gaierror:
        print(f"Unable to resolve {domain}")
        return ips
    for entry in response:
        # Only return IPv4 for now
        if entry[0] != socket.AF_INET:
            continue
        ips.append(entry[4][0])
    return ips


def check_ips(domain, ips):
    for ip in ips:
        if ipaddress.ip_address(ip).is_private:
            print(f"{domain} resolves to private ip {ip}")
            continue
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            try:
                s.connect((ip, 443))
            except TimeoutError:
                print(f"Unable to connect to {ip} for {domain}")
                continue
            except (ssl.CertificateError, ssl.SSLError):
                print(f"Certificate error for {domain}")
                continue
            except ConnectionRefusedError:
                print(f"Connection refused for {domain}")
                continue


def main():
    domain = sys.argv[1]
    domains = get_domains_from_ct(domain)
    for domain in domains:
        if domain.startswith("*"):
            continue
        print("Checking", domain)
        ips = resolve_domain(domain)
        check_ips(domain, ips)


if __name__ == "__main__":
    main()
