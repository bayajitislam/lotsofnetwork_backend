import asyncio
import ipaddress
import socket
import time
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
import httpx
import dns.resolver

router = APIRouter(prefix="/tools", tags=["Networking Tools Engine"])

# ============================================================================
# 1. IP LOOKUP & GEOLOCATION
# ============================================================================

class IpLookupRequest(BaseModel):
    query: Optional[str] = Field(None, description="IPv4, IPv6, or domain name. If empty, callers IP is detected.")


class IpLookupResponse(BaseModel):
    ip: str
    query: str
    is_valid: bool
    version: int
    hostname: Optional[str] = None
    country: str
    country_code: str
    region: str
    region_name: str
    city: str
    zip_code: str
    latitude: float
    longitude: float
    timezone: str
    isp: str
    org: str
    asn: str
    is_private: bool
    is_bogon: bool


@router.post("/ip-lookup", response_model=IpLookupResponse, summary="Lookup IP Geolocation & ASN")
@router.get("/ip-lookup", response_model=IpLookupResponse, summary="Lookup caller's public IP Geolocation")
async def ip_lookup(
    request: Request,
    payload: Optional[IpLookupRequest] = None,
    ip: Optional[str] = Query(None, description="IP address or domain to query"),
):
    target = None
    if payload and payload.query:
        target = payload.query.strip()
    elif ip:
        target = ip.strip()
    
    # If no target, determine caller IP
    if not target:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            target = forwarded.split(",")[0].strip()
        elif request.client and request.client.host:
            target = request.client.host
        else:
            target = "8.8.8.8"  # Fallback public default

    # If target is localhost / private loopback, use Cloudflare public IP as fallback for geo demo
    is_loopback = target in ["127.0.0.1", "::1", "localhost"]
    query_target = "1.1.1.1" if is_loopback else target

    # Check IP version & private check
    is_private = False
    is_bogon = False
    version = 4
    try:
        ip_obj = ipaddress.ip_address(query_target)
        version = ip_obj.version
        is_private = ip_obj.is_private
        is_bogon = ip_obj.is_reserved or ip_obj.is_multicast or ip_obj.is_loopback
    except ValueError:
        # Might be a domain name
        pass

    # Reverse DNS
    reverse_host = None
    try:
        reverse_host = socket.gethostbyaddr(query_target)[0]
    except Exception:
        pass

    # Fetch Geolocation via public API
    geo_data: Dict[str, Any] = {}
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.get(f"http://ip-api.com/json/{query_target}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query")
            if resp.status_code == 200:
                geo_data = resp.json()
    except Exception:
        pass

    return IpLookupResponse(
        ip=geo_data.get("query", query_target),
        query=target,
        is_valid=True,
        version=version,
        hostname=reverse_host,
        country=geo_data.get("country", "Unknown"),
        country_code=geo_data.get("countryCode", "UN"),
        region=geo_data.get("region", ""),
        region_name=geo_data.get("regionName", ""),
        city=geo_data.get("city", "Unknown City"),
        zip_code=geo_data.get("zip", ""),
        latitude=geo_data.get("lat", 0.0),
        longitude=geo_data.get("lon", 0.0),
        timezone=geo_data.get("timezone", "UTC"),
        isp=geo_data.get("isp", "Internet Service Provider"),
        org=geo_data.get("org", "Autonomous Organization"),
        asn=geo_data.get("as", "AS0 Unknown"),
        is_private=is_private,
        is_bogon=is_bogon,
    )


# ============================================================================
# 2. DNS LOOKUP & PROPAGATION
# ============================================================================

class DnsRecordItem(BaseModel):
    record_type: str
    value: str
    ttl: int
    priority: Optional[int] = None


class DnsLookupRequest(BaseModel):
    domain: str = Field(..., example="lotsofnetwork.com")
    record_type: Optional[str] = Field("ALL", description="ALL, A, AAAA, CNAME, MX, TXT, NS, SOA")
    nameserver: Optional[str] = Field("1.1.1.1", description="DNS resolver to query (default: Cloudflare 1.1.1.1)")


class DnsLookupResponse(BaseModel):
    domain: str
    nameserver: str
    latency_ms: float
    records: List[DnsRecordItem]
    record_count: int


@router.post("/dns-lookup", response_model=DnsLookupResponse, summary="Query DNS Records with live nameserver")
async def dns_lookup(payload: DnsLookupRequest):
    domain = payload.domain.strip().lower()
    if domain.startswith("http://"):
        domain = domain[7:]
    if domain.startswith("https://"):
        domain = domain[8:]
    domain = domain.split("/")[0].split(":")[0]

    resolver = dns.resolver.Resolver()
    resolver.nameservers = [payload.nameserver.strip() if payload.nameserver else "1.1.1.1"]
    resolver.timeout = 2.5
    resolver.lifetime = 2.5

    types_to_query = (
        ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]
        if payload.record_type.upper() == "ALL"
        else [payload.record_type.upper()]
    )

    records: List[DnsRecordItem] = []
    start_time = time.perf_counter()

    for rtype in types_to_query:
        try:
            answers = resolver.resolve(domain, rtype)
            for rdata in answers:
                priority = getattr(rdata, "preference", None)
                records.append(
                    DnsRecordItem(
                        record_type=rtype,
                        value=str(rdata).strip('"'),
                        ttl=answers.ttl,
                        priority=priority,
                    )
                )
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
        except Exception:
            continue

    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return DnsLookupResponse(
        domain=domain,
        nameserver=resolver.nameservers[0],
        latency_ms=latency_ms,
        records=records,
        record_count=len(records),
    )


# ============================================================================
# 3. SUBNET CALCULATOR & CIDR MATH
# ============================================================================

class SubnetCalcRequest(BaseModel):
    cidr: str = Field(..., example="192.168.1.0/24")


class SubnetCalcResponse(BaseModel):
    cidr_input: str
    ip_version: int
    network_address: str
    broadcast_address: Optional[str] = None
    netmask: str
    wildcard_mask: str
    prefix_length: int
    first_usable_ip: Optional[str] = None
    last_usable_ip: Optional[str] = None
    total_addresses: int
    usable_hosts: int
    binary_netmask: str
    binary_ip: str
    ip_class: str
    is_private: bool
    subnets_slash_next: List[str]


@router.post("/subnet-calculator", response_model=SubnetCalcResponse, summary="IPv4 & IPv6 Subnet Calculation")
def calculate_subnet(payload: SubnetCalcRequest):
    cidr_str = payload.cidr.strip()
    try:
        net = ipaddress.ip_network(cidr_str, strict=False)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid CIDR notation or IP address: {str(e)}",
        )

    prefix = net.prefixlen
    is_v4 = net.version == 4

    # Determine class for IPv4
    ip_class = "CIDR / Classless"
    if is_v4:
        first_octet = int(str(net.network_address).split(".")[0])
        if 1 <= first_octet <= 126:
            ip_class = "Class A"
        elif 128 <= first_octet <= 191:
            ip_class = "Class B"
        elif 192 <= first_octet <= 223:
            ip_class = "Class C"
        elif 224 <= first_octet <= 239:
            ip_class = "Class D (Multicast)"
        elif 240 <= first_octet <= 255:
            ip_class = "Class E (Experimental)"

    # Usable host range
    first_usable = None
    last_usable = None
    usable_count = 0

    if is_v4:
        if prefix == 32:
            first_usable = str(net.network_address)
            last_usable = str(net.network_address)
            usable_count = 1
        elif prefix == 31:
            first_usable = str(net.network_address)
            last_usable = str(net.broadcast_address)
            usable_count = 2
        else:
            first_usable = str(net.network_address + 1)
            last_usable = str(net.broadcast_address - 1)
            usable_count = max(0, net.num_addresses - 2)
    else:
        # IPv6
        first_usable = str(net.network_address)
        last_usable = str(net.network_address + net.num_addresses - 1)
        usable_count = net.num_addresses

    # Binary representations
    if is_v4:
        netmask_int = int(net.netmask)
        binary_netmask = ".".join(f"{(netmask_int >> (8 * i)) & 0xFF:08b}" for i in reversed(range(4)))
        ip_int = int(net.network_address)
        binary_ip = ".".join(f"{(ip_int >> (8 * i)) & 0xFF:08b}" for i in reversed(range(4)))
        wildcard_mask = str(net.hostmask)
        broadcast_str = str(net.broadcast_address)
    else:
        binary_netmask = f"{int(net.netmask):0128b}"
        binary_ip = f"{int(net.network_address):0128b}"
        wildcard_mask = str(net.hostmask)
        broadcast_str = None

    # Subnets for next prefix length (divide into 2)
    subnets_next = []
    if (is_v4 and prefix < 32) or (not is_v4 and prefix < 128):
        try:
            subnets_next = [str(s) for s in list(net.subnets(new_prefix=prefix + 1))[:4]]
        except Exception:
            pass

    return SubnetCalcResponse(
        cidr_input=cidr_str,
        ip_version=net.version,
        network_address=str(net.network_address),
        broadcast_address=broadcast_str,
        netmask=str(net.netmask),
        wildcard_mask=wildcard_mask,
        prefix_length=prefix,
        first_usable_ip=first_usable,
        last_usable_ip=last_usable,
        total_addresses=net.num_addresses,
        usable_hosts=usable_count,
        binary_netmask=binary_netmask,
        binary_ip=binary_ip,
        ip_class=ip_class,
        is_private=net.is_private,
        subnets_slash_next=subnets_next,
    )


# ============================================================================
# 4. TCP PORT CHECKER & SCANNER
# ============================================================================

COMMON_PORT_NAMES = {
    21: "FTP (File Transfer)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Unencrypted)",
    25: "SMTP (Mail Delivery)",
    53: "DNS (Domain Name System)",
    80: "HTTP (Web Traffic)",
    110: "POP3 (Mail Access)",
    143: "IMAP (Mail Access)",
    443: "HTTPS (Encrypted Web)",
    465: "SMTPS (Secure Mail)",
    587: "SMTP Submission",
    993: "IMAPS (Secure Mail)",
    995: "POP3S (Secure Mail)",
    3306: "MySQL Database",
    5432: "PostgreSQL Database",
    6379: "Redis Cache",
    8080: "HTTP Alternate",
    8443: "HTTPS Alternate",
}


class PortCheckRequest(BaseModel):
    host: str = Field(..., example="lotsofnetwork.com")
    ports: Optional[List[int]] = Field([80, 443, 22, 21, 25, 3306], description="List of ports to test (max 20)")
    timeout_seconds: Optional[float] = Field(1.5, ge=0.5, le=3.0)


class SinglePortResult(BaseModel):
    port: int
    service: str
    status: str  # open, closed, filtered/timeout
    latency_ms: Optional[float] = None


class PortCheckResponse(BaseModel):
    host: str
    resolved_ip: Optional[str] = None
    scanned_ports_count: int
    open_ports_count: int
    results: List[SinglePortResult]


async def check_single_port(host: str, port: int, timeout: float) -> SinglePortResult:
    service = COMMON_PORT_NAMES.get(port, f"Custom Port {port}")
    start = time.perf_counter()
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        latency = round((time.perf_counter() - start) * 1000, 2)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return SinglePortResult(port=port, service=service, status="open", latency_ms=latency)
    except asyncio.TimeoutError:
        return SinglePortResult(port=port, service=service, status="filtered (timeout)")
    except (ConnectionRefusedError, OSError):
        return SinglePortResult(port=port, service=service, status="closed")
    except Exception:
        return SinglePortResult(port=port, service=service, status="error")


@router.post("/port-checker", response_model=PortCheckResponse, summary="Test Open TCP Ports")
async def check_ports(payload: PortCheckRequest):
    host = payload.host.strip()
    if host.startswith("http://"):
        host = host[7:]
    if host.startswith("https://"):
        host = host[8:]
    host = host.split("/")[0].split(":")[0]

    # Resolve IP
    resolved_ip = None
    try:
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail=f"Cannot resolve hostname '{host}'")

    # Limit ports to max 20 to prevent abuse
    test_ports = payload.ports[:20] if payload.ports else [80, 443]

    tasks = [check_single_port(resolved_ip, p, payload.timeout_seconds or 1.5) for p in test_ports]
    results = await asyncio.gather(*tasks)

    open_count = sum(1 for r in results if r.status == "open")

    return PortCheckResponse(
        host=host,
        resolved_ip=resolved_ip,
        scanned_ports_count=len(results),
        open_ports_count=open_count,
        results=results,
    )
