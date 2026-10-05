import json
from typing import Dict, Any, List


def _get_top_ips(ip_counts: Dict[str, int], top_n: int, threshold: int) -> List[Dict[str, Any]]:
    """Sort IP counts and assign a status based on the defined threshold."""
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    results = []
    
    for ip, count in sorted_ips[:top_n]:
        status = "SUSPICIOUS" if count >= threshold else "NORMAL"
        results.append({"ip": ip, "count": count, "status": status})
        
    return results


def build_summary(raw_data: Dict[str, Any], top_n: int, threshold: int) -> Dict[str, Any]:
    """Assemble final metrics, extracting thresholds and formatting structures."""
    ip_counts = raw_data.pop("ip_counts")
    
    suspicious = [ip for ip, count in ip_counts.items() if count >= threshold]
    top_ips = _get_top_ips(ip_counts, top_n, threshold)
    
    return {
        **raw_data,
        "top_ips": top_ips,
        "suspicious_ips": suspicious,
    }


def generate_json(summary: Dict[str, Any]) -> str:
    """Return summary dictionary as a formatted JSON string."""
    return json.dumps(summary, indent=2)


def generate_text(summary: Dict[str, Any]) -> str:
    """Return a human-readable text report utilizing column alignment."""
    lines = [
        f"Scanned Lines    : {summary['scanned']}",
        f"Malformed Lines  : {summary['malformed']}",
        f"Failed Attempts  : {summary['failed']}",
        f"Distinct IPs     : {summary['distinct_ips']}",
        f"Busiest Hour     : {summary['busiest_hour']}",
        "",
        "--- Top Targeted Usernames ---",
    ]
    for user, count in summary["user_counts"]:
        lines.append(f"  {user:<15} : {count}")

    lines.extend(["", "--- Top Source IPs ---"])
    for item in summary["top_ips"]:
        lines.append(f"  {item['ip']:<15} : {item['count']:<5} [{item['status']}]")

    return "\n".join(lines)