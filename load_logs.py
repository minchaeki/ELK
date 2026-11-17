import re, requests, json
from datetime import datetime

LOG = r"C:\AutoSet10\server\logs\access.log"
ES = "http://localhost:9200/weblogs/_bulk"
AUTH = ("elastic", "changeme123")

# Apache combined/common 로그 파싱
pat = re.compile(r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d{3}|-) (\d+|-)')

def classify(url):
    u = requests.utils.unquote(url).lower()
    if "<script" in u or "onerror=" in u or "onmouseover=" in u: return "XSS"
    if "rlike" in u or "sleep(" in u or "union select" in u or "extractvalue" in u: return "SQLi"
    if ";id" in u or "`" in u or "$(" in u or "|nc" in u or "whoami" in u: return "CommandInjection"
    if "../" in u or "..\\" in u or "/etc/passwd" in u or "win.ini" in u: return "PathTraversal"
    if "getpassword" in u or "passtype" in u: return "InfoDisclosure"
    if "wp-login" in u or "admin.php" in u: return "AuthAttempt"
    return "normal"

bulk = []
with open(LOG, encoding="utf-8", errors="ignore") as f:
    for line in f:
        m = pat.search(line)
        if not m: continue
        ip, ts, method, url, proto, status, size = m.groups()
        try:
            t = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").isoformat()
        except:
            continue
        doc = {
            "@timestamp": t, "src_ip": ip, "method": method,
            "url": url, "status": int(status) if status.isdigit() else 0,
            "size": int(size) if size.isdigit() else 0,
            "attack_type": classify(url)
        }
        bulk.append(json.dumps({"index": {}}))
        bulk.append(json.dumps(doc))

if bulk:
    r = requests.post(ES, data="\n".join(bulk) + "\n",
                      headers={"Content-Type": "application/x-ndjson"}, auth=AUTH)
    print("상태:", r.status_code, "| 적재 건수:", len(bulk)//2)
else:
    print("파싱된 로그 없음")