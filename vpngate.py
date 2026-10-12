#!/usr/bin/env python3
"""
VPN Gate SSTP 节点检测流水线
============================
流程:
  1. 获取 VPN Gate 原始节点 (官方 api/iphone CSV, 失败时回退 GitHub 预解析镜像)
  2. 只保留「带 TCP 入口」的中继 = SSTP 可用节点
     (OpenVPN 配置里 proto tcp + remote <ip> <port>; UDP-only 中继无法走 SSTP/xray 链, 直接丢弃)
  3. 按 host+port+protocol 去重
  4. 并发调用已部署的 Cloudflare Worker:  GET {WORKER}/check?proxyip=host:port
     (单节点 HTTP 成功 != 节点可用; 以 Worker 返回 JSON 的 success 字段为准)
  5. 保留 success=true 的节点, 按国家分组, 生成 public/data.json + public/index.html
  6. 网页端 (GitHub Pages) 读取 data.json 展示

退出码:
  0 = 正常完成 (允许部分节点检测失败)
  1 = 硬性失败 (数据源全挂 / 解析不出 SSTP 节点 / Worker 完全不可达 / 程序异常)
     这些情况绝不允许"假成功"
"""

import base64
import csv
import io
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import quote

import requests

# 保证日志在任何控制台编码下都能输出 (Windows GBK 控制台不会崩)
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 配置 (均可用环境变量覆盖, 便于本地测试)
# ---------------------------------------------------------------------------
REPO_DIR = os.path.dirname(os.path.abspath(__file__))

VPNGATE_API = os.environ.get("VPNGATE_API", "http://www.vpngate.net/api/iphone/")
# 官方接口失败时的回退数据源: 预解析 JSON 镜像 (字段与官方 CSV 同源)
VPNGATE_MIRROR = os.environ.get(
    "VPNGATE_MIRROR",
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
)
# 已部署的 Cloudflare Worker 检测接口 (GET /check?proxyip=host:port, 实测确认)
# 注意: 路径必须是单斜杠 /check; 双斜杠 //check 会命中 Worker 网页路由返回 HTML (非 JSON)
WORKER_CHECK_URL = os.environ.get("CHECK_WORKER", "https://nodecheck.rizizhenhya0604.online/check?sstp=vpn:vpn@")
CONCURRENCY = max(1, int(os.environ.get("CHECK_CONCURRENCY", "32")))   # 与 Worker 网页端一致的并发模型
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "90"))          # 单请求客户端超时 (秒)
MAX_CHECK_NODES = int(os.environ.get("MAX_CHECK_NODES", "0"))         # 0=不限; 本地测试可设小值
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "60"))              # 拉取数据源超时

# 历史可用节点池: 每轮把「当轮节点 + 池内存活节点」一起检测, success=true 的写回池文件
# 供下轮复用 (对抗单轮检测假阴性 / CSV 采样间隙漏节点)。
# 池文件不提交 git (避免 48 commits/天 污染历史): CI 用 actions/cache 跨轮持久化, 本地即 pool.json
POOL_SIZE = int(os.environ.get("POOL_SIZE", "200"))                  # 池上限, 超出按质量淘汰
POOL_FAIL_STREAK = int(os.environ.get("POOL_FAIL_STREAK", "6"))      # 连续明确失败 N 轮淘汰 (worker_error 不计)
POOL_FILE = os.environ.get("POOL_FILE", os.path.join(REPO_DIR, "pool.json"))
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
TEMPLATE_HTML = os.path.join(REPO_DIR, "web", "index.html")

# 出口数据中心的关键词启发 (判断"是否住宅 IP"用, 页面标注为估算)
DATA_CENTER_ORG_KEYWORDS = [
    "GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
    "HURRICANE", "TENCENT", "ALIBABA", "ALIYUN", "LEASWEB",
]
# 常见住宅宽带运营商关键词
RESIDENTIAL_ORG_KEYWORDS = [
    "NTT EAST", "NTT WEST", "NTT COMMUNICATIONS", "NTT BROADBAND", "KDDI", "DOCOMO",
    "SOFTBANK", "AU COMMUNICATIONS", "J:COM", "JCOM", "OCN", "BIGLOBE",
    "IIJ", "SEIKO", "CLEVER-NET", "AT&T", "COMCAST", "XFINITY", "VERIZON",
    "TELUS", "ROGERS", "BELL CANADA", "VODAFONE", "ORANGE", "DEUTSCHE TELEKOM",
    "BREEZE", "TIM S.P.A", "LIBERO", "FASTWEB", "FREE FRANCE", "BT OPEN",
]

# ISO 国家码 -> 中文名 (edgetunnel 清单展示用; 未收录则回退英文原名)
COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "US": "美国", "CA": "加拿大", "RU": "俄罗斯",
    "RO": "罗马尼亚", "TH": "泰国", "VN": "越南", "DE": "德国", "FR": "法国",
    "GB": "英国", "UK": "英国", "SG": "新加坡", "TW": "台湾", "HK": "香港",
    "CN": "中国", "AU": "澳大利亚", "NL": "荷兰", "SE": "瑞典", "CH": "瑞士",
    "IT": "意大利", "ES": "西班牙", "PL": "波兰", "IN": "印度", "BR": "巴西",
    "MX": "墨西哥", "ID": "印度尼西亚", "MY": "马来西亚", "PH": "菲律宾",
    "TR": "土耳其", "UA": "乌克兰", "CZ": "捷克", "GR": "希腊", "PT": "葡萄牙",
    "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "IE": "爱尔兰", "BE": "比利时",
    "AT": "奥地利", "HU": "匈牙利", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚",
    "NZ": "新西兰", "ZA": "南非", "IL": "以色列", "AE": "阿联酋", "SA": "沙特",
    "EG": "埃及", "HR": "克罗地亚", "BY": "白俄罗斯", "GD": "格林纳达",
    "LV": "拉脱维亚", "EE": "爱沙尼亚", "LT": "立陶宛", "SK": "斯洛伐克",
    "SI": "斯洛文尼亚", "BG": "保加利亚", "RS": "塞尔维亚", "GE": "格鲁吉亚",
    "MD": "摩尔多瓦", "AM": "亚美尼亚", "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦",
    "MN": "蒙古", "NP": "尼泊尔", "LK": "斯里兰卡", "MM": "缅甸",
}

# ---------------------------------------------------------------------------
# 日志 (用户要求的分区格式)
# ---------------------------------------------------------------------------
_section = None


def log(section, msg=""):
    global _section
    if section != _section:
        print(f"========== {section} ==========")
        _section = section
    if msg:
        print(msg, flush=True)


def die(msg):
    """硬性失败: 明确报错并退出非 0, 绝不允许假成功。"""
    log("FATAL", f"[失败] {msg}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# 第 1 步: 获取 VPN Gate 原始节点
# ---------------------------------------------------------------------------
def fetch_vpngate():
    """返回 (rows, source)。rows: [{host, ip, country_long, country_short, config_b64}]
    官方 API 失败时回退镜像 JSON; 两个都失败 -> 直接 die (exit 1)。"""
    # --- 主源: 官方 CSV ---
    try:
        log("VPN GATE", f"获取官方 API: {VPNGATE_API}")
        resp = requests.get(
            VPNGATE_API,
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (compatible; gate-checker)"},
        )
        resp.raise_for_status()
        rows = parse_csv(resp.text)
        if rows:
            log("VPN GATE", f"主源(官方 API) 获取到 {len(rows)} 个原始节点")
            return rows, "vpngate.net/api/iphone"
        raise RuntimeError("官方 API 返回 0 行数据")
    except Exception as exc:
        log("VPN GATE", f"官方 API 获取失败: {exc}")

    # --- 回退源: GitHub 预解析镜像 ---
    try:
        log("VPN GATE", f"回退镜像: {VPNGATE_MIRROR}")
        resp = requests.get(VPNGATE_MIRROR, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        rows = parse_mirror_json(resp.json())
        if rows:
            log("VPN GATE", f"回退源(镜像) 获取到 {len(rows)} 个原始节点")
            return rows, "github-mirror"
    except Exception as exc:
        log("VPN GATE", f"回退镜像也失败: {exc}")
    die("VPN Gate 官方 API 与回退镜像均不可用, 数据源完全失败 (不生成空结果, 本次运行判定失败)")


def parse_csv(text):
    """解析官方 CSV。表头行含 'HostName'; 按列名映射, 列名缺失时用固定位置回退。"""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    header_idx = None
    for i, ln in enumerate(lines):
        if ln.lstrip("#").startswith("HostName"):
            header_idx = i
            break
    if header_idx is None:
        raise RuntimeError("找不到 CSV 表头行 (HostName)")

    header = lines[header_idx].lstrip("#").split(",")
    data_lines = lines[header_idx + 1:]
    # 列名映射 (不假设固定位置, 列名变化时自动适配; 全缺失时回退到已知位置)
    idx = {}
    for col in ("hostname", "ip", "countrylong", "countryshort", "openvpn_configdata_base64"):
        for i, h in enumerate(header):
            if h.strip().lstrip("*").lower() == col:
                idx[col] = i
                break
    if "openvpn_configdata_base64" not in idx:
        for i, h in enumerate(header):
            if "base64" in h.lower():
                idx["openvpn_configdata_base64"] = i
                break
    pos = {"hostname": idx.get("hostname", 0),
           "ip": idx.get("ip", 1),
           "countrylong": idx.get("countrylong", 5),
           "countryshort": idx.get("countryshort", 6),
           "openvpn_configdata_base64": idx.get("openvpn_configdata_base64", len(header) - 1)}

    rows = []
    for ln in data_lines:
        fields = next(csv.reader(io.StringIO(ln)))
        if len(fields) < 7:
            continue
        host = fields[pos["hostname"]].strip()
        ip = fields[pos["ip"]].strip()
        if not host or not ip:
            continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": fields[pos["countrylong"]].strip(),
            "country_short": fields[pos["countryshort"]].strip(),
            "config_b64": fields[pos["openvpn_configdata_base64"]].strip(),
        })
    return rows


def parse_mirror_json(data):
    """解析 GitHub 镜像 JSON: [ { "servers": [ {hostname, ip, countrylong, countryshort, openvpn_configdata_base64} ] } ]"""
    servers = []
    items = data if isinstance(data, list) else [data]
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("servers"), list):
            servers.extend(item["servers"])
        elif isinstance(item, dict):
            servers.append(item)
    rows = []
    for s in servers:
        host = str(s.get("hostname") or s.get("host") or "").strip()
        ip = str(s.get("ip") or "").strip()
        if not host or not ip:
            continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": str(s.get("countrylong") or s.get("country_long") or s.get("country") or "").strip(),
            "country_short": str(s.get("countryshort") or s.get("country_short") or "").strip(),
            "config_b64": str(s.get("openvpn_configdata_base64") or s.get("config_b64") or "").strip(),
        })
    return rows


# ---------------------------------------------------------------------------
# 第 2 步: 筛选 SSTP 节点 (只保留带 TCP 入口的中继)
# ---------------------------------------------------------------------------
_PROTO_TCP_RE = re.compile(r"^proto\s+(tcp|tcp4|tcp6)\b", re.M)
_REMOTE_RE = re.compile(r"^remote\s+\S+\s+(\d+)", re.M)


def to_sstp_nodes(rows):
    """把原始行转成 SSTP 节点: 解码 OpenVPN 配置, 仅保留 proto tcp + remote 端口。
    host 统一为 <short>.opengw.net 形式; 返回去重前的节点列表。"""
    nodes = []
    for r in rows:
        cfg = ""
        if r["config_b64"]:
            try:
                cfg = base64.b64decode(r["config_b64"], validate=False).decode("utf-8", "replace")
            except Exception:
                cfg = ""
        if not _PROTO_TCP_RE.search(cfg):
            continue  # 无 TCP 入口 -> 不是 SSTP 可用节点, 丢弃
        m = _REMOTE_RE.search(cfg)
        if not m:
            continue
        port = int(m.group(1))
        if not (1 <= port <= 65535):
            continue
        host = r["host"]
        if not host.endswith(".opengw.net"):
            host = f"{host}.opengw.net"
        nodes.append({
            "host": host,
            "port": port,
            "ip": r["ip"],
            "country": r["country_long"],
            "country_code": r["country_short"],
        })
    return nodes


def dedupe(nodes):
    """按 host+port+protocol 去重。"""
    seen = set()
    out = []
    for n in nodes:
        key = (n["host"].lower(), n["port"], "sstp")
        if key in seen:
            continue
        seen.add(key)
        out.append(n)
    return out


# ---------------------------------------------------------------------------
# 历史可用节点池 (不进 git; CI 用 actions/cache 持久化, 本地即 pool.json)
# ---------------------------------------------------------------------------
def _parse_ts(s):
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _now_ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def load_pool():
    """加载历史池。返回 dict: {(host_lower, port): pool_entry}。文件不存在/损坏 -> 空池。"""
    if not os.path.exists(POOL_FILE):
        log("POOL", "无历史池文件, 从空池开始")
        return {}
    try:
        with open(POOL_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        entries = data.get("nodes") if isinstance(data, dict) else data
        pool = {}
        for e in entries or []:
            host = str(e.get("host") or "").strip()
            port = int(e.get("port") or 0)
            if not host or not (1 <= port <= 65535):
                continue
            pool[(host.lower(), port)] = {
                "host": host, "port": port,
                "ip": e.get("ip"), "country": e.get("country"),
                "country_code": e.get("country_code"),
                "residential": e.get("residential") or "unknown",
                "first_seen": e.get("first_seen") or _now_ts(),
                "last_success_at": e.get("last_success_at") or _now_ts(),
                "fail_streak": int(e.get("fail_streak") or 0),
                "success_count": int(e.get("success_count") or 0),
                "latency_ms": e.get("latency_ms"),
            }
        log("POOL", f"加载历史池: {len(pool)} 节点 ({os.path.basename(POOL_FILE)})")
        return pool
    except Exception as exc:
        log("POOL", f"历史池文件损坏, 忽略并重建: {exc}")
        return {}


def merge_with_pool(nodes, pool):
    """当轮节点 ∪ 池内存活节点 = 本轮检测候选集 (去重, 当轮优先)。
    池内节点标记 from_pool=true, 便于统计与产物标注。"""
    pool_alive = [dict(v, from_pool=True) for (h, p), v in pool.items()
                  if (h, p) not in {(n["host"].lower(), n["port"]) for n in nodes}]
    merged = nodes + pool_alive
    log("POOL", f"合并: 当轮 {len(nodes)} + 池内独有 {len(pool_alive)} -> 检测候选 {len(merged)}")
    return merged


def update_pool(pool, results):
    """用本轮检测结果更新池, 然后按质量淘汰到 POOL_SIZE 上限。返回淘汰统计。"""
    now = _now_ts()
    merged = dict(pool)
    for r in results:
        key = (r["host"].lower(), r["port"])
        prev = merged.get(key)
        if r.get("success"):
            merged[key] = {
                "host": r["host"], "port": r["port"],
                "ip": (r.get("exit") or {}).get("ip") or (prev or {}).get("ip") or r.get("ip"),
                "country": r.get("country"),
                "country_code": r.get("country_code"),
                "residential": r.get("residential") or "unknown",
                "first_seen": (prev or {}).get("first_seen") or now,
                "last_success_at": now,
                "fail_streak": 0,
                "success_count": ((prev or {}).get("success_count") or 0) + 1,
                "latency_ms": r.get("latency_ms"),
            }
        elif prev:
            # 只对池内已有节点累计失败; 当轮新节点失败不入池
            if r.get("worker_error"):
                pass  # Worker 抖动 (超时/非200/网络异常) 不计, 防止一轮抖动刷光全池
            else:
                prev["fail_streak"] = int(prev.get("fail_streak") or 0) + 1
        # 当轮新节点明确失败: 不入池, 自然消失

    # 淘汰 1: 连续明确失败 >= POOL_FAIL_STREAK 轮 (3 小时 @ 30min/轮)
    evicted_streak = [k for k, v in merged.items() if int(v.get("fail_streak") or 0) >= POOL_FAIL_STREAK]
    for k in evicted_streak:
        del merged[k]

    # 淘汰 2: 超过 POOL_SIZE 上限 -> 按 (success_count, last_success_at) 质量降序保留
    evicted_overflow = 0
    if len(merged) > POOL_SIZE:
        ranked = sorted(
            merged.items(),
            key=lambda kv: (int(kv[1].get("success_count") or 0),
                            _parse_ts(kv[1].get("last_success_at")) or datetime.min.replace(tzinfo=timezone.utc)),
        )
        evicted_overflow = len(merged) - POOL_SIZE
        for k, _ in ranked[:evicted_overflow]:
            del merged[k]

    return merged, {"evicted_streak": len(evicted_streak), "evicted_overflow": evicted_overflow}


def save_pool(pool):
    """写回池文件 (utf-8, 缩进 1)。CI 里该文件位于 workspace, 由 actions/cache 恢复/保存。"""
    nodes = sorted(pool.values(), key=lambda v: (-int(v.get("success_count") or 0), v["host"]))
    out = {"updated_at": _now_ts(), "size": len(nodes), "max_size": POOL_SIZE, "nodes": nodes}
    with open(POOL_FILE, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    log("POOL", f"写回历史池: {len(nodes)} 节点 -> {os.path.basename(POOL_FILE)} (上限 {POOL_SIZE})")


# ---------------------------------------------------------------------------
# 第 3 步: 并发调用 Cloudflare Worker
# ---------------------------------------------------------------------------
def classify_network(host, exit_org, is_datacenter=None):
    """住宅/机房分类, 按可信度排序:
    1) Worker 返回的真实 is_datacenter 标志 (IP 情报库);
    2) 出口 ASN 组织名关键词;
    3) host 前缀启发式 (最后兜底, 属估算)。"""
    # 1) 真实数据中心标志 (SSTP 版 Worker 顶层 exit 直接给出)
    if is_datacenter is True:
        return "datacenter"
    if is_datacenter is False:
        return "residential"
    # 2) 出口组织名关键词
    org = (exit_org or "").upper()
    if org:
        if any(k in org for k in DATA_CENTER_ORG_KEYWORDS):
            return "datacenter"
        if any(k in org for k in RESIDENTIAL_ORG_KEYWORDS):
            return "residential"
    # 3) host 前缀启发式 (估算)
    h = host.lower()
    if h.startswith("public-vpn"):
        return "datacenter"      # VPN Gate 官方公共中继 (机房/托管)
    if re.match(r"^vpn\d{5,}", h) or re.match(r"^vpnv\d+", h):
        return "residential"     # 数字编号 = 注册的家用宽带中继 (家宽, 估算)
    return "unknown"


def check_one(node, session):
    """调用 Worker 检测单节点。返回节点+检测结果的合并 dict。
    单节点失败 (网络错误/非 200/坏 JSON) 不会抛出, 统一记 success=False。"""
    url = WORKER_CHECK_URL + quote(f"{node['host']}:{node['port']}", safe="")
    out = dict(node)
    out["protocol"] = "sstp"
    out["link"] = f"sstp://vpn:vpn@{node['host']}:{node['port']}"
    out["status"] = "failed"
    out["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out["exit"] = None
    out["residential"] = "unknown"
    try:
        r = session.get(url, timeout=CHECK_TIMEOUT, headers={"User-Agent": "Mozilla/5.0 (gate-checker)"})
        if r.status_code != 200:
            out["error"] = f"HTTP {r.status_code}"
            out["worker_error"] = True
            return out
        j = r.json()
        ok = bool(j.get("success"))
        out["success"] = ok
        out["status"] = "success" if ok else "failed"
        out["latency_ms"] = j.get("responseTime")
        out["colo"] = j.get("colo")
        out["error"] = (None if ok else (j.get("error") or j.get("message") or "check failed"))
        # SSTP 版 Worker: 顶层直接返回 exit, 含真实 is_datacenter 标志 + 嵌套 asn 对象
        exit_info = j.get("exit") or {}
        if exit_info:
            asn = exit_info.get("asn") or {}
            org = asn.get("org") or asn.get("name") or ""
            out["exit"] = {
                "ip": exit_info.get("ip"),
                "country": exit_info.get("country"),
                "country_code": exit_info.get("country_code"),
                "city": exit_info.get("city"),
                "continent": exit_info.get("continent"),
                "asn": asn.get("asn"),
                "org": org,
                "type": asn.get("type"),
                "is_datacenter": exit_info.get("is_datacenter"),
            }
            out["residential"] = classify_network(out["host"], org, exit_info.get("is_datacenter"))
        else:
            out["residential"] = classify_network(out["host"], None, None)
        return out
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["worker_error"] = True
        return out


def check_all(nodes, session):
    """32 并发 (与网页端一致)。单节点失败不影响整体; 但区分'节点不可用'与'Worker 异常'。"""
    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(check_one, n, session) for n in nodes]
        for fut in as_completed(futures):
            results.append(fut.result())
    return results


# ---------------------------------------------------------------------------
# 第 4 步: 生成网页数据
# ---------------------------------------------------------------------------
def build_outputs(results, raw_count, sstp_count, source, pool_stats=None):
    available = [r for r in results if r.get("success")]
    countries = {}
    for n in available:
        c = n["country"] or "未知"
        countries.setdefault(c, {"code": n["country_code"] or "?", "nodes": []})["nodes"].append(n)

    pool_stats = pool_stats or {}
    stats = {
        "raw_nodes": raw_count,
        "sstp_nodes": sstp_count,
        "checked": len(results),
        "success": len(available),
        "failed": len(results) - len(available),
        "countries": len(countries),
        "residential_est": sum(1 for n in available if n["residential"] == "residential"),
        "datacenter_est": sum(1 for n in available if n["residential"] == "datacenter"),
        # 历史池统计 (本轮从池里救回的节点数 = 池内独有且当轮 success)
        "pool_size": pool_stats.get("size", 0),
        "pool_evicted_streak": pool_stats.get("evicted_streak", 0),
        "pool_evicted_overflow": pool_stats.get("evicted_overflow", 0),
        "pool_rescued": sum(1 for n in available if n.get("from_pool")),
    }

    by_country = {}
    for name, grp in countries.items():
        grp["count"] = len(grp["nodes"])
        grp["residential"] = sum(1 for n in grp["nodes"] if n["residential"] == "residential")
        grp["datacenter"] = sum(1 for n in grp["nodes"] if n["residential"] == "datacenter")
        grp["nodes"].sort(key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 0, n["host"]))
        by_country[name] = grp

    data = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source,
        "worker": WORKER_CHECK_URL,
        "stats": stats,
        "countries": by_country,
        "available": available,
    }
    return data


CHAIN_URL = os.environ.get("CHAIN_URL", "https://goorwl.github.io/nodeCheck/chains.txt")


def build_chains_text(data):
    """生成 edgetunnel 链式代理清单: 按国家分组, 每国编号固定, 住宅优先, 延迟升序。
    每行 = 「名字 + $sstp://vpn:vpn@host:port」, 名字不变, 指令每 30 分钟自动换。"""
    countries = data["countries"]
    lines = [
        # 注意: 注释里禁止英文逗号 "," (同 build_hosts_text 的原因)
        "# VPN Gate SSTP 节点 -> edgetunnel 链式代理清单",
        "# 用法: 在 edgetunnel 节点备注里直接粘贴下面任意一行 (名字与指令连写)",
        f"# 自动更新: {data['generated_at']} (每 30 分钟重新检测)",
        f"# 固定地址: {CHAIN_URL}",
        "#   例: 日本-住宅-01$sstp://vpn:vpn@vpnxxx.opengw.net:443",
        "# 名字保持不变, 只有 $sstp:// 后面的地址每 30 分钟自动更换",
        "# 账号密码固定 vpn:vpn ; 端口必须保留",
        "# ========================================================",
    ]
    ordered = sorted(
        countries.items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("residential") == "residential" else 1,
                n.get("latency_ms") is None,
                n.get("latency_ms") or 0,
                n.get("host") or "",
            ),
        )
        lines.append("")
        lines.append(
            f"# ---- {zh} {code} · {grp['count']} 节点 (住宅 {grp['residential']} / 机房 {grp['datacenter']}) ----"
        )
        res_nodes = [n for n in nodes if n.get("residential") == "residential"]
        dc_nodes = [n for n in nodes if n.get("residential") != "residential"]
        for i, n in enumerate(res_nodes, 1):
            lines.append(f"{zh}-住宅-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
        for i, n in enumerate(dc_nodes, 1):
            lines.append(f"{zh}-机房-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
    return "\n".join(lines) + "\n"
EDGE_HOSTS = [
    h.strip()
    for h in os.environ.get(
        "EDGE_HOSTS",
        "cf.itv888.cn:443,bbs.alipansou.com:443,www.udacity.com:443,www.mfyx.cn:443,hzytjy.cn:443,cdn.7zz.cn:443,c-power.com.cn:443,www.5h.com:443,cf.qq.ms:443,"
        "cloudflare-ip.mofashi.ltd:443,www.whatismyip.com:443,cf.0sm.com:443,pubs.acs.org:443,www.4429.com.cn:443,cdnjs.loli.net:443",
    ).split(",")
    if h.strip()
]

HOSTS_URL = os.environ.get("HOSTS_URL", "https://goorwl.github.io/nodeCheck/hosts.txt")


def build_hosts_text(data):
    """生成可直接粘贴到 edgetunnel 后台「自定义优选IP」框的清单。
    每行 = 入口地址#名字$sstp://... ; 名字固定, 底下 SSTP 节点每 30 分钟自动换。"""
    countries = data["countries"]
    # 入口: 默认用 7 个实测可用优选域名循环分配; 可用 HOSTS_ENTRY 覆盖(逗号分隔)
    _entry = os.environ.get("HOSTS_ENTRY", "").strip()
    edge = [e.strip() for e in _entry.split(",") if e.strip()] or EDGE_HOSTS or [f"{EDT_DOMAIN}:443"]
    lines = [
        # 注意: 注释里禁止英文逗号 ","!
        # edgetunnel 拉取 URL 后按「第一行是否含逗号」判定 CSV, 含逗号会整文件静默丢弃 (无法解析)
        "# edgetunnel「自定义优选IP」清单",
        "# 用法一: 整段复制追加到后台「自定义优选IP」框",
        "# 用法二: 直接把本文件的 URL 填进后台「自定义优选IP」框 (自动更新)",
        f"# 自动更新: {data['generated_at']} (每 30 分钟重新检测)",
        f"# 固定地址: {HOSTS_URL}",
        "# 每行 = 入口地址#名字$sstp://vpn:vpn@节点:端口",
        "# 入口用 7 个实测可用优选域名循环分配",
        "# 名字 = 国家-住宅/机房-编号、直接区分住宅与机房",
        "# 名字固定; 只有 $sstp:// 后面的节点地址每 30 分钟自动更换",
        "# 账号密码固定 vpn:vpn ; 节点端口必须保留",
        "# ========================================================",
    ]
    idx = 0
    ordered = sorted(
        countries.items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("residential") == "residential" else 1,
                n.get("latency_ms") is None,
                n.get("latency_ms") or 0,
                n.get("host") or "",
            ),
        )
        lines.append("")
        lines.append(
            f"# ---- {zh} {code} · {grp['count']} 节点 (住宅 {grp['residential']} / 机房 {grp['datacenter']}) ----"
        )
        res_nodes = [n for n in nodes if n.get("residential") == "residential"]
        dc_nodes = [n for n in nodes if n.get("residential") != "residential"]
        for i, n in enumerate(res_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            lines.append(f"{entry}#{zh}-住宅-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
        for i, n in enumerate(dc_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            lines.append(f"{entry}#{zh}-机房-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
    return "\n".join(lines) + "\n"


# edgetunnel 完整订阅 (vless://) 配置
EDT_UUID = os.environ.get("EDT_UUID", "6df70e07-3730-4d54-8c07-d187ac0e0878")
EDT_DOMAIN = os.environ.get("EDT_DOMAIN", "jpnode2608.jintiantq0604.fun")
EDT_FINGERPRINT = os.environ.get("EDT_FINGERPRINT", "chrome")
SUB_URL = os.environ.get("SUB_URL", "https://goorwl.github.io/nodeCheck/sub.txt")


def _b64_secret_encode(plaintext, secret):
    """复刻 edgetunnel 的 base64SecretEncode: UTF-8 循环密钥 XOR + 标准 base64。"""
    data = plaintext.encode("utf-8")
    key = secret.encode("utf-8")
    mixed = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
    return base64.b64encode(mixed).decode("ascii")


def _socks5_account(address, default_port=80):
    """复刻 edgetunnel 的 获取SOCKS5账号: user:pass@host:port -> {username,password,hostname,port}。"""
    address = re.sub(r"^(socks5|http|https|turn|sstp)://", "", address.strip(), flags=re.I).split("#")[0].strip()
    at = address.rfind("@")
    auth, hostpart = (address[:at], address[at + 1:]) if at != -1 else ("", address)
    hostpart = hostpart.split("/")[0]
    username = password = None
    if auth:
        if ":" not in auth:
            try:
                auth = base64.b64decode(auth + "=" * (-len(auth) % 4)).decode("utf-8")
            except Exception:
                pass
        parts = auth.split(":", 1)
        username = parts[0]
        password = parts[1] if len(parts) > 1 else None
    hostname, port = hostpart, default_port
    if hostpart.count(":") == 1 and not hostpart.startswith("["):
        h, p = hostpart.rsplit(":", 1)
        if p.isdigit():
            hostname, port = h, int(p)
    return {"username": username, "password": password, "hostname": hostname, "port": port}


def build_sub_text(data):
    """生成 edgetunnel 完整 vless:// 订阅 (链式代理编码在 path)。
    填进 edgetunnel 后台「订阅链接」URL, 客户端定时拉取即可自动轮换。"""
    countries = data["countries"]
    lines = [
        "# edgetunnel 完整订阅 (vless://) —— 填进后台「订阅链接」URL",
        f"# 自动更新: {data['generated_at']} (每 30 分钟重新检测)",
        f"# 固定地址: {SUB_URL}",
        f"# 节点域名: {EDT_DOMAIN} (传输 ws / TLS / fingerprint {EDT_FINGERPRINT})",
        "# 名字固定; $sstp:// 链式代理(编码在 path)每 30 分钟自动更换",
        "# 账号密码固定 vpn:vpn ; 节点端口已编码进 path",
        "# ========================================================",
    ]
    ordered = sorted(
        countries.items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("residential") == "residential" else 1,
                n.get("latency_ms") is None,
                n.get("latency_ms") or 0,
                n.get("host") or "",
            ),
        )
        for i, n in enumerate(nodes, 1):
            name = f"{zh}-{i:02d}"
            chain = {"type": "sstp", **_socks5_account(f"vpn:vpn@{n['host']}:{n['port']}", 443)}
            chain_json = json.dumps(chain, separators=(",", ":"))
            enc = _b64_secret_encode(chain_json, EDT_UUID)
            path = quote("/video/" + enc, safe="")
            link = (
                f"vless://{EDT_UUID}@{EDT_DOMAIN}:443?security=tls&type=ws"
                f"&host={EDT_DOMAIN}&fp={EDT_FINGERPRINT}&sni={EDT_DOMAIN}"
                f"&path={path}&encryption=none&alpn=#{quote(name, safe='')}"
            )
            lines.append(link)
    return "\n".join(lines) + "\n"


def write_outputs(data):
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    data_path = os.path.join(PUBLIC_DIR, "data.json")
    with open(data_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

    # 固定网页: 始终用 web/index.html 模板生成同一个 index.html (数据来自 data.json)
    html_path = os.path.join(PUBLIC_DIR, "index.html")
    if os.path.exists(TEMPLATE_HTML):
        with open(TEMPLATE_HTML, "r", encoding="utf-8") as f:
            html = f.read()
    else:
        html = ("<html><head><meta charset='utf-8'><title>VPN Gate SSTP 节点</title></head>"
                "<body><h1>VPN Gate SSTP 节点</h1><pre id='out'></pre></body>"
                "<script>fetch('data.json').then(r=>r.json()).then(d=>out.textContent=JSON.stringify(d.stats)).catch(e=>out.textContent='加载失败:'+e)</script></html>")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    # edgetunnel 链式代理清单 (固定 URL, 方案一: 名字不变、指令自动换)
    chains_path = os.path.join(PUBLIC_DIR, "chains.txt")
    with open(chains_path, "w", encoding="utf-8") as f:
        f.write(build_chains_text(data))

    # 可直接粘贴进后台「自定义优选IP」框的清单 (入口地址#名字$sstp://...)
    hosts_path = os.path.join(PUBLIC_DIR, "hosts.txt")
    with open(hosts_path, "w", encoding="utf-8") as f:
        f.write(build_hosts_text(data))

    # 完整 vless:// 订阅 (填进后台「订阅链接」URL, 客户端自动轮换)
    sub_path = os.path.join(PUBLIC_DIR, "sub.txt")
    with open(sub_path, "w", encoding="utf-8") as f:
        f.write(build_sub_text(data))
    return data_path, html_path, chains_path, hosts_path, sub_path


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    session = requests.Session()

    # 1) 数据源
    rows, source = fetch_vpngate()
    raw_count = len(rows)
    if raw_count == 0:
        die("VPN Gate 返回 0 个原始节点 (数据源异常, 不允许生成空结果)")

    # 2) SSTP 筛选 + 去重
    sstp_nodes = to_sstp_nodes(rows)
    sstp_count = len(sstp_nodes)
    if sstp_count == 0:
        die(f"从 {raw_count} 个原始节点中没有解析出任何 SSTP(TCP) 节点 — 数据格式可能已变化, 需要人工适配")
    uniq = dedupe(sstp_nodes)

    if MAX_CHECK_NODES > 0:
        uniq = uniq[:MAX_CHECK_NODES]

    log("VPN GATE", f"获取原始节点: {raw_count}")
    log("VPN GATE", f"SSTP 节点: {sstp_count}")
    log("VPN GATE", f"去重后: {len(uniq)}")

    # 2.5) 历史池合并: 当轮节点 + 池内存活节点 一起检测
    pool = load_pool()
    candidates = merge_with_pool(uniq, pool)

    # 3) 并发检测
    log("CLOUDFLARE WORKER", f"提交检测: {len(candidates)} (并发 {CONCURRENCY}, 单请求超时 {CHECK_TIMEOUT}s)")
    t0 = time.time()
    results = check_all(candidates, session)
    elapsed = time.time() - t0

    success = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]
    worker_errors = [r for r in failed if r.get("worker_error")]

    log("CLOUDFLARE WORKER", f"检测成功: {len(success)}")
    log("CLOUDFLARE WORKER", f"检测失败: {len(failed)}" + (f" (其中 Worker 异常 {len(worker_errors)})" if worker_errors else ""))
    log("CLOUDFLARE WORKER", f"耗时: {elapsed:.1f}s")

    # 硬性失败: Worker 完全不可达 (没有任何一个请求拿到正常响应)
    if candidates and not success and len(worker_errors) == len(candidates):
        die("Worker 全部请求异常, 检测服务不可用 — 本次运行判定失败 (不生成空结果)")

    # 3.5) 更新历史池: success 节点写回, 连续失败淘汰, 上限 POOL_SIZE
    new_pool, evicted = update_pool(pool, results)
    save_pool(new_pool)
    pool_stats = {"size": len(new_pool), **evicted}

    # 4) 结果 + 网页
    data = build_outputs(results, raw_count, sstp_count, source, pool_stats)
    log("RESULT", f"可用节点: {len(success)}")
    log("RESULT", f"国家数量: {data['stats']['countries']}")

    data_path, html_path, chains_path, hosts_path, sub_path = write_outputs(data)
    log("WEBSITE", f"生成 {os.path.relpath(data_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(html_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(chains_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(hosts_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(sub_path, REPO_DIR)}")
    log("WEBSITE", "完成 (GitHub Pages 部署由 workflow 执行)")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")
