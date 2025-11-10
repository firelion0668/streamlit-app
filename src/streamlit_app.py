#!/usr/bin/env python3

import streamlit as st
import os
import sys
import json
import base64
import time
import re
import subprocess
import requests
import platform
import logging
import threading
import random
import string

# ====================== 配置 & 日志 ======================
DDDEBUG = os.environ.get('DDDEBUG', 'false').lower() in ('true', '1', 'yes')

logger = logging.getLogger()
logger.setLevel(logging.DEBUG if DDDEBUG else logging.INFO)

if logger.handlers:
    logger.handlers.clear()

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG if DDDEBUG else logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

log = logging.getLogger()  # 快捷别名

# 环境变量
UPLOAD_URL = os.environ.get('UPLOAD_URL', '')
PROJECT_URL = os.environ.get('PROJECT_URL', '')
AUTO_ACCESS = os.environ.get('AUTO_ACCESS', 'false').lower() == 'true'
FILE_PATH = os.environ.get('FILE_PATH', '/tmp/.cache')
SUB_PATH = os.environ.get('SUB_PATH', 'sub')
UUID = os.environ.get('ID', '1f6f5a40-80d0-4dbf-974d-4d53ff18d639')
PASSWD = os.environ.get('PASSWD', 'admin123')
NEZHA_SERVER = os.environ.get('NEZHA_SERVER', '')
NEZHA_PORT = os.environ.get('NEZHA_PORT', '')
NEZHA_KEY = os.environ.get('NEZHA_KEY', '')
ARGO_DOMAIN = os.environ.get('HOST', '')
ARGO_AUTH = os.environ.get('DATA', '')
ARGO_PORT = int(os.environ.get('PORT', 8001))
CFIP = os.environ.get('GOODIP', '194.53.53.7')
CFPORT = int(os.environ.get('GOODPORT', 443))
NAME = os.environ.get('NAME', '')

os.makedirs(FILE_PATH, exist_ok=True)

# 路径
subPath = os.path.join(FILE_PATH, 'sub.txt')
bootLogPath = os.path.join(FILE_PATH, 'boot.log')
configPath = os.path.join(FILE_PATH, 'config.json')
npmPath = os.path.join(FILE_PATH, 'npm')
phpPath = os.path.join(FILE_PATH, 'php')
lockFile = os.path.join(FILE_PATH, 'service.lock')  # 永久保留

log.info(f"Configuration loaded | DDDEBUG={'ON' if DDDEBUG else 'OFF'}")
log.debug(f"FILE_PATH={FILE_PATH} | lockFile={lockFile}")


# ====================== 工具函数 ======================
def generate_random_name(length=5):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def check_passwd(user_input: str) -> bool:
    return user_input.strip() == PASSWD.strip()


# ====================== 永久内存缓存订阅 =======================
@st.cache_data(show_spinner=False)
def get_global_subscription(_domain: str) -> str:
    log.debug(f"Generating subscription content for domain: {_domain}")
    ISP = 'Unknown'
    try:
        meta = requests.get('https://speed.cloudflare.com/meta', timeout=5).json()
        ISP = f"{meta.get('country','')}-{meta.get('asOrganization','')}".replace(' ', '_') or 'CF-Node'
        log.debug(f"ISP detected via Cloudflare: {ISP}")
    except Exception as e:
        ISP = f"{NAME}-Node" if NAME else 'CF-Node'
        log.debug(f"ISP detection failed, using fallback: {ISP} | error: {e}")

    VMESS = {
        "v": "2", "ps": f"{NAME}-{ISP}", "add": CFIP, "port": CFPORT, "id": UUID,
        "aid": "0", "scy": "none", "net": "ws", "type": "none", "host": _domain,
        "path": "/vmess-argo?ed=2560", "tls": "tls", "sni": _domain, "alpn": "", "fp": "chrome"
    }
    raw = f"""vless://{UUID}@{CFIP}:{CFPORT}?encryption=none&security=tls&sni={_domain}&fp=chrome&type=ws&host={_domain}&path=%2Fvless-argo%3Fed%3D2560#{NAME}-{ISP}

vmess://{base64.b64encode(json.dumps(VMESS).encode()).decode()}

trojan://{UUID}@{CFIP}:{CFPORT}?security=tls&sni={_domain}&fp=chrome&type=ws&host={_domain}&path=%2Ftrojan-argo%3Fed%3D2560#{NAME}-{ISP}
"""
    b64_content = base64.b64encode(raw.encode('utf-8')).decode('utf-8')
    log.debug(f"Generated base64 subscription | length={len(b64_content)}")

    # 临时写入 sub.txt（仅用于上传）
    try:
        with open(subPath, 'w', encoding='utf-8') as f:
            f.write(b64_content)
        log.debug(f"Subscription written to: {subPath}")
        if UPLOAD_URL and PROJECT_URL:
            try:
                upload_payload = {"subscription": [f"{PROJECT_URL}/{SUB_PATH}"]}
                log.debug(f"Uploading subscription URL: {upload_payload}")
                requests.post(
                    f"{UPLOAD_URL}/api/add-subscriptions",
                    json=upload_payload,
                    timeout=10
                )
                log.info("Subscription URL uploaded successfully")
            except Exception as e:
                log.warning(f"Upload failed: {e}")
    except Exception as e:
        log.warning(f"Failed to write sub.txt: {e}")

    return b64_content


# ====================== 全局服务启动（只看 lockFile）======================
@st.cache_resource(show_spinner="Starting global proxy service...")
def start_proxy_service_once():
    # === 关键：只看 lockFile 是否存在 ===
    if os.path.exists(lockFile):
        log.info("Service already initialized (lockFile exists)")
        domain = ARGO_DOMAIN
        if not domain and os.path.exists(bootLogPath):
            try:
                with open(bootLogPath, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if m := re.search(r'https?://([^ ]*trycloudflare\.com)', content):
                        domain = m.group(1)
                        log.debug(f"Extracted domain from boot.log: {domain}")
            except Exception as e:
                log.debug(f"Failed to read boot.log: {e}")
        return domain or "unknown.trycloudflare.com"

    # === 初始化流程 ===
    log.info("Starting global proxy service initialization...")
    web_file_name = generate_random_name(5)
    bot_file_name = generate_random_name(5)
    webPath = os.path.join(FILE_PATH, web_file_name)
    botPath = os.path.join(FILE_PATH, bot_file_name)

    log.debug(f"Generated file names: web={web_file_name}, bot={bot_file_name}")
    log.debug(f"Web path: {webPath}, Bot path: {botPath}")

    # 1. 生成 xray 配置
    log.info("Generating xray configuration...")
    config = {
        "log": {"access": "/dev/null", "error": "/dev/null", "loglevel": "none"},
        "inbounds": [
            {
                "port": ARGO_PORT, "protocol": "vless",
                "settings": {"clients": [{"id": UUID, "flow": "xtls-rprx-vision"}], "decryption": "none",
                             "fallbacks": [{"dest": 3001}, {"path": "/vless-argo", "dest": 3002},
                                           {"path": "/vmess-argo", "dest": 3003}, {"path": "/trojan-argo", "dest": 3004}]},
                "streamSettings": {"network": "tcp"}
            },
            {"port": 3001, "listen": "127.0.0.1", "protocol": "vless", "settings": {"clients": [{"id": UUID}], "decryption": "none"},
             "streamSettings": {"network": "tcp", "security": "none"}},
            {"port": 3002, "listen": "127.0.0.1", "protocol": "vless", "settings": {"clients": [{"id": UUID, "level": 0}], "decryption": "none"},
             "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": "/vless-argo"}},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "metadataOnly": False}},
            {"port": 3003, "listen": "127.0.0.1", "protocol": "vmess", "settings": {"clients": [{"id": UUID, "alterId": 0}]},
             "streamSettings": {"network": "ws", "wsSettings": {"path": "/vmess-argo"}},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "metadataOnly": False}},
            {"port": 3004, "listen": "127.0.0.1", "protocol": "trojan", "settings": {"clients": [{"password": UUID}]},
             "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": "/trojan-argo"}},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "metadataOnly": False}},
        ],
        "dns": {"servers": ["https+local://1.1.1.1/dns-query", "https+local://8.8.8.8/dns-query"]},
        "routing": {"rules": [{"type": "field", "domain": ["v.com"], "outboundTag": "force-to-ip"}]},
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
            {"tag": "force-to-ip", "protocol": "freedom", "settings": {"redirect": "127.0.0.1:0"}}
        ]
    }
    try:
        with open(configPath, 'w') as f:
            json.dump(config, f, indent=2)
        log.debug(f"Xray config written to: {configPath}")
    except Exception as e:
        log.error(f"Failed to write config.json: {e}")
        raise

    # 2. 下载文件
    arch = 'arm' if 'arm' in platform.machine().lower() or 'aarch64' in platform.machine().lower() else 'amd'
    log.info(f"Detected architecture: {arch}64")
    files = [
        {"fileName": web_file_name, "fileUrl": f"https://{arch}64.ssss.nyc.mn/web"},
        {"fileName": bot_file_name, "fileUrl": f"https://{arch}64.ssss.nyc.mn/2go"}
    ]

    if NEZHA_SERVER and NEZHA_KEY:
        agent = "agent" if NEZHA_PORT else "v1"
        agent_name = "npm" if NEZHA_PORT else "php"
        agent_path = os.path.join(FILE_PATH, agent_name)
        if agent_name == "npm":
            globals()['npmPath'] = agent_path
        else:
            globals()['phpPath'] = agent_path
        files.insert(0, {"fileName": agent_name, "fileUrl": f"https://{arch}64.ssss.nyc.mn/{agent}"})
        log.info(f"Adding Nezha agent: {agent_name} -> {agent_path}")

    for f in files:
        path = os.path.join(FILE_PATH, f['fileName'])
        log.debug(f"Downloading {f['fileName']} from {f['fileUrl']}")
        try:
            r = requests.get(f['fileUrl'], stream=True, timeout=15)
            r.raise_for_status()
            with open(path, 'wb') as wf:
                for c in r.iter_content(8192):
                    wf.write(c)
            os.chmod(path, 0o775)
            log.debug(f"Downloaded and chmod 775: {path}")
        except Exception as e:
            log.error(f"Failed to download {f['fileName']}: {e}")
            raise

    # 3. 启动 xray
    log.info("Starting xray core...")
    try:
        subprocess.Popen([webPath, '-c', configPath], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(5)
        log.debug("xray started, waiting 5s for stabilization")
    except Exception as e:
        log.error(f"Failed to start xray: {e}")
        raise

    # 4. 启动 cloudflared
    log.info("Starting Argo tunnel (cloudflared)...")
    cfd_cmd = [botPath]
    if re.match(r'^[A-Z0-9a-z=]{120,250}$', ARGO_AUTH):
        cfd_cmd += ["tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2", "run", "--token", ARGO_AUTH]
        log.debug("Using Argo token mode")
    elif 'TunnelSecret' in ARGO_AUTH:
        with open(os.path.join(FILE_PATH, 'tunnel.json'), 'w') as f:
            f.write(ARGO_AUTH)
        try:
            tunnel_id = json.loads(ARGO_AUTH).get("TunnelID") or ARGO_AUTH.split('"')[11]
        except:
            tunnel_id = "unknown"
        yaml_content = f"""tunnel: {tunnel_id}
credentials-file: {os.path.join(FILE_PATH, 'tunnel.json')}
protocol: http2
ingress:
  - hostname: {ARGO_DOMAIN}
    service: http://localhost:{ARGO_PORT}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
"""
        with open(os.path.join(FILE_PATH, 'tunnel.yml'), 'w') as f:
            f.write(yaml_content)
        cfd_cmd += ["tunnel", "--edge-ip-version", "auto", "--config", os.path.join(FILE_PATH, 'tunnel.yml'), "run"]
        log.debug("Using Argo config file mode")
    else:
        cfd_cmd += ["tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2",
                    "--logfile", bootLogPath, "--loglevel", "info", "--url", f"http://localhost:{ARGO_PORT}"]
        log.debug("Using ephemeral tunnel mode (trycloudflare)")

    log.debug(f"cloudflared command: {' '.join(cfd_cmd)}")
    try:
        subprocess.Popen(cfd_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)
    except Exception as e:
        log.error(f"Failed to start cloudflared: {e}")
        raise

    # 5. 提取域名
    domain = ARGO_DOMAIN or _extract_argo_domain_from_log()
    log.info(f"Argo domain resolved: {domain}")

    # 6. 生成订阅
    log.info("Generating subscription links...")
    get_global_subscription(domain)

    # 7. 创建 lockFile（永久保留）
    try:
        with open(lockFile, 'w') as f:
            f.write(str(int(time.time())))
        log.info("lockFile created - service permanently initialized")
    except Exception as e:
        log.error(f"Failed to create lockFile: {e}")
        raise

    # 8. 访问任务
    if AUTO_ACCESS and PROJECT_URL:
        try:
            requests.post('https://oooo.serv00.net/add-url', json={"url": PROJECT_URL}, timeout=5)
            log.debug("AUTO_ACCESS URL submitted")
        except Exception as e:
            log.debug(f"AUTO_ACCESS failed: {e}")

    log.info("GLOBAL SERVICE INITIALIZED SUCCESSFULLY")
    return domain


def _extract_argo_domain_from_log():
    log.debug("Attempting to extract Argo domain from boot.log")
    for i in range(15):
        if os.path.exists(bootLogPath):
            try:
                with open(bootLogPath, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if m := re.search(r'https?://([^ ]*trycloudflare\.com)', content):
                        domain = m.group(1)
                        log.debug(f"Domain found in log (attempt {i+1}): {domain}")
                        return domain
                    else:
                        log.debug(f"No domain found in log (attempt {i+1})")
            except Exception as e:
                log.debug(f"Error reading boot.log (attempt {i+1}): {e}")
        else:
            log.debug(f"boot.log not exists yet (attempt {i+1}), waiting...")
        time.sleep(2)
    log.warning("Failed to extract domain after 15 attempts")
    return "unknown.trycloudflare.com"


# ====================== 自动清理（90秒后，**不删 lockFile**）======================
def schedule_cleanup():
    def _cleanup():
        time.sleep(90)
        files = [bootLogPath, configPath, subPath]  # 不删 lockFile
        for path in [globals().get('webPath'), globals().get('botPath'), npmPath, phpPath]:
            if path and os.path.exists(path):
                files.append(path)
        for ext in ['tunnel.json', 'tunnel.yml']:
            f = os.path.join(FILE_PATH, ext)
            if os.path.exists(f):
                files.append(f)
        if files:
            cmd = f"rm -f {' '.join(files)}"
            log.debug(f"Cleaning up temporary files: {cmd}")
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            log.info(f"Temporary files cleaned ({len(files)} files), lockFile kept")
    threading.Thread(target=_cleanup, daemon=True).start()


# ====================== 主界面 ======================
def main():
    st.set_page_config(page_title="Viewer", layout="centered")
    st.title("Viewer")
    st.markdown("---")

    # 初始化 session_state
    if "passwd_verified" not in st.session_state:
        st.session_state.passwd_verified = False
    if "argo_domain" not in st.session_state:
        st.session_state.argo_domain = None

    # === 1. 判断是否已初始化：只看 lockFile 是否存在 ===
    if not os.path.exists(lockFile):
        with st.spinner("Initializing global service (first user triggers)..."):
            try:
                domain = start_proxy_service_once()
                st.session_state.argo_domain = domain
                schedule_cleanup()  # 清理临时文件（不删 lockFile）
                st.success("Service initialized!")
                st.info("Refresh and enter password")
                time.sleep(1)
                st.rerun()
            except Exception as e:
                st.error(f"Init failed: {e}")
                log.error(f"Service initialization error: {e}", exc_info=True)
        return
    else:
        # lockFile 存在 → 服务已初始化
        if st.session_state.argo_domain is None:
            domain = ARGO_DOMAIN
            if not domain and os.path.exists(bootLogPath):
                try:
                    with open(bootLogPath, 'r') as f:
                        if m := re.search(r'https?://([^ ]*trycloudflare\.com)', f.read()):
                            domain = m.group(1)
                            log.debug(f"Domain from boot.log in UI: {domain}")
                except Exception as e:
                    log.debug(f"UI boot.log read failed: {e}")
            st.session_state.argo_domain = domain or "unknown.trycloudflare.com"

    # === 2. 密码验证 ===
    if not st.session_state.passwd_verified:
        pwd = st.text_input("Enter password", type="password", placeholder="Default: admin123")
        if pwd:
            if check_passwd(pwd):
                st.session_state.passwd_verified = True
                st.success("Login successful!")
                log.info("User logged in successfully")
                st.rerun()
            else:
                st.error("Incorrect password")
                log.warning("Login failed: incorrect password")
        else:
            st.info("Please enter the correct password")
        return

    # === 3. 显示订阅（内存缓存）===
    b64_content = get_global_subscription(st.session_state.argo_domain)

    st.subheader("Subscription (Base64)")
    st.text_area("Click to select all", b64_content, height=150)
    st.download_button("Download sub.txt", b64_content, "sub.txt", "text/plain")
    st.success("Done!")

    if st.button("Force Refresh Cache (Admin)"):
        get_global_subscription.clear()
        st.success("Refreshing cache...")
        log.info("Admin forced subscription cache refresh")
        st.rerun()


if __name__ == "__main__":
    main()
    sys.stdout.flush()
