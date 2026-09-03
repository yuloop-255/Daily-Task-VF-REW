#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Daily Task 自动任务 (Playwright + hcaptcha-challenger + Gemini 免费API)
═══════════════════════════════════════════════════════════════
完全免费方案：
  - hcaptcha-challenger 通过 Gemini 免费额度自动解 hCaptcha
  - 不需要 NopeCHA，不需要付费
  - 任意代理节点可用（sing-box 转换 vless/vmess/trojan/ss/hysteria2/tuic）
  - GitHub Actions 全自动无人值守

[优化版 v2.0]
✅ 增加验证码重试机制（最多10次）
✅ 优化Gemini模型选择（自动降级）
✅ 增加代理IP质量检测
✅ 改进错误处理和调试信息
✅ 增加任务级重试

环境变量：
  ACCOUNTS          邮箱:密码（必填）
  GEMINI_API_KEY    Gemini API Key（必填，多个用逗号分隔）
  PROXY_STR         代理节点（选填）
  TG_BOT_TOKEN      Telegram Bot Token（选填）
  TG_CHAT_ID        Telegram Chat ID（选填）
"""

import os
import re
import json
import time
import base64
import asyncio
import subprocess
import requests
from urllib.parse import urlparse, parse_qs, unquote

# ================= 配置 =================
LOGIN_URL   = os.getenv("TASK_LOGIN_URL", "")
PROJECTS_URL = os.getenv("TASK_PROJECTS_URL", "")
IPTEST_URL  = "https://api.ipify.org"

TG_TOKEN    = os.getenv("TG_BOT_TOKEN", "")
TG_CHAT_ID  = os.getenv("TG_CHAT_ID", "")
PROXY_STR   = os.getenv("PROXY_STR", "")
GEMINI_KEYS = [k.strip() for k in os.getenv("GEMINI_API_KEY", "").split(",") if k.strip()]

SS_DIR = "screenshots"
MAX_CAPTCHA_ATTEMPTS = 10  # 增加到10次
CAPTCHA_TIMEOUT = 60  # 验证码超时时间
# ========================================


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def send_tg(message):
    if not TG_TOKEN or not TG_CHAT_ID:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
            data={"chat_id": TG_CHAT_ID, "text": message},
            timeout=15,
        )
    except Exception as e:
        log(f"⚠️ TG 推送失败: {e}")


async def send_tg_screenshot(page, caption="debug"):
    if not TG_TOKEN or not TG_CHAT_ID:
        return
    try:
        path = f"/tmp/tg_{int(time.time())}.png"
        await page.screenshot(path=path)
        with open(path, "rb") as f:
            requests.post(
                f"https://api.telegram.org/bot{TG_TOKEN}/sendPhoto",
                data={"chat_id": TG_CHAT_ID, "caption": caption[:900]},
                files={"photo": f},
                timeout=30,
            )
        os.remove(path)
        log("📸 截图已推送 TG")
    except Exception as e:
        log(f"⚠️ 截图推送失败: {e}")


async def save_screenshot(page, name):
    os.makedirs(SS_DIR, exist_ok=True)
    try:
        await page.screenshot(path=os.path.join(SS_DIR, f"{name}.png"))
    except Exception as e:
        log(f"⚠️ 截图失败 ({name}): {e}")


def mask_email(email):
    try:
        local, domain = (email or "").split("@", 1)
        if len(local) <= 2:
            masked = local[0] + "*"
        else:
            masked = local[0] + "*" * (len(local) - 2) + local[-1]
        return f"{masked}@{domain}"
    except Exception:
        return "***"


def parse_account(raw):
    value = (raw or "").strip()
    index = value.find(":")
    if index <= 0 or index == len(value) - 1:
        raise ValueError("ACCOUNTS 格式错误，应为 邮箱:密码")
    return value[:index].strip(), value[index + 1:].strip()


# ══════════════════════════════════════════════════════════
# 代理转换（优化版）
# ══════════════════════════════════════════════════════════

def generate_config(proxy_url):
    proxy_url = proxy_url.strip()
    if proxy_url.startswith("{") and proxy_url.endswith("}"):
        try:
            json.loads(proxy_url)
            return proxy_url
        except Exception:
            pass

    parsed = urlparse(proxy_url)
    scheme = parsed.scheme.lower()
    outbound = {"tag": "proxy"}

    if scheme == "vless":
        outbound["type"] = "vless"
        outbound["server"] = parsed.hostname
        outbound["server_port"] = parsed.port
        outbound["uuid"] = unquote(parsed.username or "")
        params = parse_qs(parsed.query)

        flow = unquote(params.get("flow", [""])[0])
        if flow:
            outbound["flow"] = flow

        security = unquote(params.get("security", [""])[0])
        if security in ("tls", "reality"):
            outbound["tls"] = {"enabled": True}
            if "sni" in params:
                outbound["tls"]["server_name"] = unquote(params["sni"][0])
            if "fp" in params:
                outbound["tls"]["utls"] = {"enabled": True, "fingerprint": unquote(params["fp"][0])}
            if "pbk" in params:
                outbound["tls"]["reality"] = {
                    "enabled": True,
                    "public_key": unquote(params["pbk"][0]),
                    "short_id": unquote(params.get("sid", [""])[0]),
                }
            if params.get("allowInsecure", ["0"])[0] in ("1", "true"):
                outbound["tls"]["insecure"] = True

        network = unquote(params.get("type", ["tcp"])[0])
        if network == "ws":
            ws_path = unquote(params.get("path", ["/"])[0])
            transport = {
                "type": "ws",
                "path": ws_path,
                "headers": {"Host": unquote(params.get("host", [""])[0])},
            }
            if "?" in ws_path:
                path_only, query = ws_path.split("?", 1)
                transport["path"] = path_only or "/"
                ws_params = parse_qs(query)
                if ws_params.get("ed"):
                    transport["max_early_data"] = int(ws_params["ed"][0])
                    transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
            outbound["transport"] = transport
        elif network == "grpc":
            outbound["transport"] = {
                "type": "grpc",
                "service_name": unquote(params.get("serviceName", [""])[0]),
            }

    elif scheme == "trojan":
        outbound["type"] = "trojan"
        outbound["server"] = parsed.hostname
        outbound["server_port"] = parsed.port
        outbound["password"] = unquote(parsed.username or "")
        params = parse_qs(parsed.query)
        outbound["tls"] = {"enabled": True}
        if "sni" in params:
            outbound["tls"]["server_name"] = unquote(params["sni"][0])
        if params.get("allowInsecure", ["0"])[0] in ("1", "true"):
            outbound["tls"]["insecure"] = True
        if unquote(params.get("type", ["tcp"])[0]) == "ws":
            outbound["transport"] = {
                "type": "ws",
                "path": unquote(params.get("path", ["/"])[0]),
                "headers": {"Host": unquote(params.get("host", [""])[0])},
            }

    elif scheme == "vmess":
        raw = parsed.netloc + parsed.path
        decoded = None
        for padding in ("", "=", "=="):
            try:
                decoded = base64.b64decode(raw + padding).decode("utf-8")
                json.loads(decoded)
                break
            except Exception:
                continue
        if decoded is None:
            raise ValueError(f"无法解析 VMess: {raw[:60]}")
        v = json.loads(decoded)
        outbound["type"] = "vmess"
        outbound["server"] = v.get("add")
        outbound["server_port"] = int(v.get("port", 443))
        outbound["uuid"] = v.get("id")
        outbound["security"] = v.get("scy") or "auto"
        outbound["alter_id"] = int(v.get("aid", 0))
        if v.get("tls") == "tls":
            outbound["tls"] = {
                "enabled": True,
                "server_name": v.get("sni") or v.get("host") or v.get("add"),
            }
        if v.get("net") == "ws":
            outbound["transport"] = {
                "type": "ws",
                "path": v.get("path") or "/",
                "headers": {"Host": v.get("host") or v.get("add")},
            }

    elif scheme == "hysteria2" or scheme == "hy2":
        outbound["type"] = "hysteria2"
        outbound["server"] = parsed.hostname
        outbound["server_port"] = parsed.port
        outbound["password"] = unquote(parsed.username or "")
        params = parse_qs(parsed.query)
        outbound["tls"] = {"enabled": True}
        if "sni" in params:
            outbound["tls"]["server_name"] = unquote(params["sni"][0])
        if params.get("insecure", ["0"])[0] in ("1", "true"):
            outbound["tls"]["insecure"] = True

    elif scheme == "tuic":
        outbound["type"] = "tuic"
        outbound["server"] = parsed.hostname
        outbound["server_port"] = parsed.port
        auth_user = unquote(parsed.username or "")
        auth_pass = unquote(parsed.password or "")
        if ":" in auth_user:
            outbound["uuid"], outbound["password"] = auth_user.split(":", 1)
        else:
            outbound["uuid"] = auth_user
            outbound["password"] = auth_pass
        params = parse_qs(parsed.query)
        outbound["congestion_control"] = unquote(params.get("congestion_control", ["bbr"])[0])
        outbound["udp_relay_mode"] = unquote(params.get("udp_relay_mode", ["quic-rfc"])[0])
        outbound["tls"] = {"enabled": True}
        if "sni" in params:
            outbound["tls"]["server_name"] = unquote(params["sni"][0])
        if params.get("insecure", ["0"])[0] in ("1", "true"):
            outbound["tls"]["insecure"] = True

    elif scheme == "ss":
        outbound["type"] = "shadowsocks"
        outbound["server"] = parsed.hostname
        outbound["server_port"] = parsed.port
        if parsed.username:
            try:
                decoded = base64.b64decode(parsed.username + "==").decode()
                if ":" in decoded:
                    outbound["method"], outbound["password"] = decoded.split(":", 1)
                else:
                    outbound["method"] = unquote(parsed.username)
                    outbound["password"] = unquote(parsed.password or "")
            except Exception:
                outbound["method"] = unquote(parsed.username)
                outbound["password"] = unquote(parsed.password or "")

    else:
        # http/socks5 直接透传给 Playwright，不经过 sing-box
        return None

    config = {
        "log": {"level": "info"},
        "inbounds": [{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": 8080,
        }],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "route": {"rules": [{"inbound": ["mixed-in"], "outbound": "proxy"}]},
    }
    return json.dumps(config, indent=2)


def _launch_singbox(proxy_url):
    """用指定节点启动 sing-box，成功返回 True"""
    config_json = generate_config(proxy_url)
    if not config_json:
        return False
    with open("/tmp/singbox-config.json", "w") as f:
        f.write(config_json)
    try:
        subprocess.Popen(
            ["sing-box", "run", "-c", "/tmp/singbox-config.json"],
            stdout=open("/tmp/singbox.log", "w"),
            stderr=subprocess.STDOUT,
        )
        time.sleep(4)
        r = requests.get("https://api.ipify.org",
                         proxies={"http": "http://127.0.0.1:8080",
                                  "https": "http://127.0.0.1:8080"},
                         timeout=10)
        log(f"✅ Sing-Box 已启动，出口IP: {r.text.strip()}")
        return True
    except Exception as e:
        log(f"⚠️ 节点启动失败: {str(e)[:80]}")
        return False


def start_proxy():
    """启动本地代理。支持逗号分隔多节点：坏节点自动切换下一个"""
    if not PROXY_STR:
        log("🌐 未配置代理，直连模式")
        return None

    nodes = [n.strip() for n in PROXY_STR.split("\n") if n.strip()]
    if len(nodes) == 1 and "," in nodes[0]:
        nodes = [n.strip() for n in nodes[0].split(",") if n.strip()]

    # 多节点时先杀掉可能残留的 sing-box
    if len(nodes) > 1:
        subprocess.run(["pkill", "-f", "sing-box run"], capture_output=True)

    for i, node in enumerate(nodes, 1):
        # http/socks5 直接返回给浏览器用
        p = urlparse(node)
        if p.scheme in ("http", "https", "socks5", "socks4"):
            log(f"🌐 使用直连代理[{i}/{len(nodes)}]: {p.scheme}://{p.hostname}:{p.port}")
            return f"{p.scheme}://{p.hostname}:{p.port}"

        log(f"🌐 启动节点 {i}/{len(nodes)} ({node[:40]}...)...")
        if len(nodes) > 1 and i > 1:
            subprocess.run(["pkill", "-f", "sing-box run"], capture_output=True)
            time.sleep(1)
        if _launch_singbox(node):
            # 验证IP质量
            if check_ip_quality():
                return "http://127.0.0.1:8080"
            else:
                log("⚠️ IP质量不佳，尝试下一个节点")
                subprocess.run(["pkill", "-f", "sing-box run"], capture_output=True)

    log("❌ 所有节点均失败，尝试直连")
    return None


def check_ip_quality():
    """检查IP质量（简单检查）"""
    try:
        # 测试延迟和可用性
        start = time.time()
        r = requests.get("https://www.google.com",
                        proxies={"http": "http://127.0.0.1:8080",
                                "https": "http://127.0.0.1:8080"},
                        timeout=10)
        latency = time.time() - start
        if r.status_code == 200 and latency < 5:
            log(f"✅ IP质量检查通过 (延迟: {latency:.2f}s)")
            return True
    except:
        pass
    return False


# ══════════════════════════════════════════════════════════
# hCaptcha 检测（优化版）
# ══════════════════════════════════════════════════════════

async def is_hcaptcha_present(page):
    return await page.evaluate("""
        () => !!(document.querySelector('.h-captcha')
              || document.querySelector('iframe[src*="hcaptcha.com"]'))
    """)


async def is_cf_page(page):
    title = await page.title()
    if "Just a moment" in title or "Attention Required" in title:
        return True
    body = await page.evaluate("() => document.body ? document.body.innerText : ''")
    if "Verify you are human" in body or "Performing security verification" in body:
        return True
    return await page.evaluate("""
        () => !!(document.querySelector('[id^="cf-chl-widget"]')
              || document.querySelector('.cf-turnstile')
              || document.querySelector('iframe[src*="challenges.cloudflare.com"]'))
    """)


async def try_click_turnstile(page):
    """主动点击 Cloudflare Turnstile 复选框"""
    try:
        box = await page.evaluate("""
            () => {
                var w = document.querySelector('[id^="cf-chl-widget"], .cf-turnstile');
                var target = w;
                if (!target) {
                    var f = document.querySelector('iframe[src*="challenges.cloudflare.com"]');
                    if (f) target = f;
                }
                if (!target) return null;
                var r = target.getBoundingClientRect();
                if (r.width < 10) return null;
                return {x: r.left + 28, y: r.top + r.height / 2};
            }
        """)
        if box:
            await page.mouse.click(box["x"], box["y"])
            log(f"  🖱️ 已点击 Turnstile 复选框 ({box['x']:.0f},{box['y']:.0f})")
            return True
    except Exception as e:
        log(f"  ⚠️ Turnstile 点击失败: {str(e)[:80]}")
    return False


async def wait_cf_pass(page, timeout=120):
    """等待 Cloudflare 通过，期间主动点击 Turnstile 复选框"""
    start = time.time()
    clicked = 0
    while time.time() - start < timeout:
        if not await is_cf_page(page):
            log("  ✅ Cloudflare 已通过")
            return True
        # 每隔一段时间尝试点击复选框（首次立即点）
        elapsed = time.time() - start
        if clicked == 0 or (elapsed > clicked * 25 and clicked < 4):
            await try_click_turnstile(page)
            clicked += 1
        await asyncio.sleep(3)
    log(f"  ❌ Cloudflare 超时 ({timeout}s)")
    return False


async def get_token(page):
    return await page.evaluate("""
        () => {
            var ta = document.querySelector('textarea[name="h-captcha-response"], textarea[name="g-recaptcha-response"]');
            return (ta && ta.value && ta.value.length > 20) ? ta.value : '';
        }
    """)


def install_token_listener(page, holder):
    """监听 checkcaptcha 响应，挑战通过时直接抓 token（不依赖库的内部队列）"""
    async def on_response(response):
        try:
            if "/checkcaptcha" in response.url:
                data = await response.json()
                token = data.get("generated_pass_UUID", "")
                if token:
                    holder["token"] = token
                    holder["passed"] = True
                    log("  🎯 拦截到 hCaptcha 通过 token！")
        except Exception:
            pass
    page.on("response", on_response)


async def wait_token(page, holder, timeout=CAPTCHA_TIMEOUT):
    """等待 token 出现（监听器抓到的或页面 textarea 里的）"""
    start = time.time()
    while time.time() - start < timeout:
        if holder.get("token"):
            return holder["token"]
        t = await get_token(page)
        if t:
            return t
        await asyncio.sleep(2)
    return ""


# ══════════════════════════════════════════════════════════
# 登录 & 续期（优化版）
# ══════════════════════════════════════════════════════════

async def build_agent(page, key_index=0):
    """用第 key_index 个 Key 初始化 hcaptcha-challenger Agent
    模型策略：自动选择可用模型，429 时自动降级
    """
    from hcaptcha_challenger import AgentV, AgentConfig
    os.environ["GEMINI_API_KEY"] = GEMINI_KEYS[key_index % len(GEMINI_KEYS)]
    
    # 模型优先级列表（自动降级）
    models = ["gemini-3.6-flash", "gemini-3.5-flash-lite", "gemini-2.0-flash-exp"]
    primary_model = models[key_index % len(models)]
    
    agent_config = AgentConfig(
        CHALLENGE_CLASSIFIER_MODEL="gemini-3.5-flash-lite",
        IMAGE_CLASSIFIER_MODEL=primary_model,
        SPATIAL_POINT_REASONER_MODEL=primary_model,
        SPATIAL_PATH_REASONER_MODEL=primary_model,
        EXECUTION_TIMEOUT=240,
        RESPONSE_TIMEOUT=90,
        RETRY_ON_FAILURE=True,
        WAIT_FOR_CHALLENGE_VIEW_TO_RENDER_MS=5000,
    )
    log(f"  🧠 识别模型: {primary_model}")
    return AgentV(page=page, agent_config=agent_config)


async def solve_hcaptcha(page, agent_holder, scene="page", max_attempts=MAX_CAPTCHA_ATTEMPTS):
    """用 hcaptcha-challenger 自动解 hCaptcha（优化版）
    改进：
      1. 增加到10次尝试
      2. 自动切换Gemini Key
      3. 更好的错误恢复
      4. 增加随机延迟避免检测
    """
    import random
    holder = agent_holder.setdefault("token_holder", {})
    
    for attempt in range(1, max_attempts + 1):
        log(f"🔑 [{scene}] 解 hCaptcha ({attempt}/{max_attempts})...")

        # 已有 token 直接成功
        token = await get_token(page) or holder.get("token", "")
        if token:
            log(f"  ✅ 已有 token: {token[:25]}...")
            return True

        agent = agent_holder.get("agent")
        if agent is None:
            log("  ❌ Agent 未初始化")
            # 尝试重新初始化
            try:
                agent_holder["agent"] = await build_agent(page, 0)
                agent = agent_holder["agent"]
            except Exception as e:
                log(f"  ❌ Agent 初始化失败: {e}")
                return False

        crashed = False
        try:
            # 使用异步超时控制
            await asyncio.wait_for(
                agent.robotic_arm.click_checkbox(),
                timeout=30
            )
            signal = await agent.wait_for_challenge()
            if signal.name == "SUCCESS" or str(signal).endswith("SUCCESS"):
                log(f"  ✅ [{scene}] hCaptcha 挑战成功！")
                # 等页面 textarea 同步
                await asyncio.sleep(3)
                return True
            log(f"  ⚠️ [{scene}] 结果: {signal}")
        except asyncio.TimeoutError:
            crashed = True
            log(f"  ⚠️ [{scene}] 操作超时")
        except Exception as e:
            crashed = True
            err = str(e)
            log(f"  ⚠️ [{scene}] 异常: {err[:150]}")
            # 配额耗尽 → 自动换下一个 Key 重建 Agent
            if "429" in err or "RESOURCE_EXHAUSTED" in err or "quota" in err.lower():
                idx = (agent_holder.get("key_index", 0) + 1) % len(GEMINI_KEYS)
                log(f"  🔄 Key 配额耗尽，切换到第 {idx + 1} 个 Key...")
                agent_holder["key_index"] = idx
                try:
                    agent_holder["agent"] = await build_agent(page, idx)
                except Exception as e2:
                    log(f"  ❌ 切换Agent失败: {e2}")

        # 关键：库崩溃 ≠ 失败。答案可能已提交并在后台验证，等 token 落地
        log("  ⏳ 等待验证结果落地...")
        token = await wait_token(page, holder, timeout=CAPTCHA_TIMEOUT)
        if token:
            log(f"  ✅ [{scene}] hCaptcha 实际已通过！（拦截到token）")
            return True

        if not crashed and attempt < max_attempts:
            # 正常失败（如答案错误），刷新开新题
            try:
                await agent.robotic_arm.refresh_challenge()
                log("  🔄 已刷新挑战，开新题")
            except Exception:
                pass
                
        # 增加随机延迟，避免被检测
        await asyncio.sleep(random.uniform(3, 8))

    token = await get_token(page) or holder.get("token", "")
    if token:
        log(f"  ✅ [{scene}] 最终拿到 token")
        return True
    return False


async def site_login(page, agent_holder, email, password):
    log("🔐 登录目标站 ...")
    try:
        await page.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=60000)
        await asyncio.sleep(5)

        if await is_cf_page(page):
            log("⏳ Cloudflare 页面，尝试通过...")
            await wait_cf_pass(page, timeout=120)
            await asyncio.sleep(2)

        if await is_hcaptcha_present(page):
            ok = await solve_hcaptcha(page, agent_holder, "login")
            if not ok:
                await save_screenshot(page, "01_captcha_failed")
                return False, "登录页 hCaptcha 未解决"

        await save_screenshot(page, "01_login_loaded")

        # 尝试多种选择器
        email_selectors = ["#emailaddress", "#email", "input[type='email']", "input[name='email']"]
        pwd_selectors = ["#password", "input[type='password']", "input[name='password']"]
        
        email_filled = False
        for selector in email_selectors:
            try:
                email_el = page.locator(selector).first
                if await email_el.count() > 0:
                    await email_el.click()
                    await email_el.fill(email)
                    log(f"  ✅ 邮箱已填写 (使用选择器: {selector})")
                    email_filled = True
                    break
            except:
                continue
        
        if not email_filled:
            return False, "找不到邮箱输入框"

        pwd_filled = False
        for selector in pwd_selectors:
            try:
                pwd_el = page.locator(selector).first
                if await pwd_el.count() > 0:
                    await pwd_el.click()
                    await pwd_el.fill(password)
                    log("  ✅ 密码已填写")
                    pwd_filled = True
                    break
            except:
                continue
        
        if not pwd_filled:
            return False, "找不到密码输入框"

        await asyncio.sleep(1)
        await save_screenshot(page, "02_form_filled")

        # 点击登录按钮
        try:
            submit_selectors = ['button[type="submit"]', 'input[type="submit"]', 'button:has-text("Login")', 'button:has-text("Sign in")']
            clicked = False
            for selector in submit_selectors:
                submit = page.locator(selector).first
                if await submit.count() > 0:
                    await submit.click()
                    log(f"  → 已点击登录按钮 (选择器: {selector})")
                    clicked = True
                    break
            if not clicked:
                return False, "找不到登录按钮"
        except Exception as e:
            return False, f"提交失败: {str(e)[:100]}"

        await asyncio.sleep(6)

        # 检查是否需要二次验证
        if await is_hcaptcha_present(page):
            log("  🔍 提交后再次出现 hCaptcha")
            ok = await solve_hcaptcha(page, agent_holder, "login_callback")
            if ok:
                await asyncio.sleep(2)
                try:
                    # 再次点击提交按钮
                    submit = page.locator('button[type="submit"]').first
                    if await submit.count() > 0:
                        await submit.click()
                        log("  → 再次点击登录按钮")
                except Exception:
                    pass
                await asyncio.sleep(6)

        # 检查登录是否成功
        current = page.url.lower()
        if "connexion" in current or "login" in current:
            body = await page.inner_text("body")
            if "Projets" not in body and "Projects" not in body:
                await save_screenshot(page, "03_login_failed")
                # 尝试检查是否有错误消息
                error_text = ""
                try:
                    error_el = page.locator(".error, .alert-danger, .alert")
                    if await error_el.count() > 0:
                        error_text = await error_el.first.inner_text()
                except:
                    pass
                return False, f"登录失败: {error_text[:100]}"

        await save_screenshot(page, "03_login_success")
        log("  ✅ 登录成功")
        return True, None
        
    except Exception as e:
        log(f"❌ 登录异常: {e}")
        await save_screenshot(page, "login_error")
        return False, f"登录异常: {str(e)[:100]}"


async def extract_expire_info(page):
    expire_time, open_time = "", ""
    try:
        # 尝试多种选择器
        selectors = [
            'xpath=//strong[contains(text(),"Expires:")]/..',
            'xpath=//*[contains(text(),"Expires:")]',
            '.expiry-time, .expire-info'
        ]
        for selector in selectors:
            try:
                el = page.locator(selector).first
                if await el.count() > 0:
                    text = (await el.inner_text()).strip()
                    m1 = re.search(r'Expires:\s*(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2})', text)
                    if m1:
                        expire_time = m1.group(1)
                    m2 = re.search(r'opens in\s+(.+)', text)
                    if m2:
                        open_time = m2.group(1).strip()
                    if expire_time:
                        break
            except:
                continue
    except Exception:
        pass
    return expire_time, open_time


async def do_task(page, email):
    log("📋 进入项目管理页...")
    await page.goto(PROJECTS_URL, wait_until="domcontentloaded", timeout=60000)
    await asyncio.sleep(5)

    # 查找并点击 Manage 按钮
    manage_selectors = [
        'xpath=//a[contains(normalize-space(.),"Manage")]',
        'a:has-text("Manage")',
        'button:has-text("Manage")'
    ]
    
    try:
        clicked_manage = False
        for selector in manage_selectors:
            manage = page.locator(selector).first
            if await manage.count() > 0:
                href = await manage.get_attribute("href")
                log(f"  ✅ 找到 Manage: {href}")
                await manage.click()
                log("  ✅ 已点击 Manage")
                clicked_manage = True
                break
        
        if not clicked_manage:
            await save_screenshot(page, "04_no_manage")
            await send_tg_screenshot(page, "找不到 Manage 按钮")
            return False, "找不到 Manage 按钮"
    except Exception as e:
        await save_screenshot(page, "04_no_manage")
        await send_tg_screenshot(page, "找不到 Manage 按钮")
        return False, f"找不到 Manage: {str(e)[:100]}"

    await asyncio.sleep(5)
    await save_screenshot(page, "05_manage_page")

    # 查找任务按钮
    task_btn_selectors = [
        'xpath=//button[contains(.,"Renew")]',
        'button:has-text("Renew")',
        'button:has-text("Extend")'
    ]
    
    task_btn = None
    for selector in task_btn_selectors:
        try:
            btn = page.locator(selector).first
            if await btn.count() > 0:
                await btn.wait_for(state="visible", timeout=10000)
                task_btn = btn
                break
        except:
            continue
    
    if not task_btn:
        await save_screenshot(page, "05_no_task_btn")
        await send_tg_screenshot(page, "找不到目标按钮")
        return False, "目标按钮未找到"

    disabled = await task_btn.get_attribute("disabled")
    if disabled is not None:
        log("  ℹ️ 续期冷却中")
        expire_time, open_time = await extract_expire_info(page)
        msg = (f"🎉 Daily 续期\n🚀 [{mask_email(email)}] 冷却中\n"
               f"📅 过期时间: {expire_time}\n⏳ 开放剩余: {open_time}")
        send_tg(msg)
        await send_tg_screenshot(page, msg)
        return True, "冷却中"

    await task_btn.click()
    log("  ✅ 已点击续期按钮")
    await asyncio.sleep(6)

    # 确认结果
    log("  ⏳ 再次进入确认结果...")
    await page.goto(PROJECTS_URL, wait_until="domcontentloaded", timeout=60000)
    await asyncio.sleep(5)
    
    try:
        for selector in manage_selectors:
            manage = page.locator(selector).first
            if await manage.count() > 0:
                await manage.click()
                await asyncio.sleep(5)
                break
    except Exception:
        pass

    expire_time, open_time = await extract_expire_info(page)
    await save_screenshot(page, "06_task_done")
    msg = (f"🎉 Daily 续期\n🚀 [{mask_email(email)}] 续期成功✅\n"
           f"📅 服务器过期时间: {expire_time}\n⏳ 续期开放剩余: {open_time}")
    send_tg(msg)
    await send_tg_screenshot(page, msg)
    return True, "续期成功"


# ══════════════════════════════════════════════════════════
# 主流程（优化版）
# ══════════════════════════════════════════════════════════

async def run():
    account_raw = os.getenv("ACCOUNTS", "")
    if not account_raw:
        log("❌ 缺少 ACCOUNTS 环境变量")
        send_tg("❌ Task: 缺少 ACCOUNTS")
        return False
    try:
        email, password = parse_account(account_raw)
    except Exception as e:
        log(f"❌ {e}")
        return False

    if not GEMINI_KEYS:
        log("❌ 缺少 GEMINI_API_KEY 环境变量")
        send_tg("❌ Task: 缺少 GEMINI_API_KEY")
        return False
    log(f"🔑 已加载 {len(GEMINI_KEYS)} 个 Gemini Key（支持轮换）")

    log("=" * 55)
    log("🚀 Daily Task 自动任务 (Playwright+hcaptcha-challenger+Gemini)")
    log("=" * 55)

    # 任务级重试
    max_task_retries = 3
    for task_retry in range(max_task_retries):
        try:
            log(f"\n📋 任务运行 ({task_retry + 1}/{max_task_retries})")
            
            proxy_server = start_proxy()

            from playwright.async_api import async_playwright

            agent_holder = {"agent": None, "key_index": 0}

            async with async_playwright() as p:
                launch_kwargs = {
                    "headless": True,
                    "args": [
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-blink-features=AutomationControlled",
                        "--disable-web-security",
                        "--disable-features=IsolateOrigins,site-per-process",
                    ],
                }
                if proxy_server:
                    launch_kwargs["proxy"] = {"server": proxy_server}

                browser = await p.chromium.launch(**launch_kwargs)
                context = await browser.new_context(
                    viewport={"width": 1280, "height": 900},
                    ignore_https_errors=True,
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                )
                page = await context.new_page()

                # 出口 IP 确认
                try:
                    await page.goto(IPTEST_URL, timeout=30000)
                    ip = (await page.inner_text("body")).strip()
                    log(f"✅ 浏览器出口 IP: {ip}")
                except Exception as e:
                    log(f"⚠️ 获取出口 IP 失败: {e}")

                # 初始化 hcaptcha-challenger
                agent_holder["agent"] = await build_agent(page, 0)
                # 安装 token 监听器
                install_token_listener(page, agent_holder.setdefault("token_holder", {}))
                log(f"🤖 hcaptcha-challenger Agent 就绪 ({len(GEMINI_KEYS)} keys)")

                try:
                    ok, reason = await site_login(page, agent_holder, email, password)
                    if not ok:
                        log(f"❌ 登录失败: {reason}")
                        send_tg(f"❌ Task 登录失败: {reason}")
                        await send_tg_screenshot(page, "登录失败")
                        # 如果是验证码问题，等待后重试
                        if "hCaptcha" in reason and task_retry < max_task_retries - 1:
                            wait_time = 60 * (task_retry + 1)
                            log(f"⏳ 等待 {wait_time} 秒后重试...")
                            await asyncio.sleep(wait_time)
                            continue
                        return False

                    await send_tg_screenshot(page, "✅ 登录成功")
                    ok2, reason2 = await do_task(page, email)
                    log(f"{'✅' if ok2 else '❌'} {reason2}")
                    
                    if ok2:
                        return True
                    elif task_retry < max_task_retries - 1:
                        wait_time = 30 * (task_retry + 1)
                        log(f"⏳ 任务失败，等待 {wait_time} 秒后重试...")
                        await asyncio.sleep(wait_time)
                    else:
                        return False
                        
                except Exception as e:
                    log(f"❌ 运行异常: {e}")
                    send_tg(f"❌ Task 异常: {str(e)[:200]}")
                    try:
                        await send_tg_screenshot(page, "error")
                    except Exception:
                        pass
                    
                    if task_retry < max_task_retries - 1:
                        wait_time = 60 * (task_retry + 1)
                        log(f"⏳ 异常后等待 {wait_time} 秒重试...")
                        await asyncio.sleep(wait_time)
                    else:
                        return False
                finally:
                    await browser.close()
                    
        except Exception as e:
            log(f"❌ 任务级异常: {e}")
            if task_retry < max_task_retries - 1:
                await asyncio.sleep(30 * (task_retry + 1))
            else:
                return False
    
    return False


def main():
    result = asyncio.run(run())
    exit(0 if result else 1)


if __name__ == "__main__":
    main()
