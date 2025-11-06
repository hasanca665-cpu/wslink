
import os
import re
import json
import uuid
import shutil
import random
import hashlib
import hmac
from dataclasses import dataclass, asdict, field
from typing import Dict, Any, Optional, List, Tuple
from http.cookiejar import MozillaCookieJar
import aiohttp
import aiofiles
import asyncio
from datetime import datetime, timezone, timedelta
import logging
from telegram import Update, ReplyKeyboardMarkup, KeyboardButton, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes, CallbackQueryHandler
from telegram.error import NetworkError, BadRequest
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import time
import base64
import socket
import requests
import pytz
import threading
from collections import defaultdict
from datetime import datetime, timedelta

# ---------- Utilities ----------
def _luhn_checksum(number: str) -> int:
    def digits_of(n): return [int(d) for d in n]
    digits = digits_of(number)
    odd = digits[-1::-2]
    even = digits[-2::-2]
    total = sum(odd)
    for d in even:
        d2 = d * 2
        total += d2 if d2 < 10 else d2 - 9
    return total % 10

def generate_imei(seed: str) -> str:
    tacs = ["358240", "352099", "356938", "353918", "357805", "355031", "354859"]
    tac = random.Random(seed).choice(tacs)
    rnd = random.Random(seed + "imei")
    snr = "".join(str(rnd.randrange(0, 10)) for _ in range(8))
    partial = tac + snr
    checksum = _luhn_checksum(partial + "0")
    check_digit = (10 - checksum) % 10
    return partial + str(check_digit)

def generate_android_id(seed: str) -> str:
    rnd = random.Random(seed + "android")
    return "".join(rnd.choice("0123456789abcdef") for _ in range(16))

def generate_mac(seed: str) -> str:
    rnd = random.Random(seed + "mac")
    first = rnd.randrange(0, 256) | 0b00000010
    mac_bytes = [first] + [rnd.randrange(0, 256) for _ in range(5)]
    return ":".join(f"{b:02X}" for b in mac_bytes)

def generate_device_seed(name: str) -> str:
    base = f"{name}::{uuid.uuid5(uuid.NAMESPACE_DNS, name)}"
    return hashlib.sha256(base.encode()).hexdigest()

def stable_hash(seed: str, *parts: str, length: int = 32) -> str:
    msg = "||".join(parts)
    h = hmac.new(seed.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return h[:length]

def random_hex(length):
    return ''.join(random.choice('0123456789abcdef') for _ in range(length))

def get_bd_timezone_locale():
    tz = "Asia/Dhaka"
    tz_offset = int(datetime.now(pytz.timezone(tz)).utcoffset().total_seconds()/3600)
    locale = "bn_BD"
    language = "bn"
    return tz, tz_offset, locale, language

def get_device_network_info():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "127.0.0.1"

    try:
        r = requests.get("https://ipinfo.io/json").json()
        public_ip = r.get("ip", local_ip)
        isp = r.get("org", "Unknown ISP")
        asn = r.get("asn", "Unknown ASN")
        hostname = r.get("hostname", socket.gethostname())
    except:
        public_ip = local_ip
        isp = "Unknown ISP"
        asn = "Unknown ASN"
        hostname = socket.gethostname()

    return {
        "local_ip": local_ip,
        "public_ip": public_ip,
        "hostname": hostname,
        "isp": isp,
        "asn": asn,
        "proxy": None,
        "type": "real_device"
    }

def generate_behavior():
    return {
        "typing_speed_ms": random.randint(80,250),
        "click_delay_ms": random.randint(100,500),
        "scroll_speed_px": random.randint(200,1000)
    }

def generate_installed_apps():
    common_apps = ["WhatsApp", "Gmail", "YouTube", "Chrome", "Facebook", "Instagram", "Camera"]
    return random.sample(common_apps, random.randint(3, len(common_apps)))

@dataclass
class DeviceProfile:
    name: str
    seed: str
    device_id: str
    android_id: str
    imei: str
    mac_wifi: str
    ua: str
    canvas_fp: str
    audio_fp: str
    battery: Dict[str, Any]
    screen: Dict[str, Any]
    sensors: List[str]
    installed_apps: List[str]
    storage: Dict[str, Any]
    timezone: str
    utc_offset_hours: float
    locale: str
    language: str
    network: Dict[str, Any]
    behavior: Dict[str, Any]
    created_at: str
    proxy: Optional[Dict[str, str]] = None  # নতুন ফিল্ড: প্রক্সি তথ্য

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "DeviceProfile":
        return DeviceProfile(**d)

# ---------- Manager ----------
class DeviceProfileManager:
    def __init__(self, base_dir: str = "devices"):
        self.base_dir = base_dir
        os.makedirs(self.base_dir, exist_ok=True)

    def _profile_path(self, name: str) -> str:
        safe = re.sub(r"[^a-zA-Z0-9_\-\.]+", "_", name)
        return os.path.join(self.base_dir, f"{safe}.json")

    def _cookie_path(self, name: str) -> str:
        safe = re.sub(r"[^a-zA-Z0-9_\-\.]+", "_", name)
        return os.path.join(self.base_dir, f"{safe}.cookies.txt")

    def exists(self, name: str) -> bool:
        return os.path.exists(self._profile_path(name))

    def load(self, name: str) -> DeviceProfile:
        with open(self._profile_path(name), "r", encoding="utf-8") as f:
            data = json.load(f)
        return DeviceProfile.from_dict(data)

    def save(self, profile: DeviceProfile) -> None:
        with open(self._profile_path(profile.name), "w", encoding="utf-8") as f:
            json.dump(profile.to_dict(), f, ensure_ascii=False, indent=2)

    async def create(self, name: str) -> DeviceProfile:
        seed = generate_device_seed(name + str(uuid.uuid4()))
        tz, tz_offset, locale, language = get_bd_timezone_locale()
        net_info = get_device_network_info()

        used_devices = load_used_devices()
        while True:
            device_id = stable_hash(seed, "device", length=32)
            if device_id not in used_devices:
                break
            seed = generate_device_seed(name + str(uuid.uuid4()))

        user_agents = await load_user_agents_from_file()
        if not user_agents:
            user_agents = ANDROID_UAS
        ua = random.choice(user_agents)

        profile = DeviceProfile(
            name=name,
            seed=seed,
            device_id=device_id,
            android_id=generate_android_id(seed),
            imei=generate_imei(seed),
            mac_wifi=generate_mac(seed),
            ua=ua,
            canvas_fp=stable_hash(seed, ua, "canvas", length=40),
            audio_fp=stable_hash(seed, ua, "audio", length=40),
            battery={
                "level": random.randint(20,100),
                "charging": random.choice([True, False])
            },
            screen={
                "width": random.choice([1080, 1440, 1600, 2160]),
                "height": random.choice([1920, 2340, 3200, 3840]),
                "density": random.choice([2.5, 3, 3.5])
            },
            sensors=random.sample(["accelerometer", "gyroscope", "magnetometer", "light", "proximity"], random.randint(3,5)),
            installed_apps=generate_installed_apps(),
            storage={},
            timezone=tz,
            utc_offset_hours=tz_offset,
            locale=locale,
            language=language,
            network=net_info,
            behavior=generate_behavior(),
            created_at=datetime.now().isoformat()
        )
        await save_used_device(device_id)
        self.save(profile)
        cj = MozillaCookieJar(self._cookie_path(name))
        cj.save(ignore_discard=True, ignore_expires=True)
        return profile

    def reset_all(self):
        if os.path.exists(self.base_dir):
            shutil.rmtree(self.base_dir)
        os.makedirs(self.base_dir, exist_ok=True)
        # used_devices.json ডিলিট করা হবে না

    async def create_new_device(self, user_tag: str) -> DeviceProfile:
        return await self.create(user_tag)

    async def set_proxy(self, name: str, proxy_string: str) -> bool:
        proxy = parse_proxy_string(proxy_string)
        if not proxy:
            return False
        profile = self.load(name)
        profile.proxy = proxy
        self.save(profile)
        logger.info(f"Proxy set for device {name}: {proxy['host']}:{proxy['port']}")
        return True

    async def auto_set_proxy(self, name: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        """
        Automatically select and set a proxy from proxies.txt for the given device profile.
        Returns (success, proxy_info, message).
        """
        proxy_string = await select_random_proxy()
        if not proxy_string:
            return False, None, "No valid proxies found in proxies.txt."
        
        success = await self.set_proxy(name, proxy_string)
        if not success:
            return False, None, "Invalid proxy format in proxies.txt."
        
        profile = self.load(name)
        proxy_info = await fetch_proxy_info(profile.proxy)
        if not proxy_info.get("success"):
            return False, None, f"Failed to connect to proxy: {proxy_info.get('error')}"
        
        logger.info(f"Automatically set proxy for device {name}: {proxy_string}")
        return True, proxy_info, "Proxy set successfully!"

    async def build_session(self, name: str) -> aiohttp.ClientSession:
        profile = self.load(name)
        headers = {
            "User-Agent": profile.ua,
            "X-Device-ID": profile.device_id,
            "X-Android-ID": profile.android_id,
            "X-IMEI": profile.imei,
            "X-Canvas-FP": profile.canvas_fp,
            "X-Audio-FP": profile.audio_fp
        }
        if profile.proxy:
            proxy_url = f"http://{profile.proxy['username']}:{profile.proxy['password']}@{profile.proxy['host']}:{profile.proxy['port']}"
            session = aiohttp.ClientSession(headers=headers, connector=aiohttp.TCPConnector(ssl=False), proxy=proxy_url)
        else:
            session = aiohttp.ClientSession(headers=headers, connector=aiohttp.TCPConnector(ssl=False))
        return session

def parse_proxy_string(proxy_string: str) -> Optional[Dict[str, str]]:
    try:
        parts = proxy_string.split(':')
        if len(parts) != 4:
            raise ValueError("Invalid proxy format. Expected format: host:port:username:password")
        host, port, username, password = parts
        if not host or not port.isdigit() or not username or not password:
            raise ValueError("Invalid proxy components")
        return {
            "host": host,
            "port": port,
            "username": username,
            "password": password
        }
    except Exception as e:
        logger.error(f"Error parsing proxy string: {str(e)}")
        return None

async def fetch_proxy_info(proxy: Dict[str, str]) -> Dict[str, Any]:
    try:
        proxy_url = f"http://{proxy['username']}:{proxy['password']}@{proxy['host']}:{proxy['port']}"
        async with aiohttp.ClientSession() as session:
            async with session.get("https://ipinfo.io/json", proxy=proxy_url, timeout=10) as response:
                if response.status != 200:
                    return {"success": False, "error": f"HTTP {response.status}"}
                data = await response.json()
                return {
                    "success": True,
                    "public_ip": data.get("ip", "Unknown"),
                    "location": {
                        "country": data.get("country", "Unknown"),
                        "region": data.get("region", "Unknown"),
                        "city": data.get("city", "Unknown"),
                        "zip_code": data.get("postal", "Unknown"),
                        "latitude": data.get("loc", "").split(",")[0] if data.get("loc") else "Unknown",
                        "longitude": data.get("loc", "").split(",")[1] if data.get("loc") else "Unknown",
                        "timezone": data.get("timezone", "Unknown")
                    },
                    "network": {
                        "isp": data.get("org", "Unknown"),
                        "organization": data.get("org", "Unknown"),
                        "as_number": data.get("asn", "Unknown"),
                        "proxy_vpn": data.get("vpn", False),
                        "hosting": data.get("hosting", False)
                    }
                }
    except Exception as e:
        logger.error(f"Error fetching proxy info: {str(e)}")
        return {"success": False, "error": str(e)}

async def load_proxies_from_file():
    proxy_file = "proxies.txt"
    proxies = []
    try:
        async with aiofiles.open(proxy_file, 'r') as f:
            async for line in f:
                proxy_string = line.strip()
                if proxy_string and parse_proxy_string(proxy_string):
                    proxies.append(proxy_string)
        logger.info(f"Loaded {len(proxies)} valid proxies from {proxy_file}")
        return proxies
    except Exception as e:
        logger.error(f"Error loading proxies from {proxy_file}: {str(e)}")
        return []

async def select_random_proxy():
    proxies = await load_proxies_from_file()
    if not proxies:
        return None
    return random.choice(proxies)

# Constants
KEY = b'djchdnfkxnjhgvuy'
IV = b'ayghjuiklobghfrt'
TELEGRAM_TOKEN = "7390288812:AAGsGZriy4dprHYmQoRUZltMCmvTUitpz4I"
ADMIN_ID = 5624278091
TOKEN_FILE = "tokens.json"
USER_STATUS_FILE = "user_status.json"
USER_AGENTS_FILE = "user_agents.json"  # Legacy
USED_USER_AGENTS_FILE = "used_user_agents.json"  # Legacy
DEVICE_HISTORY_FILE = "device_history.json"  # Legacy
REQUEST_TIMEOUT = 8
MAX_RETRIES = 3
MAX_CODE_ATTEMPTS = 10
CODE_CHECK_INTERVAL = 2
# Balance system files
NUMBER_TRACKING_FILE = "number_tracking.json"
BALANCE_CONFIG_FILE = "balance_config.json"
USER_BALANCES_FILE = "user_balances.json"
WITHDRAWAL_REQUESTS_FILE = "withdrawal_requests.json"
DAILY_STATS_FILE = "daily_stats.json"
REGISTRATION_FILE = "registration_data.txt"
ANDROID_UAS = [
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Xiaomi 14 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; SM-N986B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; OnePlus 11R) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-F731B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Moto G84) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36"
]

# Website configurations
WEBSITE_CONFIGS = {
    "TASK 1": {
        "name": "TASK 1",
        "api_domain": "https://diy22.club/",
        "origin": "https://diy22.net",
        "referer": "https://diy22.net/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/ws_phone/sendCode",
        "get_code_path": "api/ws_phone/getCode",
        "phone_list_url": "https://diy22.club/api/ws_phone/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code"
    },"TASK 2": {
        "name": "TASK 2",
        "api_domain": "https://sms323.club/",
        "origin": "https://sms323.com",
        "referer": "https://sms323.com/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/ws_phone/sendCode",
        "get_code_path": "api/ws_phone/getCode",
        "phone_list_url": "https://sms323.club/api/ws_phone/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code"
    },"TASK 3": {
        "name": "TASK 3",
        "api_domain": "https://ok8job.cc/",
        "origin": "https://www.ok8job.net",
        "referer": "https://www.ok8job.net/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/ws_phone/sendCode",
        "get_code_path": "api/ws_phone/getCode",
        "phone_list_url": "https://ok8job.cc/api/ws_phone/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code"
    },"TASK 4": {
        "name": "TASK 4",
        "api_domain": "https://tg377.club/",
        "origin": "https://tg377.vip",
        "referer": "https://tg377.vip/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/ws_phone/sendCode",
        "get_code_path": "api/ws_phone/getCode",
        "phone_list_url": "https://tg377.club/api/ws_phone/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code"
    },
    "TASK 5": {
        "name": "TASK 5",
        "api_domain": "https://sms323.club/",
        "origin": "https://sms323.com",
        "referer": "https://sms323.com/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/ws_phone/sendCode",
        "get_code_path": "api/ws_phone/getCode",
        "phone_list_url": "https://sms323.club/api/ws_phone/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code"
    },
    "TASK 6": {
        "name": "TASK 6",
        "api_domain": "https://diy22.club/",
        "origin": "https://diy22.net",
        "referer": "https://diy22.net/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/ws_phone/sendCode",
        "get_code_path": "api/ws_phone/getCode",
        "phone_list_url": "https://diy22.club/api/ws_phone/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code"
    }
}

# Fixed headers for consistency
ACCEPT_LANGUAGE = "en-US,en;q=0.9"
SEC_CH_UA_PLATFORM = '"Android"'
SEC_CH_UA_LIST = [
    '"Not)A;Brand";v="99", "Chromium";v="113", "Google Chrome";v="113"',
    '"Not)A;Brand";v="24", "Chromium";v="119", "UCBrowser";v="16.8"',
    '"Not)A;Brand";v="8", "Chromium";v="111", "Google Chrome";v="111"',
]
SEC_CH_UA_MOBILE = "?1"
DEFAULT_SELECTED_WEBSITE = "Main"

# Randomization for headers to reduce fingerprinting
def get_random_accept_encoding():
    encodings = [
        "gzip, deflate",
        "gzip, deflate, br",
        "gzip, deflate, br, zstd",
        "deflate, br"
    ]
    return random.choice(encodings)

def get_random_sec_fetch_headers():
    sites = ["none", "same-origin", "same-site", "cross-site"]
    modes = ["cors", "navigate", "no-cors"]
    dests = ["empty", "document", "object"]
    return {
        "sec-fetch-site": random.choice(sites),
        "sec-fetch-mode": random.choice(modes),
        "sec-fetch-dest": random.choice(dests)
    }

def get_random_priority():
    priorities = ["u=0", "u=1", "u=1, i"]
    return random.choice(priorities)


class AutoNumberMonitor:
    def __init__(self, application):
        self.application = application
        self.user_tasks = {}  # user_id -> task
        self.user_data = {}   # user_id -> monitoring data
        self.lock = asyncio.Lock()
        self.is_running = True
        logger.info("🔄 New AutoNumberMonitor initialized - 100% working version")
    
    async def start_monitoring(self, user_id: int, website: str, token: str, device_name: str):
        """নতুন এবং সহজ মনিটরিং সিস্টেম - ১০০% কাজ করবে"""
        user_id_str = str(user_id)
        
        async with self.lock:
            # যদি আগে থেকে মনিটরিং চলছে, বন্ধ করুন
            if user_id_str in self.user_tasks:
                try:
                    self.user_tasks[user_id_str].cancel()
                    await asyncio.sleep(1)
                    del self.user_tasks[user_id_str]
                except Exception as e:
                    logger.error(f"Error stopping previous monitoring: {e}")
            
            # নতুন ইউজার ডেটা সেট করুন
            self.user_data[user_id_str] = {
                'website': website,
                'token': token,
                'device_name': device_name,
                'last_check': datetime.now().isoformat(),
                'is_active': True,
                'processed_numbers': set()
            }
            
            # নতুন টাস্ক শুরু করুন
            self.user_tasks[user_id_str] = asyncio.create_task(
                self._simple_monitor_loop(user_id, website, token, device_name)
            )
            
            logger.info(f"🚀 NEW MONITORING started for user {user_id} on {website}")
            return True
    
    async def stop_monitoring(self, user_id: int):
        """মনিটরিং বন্ধ করুন"""
        user_id_str = str(user_id)
        
        async with self.lock:
            if user_id_str in self.user_tasks:
                try:
                    self.user_tasks[user_id_str].cancel()
                    await asyncio.sleep(0.5)
                except Exception as e:
                    logger.error(f"Error cancelling task: {e}")
                
                # ক্লিনআপ
                if user_id_str in self.user_tasks:
                    del self.user_tasks[user_id_str]
                if user_id_str in self.user_data:
                    self.user_data[user_id_str]['is_active'] = False
                
                logger.info(f"🛑 Monitoring stopped for user {user_id}")
                return True
            
            return False
    
    async def _simple_monitor_loop(self, user_id: int, website: str, token: str, device_name: str):
        """সরল এবং নির্ভরযোগ্য মনিটরিং লুপ"""
        user_id_str = str(user_id)
        website_config = WEBSITE_CONFIGS.get(website, WEBSITE_CONFIGS.get("TASK 3"))
        
        logger.info(f"🔄 Simple monitor loop started for user {user_id} on {website}")
        
        try:
            while True:
                try:
                    # 30 সেকেন্ড অপেক্ষা করুন
                    await asyncio.sleep(30)
                    
                    # ইউজার ডেটা চেক করুন
                    if user_id_str not in self.user_data or not self.user_data[user_id_str].get('is_active', True):
                        logger.info(f"Monitoring stopped for user {user_id} - exiting loop")
                        break
                    
                    # ফোন লিস্ট ফেচ করুন
                    current_online = await self._fetch_simple_phone_list(user_id, website, token, device_name)
                    if current_online is None:
                        continue
                    
                    # শেষ চেক টাইম আপডেট করুন
                    self.user_data[user_id_str]['last_check'] = datetime.now().isoformat()
                    
                    # নতুন নাম্বার প্রসেস করুন
                    if current_online:
                        await self._process_simple_numbers(user_id, website, current_online)
                    
                except asyncio.CancelledError:
                    logger.info(f"Monitoring cancelled for user {user_id}")
                    break
                except Exception as e:
                    logger.error(f"Error in simple monitor loop for user {user_id}: {str(e)}")
                    await asyncio.sleep(10)  # ত্রুটি হলে 10 সেকেন্ড অপেক্ষা করুন
        
        except Exception as e:
            logger.error(f"Monitor loop crashed for user {user_id}: {str(e)}")
        finally:
            # ক্লিনআপ
            async with self.lock:
                if user_id_str in self.user_tasks:
                    try:
                        del self.user_tasks[user_id_str]
                    except:
                        pass
            logger.info(f"✅ Monitor loop exited for user {user_id}")
    
    async def _fetch_simple_phone_list(self, user_id: int, website: str, token: str, device_name: str):
        """সরল ফোন লিস্ট ফেচিং"""
        user_id_str = str(user_id)
        website_config = WEBSITE_CONFIGS.get(website, WEBSITE_CONFIGS.get("TASK 3"))
        
        try:
            async with await device_manager.build_session(device_name) as session:
                headers = {
                    'Accept': 'application/json, text/plain, */*',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'token': token,
                    'Origin': website_config.get('origin', ''),
                    'Referer': website_config.get('referer', ''),
                    'X-Requested-With': 'mark.via.gp',
                    "accept-language": "en-US,en;q=0.9",
                    "sec-ch-ua": '"Not)A;Brand";v="99", "Chromium";v="113", "Google Chrome";v="113"',
                    "sec-ch-ua-mobile": "?1",
                    "sec-ch-ua-platform": '"Android"',
                    "sec-fetch-site": "cross-site",
                    "sec-fetch-mode": "cors",
                    "sec-fetch-dest": "empty",
                    "priority": "u=1, i"
                }

                async with asyncio.timeout(REQUEST_TIMEOUT):
                    async with session.post(website_config['phone_list_url'], headers=headers) as response:
                        if response.status != 200:
                            logger.error(f"Phone list API returned status {response.status} for user {user_id}")
                            return None

                        data = await response.json()
                        if data.get("code") != 1:
                            logger.error(f"Phone list API error for user {user_id}: {data.get('msg', 'Unknown error')}")
                            return None

                        phones = data.get("data", []) or []
                        online_numbers = set()
                        
                        for phone_data in phones:
                            phone_raw = str(phone_data.get("phone", ""))
                            status = int(phone_data.get("status", 0))
                            
                            if status == 1 and len(phone_raw) >= 10:
                                # নাম্বার নরমালাইজ করুন
                                if phone_raw.startswith('1') and len(phone_raw) == 11:
                                    phone = "+" + phone_raw
                                elif len(phone_raw) == 10:
                                    phone = "+1" + phone_raw
                                else:
                                    phone = "+" + phone_raw
                                
                                online_numbers.add(phone)

                        logger.info(f"📱 Fetched {len(online_numbers)} online numbers for user {user_id}")
                        return online_numbers

        except asyncio.TimeoutError:
            logger.error(f"Phone list timeout for user {user_id}")
            return None
        except Exception as e:
            logger.error(f"Error fetching phone list for user {user_id}: {str(e)}")
            return None
            
            
            
async def _process_simple_numbers(self, user_id: int, website: str, online_numbers: set):
    """সরল নাম্বার প্রসেসিং - COMPLETE MULTI-ACCOUNT সাপোর্ট"""
    user_id_str = str(user_id)
    
    if user_id_str not in self.user_data:
        return
    
    processed = self.user_data[user_id_str].get('processed_numbers', set())
    new_numbers = online_numbers - processed
    
    if not new_numbers:
        return
    
    logger.info(f"🎉 Found {len(new_numbers)} new online numbers for user {user_id}")
    
    for phone in new_numbers:
        try:
            # রেস্ট্রিকশন চেক করুন
            if not number_tracker.can_submit_number(phone, user_id, website):
                logger.info(f"⏳ Number {phone} restricted for user {user_id} - skipping")
                continue
            
            # ✅ MULTI-ACCOUNT: পরবর্তী অ্যাকাউন্টে সুইচ করুন
            next_token = multi_account_manager.get_next_account_token(website)
            
            if next_token:
                # নতুন টোকেন সেভ করুন
                await save_token(user_id, 'main', next_token, website)
                
                # মনিটরিং আপডেট করুন
                self.user_data[user_id_str]['token'] = next_token
                
                current_info = multi_account_manager.get_current_account_info(website)
                if current_info:
                    logger.info(f"🔄 Auto-switched to account: {current_info['username']}")
            
            # ব্যালেন্স যোগ করুন
            result = balance_manager.add_online_number(user_id, website, phone)
            
            # রেস্ট্রিকশন রেকর্ড করুন
            number_tracker.record_number_submission(phone, user_id, website)
            
            # প্রসেসড লিস্টে যোগ করুন
            processed.add(phone)
            self.user_data[user_id_str]['processed_numbers'] = processed
            
            # নোটিফিকেশন পাঠান (অ্যাকাউন্ট ইনফো সহ)
            await self._send_multi_account_notification(user_id, website, phone, result)
            
            logger.info(f"💰 Balance added for user {user_id}: +{result.get('balance_added')} for {phone}")
            
        except Exception as e:
            logger.error(f"Error processing phone {phone} for user {user_id}: {e}")

async def _send_multi_account_notification(self, user_id: int, website: str, phone: str, result: dict):
    """মাল্টি-অ্যাকাউন্ট নোটিফিকেশন"""
    try:
        user_stats = balance_manager.get_user_stats(user_id)
        current_account = multi_account_manager.get_current_account_info(website)
        
        if user_stats and current_account:
            notification_msg = (
                f"🎉 **নতুন নাম্বার অনলাইন!**\n\n"
                f"📱 নাম্বার: `{phone}`\n"
                f"💰 যোগ হয়েছে: {result.get('balance_added', 0)} BDT\n"
                f"💵 মোট ব্যালেন্স: {user_stats['total_balance']} BDT\n"
                f"📊 আজকের অনলাইন: {user_stats['today_count']} টি\n"
                f"🌐 Task: {website}\n"
                f"👤 অ্যাকাউন্ট: {current_account['username']} ({current_account['index'] + 1}/{current_account['total_accounts']})\n\n"
                f"✅ স্বয়ংক্রিয়ভাবে ব্যালেন্স যোগ করা হয়েছে।"
            )
        else:
            notification_msg = f"🎉 নতুন নাম্বার অনলাইন: {phone} (Task: {website})"

        await self.application.bot.send_message(
            user_id,
            notification_msg,
            parse_mode='Markdown'
        )
        logger.info(f"📨 Multi-account notification sent to user {user_id}")
        
    except Exception as e:
        logger.error(f"❌ Failed to send multi-account notification: {e}")
    
    async def _send_simple_notification(self, user_id: int, website: str, phone: str, result: dict):
        """সরল নোটিফিকেশন সিস্টেম"""
        try:
            user_stats = balance_manager.get_user_stats(user_id)
            if user_stats:
                notification_msg = (
                    f"🎉 **নতুন নাম্বার অনলাইন!**\n\n"
                    f"📱 নাম্বার: `{phone}`\n"
                    f"💰 যোগ হয়েছে: {result.get('balance_added', 0)} BDT\n"
                    f"💵 মোট ব্যালেন্স: {user_stats['total_balance']} BDT\n"
                    f"📊 আজকের অনলাইন: {user_stats['today_count']} টি\n"
                    f"🌐 Task: {website}\n\n"
                    f"✅ স্বয়ংক্রিয়ভাবে ব্যালেন্স যোগ করা হয়েছে।"
                )
            else:
                notification_msg = f"🎉 নতুন নাম্বার অনলাইন: {phone} (Task: {website})"

            await self.application.bot.send_message(
                user_id,
                notification_msg,
                parse_mode='Markdown'
            )
            logger.info(f"📨 Notification sent to user {user_id} for {phone}")
            
        except Exception as e:
            logger.error(f"❌ Failed to send notification to user {user_id}: {e}")
    
    def is_user_monitoring(self, user_id: int):
        """চেক করুন ইউজার মনিটরিং করছে কিনা"""
        user_id_str = str(user_id)
        return user_id_str in self.user_tasks and user_id_str in self.user_data and self.user_data[user_id_str].get('is_active', False)
    
    def get_monitoring_status(self, user_id: int):
        """মনিটরিং স্ট্যাটাস রিটার্ন করুন"""
        user_id_str = str(user_id)
        if user_id_str in self.user_data:
            data = self.user_data[user_id_str]
            return {
                'website': data['website'],
                'device': data['device_name'],
                'last_check': data['last_check'],
                'is_running': self.is_user_monitoring(user_id)
            }
        return None
    
    async def stop_all_monitoring(self):
        """সব মনিটরিং বন্ধ করুন"""
        async with self.lock:
            user_ids = list(self.user_tasks.keys())
            for user_id_str in user_ids:
                try:
                    user_id = int(user_id_str)
                    await self.stop_monitoring(user_id)
                except Exception as e:
                    logger.error(f"Error stopping monitoring for user {user_id_str}: {e}")
            
            logger.info("🛑 All monitoring stopped")
    
    def get_all_monitoring_users(self):
        """সব মনিটরিং ইউজার লিস্ট রিটার্ন করুন"""
        return list(self.user_data.keys())


# Number tracking system


class NumberTracking:
    def __init__(self):
        self.tracking_data = {}
        self.load_data()
    
    def load_data(self):
        try:
            if os.path.exists(NUMBER_TRACKING_FILE):
                with open(NUMBER_TRACKING_FILE, 'r', encoding='utf-8') as f:
                    self.tracking_data = json.load(f)
        except Exception as e:
            logger.error(f"Error loading number tracking data: {str(e)}")
            self.tracking_data = {}
    
    def save_data(self):
        try:
            tmp = NUMBER_TRACKING_FILE + ".tmp"
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(self.tracking_data, f, indent=4, ensure_ascii=False)
            os.replace(tmp, NUMBER_TRACKING_FILE)
        except Exception as e:
            logger.error(f"Error saving number tracking data: {str(e)}")
    
    def can_submit_number(self, phone_number: str, user_id: int, website: str) -> bool:
        """চেক করুন যে ইউজার এই নাম্বারটি এই টাস্কে ২৪ ঘন্টার মধ্যে submit করতে পারবে কিনা"""
        user_id_str = str(user_id)
        
        if user_id_str not in self.tracking_data:
            return True
        
        user_data = self.tracking_data[user_id_str]
        
        # ✅ FIXED: টাস্ক-ওয়াইজ চেক করুন
        tracking_key = f"{website}_{phone_number}"
        
        if tracking_key not in user_data:
            return True
        
        last_submit_time = user_data[tracking_key]
        current_time = time.time()
        
        # ২৪ ঘন্টা (86400 সেকেন্ড) অপেক্ষা করতে হবে
        if current_time - last_submit_time >= 86400:
            # সময় পার হয়ে গেলে রেকর্ড ডিলিট করুন
            del self.tracking_data[user_id_str][tracking_key]
            self.save_data()
            return True
        
        return False
    
    def record_number_submission(self, phone_number: str, user_id: int, website: str):
        """নাম্বার successfulভাবে online হলে টাস্ক-ওয়াইজ রেকর্ড রাখো (synchronous + atomic save)"""
        user_id_str = str(user_id)

        if user_id_str not in self.tracking_data:
            self.tracking_data[user_id_str] = {}

        tracking_key = f"{website}_{phone_number}"
        self.tracking_data[user_id_str][tracking_key] = time.time()

        # Save immediately (atomic)
        try:
            self.save_data()
            logger.info(f"Number {phone_number} restricted for user {user_id_str} on {website} for 24 hours")
        except Exception as e:
            logger.error(f"Failed to save tracking after recording {phone_number}: {e}")
    
    def get_remaining_time(self, phone_number: str, user_id: int, website: str) -> int:
        """কত সময় বাকি আছে তা রিটার্ন করুন (সেকেন্ডে) - টাস্ক-ওয়াইজ"""
        user_id_str = str(user_id)
        
        tracking_key = f"{website}_{phone_number}"
        
        if user_id_str not in self.tracking_data or tracking_key not in self.tracking_data[user_id_str]:
            return 0
        
        last_submit_time = self.tracking_data[user_id_str][tracking_key]
        current_time = time.time()
        elapsed = current_time - last_submit_time
        remaining = 86400 - elapsed
        
        
        
        return max(0, int(remaining))

number_tracker = NumberTracking()






class BalanceManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.balance_config = {}
        self.user_balances = {}
        self.withdrawal_requests = {}
        self.daily_stats = {}
        self.monthly_stats = {}
        self.load_data()
    
    def load_data(self):
        """সকল ডেটা ফাইল লোড করুন"""
        try:
            # Balance config লোড
            if os.path.exists(BALANCE_CONFIG_FILE):
                with open(BALANCE_CONFIG_FILE, 'r', encoding='utf-8') as f:
                    self.balance_config = json.load(f)
            else:
                self.balance_config = {
                    "balance_per_online": 0.50, 
                    "admin_id": 5624278091,
                    "min_withdrawal": 50.0,
                    "auto_reset_daily": False,
                    "income_percentage": 100  # নতুন ফিচার: ইনকাম পার্সেন্টেজ
                }
            
            # User balances লোড
            if os.path.exists(USER_BALANCES_FILE):
                with open(USER_BALANCES_FILE, 'r', encoding='utf-8') as f:
                    self.user_balances = json.load(f)
            else:
                self.user_balances = {}
            
            # Withdrawal requests লোড
            if os.path.exists(WITHDRAWAL_REQUESTS_FILE):
                with open(WITHDRAWAL_REQUESTS_FILE, 'r', encoding='utf-8') as f:
                    self.withdrawal_requests = json.load(f)
            else:
                self.withdrawal_requests = {}
            
            # Daily stats লোড
            if os.path.exists(DAILY_STATS_FILE):
                with open(DAILY_STATS_FILE, 'r', encoding='utf-8') as f:
                    self.daily_stats = json.load(f)
            else:
                self.daily_stats = {}
            
            # Monthly stats লোড
            if os.path.exists(MONTHLY_STATS_FILE):
                with open(MONTHLY_STATS_FILE, 'r', encoding='utf-8') as f:
                    self.monthly_stats = json.load(f)
            else:
                self.monthly_stats = {}
                
            self.cleanup_old_data()
            self.save_all_data()
            
        except Exception as e:
            logger.error(f"Error loading balance data: {str(e)}")
            # ডিফল্ট ভ্যালু সেট করুন
            self.balance_config = {
                "balance_per_online": 0.50, 
                "admin_id": 5624278091,
                "min_withdrawal": 50.0,
                "auto_reset_daily": False,
                "income_percentage": 100
            }
            self.user_balances = {}
            self.withdrawal_requests = {}
            self.daily_stats = {}
            self.monthly_stats = {}
    
    def save_all_data(self):
        """সকল ডেটা সেভ করুন"""
        try:
            with open(BALANCE_CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.balance_config, f, indent=4, ensure_ascii=False)
            with open(USER_BALANCES_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.user_balances, f, indent=4, ensure_ascii=False)
            with open(WITHDRAWAL_REQUESTS_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.withdrawal_requests, f, indent=4, ensure_ascii=False)
            with open(DAILY_STATS_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.daily_stats, f, indent=4, ensure_ascii=False)
            with open(MONTHLY_STATS_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.monthly_stats, f, indent=4, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Error saving balance data: {str(e)}")
    
    def get_today_key(self):
        """আজকের তারিখ কী রিটার্ন করুন"""
        return datetime.now().strftime("%Y-%m-%d")
    
    def get_month_key(self):
        """বর্তমান মাসের কী রিটার্ন করুন"""
        return datetime.now().strftime("%Y-%m")
    
    def cleanup_old_data(self):
        """পুরানো ডেটা ক্লিনআপ করুন (৩০ দিনের বেশি)"""
        try:
            cutoff_date = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
            
            # পুরানো ডেইলি স্ট্যাটস ডিলিট করুন
            keys_to_delete = []
            for date_key in self.daily_stats.keys():
                if date_key < cutoff_date:
                    keys_to_delete.append(date_key)
            
            for key in keys_to_delete:
                del self.daily_stats[key]
                
        except Exception as e:
            logger.error(f"Error cleaning up old data: {str(e)}")
    
    def add_online_number(self, user_id: int, website: str, phone_number: str = None):
        """নতুন অনলাইন নাম্বার ডিটেক্ট হলে ব্যালেন্স যোগ করুন"""
        with self.lock:
            user_id_str = str(user_id)
            today_key = self.get_today_key()
            month_key = self.get_month_key()
            
            # ইউজার ডেটা ইনিশিয়ালাইজ করুন যদি না থাকে
            if user_id_str not in self.user_balances:
                self.user_balances[user_id_str] = {
                    "total_balance": 0.0,
                    "lifetime_earnings": 0.0,
                    "withdrawn_amount": 0.0,
                    "total_online_count": 0,
                    "created_at": datetime.now().isoformat()
                }
            
            # ডেইলি স্ট্যাটস ইনিশিয়ালাইজ করুন
            if today_key not in self.daily_stats:
                self.daily_stats[today_key] = {}
            if user_id_str not in self.daily_stats[today_key]:
                self.daily_stats[today_key][user_id_str] = {
                    "online_count": 0,
                    "websites": {},
                    "total_earnings": 0.0
                }
            
            # মান্থলি স্ট্যাটস ইনিশিয়ালাইজ করুন
            if month_key not in self.monthly_stats:
                self.monthly_stats[month_key] = {}
            if user_id_str not in self.monthly_stats[month_key]:
                self.monthly_stats[month_key][user_id_str] = {
                    "online_count": 0,
                    "total_earnings": 0.0
                }
            
            # ব্যালেন্স যোগ করুন
            balance_to_add = self.balance_config["balance_per_online"]
            self.user_balances[user_id_str]["total_balance"] += balance_to_add
            self.user_balances[user_id_str]["lifetime_earnings"] += balance_to_add
            self.user_balances[user_id_str]["total_online_count"] += 1
            
            # ডেইলি স্ট্যাটস আপডেট করুন
            self.daily_stats[today_key][user_id_str]["online_count"] += 1
            self.daily_stats[today_key][user_id_str]["websites"][website] = self.daily_stats[today_key][user_id_str]["websites"].get(website, 0) + 1
            self.daily_stats[today_key][user_id_str]["total_earnings"] += balance_to_add
            
            # মান্থলি স্ট্যাটস আপডেট করুন
            self.monthly_stats[month_key][user_id_str]["online_count"] += 1
            self.monthly_stats[month_key][user_id_str]["total_earnings"] += balance_to_add
            
            self.save_all_data()
            
            result = {
                "balance_added": balance_to_add,
                "new_balance": self.user_balances[user_id_str]["total_balance"],
                "daily_count": self.daily_stats[today_key][user_id_str]["online_count"],
                "phone_number": phone_number,
                "website": website
            }
            
            logger.info(f"Balance added for user {user_id_str}: +{balance_to_add} BDT (Total: {result['new_balance']} BDT)")
            return result
    
    def get_user_stats(self, user_id: int):
        """ইউজারের সম্পূর্ণ স্ট্যাটস রিটার্ন করুন"""
        user_id_str = str(user_id)
        
        if user_id_str not in self.user_balances:
            return None
        
        user_data = self.user_balances[user_id_str]
        
        # গত ৭ দিনের আয় ক্যালকুলেট করুন
        last_7_days = 0.0
        last_30_days = 0.0
        today = datetime.now()
        
        for i in range(7):
            date_key = (today - timedelta(days=i)).strftime("%Y-%m-%d")
            if date_key in self.daily_stats and user_id_str in self.daily_stats[date_key]:
                earnings = self.daily_stats[date_key][user_id_str].get("total_earnings", 0)
                last_7_days += earnings
        
        # গত ৩০ দিনের আয় ক্যালকুলেট করুন
        for i in range(30):
            date_key = (today - timedelta(days=i)).strftime("%Y-%m-%d")
            if date_key in self.daily_stats and user_id_str in self.daily_stats[date_key]:
                earnings = self.daily_stats[date_key][user_id_str].get("total_earnings", 0)
                last_30_days += earnings
        
        # বর্তমান মাসের আয়
        current_month = self.get_month_key()
        month_earnings = 0.0
        if current_month in self.monthly_stats and user_id_str in self.monthly_stats[current_month]:
            month_earnings = self.monthly_stats[current_month][user_id_str].get("total_earnings", 0)
        
        # আজকের কাউন্ট
        today_key = self.get_today_key()
        today_count = self.daily_stats.get(today_key, {}).get(user_id_str, {}).get("online_count", 0)
        
        return {
            "total_balance": round(user_data.get("total_balance", 0), 2),
            "lifetime_earnings": round(user_data.get("lifetime_earnings", 0), 2),
            "withdrawn_amount": round(user_data.get("withdrawn_amount", 0), 2),
            "total_online_count": user_data.get("total_online_count", 0),
            "last_7_days": round(last_7_days, 2),
            "last_30_days": round(last_30_days, 2),
            "current_month": round(month_earnings, 2),
            "today_count": today_count,
            "created_at": user_data.get("created_at", "unknown")
        }
    
    def request_withdrawal(self, user_id: int, bkash_number: str, name: str, amount: float):
        """উত্তোলন রিকোয়েস্ট তৈরি করুন"""
        with self.lock:
            user_id_str = str(user_id)
            
            if user_id_str not in self.user_balances:
                return False, "User balance not found"
            
            current_balance = self.user_balances[user_id_str]["total_balance"]
            min_withdrawal = self.balance_config.get("min_withdrawal", 50.0)
            
            if current_balance < amount:
                return False, f"Insufficient balance. Your balance: {current_balance} BDT"
            
            if amount < min_withdrawal:
                return False, f"Minimum withdrawal amount is {min_withdrawal} BDT"
            
            # উত্তোলন রিকোয়েস্ট তৈরি করুন
            request_id = str(int(time.time()))
            self.withdrawal_requests[request_id] = {
                "user_id": user_id_str,
                "bkash_number": bkash_number,
                "name": name,
                "amount": amount,
                "status": "pending",
                "timestamp": datetime.now().isoformat(),
                "user_balance_before": current_balance
            }
            
            # ব্যালেন্স থেকে Amount কেটে নিন (অস্থায়ীভাবে হোল্ড করুন)
            self.user_balances[user_id_str]["total_balance"] -= amount
            
            self.save_all_data()
            
            logger.info(f"Withdrawal request created: {request_id} for user {user_id_str} - {amount} BDT (Balance held)")
            return True, request_id
    
    def process_withdrawal(self, request_id: str, action: str, admin_id: int):
        """উত্তোলন রিকোয়েস্ট প্রসেস করুন"""
        with self.lock:
            if request_id not in self.withdrawal_requests:
                return False, "Request not found"
            
            request = self.withdrawal_requests[request_id]
            user_id_str = request["user_id"]
            
            if request["status"] != "pending":
                return False, "Request already processed"
            
            if action == "approve":
                # উত্তোলন অ্যাপ্রুভ করা হলে Amount permanently ডিডাক্ট করা হবে
                if user_id_str in self.user_balances:
                    self.user_balances[user_id_str]["withdrawn_amount"] += request["amount"]
                    # Amount already deducted during request, so no need to deduct again
                
                request["status"] = "approved"
                request["processed_by"] = str(admin_id)
                request["processed_at"] = datetime.now().isoformat()
                self.save_all_data()
                
                logger.info(f"Withdrawal approved: {request_id} for user {user_id_str}")
                return True, "approved"
            
            elif action == "reject":
                # উত্তোলন রিজেক্ট করা হলে Amount ফেরত দিন
                if user_id_str in self.user_balances:
                    self.user_balances[user_id_str]["total_balance"] += request["amount"]
                
                request["status"] = "rejected"
                request["processed_by"] = str(admin_id)
                request["processed_at"] = datetime.now().isoformat()
                self.save_all_data()
                
                logger.info(f"Withdrawal rejected: {request_id} for user {user_id_str} (Balance refunded)")
                return True, "rejected"
            
            return False, "Invalid action"
    
    def update_balance_rate(self, new_rate: float, admin_id: int, context=None):
        """ব্যালেন্স রেট আপডেট করুন - WITH NOTIFICATION"""
        with self.lock:
            if new_rate < 0:
                return False
            
            old_rate = self.balance_config["balance_per_online"]
            self.balance_config["balance_per_online"] = new_rate
            self.balance_config["last_rate_update"] = datetime.now().isoformat()
            self.balance_config["updated_by"] = str(admin_id)
            
            self.save_all_data()
            
            logger.info(f"Balance rate updated by {admin_id}: {old_rate} -> {new_rate} BDT")
            
            # ✅ Send notification to all users if context is provided
            if context:
                notification_msg = (
                    f"📢 **ব্যালেন্স রেট আপডেট!**\n\n"
                    f"💰 নতুন ব্যালেন্স রেট: {new_rate} BDT\n"
                    f"📊 প্রতি অনলাইন নাম্বারে এখন {new_rate} BDT যোগ হবে\n"
                    f"⏰ আপডেট সময়: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                )
                
                # Run notification in background
                asyncio.create_task(self.notify_all_users(context, notification_msg))
            
            return True
    
    async def notify_all_users(self, context, message):
        """সকল ইউজারকে নোটিফাই করুন"""
        try:
            for user_id_str in self.user_balances.keys():
                try:
                    await context.bot.send_message(
                        int(user_id_str),
                        message,
                        parse_mode='Markdown'
                    )
                    logger.info(f"Notification sent to user {user_id_str}")
                    await asyncio.sleep(0.1)  # Rate limiting
                except Exception as e:
                    logger.error(f"Failed to notify user {user_id_str}: {str(e)}")
        except Exception as e:
            logger.error(f"Error in notify_all_users: {str(e)}")
    
    def get_pending_withdrawals(self):
        """পেন্ডিং উত্তোলন রিকোয়েস্টগুলো রিটার্ন করুন"""
        return {
            k: v for k, v in self.withdrawal_requests.items() 
            if v.get("status") == "pending"
        }
    
    def get_all_users_stats(self):
        """সকল ইউজারের সামারি স্ট্যাটস রিটার্ন করুন"""
        total_balance = 0.0
        total_lifetime = 0.0
        total_withdrawn = 0.0
        total_online_count = 0
        active_users = 0
        
        for user_data in self.user_balances.values():
            total_balance += user_data.get("total_balance", 0)
            total_lifetime += user_data.get("lifetime_earnings", 0)
            total_withdrawn += user_data.get("withdrawn_amount", 0)
            total_online_count += user_data.get("total_online_count", 0)
            if user_data.get("total_balance", 0) > 0:
                active_users += 1
        
        return {
            "total_users": len(self.user_balances),
            "active_users": active_users,
            "total_balance": round(total_balance, 2),
            "total_lifetime": round(total_lifetime, 2),
            "total_withdrawn": round(total_withdrawn, 2),
            "total_online_count": total_online_count,
            "balance_rate": self.balance_config["balance_per_online"]
        }
    
    def get_today_stats(self):
        """আজকের সামারি স্ট্যাটস রিটার্ন করুন"""
        today_key = self.get_today_key()
        today_data = self.daily_stats.get(today_key, {})
        
        total_online = 0
        total_earnings = 0.0
        active_users = len(today_data)
        
        for user_data in today_data.values():
            total_online += user_data.get("online_count", 0)
            total_earnings += user_data.get("total_earnings", 0.0)
        
        return {
            "date": today_key,
            "active_users": active_users,
            "total_online": total_online,
            "total_earnings": round(total_earnings, 2),
            "estimated_balance": total_online * self.balance_config["balance_per_online"]
        }

# নতুন কনস্ট্যান্টস যোগ করুন
MONTHLY_STATS_FILE = "monthly_stats.json"

# ব্যালেন্স ম্যানেজার ইনিশিয়ালাইজ করুন
balance_manager = BalanceManager()





# Custom logging filter to mask sensitive data
class SensitiveDataFilter(logging.Filter):
    def filter(self, record):
        if hasattr(record, 'msg'):
            record.msg = re.sub(r'\+\d{11,12}', '****MASKED_PHONE****', record.msg)
            record.msg = re.sub(r'(?<=token: )[\w-]{10}[\w-]+', lambda m: m.group(0)[:10] + '...', record.msg)
            record.msg = re.sub(r'(?<=password: )[\w@.-]+', '****MASKED_PASSWORD****', record.msg)
            record.msg = re.sub(r'(?<=username: )[\w@.-]+', '****MASKED_USERNAME****', record.msg)
        return True

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("bot.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
logger.addFilter(SensitiveDataFilter())

token_cache = {}
user_status_cache = {"approved": [], "blocked": []}
cache_loaded = False

device_manager = DeviceProfileManager()

async def load_user_agents_from_file():
    ua_file = "ua_agents.txt"
    user_agents = []
    try:
        async with aiofiles.open(ua_file, 'r') as f:
            async for line in f:
                # অতিরিক্ত টেক্সট (যেমন, নম্বর বা ডট) রিমুভ করা
                agent = re.sub(r'^\d+\.\s*|\s*$', '', line.strip())
                if agent and detect_platform_from_user_agent(agent) in ['android', 'default']:
                    user_agents.append(agent)
        logger.info(f"Loaded {len(user_agents)} valid Android User Agents from {ua_file}")
        return user_agents
    except Exception as e:
        logger.error(f"Error loading User Agents from {ua_file}: {str(e)}")
        return []

USED_DEVICES_FILE = "used_devices.json"

def load_used_devices():
    try:
        if os.path.exists(USED_DEVICES_FILE):
            with open(USED_DEVICES_FILE, 'r') as f:
                return set(json.load(f))
        return set()
    except Exception as e:
        logger.error(f"Error loading used devices: {str(e)}")
        return set()

async def save_used_device(device_id):
    used = load_used_devices()
    used.add(device_id)
    async with aiofiles.open(USED_DEVICES_FILE, 'w') as f:
        await f.write(json.dumps(list(used), indent=4))

def detect_platform_from_user_agent(user_agent):
    user_agent_lower = user_agent.lower()
    if 'android' in user_agent_lower:
        return 'android'
    elif 'windows' in user_agent_lower:
        return 'windows'
    elif 'iphone' in user_agent_lower or 'ipad' in user_agent_lower:
        return 'ios'
    elif 'mac os' in user_agent_lower or 'macintosh' in user_agent_lower:
        return 'macos'
    elif 'linux' in user_agent_lower:
        return 'linux'
    else:
        return 'default'

def get_main_keyboard(selected_website=DEFAULT_SELECTED_WEBSITE, user_id=None):
    link_text = f"Link {selected_website} WhatsApp"
    number_list_text = f"{selected_website} Number List"
    device_set = device_manager.exists(str(user_id))
    set_user_agent_text = f"{'✅ ' if device_set else ''}Set User Agent"
    
    # মাল্টি-অ্যাকাউন্ট বাটন যোগ করুন
    multi_account_text = "🔢 Multi Accounts"

    keyboard = [
        [KeyboardButton("Log in Account"), KeyboardButton(link_text)],  # 1st row
        [KeyboardButton("My Balance"), KeyboardButton("Withdraw")],      # 2nd row
        [KeyboardButton(number_list_text), KeyboardButton(set_user_agent_text)],  # 3rd row
        [KeyboardButton(multi_account_text)]  # 4th row: নতুন বাটন
    ]

    # Add admin button if user is admin
    if user_id == balance_manager.balance_config["admin_id"]:
        keyboard.append([KeyboardButton("Admin Panel")])  # 5th row (only for admin)

    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True, one_time_keyboard=False)

def get_website_selection_keyboard():
    # WEBSITE_CONFIGS থেকে সব ওয়েবসাইটের নাম নেওয়া
    websites = list(WEBSITE_CONFIGS.keys())
    # দুটি করে বাটন এক সারিতে রাখার জন্য
    keyboard = []
    for i in range(0, len(websites), 2):
        row = [KeyboardButton(websites[i])]
        if i + 1 < len(websites):
            row.append(KeyboardButton(websites[i + 1]))
        keyboard.append(row)
    # Back to Main Menu বাটন যুক্ত করা
    keyboard.append([KeyboardButton("Back to Main Menu")])
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True, one_time_keyboard=True)

def get_confirmation_keyboard():
    keyboard = [
        [KeyboardButton("Yes"), KeyboardButton("No")]
    ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True, one_time_keyboard=True)

def load_user_status():
    global user_status_cache, cache_loaded
    if not cache_loaded:
        try:
            if os.path.exists(USER_STATUS_FILE):
                with open(USER_STATUS_FILE, 'r') as f:
                    user_status_cache = json.load(f)
            cache_loaded = True
        except Exception as e:
            logger.error(f"Error loading user status: {str(e)}")
    return user_status_cache

async def save_user_status(status):
    global user_status_cache
    try:
        user_status_cache = status
        async with aiofiles.open(USER_STATUS_FILE, 'w') as f:
            await f.write(json.dumps(status, indent=4))
    except Exception as e:
        logger.error(f"Error saving user status: {str(e)}")

def load_tokens():
    global token_cache, cache_loaded
    if not cache_loaded:
        try:
            if os.path.exists(TOKEN_FILE):
                with open(TOKEN_FILE, 'r') as f:
                    token_cache = json.load(f)
            cache_loaded = True
        except Exception as e:
            logger.error(f"Error loading tokens: {str(e)}")
    return token_cache

async def save_token(user_id, account_type, token, website):
    global token_cache
    try:
        tokens = load_tokens()
        if str(user_id) not in tokens:
            tokens[str(user_id)] = {}
        if website not in tokens[str(user_id)]:
            tokens[str(user_id)][website] = {}
        tokens[str(user_id)][website][account_type] = token
        token_cache = tokens
        async with aiofiles.open(TOKEN_FILE, 'w') as f:
            await f.write(json.dumps(tokens, indent=4))
        logger.info(f"Token saved for user {user_id} ({account_type} account, {website})")
        
        # ✅ REMOVED: এখানে মনিটরিং শুরু করার লজিক থাকবে না
        # মনিটরিং শুধুমাত্র লগইন সাকসেস বা /start কমান্ডে শুরু হবে
        
    except Exception as e:
        logger.error(f"Error saving token for user {user_id}: {str(e)}")

async def remove_token(user_id, account_type=None, website=None):
    global token_cache
    try:
        tokens = load_tokens()
        if str(user_id) in tokens:
            if website and account_type:
                if website in tokens[str(user_id)] and account_type in tokens[str(user_id)][website]:
                    del tokens[str(user_id)][website][account_type]
                    logger.info(f"Token removed for user {user_id} ({account_type} account, {website})")
            elif website:
                if website in tokens[str(user_id)]:
                    del tokens[str(user_id)][website]
                    logger.info(f"All tokens removed for user {user_id} ({website})")
            else:
                del tokens[str(user_id)]
                logger.info(f"All tokens removed for user {user_id}")
            token_cache = tokens
            async with aiofiles.open(TOKEN_FILE, 'w') as f:
                await f.write(json.dumps(tokens, indent=4))
            return True
        return False
    except Exception as e:
        logger.error(f"Error removing token for user {user_id}: {str(e)}")
        return False

async def reset_all(user_id):
    try:
        await remove_token(user_id)
        if os.path.exists(device_manager.base_dir):
            shutil.rmtree(device_manager.base_dir)
        os.makedirs(device_manager.base_dir, exist_ok=True)
        for website in WEBSITE_CONFIGS:
            track_file = f"online_durations_{website.lower()}.json"
            if os.path.exists(track_file):
                os.remove(track_file)
        if os.path.exists("bot.log"):
            os.remove("bot.log")
            logger.info(f"Log file bot.log deleted by user {user_id} during reset_all")
        logger.info(f"Reset all completed by user {user_id}, devices, cookies, and proxies cleared. Used devices preserved.")
        return True, (
            f"✅ Reset all completed successfully.\n\n"
            f"Please set a new User Agent using 'Set User Agent' and optionally a new proxy using 'Set Proxy' to create a new device identity."
        )
    except Exception as e:
        logger.error(f"Error resetting all for user {user_id}: {str(e)}")
        return False, f"❌ Error resetting all: {str(e)}"

class MultiAccountManager:
    def __init__(self):
        self.accounts_file = "multi_accounts.json"
        self.accounts_data = {}
        self.current_account_index = {}
        self.active_tokens = {}  # website -> {username: token}
        self.load_accounts()
    
    def load_accounts(self):
        try:
            if os.path.exists(self.accounts_file):
                with open(self.accounts_file, 'r', encoding='utf-8') as f:
                    self.accounts_data = json.load(f)
                # লগার না থাকলে প্রিন্ট ব্যবহার করুন
                print(f"✅ Multi-accounts loaded for websites: {list(self.accounts_data.keys())}")
                for website, accounts in self.accounts_data.items():
                    print(f"📊 {website}: {len(accounts)} accounts")
            else:
                print("ℹ️ No multi-accounts file found - creating empty file")
                # খালি ফাইল তৈরি করুন
                with open(self.accounts_file, 'w', encoding='utf-8') as f:
                    json.dump({"TASK 3": []}, f, indent=2)
        except Exception as e:
            print(f"❌ Error loading multi-accounts: {str(e)}")
            self.accounts_data = {}
    
    async def login_all_accounts(self, website: str, device_name: str):
        """সকল অ্যাকাউন্ট একসাথে লগইন করুন"""
        if website not in self.accounts_data:
            return False
        
        website_config = WEBSITE_CONFIGS.get(website, WEBSITE_CONFIGS.get("TASK 3"))
        success_count = 0
        
        print(f"🔄 Logging in ALL accounts for {website}...")
        
        for account in self.accounts_data[website]:
            try:
                username = account['username']
                password = account['password']
                
                print(f"⏳ Logging in: {username}")
                login_result = await login_with_credentials(username, password, website_config, device_name)
                
                if login_result["success"]:
                    if website not in self.active_tokens:
                        self.active_tokens[website] = {}
                    self.active_tokens[website][username] = login_result["token"]
                    success_count += 1
                    print(f"✅ Login successful: {username}")
                else:
                    print(f"❌ Login failed: {username} - {login_result.get('error')}")
                    
            except Exception as e:
                print(f"❌ Error logging in {account['username']}: {str(e)}")
        
        print(f"🎯 Login summary for {website}: {success_count}/{len(self.accounts_data[website])} successful")
        return success_count > 0
    
    def get_next_account_token(self, website: str):
        """পরবর্তী অ্যাকাউন্টের টোকেন রিটার্ন করুন"""
        if website not in self.accounts_data or not self.accounts_data[website]:
            return None
        
        if website not in self.current_account_index:
            self.current_account_index[website] = 0
        else:
            self.current_account_index[website] = (self.current_account_index[website] + 1) % len(self.accounts_data[website])
        
        current_account = self.accounts_data[website][self.current_account_index[website]]
        username = current_account['username']
        
        # একটিভ টোকেন থেকে নিন
        if website in self.active_tokens and username in self.active_tokens[website]:
            token = self.active_tokens[website][username]
            print(f"🔄 Switching to account: {username} (index: {self.current_account_index[website]})")
            return token
        else:
            print(f"❌ No active token for: {username}")
            return None
    
    def get_current_account_info(self, website: str):
        """বর্তমান অ্যাকাউন্টের তথ্য রিটার্ন করুন"""
        if website not in self.accounts_data or not self.accounts_data[website]:
            return None
        
        if website not in self.current_account_index:
            self.current_account_index[website] = 0
        
        account = self.accounts_data[website][self.current_account_index[website]]
        username = account['username']
        token_available = website in self.active_tokens and username in self.active_tokens[website]
        
        return {
            'username': username,
            'index': self.current_account_index[website],
            'total_accounts': len(self.accounts_data[website]),
            'token_available': token_available
        }
    
    def get_all_accounts_status(self, website: str):
        """সকল অ্যাকাউন্টের স্ট্যাটাস রিটার্ন করুন"""
        if website not in self.accounts_data:
            return []
        
        accounts_status = []
        for i, account in enumerate(self.accounts_data[website]):
            username = account['username']
            token_available = website in self.active_tokens and username in self.active_tokens[website]
            is_current = i == self.current_account_index.get(website, 0)
            
            accounts_status.append({
                'username': username,
                'token_available': token_available,
                'is_current': is_current,
                'index': i
            })
        
        return accounts_status

# গ্লোবাল ইনস্ট্যান্স তৈরি
multi_account_manager = MultiAccountManager()




async def encrypt_phone(phone):
    try:
        phone = phone.replace("+", "")
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        padded = pad(phone.encode(), AES.block_size)
        encrypted = cipher.encrypt(padded)
        return b64encode(encrypted).decode()
    except Exception as e:
        logger.error(f"Error encrypting phone: {str(e)}")
        raise

def encrypt_username(plain_text: str) -> str:
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    padded_text = pad(plain_text.encode('utf-8'), AES.block_size)
    encrypted_bytes = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted_bytes).decode('utf-8')

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    logger.info(f"Start command triggered by user {user_id}")
    
    if 'selected_website' not in context.user_data:
        context.user_data['selected_website'] = DEFAULT_SELECTED_WEBSITE
    
    selected_website = context.user_data['selected_website']
    
    welcome_message = "👋 Welcome to the WhatsApp Linking Bot!\n\nThis System made by HASAN."
    
    # ✅ FIXED: শুধুমাত্র সিলেক্টেড ওয়েবসাইটের জন্য মনিটরিং রিস্টার্ট করুন
    tokens = load_tokens()
    if str(user_id) in tokens and selected_website in tokens[str(user_id)]:
        token = tokens[str(user_id)][selected_website].get('main')
        device_name = str(user_id)
        
        if device_manager.exists(device_name) and token:
            global auto_monitor
            if auto_monitor:
                # শুধুমাত্র যদি মনিটরিং না চলতে থাকে অথবা ভিন্ন ওয়েবসাইটে চলতে থাকে
                current_status = auto_monitor.get_monitoring_status(user_id)
                if not current_status or current_status['website'] != selected_website:
                    try:
                        # পুরানো মনিটরিং বন্ধ করুন
                        if auto_monitor.is_user_monitoring(user_id):
                            await auto_monitor.stop_monitoring(user_id)
                            await asyncio.sleep(2)
                        
                        # নতুন মনিটরিং শুরু করুন
                        await auto_monitor.start_monitoring(user_id, selected_website, token, device_name)
                        logger.info(f"✅ Auto monitoring STARTED for user {user_id} on {selected_website} via /start")
                    except Exception as e:
                        logger.error(f"❌ Failed to start auto monitoring: {str(e)}")
                else:
                    logger.info(f"🔄 Auto monitoring already running for user {user_id} on {selected_website}")
    
    # Check if user has any accounts
    has_accounts = False
    if str(user_id) in tokens:
        for website in WEBSITE_CONFIGS:
            if website in tokens[str(user_id)] and tokens[str(user_id)][website].get('main'):
                has_accounts = True
                break
    
    if has_accounts:
        # ✅ FIXED: শুধুমাত্র বর্তমান সিলেক্টেড ওয়েবসাইটের স্ট্যাটাস দেখান
        current_status = auto_monitor.get_monitoring_status(user_id) if auto_monitor else None
        if current_status and current_status['is_running']:
            monitoring_info = f"\n🤖 Auto monitoring: ACTIVE ({current_status['website']})"
        else:
            monitoring_info = "\n🤖 Auto monitoring: INACTIVE"
        
        message = f"✅ You have accounts setup!\n\n{welcome_message}{monitoring_info}"
        logger.info(f"User {user_id} menu refreshed (logged in)")
    else:
        message = welcome_message
        logger.info(f"User {user_id} menu refreshed (not logged in)")
    
    await update.message.reply_text(
        message,
        reply_markup=get_main_keyboard(selected_website, user_id)
    )
        
async def login_with_credentials(username, password, website_config, device_name):
    async with await device_manager.build_session(device_name) as session:
        for attempt in range(MAX_RETRIES):
            try:
                url = f"{website_config['api_domain']}{website_config['login_path']}"
                headers = {
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Encoding": get_random_accept_encoding(),
                    "Content-Type": "application/x-www-form-urlencoded",
                    "origin": website_config['origin'],
                    "x-requested-with": "mark.via.gp",
                    "referer": website_config['referer'],
                    "accept-language": ACCEPT_LANGUAGE,
                    "sec-ch-ua": random.choice(SEC_CH_UA_LIST),
                    "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
                    "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
                    **get_random_sec_fetch_headers(),
                    "priority": get_random_priority()
                }
                data = {
                    "username": username,
                    "password": password
                }
                await asyncio.sleep(random.uniform(0.5, 2.0))
                async with asyncio.timeout(REQUEST_TIMEOUT):
                    async with session.post(url, headers=headers, data=data) as response:
                        response_data = await response.json()
                        if response_data.get("code") == 1:
                            token = response_data.get("data", {}).get("token")
                            if not token:
                                token = response_data.get("data", {}).get("userinfo", {}).get("token")
                            if token:
                                # ✅ FIXED: শুধুমাত্র লগইন করা ওয়েবসাইটের জন্য মনিটরিং শুরু করুন
                                user_id = None
                                try:
                                    user_id = int(device_name)
                                except:
                                    pass
                                
                                if user_id:
                                    global auto_monitor
                                    if auto_monitor:
                                        # শুধুমাত্র যদি একই ইউজারের জন্য অন্য ওয়েবসাইটে মনিটরিং চলছে
                                        current_status = auto_monitor.get_monitoring_status(user_id)
                                        if current_status and current_status['website'] != website_config['name']:
                                            # পুরানো মনিটরিং বন্ধ করুন
                                            await auto_monitor.stop_monitoring(user_id)
                                            await asyncio.sleep(2)
                                        
                                        # নতুন মনিটরিং শুরু করুন
                                        website = website_config['name']
                                        await auto_monitor.start_monitoring(user_id, website, token, device_name)
                                        logger.info(f"🔄 Monitoring started for user {user_id} on {website} after login")
                                
                                return {
                                    "success": True,
                                    "token": token,
                                    "response": response_data
                                }
                            return {
                                "success": False,
                                "error": "✅ Login successful but no token received",
                                "response": response_data
                            }
                        return {
                            "success": False,
                            "error": "🔑 Invalid credentials",
                            "response": response_data
                        }
            except asyncio.TimeoutError:
                if attempt == MAX_RETRIES - 1:
                    error_msg = "⏰ Connection timeout"
                    logger.error(error_msg)
                    return {
                        "success": False,
                        "error": error_msg,
                        "response": None
                    }
                await asyncio.sleep(1)
            except Exception as e:
                if attempt == MAX_RETRIES - 1:
                    error_msg = "🌐 Connection failed"
                    logger.error(error_msg)
                    return {
                        "success": False,
                        "error": error_msg,
                        "response": None
                    }
                await asyncio.sleep(1)

async def register_account(website_config, phone_number, password, confirm_password, invite_code, device_name, reg_host):
    async with await device_manager.build_session(device_name) as session:
        for attempt in range(MAX_RETRIES):
            try:
                encrypted_username = encrypt_username(phone_number)
                url = f"{website_config['api_domain']}{website_config['signup_path']}"
                headers = {
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Encoding": get_random_accept_encoding(),
                    "Content-Type": "application/x-www-form-urlencoded",
                    "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
                    "accept-language": ACCEPT_LANGUAGE,
                    "sec-ch-ua": random.choice(SEC_CH_UA_LIST),
                    "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
                    "token": "",
                    "origin": website_config['origin'],
                    "x-requested-with": "mark.via.gp",
                    "referer": website_config['referer'],
                    "priority": get_random_priority()
                }
                data = {
                    "username": encrypted_username,
                    "password": password,
                    "confirm_password": confirm_password,
                    website_config['referral_field']: invite_code if invite_code else "",
                    "reg_host": reg_host
                }
                logger.info(f"Sending registration request to {url} for attempt {attempt + 1}/{MAX_RETRIES}")
                await asyncio.sleep(random.uniform(0.5, 2.0))
                async with asyncio.timeout(REQUEST_TIMEOUT):
                    async with session.post(url, headers=headers, data=data) as response:
                        if response.status != 200:
                            logger.error(f"Registration failed with status {response.status} for {website_config['name']}")
                            if attempt == MAX_RETRIES - 1:
                                return {
                                    "code": -1,
                                    "msg": f"Registration failed with HTTP status {response.status}",
                                    "data": None
                                }
                            await asyncio.sleep(1)
                            continue
                        response_data = await response.json()
                        logger.info(f"Registration response for {website_config['name']}: {json.dumps(response_data, indent=2)}")
                        return response_data
            except asyncio.TimeoutError:
                logger.error(f"Registration request timed out after {REQUEST_TIMEOUT} seconds for {website_config['name']}")
                if attempt == MAX_RETRIES - 1:
                    return {
                        "code": -1,
                        "msg": f"Registration request timed out after {REQUEST_TIMEOUT} seconds",
                        "data": None
                    }
                await asyncio.sleep(1)
            except Exception as e:
                logger.error(f"Error in register_account for {website_config['name']}: {str(e)}")
                if attempt == MAX_RETRIES - 1:
                    return {
                        "code": -1,
                        "msg": f"Registration failed: {str(e)}",
                        "data": None
                    }
                await asyncio.sleep(1)
        logger.error(f"Registration failed after {MAX_RETRIES} attempts for {website_config['name']}")
        return {
            "code": -1,
            "msg": f"Registration failed after {MAX_RETRIES} attempts",
            "data": None
        }

async def send_code(token, phone_encrypted, website_config, device_name, phone_plain=None):
    async with await device_manager.build_session(device_name) as session:
        for attempt in range(MAX_RETRIES):
            try:
                # ✅ ফোন নাম্বার থেকে কান্ট্রি কোড বের করা
                area_code = "1"
                if phone_plain:
                    match = re.match(r'^\+?(\d{1,4})', phone_plain)
                    if match:
                        code = match.group(1)
                        area_map = {
                            "93": "93",     # Afghanistan
    "355": "355",   # Albania
    "213": "213",   # Algeria
    "376": "376",   # Andorra
    "244": "244",   # Angola
    "1": "1",       # USA/Canada
    "1": "1",       # Caribbean
    "54": "54",     # Argentina
    "374": "374",   # Armenia
    "297": "297",   # Aruba
    "61": "61",     # Australia
    "43": "43",     # Austria
    "994": "994",   # Azerbaijan
    "973": "973",   # Bahrain
    "880": "880",   # Bangladesh
    "1": "1",       # Barbados
    "375": "375",   # Belarus
    "32": "32",     # Belgium
    "501": "501",   # Belize
    "229": "229",   # Benin
    "975": "975",   # Bhutan
    "591": "591",   # Bolivia
    "387": "387",   # Bosnia
    "267": "267",   # Botswana
    "55": "55",     # Brazil
    "673": "673",   # Brunei
    "359": "359",   # Bulgaria
    "226": "226",   # Burkina Faso
    "257": "257",   # Burundi
    "855": "855",   # Cambodia
    "237": "237",   # Cameroon
    "1": "1",       # Canada
    "238": "238",   # Cape Verde
    "236": "236",   # Central African Republic
    "235": "235",   # Chad
    "56": "56",     # Chile
    "86": "86",     # China
    "57": "57",     # Colombia
    "269": "269",   # Comoros
    "242": "242",   # Congo
    "682": "682",   # Cook Islands
    "506": "506",   # Costa Rica
    "385": "385",   # Croatia
    "53": "53",     # Cuba
    "357": "357",   # Cyprus
    "420": "420",   # Czech Republic
    "243": "243",   # Democratic Republic of Congo
    "45": "45",     # Denmark
    "253": "253",   # Djibouti
    "1": "1",       # Dominica
    "1": "1",       # Dominican Republic
    "670": "670",   # East Timor
    "593": "593",   # Ecuador
    "20": "20",     # Egypt
    "503": "503",   # El Salvador
    "240": "240",   # Equatorial Guinea
    "291": "291",   # Eritrea
    "372": "372",   # Estonia
    "251": "251",   # Ethiopia
    "500": "500",   # Falkland Islands
    "298": "298",   # Faroe Islands
    "679": "679",   # Fiji
    "358": "358",   # Finland
    "33": "33",     # France
    "594": "594",   # French Guiana
    "689": "689",   # French Polynesia
    "241": "241",   # Gabon
    "220": "220",   # Gambia
    "995": "995",   # Georgia
    "49": "49",     # Germany
    "233": "233",   # Ghana
    "350": "350",   # Gibraltar
    "30": "30",     # Greece
    "299": "299",   # Greenland
    "1": "1",       # Grenada
    "590": "590",   # Guadeloupe
    "1": "1",       # Guam
    "502": "502",   # Guatemala
    "224": "224",   # Guinea
    "245": "245",   # Guinea-Bissau
    "592": "592",   # Guyana
    "509": "509",   # Haiti
    "504": "504",   # Honduras
    "852": "852",   # Hong Kong
    "36": "36",     # Hungary
    "354": "354",   # Iceland
    "91": "91",     # India
    "62": "62",     # Indonesia
    "98": "98",     # Iran
    "964": "964",   # Iraq
    "353": "353",   # Ireland
    "972": "972",   # Israel
    "39": "39",     # Italy
    "1": "1",       # Jamaica
    "81": "81",     # Japan
    "962": "962",   # Jordan
    "7": "7",       # Kazakhstan
    "254": "254",   # Kenya
    "686": "686",   # Kiribati
    "965": "965",   # Kuwait
    "996": "996",   # Kyrgyzstan
    "856": "856",   # Laos
    "371": "371",   # Latvia
    "961": "961",   # Lebanon
    "266": "266",   # Lesotho
    "231": "231",   # Liberia
    "218": "218",   # Libya
    "423": "423",   # Liechtenstein
    "370": "370",   # Lithuania
    "352": "352",   # Luxembourg
    "853": "853",   # Macau
    "389": "389",   # Macedonia
    "261": "261",   # Madagascar
    "265": "265",   # Malawi
    "60": "60",     # Malaysia
    "960": "960",   # Maldives
    "223": "223",   # Mali
    "356": "356",   # Malta
    "692": "692",   # Marshall Islands
    "596": "596",   # Martinique
    "222": "222",   # Mauritania
    "230": "230",   # Mauritius
    "262": "262",   # Mayotte
    "52": "52",     # Mexico
    "691": "691",   # Micronesia
    "373": "373",   # Moldova
    "377": "377",   # Monaco
    "976": "976",   # Mongolia
    "382": "382",   # Montenegro
    "1": "1",       # Montserrat
    "212": "212",   # Morocco
    "258": "258",   # Mozambique
    "95": "95",     # Myanmar
    "264": "264",   # Namibia
    "674": "674",   # Nauru
    "977": "977",   # Nepal
    "31": "31",     # Netherlands
    "687": "687",   # New Caledonia
    "64": "64",     # New Zealand
    "505": "505",   # Nicaragua
    "227": "227",   # Niger
    "234": "234",   # Nigeria
    "683": "683",   # Niue
    "850": "850",   # North Korea
    "47": "47",     # Norway
    "968": "968",   # Oman
    "92": "92",     # Pakistan
    "680": "680",   # Palau
    "970": "970",   # Palestine
    "507": "507",   # Panama
    "675": "675",   # Papua New Guinea
    "595": "595",   # Paraguay
    "51": "51",     # Peru
    "63": "63",     # Philippines
    "48": "48",     # Poland
    "351": "351",   # Portugal
    "1": "1",       # Puerto Rico
    "974": "974",   # Qatar
    "262": "262",   # Reunion
    "40": "40",     # Romania
    "7": "7",       # Russia
    "250": "250",   # Rwanda
    "590": "590",   # Saint Barthelemy
    "290": "290",   # Saint Helena
    "1": "1",       # Saint Kitts and Nevis
    "1": "1",       # Saint Lucia
    "508": "508",   # Saint Pierre and Miquelon
    "1": "1",       # Saint Vincent and the Grenadines
    "685": "685",   # Samoa
    "378": "378",   # San Marino
    "239": "239",   # Sao Tome and Principe
    "966": "966",   # Saudi Arabia
    "221": "221",   # Senegal
    "381": "381",   # Serbia
    "248": "248",   # Seychelles
    "232": "232",   # Sierra Leone
    "65": "65",     # Singapore
    "421": "421",   # Slovakia
    "386": "386",   # Slovenia
    "677": "677",   # Solomon Islands
    "252": "252",   # Somalia
    "27": "27",     # South Africa
    "82": "82",     # South Korea
    "211": "211",   # South Sudan
    "34": "34",     # Spain
    "94": "94",     # Sri Lanka
    "249": "249",   # Sudan
    "597": "597",   # Suriname
    "268": "268",   # Swaziland
    "46": "46",     # Sweden
    "41": "41",     # Switzerland
    "963": "963",   # Syria
    "886": "886",   # Taiwan
    "992": "992",   # Tajikistan
    "255": "255",   # Tanzania
    "66": "66",     # Thailand
    "228": "228",   # Togo
    "690": "690",   # Tokelau
    "676": "676",   # Tonga
    "1": "1",       # Trinidad and Tobago
    "216": "216",   # Tunisia
    "90": "90",     # Turkey
    "993": "993",   # Turkmenistan
    "1": "1",       # Turks and Caicos Islands
    "688": "688",   # Tuvalu
    "256": "256",   # Uganda
    "380": "380",   # Ukraine
    "971": "971",   # United Arab Emirates
    "44": "44",     # United Kingdom
    "598": "598",   # Uruguay
    "1": "1",       # US Virgin Islands
    "998": "998",   # Uzbekistan
    "678": "678",   # Vanuatu
    "379": "379",   # Vatican City
    "58": "58",     # Venezuela
    "84": "84",     # Vietnam
    "681": "681",   # Wallis and Futuna
    "967": "967",   # Yemen
    "260": "260",   # Zambia
    "263": "263"    # Zimbabwe
                        }
                        area_code = area_map.get(code, "1")


                url = f"{website_config['api_domain']}{website_config['send_code_path']}"
                headers = {
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Encoding": get_random_accept_encoding(),
                    "Content-Type": "application/x-www-form-urlencoded",
                    "token": token,
                    "origin": website_config['origin'],
                    "x-requested-with": "mark.via.gp",
                    "referer": website_config['referer'],
                    "accept-language": ACCEPT_LANGUAGE,
                    "sec-ch-ua": random.choice(SEC_CH_UA_LIST),
                    "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
                    "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
                    **get_random_sec_fetch_headers(),
                    "priority": get_random_priority()
                }

                data = {
                    "phone": phone_encrypted,
                    "area_code": area_code
                }

                await asyncio.sleep(random.uniform(0.5, 2.0))
                async with asyncio.timeout(REQUEST_TIMEOUT):
                    async with session.post(url, headers=headers, data=data) as response:
                        response_data = await response.json()

                        # ✅ নতুন কন্ডিশন — যদি area_code সাপোর্টেড না হয়
                        if response_data.get("code") == -31 or "Please select area code" in response_data.get("msg", ""):
                            return {
                                "code": -31,
                                "msg": "🌍 Area code not supported",
                                "time": str(int(time.time())),
                                "data": None
                            }

                        # আগের "too frequent" চেক আগের মতো থাকবে
                        if response_data.get("code") == 0 and response_data.get("msg") == "Frequent requests, please wait!!":
                            logger.info(f"Frequent requests error detected, waiting 2 seconds to retry (attempt {attempt + 1}/{MAX_RETRIES})")
                            await asyncio.sleep(2)
                            continue

                        return response_data

            except asyncio.TimeoutError:
                if attempt == MAX_RETRIES - 1:
                    logger.error(f"Send code timed out after {REQUEST_TIMEOUT} seconds")
                    return {
                        "code": -1,
                        "msg": "⏰ Request timeout",
                        "time": str(int(time.time())),
                        "data": None
                    }
                await asyncio.sleep(1)

            except Exception as e:
                if attempt == MAX_RETRIES - 1:
                    logger.error(f"Error in send_code after {MAX_RETRIES} attempts: {str(e)}")
                    return {
                        "code": -1,
                        "msg": "🚫 Failed to send verification code",
                        "time": str(int(time.time())),
                        "data": None
                    }
                await asyncio.sleep(1)

        logger.error(f"Send code failed after {MAX_RETRIES} attempts")
        return {
            "code": -1,
            "msg": "🚫 Verification code sending failed",
            "time": str(int(time.time())),
            "data": None
        }

async def get_code(token, phone_plain, website_config, device_name):
    async with await device_manager.build_session(device_name) as session:
        for attempt in range(MAX_RETRIES):
            try:
                url = f"{website_config['api_domain']}{website_config['get_code_path']}"
                headers = {
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Encoding": get_random_accept_encoding(),
                    "Content-Type": "application/x-www-form-urlencoded",
                    "token": token,
                    "origin": website_config['origin'],
                    "x-requested-with": "mark.via.gp",
                    "referer": website_config['referer'],
                    "accept-language": ACCEPT_LANGUAGE,
                    "sec-ch-ua": random.choice(SEC_CH_UA_LIST),
                    "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
                    "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
                    **get_random_sec_fetch_headers(),
                    "priority": get_random_priority()
                }
                data = {"is_agree": "1", "phone": phone_plain.replace("+", "")}
                await asyncio.sleep(random.uniform(0.5, 2.0))
                async with asyncio.timeout(REQUEST_TIMEOUT):
                    async with session.post(url, headers=headers, data=data) as response:
                        return await response.json()
            except asyncio.TimeoutError:
                if attempt == MAX_RETRIES - 1:
                    logger.error(f"Get code timed out after {REQUEST_TIMEOUT} seconds")
                    raise
                await asyncio.sleep(1)
            except Exception as e:
                if attempt == MAX_RETRIES - 1:
                    logger.error(f"Error in get_code: {str(e)}")
                    raise
                await asyncio.sleep(1)

async def admin_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    
    if user_id != balance_manager.balance_config["admin_id"]:
        await update.message.reply_text(
            "❌ শুধুমাত্র এডমিন এই কমান্ড ব্যবহার করতে পারবেন।",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    
    admin_menu = (
        "🛠️ **এডমিন প্যানেল**\n\n"
        "📊 বর্তমান সেটিংস:\n"
        f"• ব্যালেন্স রেট: {balance_manager.balance_config['balance_per_online']} BDT\n"
        f"• মোট ইউজার: {len(balance_manager.user_balances)} জন\n\n"
        "⚡ দ্রুত কমান্ড:\n"
        "• /setrate 0.50 - ব্যালেন্স রেট সেট করুন\n"
        "• /userbalance 123456 - ইউজারের ব্যালেন্স দেখুন\n"
        "• /setbalance 123456 100 - ইউজারের ব্যালেন্স সেট করুন\n"
        "• /allusers - সব ইউজারের লিস্ট\n"
        "• /todaystats - আজকের স্ট্যাটস\n"
        "• /pendingwithdrawals - পেন্ডিং উত্তোলন রিকোয়েস্ট\n"
        "• /approve <id> - উত্তোলন অ্যাপ্রুভ করুন\n"
        "• /reject <id> - উত্তোলন রিজেক্ট করুন"
    )
    
    await update.message.reply_text(
        admin_menu,
        parse_mode='Markdown',
        reply_markup=get_main_keyboard(selected_website, user_id)
    )

async def set_balance_rate_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    
    if user_id != balance_manager.balance_config["admin_id"]:
        await update.message.reply_text(
            "❌ শুধুমাত্র এডমিন এই কমান্ড ব্যবহার করতে পারবেন।",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    
    if not context.args:
        current_rate = balance_manager.balance_config["balance_per_online"]
        await update.message.reply_text(
            f"💰 বর্তমান ব্যালেন্স রেট: {current_rate} BDT প্রতি অনলাইন নাম্বার\n\n"
            f"ব্যবহার: /setrate <amount>\n"
            f"উদাহরণ: /setrate 0.75\n"
            f"উদাহরণ: /setrate 1.00",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    
    try:
        new_rate = float(context.args[0])
        if new_rate < 0:
            await update.message.reply_text("❌ ব্যালেন্স রেট নেগেটিভ হতে পারবে না।")
            return
    except ValueError:
        await update.message.reply_text(
            "❌ অবৈধ Amount। দয়া করে সঠিক সংখ্যা লিখুন।",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    
    # ✅ Pass context for notifications
    if balance_manager.update_balance_rate(new_rate, user_id, context):
        await update.message.reply_text(
            f"✅ ব্যালেন্স রেট আপডেট করা হয়েছে!\n\n"
            f"💰 নতুন রেট: {new_rate} BDT প্রতি অনলাইন নাম্বার\n"
            f"👥 সকল ইউজারকে নোটিফাই করা হচ্ছে...",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
    else:
        await update.message.reply_text(
            "❌ রেট আপডেট করতে সমস্যা হয়েছে।",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )

async def user_balance_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    
    if user_id != balance_manager.balance_config["admin_id"]:
        await update.message.reply_text("❌ শুধুমাত্র এডমিন এই কমান্ড ব্যবহার করতে পারবেন।")
        return
    
    if not context.args:
        await update.message.reply_text("ব্যবহার: /userbalance <user_id>")
        return
    
    target_user_id = context.args[0]
    
    try:
        target_user_id_int = int(target_user_id)
    except ValueError:
        await update.message.reply_text("❌ অবৈধ User ID।")
        return
    
    stats = balance_manager.get_user_stats(target_user_id_int)
    if not stats:
        await update.message.reply_text(f"❌ User {target_user_id} এর কোনো ডেটা নেই।")
        return
    
    message = (
        f"👤 **ইউজার: {target_user_id}**\n\n"
        f"💵 বর্তমান ব্যালেন্স: {stats['total_balance']} BDT\n"
        f"📊 আজকের অনলাইন: {stats['today_count']} টি\n"
        f"📈 গত ৭ দিনের আয়: {stats['last_7_days']} BDT\n"
        f"📅 গত ৩০ দিনের আয়: {stats['last_30_days']} BDT\n"
        f"🏆 লাইফটাইম আয়: {stats['lifetime_earnings']} BDT\n"
        f"💸 উত্তোলন করা: {stats['withdrawn_amount']} BDT"
    )
    
    await update.message.reply_text(message, parse_mode='Markdown')

async def set_user_balance_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    
    if user_id != balance_manager.balance_config["admin_id"]:
        await update.message.reply_text("❌ শুধুমাত্র এডমিন এই কমান্ড ব্যবহার করতে পারবেন।")
        return
    
    if len(context.args) < 2:
        await update.message.reply_text("ব্যবহার: /setbalance <user_id> <amount>")
        return
    
    target_user_id = context.args[0]
    amount_str = context.args[1]
    
    try:
        target_user_id_int = int(target_user_id)
        amount = float(amount_str)
        if amount < 0:
            await update.message.reply_text("❌ ব্যালেন্স নেগেটিভ হতে পারবে না।")
            return
    except ValueError:
        await update.message.reply_text("❌ অবৈধ User ID বা Amount।")
        return
    
    with balance_manager.lock:
        user_id_str = str(target_user_id_int)
        
        if user_id_str not in balance_manager.user_balances:
            balance_manager.user_balances[user_id_str] = {
                "total_balance": 0.0,
                "lifetime_earnings": 0.0,
                "withdrawn_amount": 0.0
            }
        
        old_balance = balance_manager.user_balances[user_id_str]["total_balance"]
        balance_manager.user_balances[user_id_str]["total_balance"] = amount
        
        # Calculate lifetime earnings if increasing balance
        if amount > old_balance:
            difference = amount - old_balance
            balance_manager.user_balances[user_id_str]["lifetime_earnings"] += difference
        
        balance_manager.save_all_data()
    
    # Notify the user
    try:
        await context.bot.send_message(
            target_user_id_int,
            f"💰 **আপনার ব্যালেন্স আপডেট!**\n\n"
            f"💵 নতুন ব্যালেন্স: {amount} BDT\n"
            f"📊 পূর্বের ব্যালেন্স: {old_balance} BDT\n"
            f"⏰ আপডেট সময়: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"এডমিন দ্বারা ম্যানুয়ালি আপডেট করা হয়েছে।"
        )
    except Exception as e:
        logger.error(f"Error notifying user {target_user_id_int}: {str(e)}")
    
    await update.message.reply_text(
        f"✅ ইউজার {target_user_id} এর ব্যালেন্স আপডেট করা হয়েছে!\n\n"
        f"💰 নতুন ব্যালেন্স: {amount} BDT\n"
        f"📊 পূর্বের ব্যালেন্স: {old_balance} BDT\n"
        f"✅ ইউজারকে নোটিফাই করা হয়েছে"
    )

async def all_users_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    
    if user_id != balance_manager.balance_config["admin_id"]:
        await update.message.reply_text("❌ শুধুমাত্র এডমিন এই কমান্ড ব্যবহার করতে পারবেন।")
        return
    
    if not balance_manager.user_balances:
        await update.message.reply_text("❌ কোনো ইউজার নেই।")
        return
    
    total_balance = 0
    total_lifetime = 0
    total_withdrawn = 0
    
    users_list = []
    for user_id_str, data in balance_manager.user_balances.items():
        total_balance += data["total_balance"]
        total_lifetime += data["lifetime_earnings"]
        total_withdrawn += data["withdrawn_amount"]
        
        users_list.append(
            f"👤 {user_id_str} | 💰 {data['total_balance']} BDT | 🏆 {data['lifetime_earnings']} BDT"
        )
    
    message = (
        f"📊 **সকল ইউজার স্ট্যাটস**\n\n"
        f"👥 মোট ইউজার: {len(balance_manager.user_balances)} জন\n"
        f"💵 মোট ব্যালেন্স: {total_balance} BDT\n"
        f"🏆 মোট আয়: {total_lifetime} BDT\n"
        f"💸 মোট উত্তোলন: {total_withdrawn} BDT\n\n"
        f"**ইউজার লিস্ট:**\n" + "\n".join(users_list[:20])  # First 20 users only
    )
    
    if len(users_list) > 20:
        message += f"\n\n... এবং আরও {len(users_list) - 20} জন ইউজার"
    
    await update.message.reply_text(message, parse_mode='Markdown')

async def multi_account_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """পাওয়ারফুল মাল্টি-অ্যাকাউন্ট ম্যানেজমেন্ট"""
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    
    if not context.args:
        # মূল মেনু দেখান
        current_account = multi_account_manager.get_current_account_info(selected_website)
        all_accounts_status = multi_account_manager.get_all_accounts_status(selected_website)
        
        if not current_account:
            message = (
                f"🔢 **পাওয়ারফুল মাল্টি-অ্যাকাউন্ট সিস্টেম**\n\n"
                f"🌐 টাস্ক: {selected_website}\n"
                f"❌ কোনো অ্যাকাউন্ট কনফিগার করা নেই\n\n"
                f"⚡ **কমান্ডস:**\n"
                f"• /multiaccount login - সব অ্যাকাউন্ট লগইন করুন\n"
                f"• /multiaccount next - পরবর্তী অ্যাকাউন্ট\n"  
                f"• /multiaccount info - ডিটেইলড ইনফো\n"
                f"• /multiaccount reload - রিলোড\n\n"
                f"📁 `multi_accounts.json` ফাইলে অ্যাকাউন্ট যোগ করুন"
            )
        else:
            # অ্যাকাউন্ট স্ট্যাটাস তৈরি করুন
            status_lines = []
            for acc in all_accounts_status:
                status_icon = "🟢" if acc['token_available'] else "🔴"
                current_icon = " 👈" if acc['is_current'] else ""
                status_lines.append(f"{status_icon} {acc['username']}{current_icon}")
            
            message = (
                f"🔢 **পাওয়ারফুল মাল্টি-অ্যাকাউন্ট সিস্টেম**\n\n"
                f"🌐 টাস্ক: {selected_website}\n"
                f"👤 বর্তমান: {current_account['username']}\n"
                f"📊 মোট: {current_account['total_accounts']} টি\n"
                f"🔄 অটো-সুইচ: ✅ একটিভ\n\n"
                f"**অ্যাকাউন্ট স্ট্যাটাস:**\n" + "\n".join(status_lines) + "\n\n"
                f"⚡ প্রতি অনলাইন নাম্বারে স্বয়ংক্রিয়ভাবে সুইচ হবে!"
            )
        
        await update.message.reply_text(
            message,
            parse_mode='Markdown',
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    
    command = context.args[0].lower()
    
    if command == "login":
        # সব অ্যাকাউন্ট লগইন করুন
        device_name = str(user_id)
        
        if not device_manager.exists(device_name):
            await update.message.reply_text(
                "❌ প্রথমে 'Set User Agent' সেট করুন",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
            return
        
        await update.message.reply_text("🔄 সব অ্যাকাউন্ট লগইন করা হচ্ছে...")
        
        success = await multi_account_manager.login_all_accounts(selected_website, device_name)
        
        if success:
            # প্রথম অ্যাকাউন্ট সেট করুন
            first_token = multi_account_manager.get_next_account_token(selected_website)
            if first_token:
                await save_token(user_id, 'main', first_token, selected_website)
                
                # মনিটরিং শুরু করুন
                global auto_monitor
                if auto_monitor:
                    if auto_monitor.is_user_monitoring(user_id):
                        await auto_monitor.stop_monitoring(user_id)
                    await auto_monitor.start_monitoring(user_id, selected_website, first_token, device_name)
            
            await update.message.reply_text(
                f"✅ সব অ্যাকাউন্ট লগইন সফল!\n\n"
                f"🌐 টাস্ক: {selected_website}\n"
                f"👤 অ্যাকাউন্ট: মাল্টি-লগইন ({len(multi_account_manager.accounts_data.get(selected_website, []))} টি)\n"
                f"🔄 মনিটরিং শুরু করা হয়েছে\n\n"
                f"⚡ এখন থেকে প্রতি অনলাইন নাম্বারে অটো সুইচ হবে!",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
        else:
            await update.message.reply_text(
                f"❌ অ্যাকাউন্ট লগইন ব্যর্থ\n\n"
                f"ইউজারনেম/পাসওয়ার্ড চেক করুন",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
    
    elif command == "next":
        # ম্যানুয়ালি পরবর্তী অ্যাকাউন্টে সুইচ করুন
        next_token = multi_account_manager.get_next_account_token(selected_website)
        
        if not next_token:
            await update.message.reply_text(
                f"❌ {selected_website} এর জন্য কোনো একটিভ টোকেন নেই\n\n"
                f"প্রথমে /multiaccount login কমান্ড দিন",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
            return
        
        await save_token(user_id, 'main', next_token, selected_website)
        
        # মনিটরিং আপডেট করুন
        current_info = multi_account_manager.get_current_account_info(selected_website)
        
        if auto_monitor and auto_monitor.is_user_monitoring(user_id):
            device_name = str(user_id)
            await auto_monitor.stop_monitoring(user_id)
            await asyncio.sleep(2)
            await auto_monitor.start_monitoring(user_id, selected_website, next_token, device_name)
        
        await update.message.reply_text(
            f"✅ অ্যাকাউন্ট সুইচ সফল!\n\n"
            f"👤 নতুন অ্যাকাউন্ট: {current_info['username']}\n"
            f"📊 পজিশন: {current_info['index'] + 1}/{current_info['total_accounts']}\n"
            f"🌐 টাস্ক: {selected_website}\n"
            f"🔄 মনিটরিং আপডেট করা হয়েছে",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
    
    elif command == "info":
        # ডিটেইলড ইনফো
        all_accounts_status = multi_account_manager.get_all_accounts_status(selected_website)
        
        if not all_accounts_status:
            await update.message.reply_text(
                f"❌ {selected_website} এর জন্য কোনো অ্যাকাউন্ট কনফিগার করা নেই",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
            return
        
        detailed_info = []
        for acc in all_accounts_status:
            status = "🟢 লগইন করা" if acc['token_available'] else "🔴 লগইন নেই"
            current = " ✅ বর্তমান" if acc['is_current'] else ""
            detailed_info.append(f"{acc['index'] + 1}. {acc['username']} - {status}{current}")
        
        message = (
            f"🔢 **ডিটেইলড অ্যাকাউন্ট ইনফো - {selected_website}**\n\n" +
            "\n".join(detailed_info) +
            f"\n\n📊 মোট: {len(all_accounts_status)} টি অ্যাকাউন্ট"
        )
        
        await update.message.reply_text(
            message,
            parse_mode='Markdown',
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
    
    elif command == "reload":
        multi_account_manager.load_accounts()
        total_accounts = len(multi_account_manager.accounts_data.get(selected_website, []))
        
        await update.message.reply_text(
            f"✅ অ্যাকাউন্ট লিস্ট রিলোড করা হয়েছে\n\n"
            f"🌐 টাস্ক: {selected_website}\n"
            f"📊 মোট অ্যাকাউন্ট: {total_accounts} টি",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )

async def today_stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    
    if user_id != balance_manager.balance_config["admin_id"]:
        await update.message.reply_text("❌ শুধুমাত্র এডমিন এই কমান্ড ব্যবহার করতে পারবেন।")
        return
    
    today_key = balance_manager.get_today_key()
    today_data = balance_manager.daily_stats.get(today_key, {})
    
    if not today_data:
        await update.message.reply_text("❌ আজকের কোনো ডেটা নেই।")
        return
    
    total_online = 0
    total_users = len(today_data)
    
    for user_data in today_data.values():
        total_online += user_data.get("online_count", 0)
    
    total_balance = total_online * balance_manager.balance_config["balance_per_online"]
    
    message = (
        f"📊 **আজকের স্ট্যাটস ({today_key})**\n\n"
        f"👥 সক্রিয় ইউজার: {total_users} জন\n"
        f"🟢 মোট অনলাইন: {total_online} টি\n"
        f"💰 মোট ব্যালেন্স: {total_balance} BDT\n"
        f"📈 প্রতি অনলাইন: {balance_manager.balance_config['balance_per_online']} BDT\n\n"
        f"**ইউজার অনুযায়ী:**"
    )
    
    # Top 10 users today
    sorted_users = sorted(
        today_data.items(),
        key=lambda x: x[1].get("online_count", 0),
        reverse=True
    )[:10]
    
    for i, (user_id_str, data) in enumerate(sorted_users, 1):
        online_count = data.get("online_count", 0)
        user_balance = online_count * balance_manager.balance_config["balance_per_online"]
        message += f"\n{i}. 👤 {user_id_str} | 🟢 {online_count} | 💰 {user_balance} BDT"
    
    await update.message.reply_text(message, parse_mode='Markdown')

async def pending_withdrawals_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    
    if user_id != balance_manager.balance_config["admin_id"]:
        await update.message.reply_text("❌ শুধুমাত্র এডমিন এই কমান্ড ব্যবহার করতে পারবেন।")
        return
    
    pending_requests = {
        k: v for k, v in balance_manager.withdrawal_requests.items() 
        if v.get("status") == "pending"
    }
    
    if not pending_requests:
        await update.message.reply_text("✅ কোনো পেন্ডিং উত্তোলন রিকোয়েস্ট নেই।")
        return
    
    message = "🔄 **পেন্ডিং উত্তোলন রিকোয়েস্ট**\n\n"
    
    for request_id, request in pending_requests.items():
        message += (
            f"🆔 **রিকোয়েস্ট ID:** {request_id}\n"
            f"👤 **ইউজার:** {request['user_id']}\n"
            f"📛 **নাম:** {request['name']}\n"
            f"📱 **bKash:** {request['bkash_number']}\n"
            f"💰 **Amount:** {request['amount']} BDT\n"
            f"⏰ **সময়:** {request['timestamp'][:19]}\n"
            f"✅ **Approve:** /approve {request_id}\n"
            f"❌ **Reject:** /reject {request_id}\n"
            f"────────────────────\n"
        )
    
    await update.message.reply_text(message, parse_mode='Markdown')

async def get_phone_list(token, account_type, website_config, device_name, user_id=None, context=None):
    async with await device_manager.build_session(device_name) as session:
        if not token or len(token) < 10:
            logger.error(f"Invalid or missing token for {account_type} account")
            return f"🔑 Invalid or expired token"
        
        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Encoding': get_random_accept_encoding(),
            'token': token,
            'Origin': website_config['origin'],
            'Referer': website_config['referer'],
            'X-Requested-With': 'mark.via.gp',
            "accept-language": ACCEPT_LANGUAGE,
            "sec-ch-ua": random.choice(SEC_CH_UA_LIST),
            "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            **get_random_sec_fetch_headers(),
            "priority": get_random_priority()
        }

        logger.info(f"Fetching phone list for {account_type} account ({website_config['name']}) - DISPLAY ONLY")
        
        try:
            await asyncio.sleep(random.uniform(0.5, 2.0))
            async with asyncio.timeout(REQUEST_TIMEOUT):
                async with session.post(website_config['phone_list_url'], headers=headers) as response:
                    response.raise_for_status()
                    data = await response.json()
        except Exception as e:
            logger.error(f"Phone list request error: {str(e)}")
            return f"🌐 Connection failed"

        if data.get("code") != 1:
            logger.error(f"API response error: {data.get('msg', 'Unknown error')}")
            return f"🚫 Invalid token or no data"

        phones = data.get("data", []) or []
        now = datetime.now(timezone.utc)

        # ✅ শুধুমাত্র display করার জন্য, balance add করবেন না
        total = len(phones)
        online = sum(1 for p in phones if p.get("status") == 1)
        offline = total - online

        # ✅ Get today's income score - FIXED
        today_income_info = ""
        try:
            today_score = await get_today_income_score(token, website_config, device_name)
            if today_score and today_score != "N/A":
                today_income_info = f"💰 Income Score: {today_score}\n"
                logger.info(f"Today income score for user {user_id}: {today_score}")
        except Exception as e:
            logger.error(f"Error fetching today income score in phone list: {str(e)}")

        output = [
            f"🕒 Last Updated: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"🔗 Total Linked: {total}",
            f"🟢 Online: {online}",
            f"🔴 Offline: {offline}",
            f"💰 Balance per online: {balance_manager.balance_config['balance_per_online']} BDT"
        ]

        # ✅ Add today income score if available
        if today_income_info:
            output.insert(1, today_income_info)  # Insert after time

        output.append(f"\n📱 Phone Numbers Status ({website_config['name']}):")

        for idx, phone_data in enumerate(phones, 1):
            phone = "" + str(phone_data.get("phone", ""))[-15:]
            status = phone_data.get("status", 0)
            status_icon = "🟢" if status == 1 else "🔴"
            output.append(f"{idx:2d}. {phone} {status_icon}")

        return "\n".join(output)
        
async def get_today_income_score(token, website_config, device_name):
    """Get today's income score from the API - FIXED VERSION"""
    try:
        async with await device_manager.build_session(device_name) as session:
            headers = {
                'Accept': 'application/json, text/plain, */*',
                'Accept-Encoding': 'gzip, deflate, br',
                'token': token,
                'Origin': website_config['origin'],
                'Referer': website_config['referer'],
                'X-Requested-With': 'mark.via.gp',
                "accept-language": "en-US,en;q=0.9",
                "sec-ch-ua": '"Not)A;Brand";v="99", "Chromium";v="113", "Google Chrome";v="113"',
                "sec-ch-ua-mobile": "?1",
                "sec-ch-ua-platform": '"Android"',
                "sec-fetch-site": "cross-site",
                "sec-fetch-mode": "cors",
                "sec-fetch-dest": "empty",
                "priority": "u=1, i"
            }
            
            # API endpoint for today's income score
            api_url = f"{website_config['api_domain']}api/task_stat/wsServer"
            
            logger.info(f"Fetching today income score from: {api_url}")
            
            async with asyncio.timeout(REQUEST_TIMEOUT):
                async with session.get(api_url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        logger.info(f"Today income score API response: {data}")
                        
                        if data.get("code") == 1:
                            score_data = data.get("data", {})
                            # ✅ CORRECT FIELD NAME: today_income_score
                            today_score = score_data.get("today_income_score", 0)
                            
                            # Apply admin percentage setting
                            admin_percentage = balance_manager.balance_config.get("income_percentage", 100)
                            final_score = today_score * (admin_percentage / 100)
                            
                            logger.info(f"Today income score found: {today_score} -> {final_score} ({admin_percentage}%)")
                            return f"${final_score:.2f}"
                        else:
                            error_msg = data.get('msg', 'Unknown error')
                            logger.error(f"Today income score API error: {error_msg}")
                            return "N/A"
                    else:
                        logger.error(f"Today income score HTTP error: {response.status}")
                        return "N/A"
                        
    except asyncio.TimeoutError:
        logger.error("Today income score request timeout")
        return "Timeout"
    except Exception as e:
        logger.error(f"Error fetching today income score: {str(e)}")
        return "N/A"


async def set_income_percentage_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    
    if user_id != balance_manager.balance_config["admin_id"]:
        await update.message.reply_text("❌ শুধুমাত্র এডমিন এই কমান্ড ব্যবহার করতে পারবেন।")
        return
    
    if not context.args:
        current_percentage = balance_manager.balance_config.get("income_percentage", 100)
        await update.message.reply_text(
            f"💰 বর্তমান ইনকাম পার্সেন্টেজ: {current_percentage}%\n\n"
            f"ব্যবহার: /setincome <percentage>\n"
            f"উদাহরণ: /setincome 50 (৫০% দেখাবে)\n"
            f"উদাহরণ: /setincome 100 (১০০% দেখাবে)",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    
    try:
        new_percentage = int(context.args[0])
        if new_percentage < 1 or new_percentage > 100:
            await update.message.reply_text("❌ পার্সেন্টেজ ১ থেকে ১০০ এর মধ্যে হতে হবে।")
            return
    except ValueError:
        await update.message.reply_text("❌ অবৈধ পার্সেন্টেজ। দয়া করে সঠিক সংখ্যা লিখুন।")
        return
    
    with balance_manager.lock:
        old_percentage = balance_manager.balance_config.get("income_percentage", 100)
        balance_manager.balance_config["income_percentage"] = new_percentage
        balance_manager.save_all_data()
    
    # ✅ Send notification to all users
    notification_msg = (
        f"📢 **ইনকাম পার্সেন্টেজ আপডেট!**\n\n"
        f"💰 নতুন পার্সেন্টেজ: {new_percentage}%\n"
        f"📊 পূর্বের পার্সেন্টেজ: {old_percentage}%\n"
        f"⏰ আপডেট সময়: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    
    asyncio.create_task(balance_manager.notify_all_users(context, notification_msg))
    
    await update.message.reply_text(
        f"✅ ইনকাম পার্সেন্টেজ আপডেট করা হয়েছে: {new_percentage}%\n"
        f"👥 সকল ইউজারকে নোটিফাই করা হচ্ছে...",
        reply_markup=get_main_keyboard(selected_website, user_id)
    )


async def approve_withdrawal_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    
    if user_id != balance_manager.balance_config["admin_id"]:
        await update.message.reply_text("❌ শুধুমাত্র এডমিন এই কমান্ড ব্যবহার করতে পারবেন।")
        return
    
    if not context.args:
        await update.message.reply_text("ব্যবহার: /approve <request_id>")
        return
    
    request_id = context.args[0]
    success, result = balance_manager.process_withdrawal(request_id, "approve", user_id)
    
    if success:
        # Get request details
        request = balance_manager.withdrawal_requests.get(request_id)
        if request:
            user_id_str = request["user_id"]
            try:
                # Notify user
                await context.bot.send_message(
                    int(user_id_str),
                    f"✅ আপনার উত্তোলন রিকোয়েস্ট অনুমোদিত হয়েছে!\n\n"
                    f"💰 Amount: {request['amount']} BDT\n"
                    f"📱 bKash: {request['bkash_number']}\n"
                    f"⏰ সময়: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                    f"টাকা ২৪ ঘন্টার মধ্যে পাঠিয়ে দেওয়া হবে।\n"
                    f"💰 আপনার বর্তমান ব্যালেন্স: {balance_manager.get_user_stats(int(user_id_str))['total_balance']} BDT"
                )
            except Exception as e:
                logger.error(f"Error notifying user: {str(e)}")
        
        await update.message.reply_text(f"✅ উত্তোলন রিকোয়েস্ট #{request_id} অনুমোদিত হয়েছে।")
    else:
        await update.message.reply_text(f"❌ Error: {result}")

async def reject_withdrawal_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    
    if user_id != balance_manager.balance_config["admin_id"]:
        await update.message.reply_text("❌ শুধুমাত্র এডমিন এই কমান্ড ব্যবহার করতে পারবেন।")
        return
    
    if not context.args:
        await update.message.reply_text("ব্যবহার: /reject <request_id>")
        return
    
    request_id = context.args[0]
    success, result = balance_manager.process_withdrawal(request_id, "reject", user_id)
    
    if success:
        # Get request details
        request = balance_manager.withdrawal_requests.get(request_id)
        if request:
            user_id_str = request["user_id"]
            try:
                # Notify user
                current_stats = balance_manager.get_user_stats(int(user_id_str))
                await context.bot.send_message(
                    int(user_id_str),
                    f"❌ আপনার উত্তোলন রিকোয়েস্ট বাতিল হয়েছে।\n\n"
                    f"💰 Amount: {request['amount']} BDT\n"
                    f"📱 bKash: {request['bkash_number']}\n\n"
                    f"💰 Amount আপনার ব্যালেন্সে ফেরত দেওয়া হয়েছে।\n"
                    f"💵 আপনার বর্তমান ব্যালেন্স: {current_stats['total_balance']} BDT\n\n"
                    f"আবার চেষ্টা করুন।"
                )
            except Exception as e:
                logger.error(f"Error notifying user: {str(e)}")
        
        await update.message.reply_text(f"✅ উত্তোলন রিকোয়েস্ট #{request_id} বাতিল হয়েছে। Amount ফেরত দেওয়া হয়েছে।")
    else:
        await update.message.reply_text(f"❌ Error: {result}")

async def balance_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    
    stats = balance_manager.get_user_stats(user_id)
    if not stats:
        await update.message.reply_text(
            "❌ আপনার কোনো ব্যালেন্স তথ্য পাওয়া যায়নি।",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    
    message = (
        f"💰 **আপনার ব্যালেন্স তথ্য:**\n\n"
        f"💵 বর্তমান ব্যালেন্স: {stats['total_balance']} BDT\n"
        f"📊 আজকের অনলাইন: {stats['today_count']} টি\n"
        f"🔢 মোট অনলাইন: {stats['total_online_count']} টি\n"
        f"📈 গত ৭ দিনের আয়: {stats['last_7_days']} BDT\n"
        f"📅 গত ৩০ দিনের আয়: {stats['last_30_days']} BDT\n"
        f"🗓️ এই মাসের আয়: {stats['current_month']} BDT\n"
        f"🏆 লাইফটাইম আয়: {stats['lifetime_earnings']} BDT\n"
        f"💸 উত্তোলন করা: {stats['withdrawn_amount']} BDT\n\n"
        f"ℹ️ প্রতি অনলাইন নাম্বারে: {balance_manager.balance_config['balance_per_online']} BDT যোগ হয়"
    )
    
    await update.message.reply_text(
        message,
        parse_mode='Markdown',
        reply_markup=get_main_keyboard(selected_website, user_id)
    )

async def withdraw_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    
    if not context.args:
        await update.message.reply_text(
            "ব্যবহার: /withdraw <amount>\nউদাহরণ: /withdraw 50",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    
    try:
        amount = float(context.args[0])
    except ValueError:
        await update.message.reply_text(
            "❌ অবৈধ Amount। দয়া করে সঠিক সংখ্যা লিখুন।",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    
    context.user_data['withdraw_amount'] = amount
    context.user_data['state'] = 'awaiting_bkash_info'
    
    await update.message.reply_text(
        f"💰 উত্তোলনের Amount: {amount} BDT\n\n"
        f"📱 আপনার বিকাশ নাম্বার দিন:",
        reply_markup=get_main_keyboard(selected_website, user_id)
    )

async def set_balance_rate_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    
    if user_id != balance_manager.balance_config["admin_id"]:
        await update.message.reply_text(
            "❌ শুধুমাত্র এডমিন এই কমান্ড ব্যবহার করতে পারবেন।",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    
    if not context.args:
        current_rate = balance_manager.balance_config["balance_per_online"]
        await update.message.reply_text(
            f"বর্তমান রেট: {current_rate} BDT প্রতি অনলাইন নাম্বার\n\n"
            f"ব্যবহার: /setrate <amount>\nউদাহরণ: /setrate 0.75",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    
    try:
        new_rate = float(context.args[0])
    except ValueError:
        await update.message.reply_text(
            "❌ অবৈধ Amount। দয়া করে সঠিক সংখ্যা লিখুন।",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    
    if balance_manager.update_balance_rate(new_rate, user_id):
        await update.message.reply_text(
            f"✅ ব্যালেন্স রেট আপডেট করা হয়েছে: {new_rate} BDT প্রতি অনলাইন নাম্বার",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
    else:
        await update.message.reply_text(
            "❌ রেট আপডেট করতে সমস্যা হয়েছে।",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
                
async def stop_monitoring_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """ইউজার ম্যানুয়ালি মনিটরিং বন্ধ করার কমান্ড - NEW VERSION"""
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    
    global auto_monitor
    
    if not auto_monitor:
        await update.message.reply_text(
            "❌ মনিটরিং সিস্টেম এখনও শুরু হয়নি।",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    
    # শুধুমাত্র বর্তমান ইউজারের মনিটরিং বন্ধ করুন
    if auto_monitor.is_user_monitoring(user_id):
        try:
            await auto_monitor.stop_monitoring(user_id)
            message = "🛑 **মনিটরিং বন্ধ করা হয়েছে!**\n\nআপনার অটোমেটিক নাম্বার ডিটেকশন বন্ধ করা হয়েছে।"
            logger.info(f"User {user_id} manually stopped monitoring - SUCCESS")
        except Exception as e:
            message = f"❌ মনিটরিং বন্ধ করতে সমস্যা হয়েছে: {str(e)}"
            logger.error(f"Error stopping monitoring for user {user_id}: {str(e)}")
    else:
        message = "ℹ️ **কোনো একটিভ মনিটরিং নেই।**\n\nআপনার জন্য কোনো মনিটরিং চলছে না।"
    
    await update.message.reply_text(
        message,
        parse_mode='Markdown',
        reply_markup=get_main_keyboard(selected_website, user_id)
    )

async def login_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    text = update.message.text.strip()
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    logger.info(f"Login command triggered by user {user_id} for {selected_website}")
    
    if text.startswith('/login ') and len(context.args) > 0:
        token = context.args[0].strip()
        if len(token) > 10:
            device_name = str(user_id)
            if not device_manager.exists(device_name):
                logger.error(f"No device set for user {user_id}")
                await update.message.reply_text(
                    "❌ Please set a User Agent first using 'Set User Agent'.",
                    reply_markup=get_main_keyboard(selected_website, user_id)
                )
                return
            await save_token(user_id, 'main', token, selected_website)
            
            # ✅ অটোমেটিক মনিটরিং শুরু করুন
            global auto_monitor
            if auto_monitor:
                await auto_monitor.start_monitoring(user_id, selected_website, token, device_name)
            
            context.user_data.clear()
            context.user_data['selected_website'] = selected_website
            logger.info(f"User {user_id} saved account token via /login for {selected_website}")
            await update.message.reply_text(
                f"✅ Account login successful for {selected_website}!\nAccount token: <code>{token}...</code>",
                parse_mode='HTML',
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
        else:
            logger.error(f"User {user_id} provided invalid token via /login for {selected_website}")
            await update.message.reply_text(
                "❌ Invalid token format. Token should be longer than 10 characters.",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
        return

    context.user_data['state'] = 'awaiting_website_selection_login'
    logger.info(f"User {user_id} state set to awaiting_website_selection_login via /login")
    await update.message.reply_text(
        f"Please select a website for account login:",
        reply_markup=get_website_selection_keyboard()
    )

async def monitor_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """মনিটরিং স্ট্যাটাস চেক করার কমান্ড - শুধুমাত্র বর্তমান ইউজারের জন্য"""
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    
    global auto_monitor
    
    # ✅ চেক করুন যে auto_monitor initialized কিনা
    if not auto_monitor:
        await update.message.reply_text(
            "❌ মনিটরিং সিস্টেম এখনও শুরু হয়নি। বট রিস্টার্ট করুন।",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    
    # ✅ শুধুমাত্র বর্তমান ইউজারের স্ট্যাটাস দেখান
    status = auto_monitor.get_monitoring_status(user_id)
    
    if status:
        # Last check time format করুন
        last_check = status['last_check']
        if last_check:
            try:
                last_check_dt = datetime.fromisoformat(last_check)
                last_check_str = last_check_dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                last_check_str = last_check
        else:
            last_check_str = "কখনও না"
        
        message = (
            f"🔍 **আপনার মনিটরিং স্ট্যাটাস:**\n\n"
            f"🌐 **টাস্ক:** {status['website']}\n"
            f"📱 **ডিভাইস:** {status['device']}\n"
            f"🔄 **চলছে:** {'✅ হ্যাঁ' if status['is_running'] else '❌ না'}\n"
            f"⏰ **সর্বশেষ চেক:** {last_check_str}\n"
            f"👤 **ইউজার আইডি:** {user_id}\n\n"
            f"💡 প্রতি ৩০ সেকেন্ডে নতুন নাম্বার চেক করা হয়"
        )
    else:
        message = (
            "❌ **কোনো একটিভ মনিটরিং নেই।**\n\n"
            "মনিটরিং শুরু করতে:\n"
            "1. 'Set User Agent' ক্লিক করুন\n" 
            "2. 'Log in Account' দিয়ে লগইন করুন\n"
            "3. অটোমেটিক মনিটরিং শুরু হয়ে যাবে!\n\n"
            "বর্তমান লগইন স্ট্যাটাস চেক করতে 'My Balance' ক্লিক করুন।"
        )
    
    await update.message.reply_text(
        message,
        parse_mode='Markdown',
        reply_markup=get_main_keyboard(selected_website, user_id)
    )

async def handle_credentials(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    text = update.message.text.strip()
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    website = selected_website
    website_config = WEBSITE_CONFIGS[website]
    device_name = str(user_id)
    
    if not device_manager.exists(device_name):
        await update.message.reply_text(
            "❌ Please set user agent first using 'Set User Agent'.",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
        
    logger.info(f"Handling credentials for user {user_id} on {website}")

    if ":" in text:
        username, password = text.split(":", 1)
        username = username.strip()
        password = password.strip()
        await update.message.reply_text("⏳ Attempting login...")
        login_result = await login_with_credentials(username, password, website_config, device_name)
        if login_result["success"]:
            account_type = 'main'
            await save_token(user_id, account_type, login_result["token"], website)
            
            # ✅ অটোমেটিক মনিটরিং শুরু করুন
            global auto_monitor
            if auto_monitor and login_result["token"]:
                await auto_monitor.start_monitoring(user_id, website, login_result["token"], device_name)
                logger.info(f"✅ Auto monitoring started for user {user_id} after login")
            
            context.user_data.clear()
            context.user_data['selected_website'] = selected_website
            logger.info(f"User {user_id} login successful for {account_type} account on {website}")
            await update.message.reply_text(
                f"✅ Account login successful for {website}!\nAccount token: <code>{login_result['token']}...</code>",
                parse_mode='HTML',
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
        else:
            error_details = (
                f"❌ Login Failed\n\n"
                f"Error: {login_result['error']}\n"
                f"Response: {json.dumps(login_result['response'], indent=2) if login_result['response'] else 'None'}"
            )
            logger.error(f"Login failed for user {user_id} on {website}: {error_details}")
            await update.message.reply_text(
                f"<pre>{error_details}</pre>",
                parse_mode='HTML',
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
        return

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    user_state = context.user_data.get('state', '')
    text = update.message.text.strip()
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    logger.info(f"Message from user {user_id} on selected: {selected_website}, text: '{text}', state: {user_state}")

    # ✅ প্রথমে চেক করুন যদি মেসেজটি ফোন নাম্বার হয় (এবং state awaiting_phone না থাকে)
    if not user_state and re.match(r'^\+?[0-9\s\-\(\)]{10,}$', text.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')):
        # অটোমেটিকভাবে ফোন নাম্বার হিসেবে প্রসেস করুন
        logger.info(f"Auto-detected phone number: {text} from user {user_id}")
        context.user_data['state'] = 'awaiting_phone'
        await process_phone_number(update, context)
        return

    # বাকি কোড একই থাকবে...

    if text in WEBSITE_CONFIGS.keys() and user_state in ['awaiting_website_selection_login', 'awaiting_website_selection_register']:
        if user_state == 'awaiting_website_selection_login':
            context.user_data['selected_website'] = text
            context.user_data['state'] = 'awaiting_login'
            await update.message.reply_text(
                f"✅ Please enter your token.",
                reply_markup=get_main_keyboard(text, user_id)
            )
        elif user_state == 'awaiting_website_selection_register':
            context.user_data['register_website'] = text
            context.user_data['register_account_type'] = 'main'
            context.user_data['state'] = 'registering'
            await update.message.reply_text(
                f"📱 ফোন নাম্বার দিন:",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
        return
    elif text == "Back to Main Menu" and user_state in ['awaiting_website_selection_login', 'awaiting_website_selection_register']:
        context.user_data['state'] = ''
        await update.message.reply_text(
            f"✅ Returned to main menu.",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    elif text == "Log in Account":
        context.user_data['state'] = 'awaiting_website_selection_login'
        await update.message.reply_text(
            f"🌐 Please select a Task for account login:",
            reply_markup=get_website_selection_keyboard()
        )
        return
    elif text == f"Link {selected_website} WhatsApp":
        context.user_data['state'] = 'awaiting_phone'
        await update.message.reply_text(
            "📱 Send your WhatsApp number. Send /stop to exit.",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    elif text == f"{selected_website} Number List":
        await phone_list_command(update, context)
        return
    elif text == "Register Account":
        context.user_data['state'] = 'awaiting_website_selection_register'
        await update.message.reply_text(
            f"🌐 Please select a website for account registration:",
            reply_markup=get_website_selection_keyboard()
        )
        return
    elif text == "My Balance":
        await balance_command(update, context)
        return
    elif text == "Withdraw":
        await update.message.reply_text(
            "ব্যবহার: /withdraw <amount>\nউদাহরণ: /withdraw 50",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    elif text == "Admin Panel":
        await admin_command(update, context)
        return
    elif text.startswith("Set User Agent") or text.startswith("✅ Set User Agent"):
        device_name = str(user_id)
        try:
            profile = await device_manager.create_new_device(device_name)
            await update.message.reply_text(
                f"✅ New realistic device created and User Agent set:\n<code>{profile.ua}</code>\n\n"
                f"Device ID: {profile.device_id[:10]}...\nNew device identity created.",
                parse_mode='HTML',
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
            logger.info(f"User {user_id} created new device: UA {profile.ua}")
        except Exception as e:
            logger.error(f"Error creating device for user {user_id}: {str(e)}")
            await update.message.reply_text(
                f"❌ Error creating device: {str(e)}",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
        return
    elif text.startswith("Set Proxy") or text.startswith("✅ Set Proxy"):
        if not device_manager.exists(str(user_id)):
            await update.message.reply_text(
                "❌ Please set user agent first using 'Set User Agent'.",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
            return
        await update.message.reply_text("📡 Setting up proxy automatically...")
        success, proxy_info, message = await device_manager.auto_set_proxy(str(user_id))
        if success:
            response = (
                f"✅ {message}\n\n"
                f"🌐 Public IP: {proxy_info['public_ip']}\n\n"
                f"📍 Location Information:\n"
                f"Country: {proxy_info['location']['country']}\n"
                f"Region: {proxy_info['location']['region']}\n"
                f"City: {proxy_info['location']['city']}\n"
                f"ZIP Code: {proxy_info['location']['zip_code']}\n"
                f"Latitude: {proxy_info['location']['latitude']}\n"
                f"Longitude: {proxy_info['location']['longitude']}\n"
                f"Timezone: {proxy_info['location']['timezone']}\n\n"
                f"🏢 Network Information:\n"
                f"ISP: {proxy_info['network']['isp']}\n"
                f"Organization: {proxy_info['network']['organization']}\n"
                f"AS Number: {proxy_info['network']['as_number']}\n"
                f"Proxy/VPN: {proxy_info['network']['proxy_vpn']}\n"
                f"Hosting: {proxy_info['network']['hosting']}"
            )
            logger.info(f"Proxy automatically set for user {user_id}")
        else:
            response = f"❌ {message}"
            logger.error(f"Failed to set proxy for user {user_id}: {message}")
        await update.message.reply_text(
            response,
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    elif text == "Reset All":
        context.user_data['state'] = 'confirm_reset_all'
        await update.message.reply_text(
            "আপনি কি নিশ্চিত যে সবকিছু রিসেট করতে চান? এটি সকল ডেটা এবং লগ ফাইল মুছে ফেলবে। আপনাকে নতুন ইউজার এজেন্ট ম্যানুয়ালি সেট করতে হবে।",
            reply_markup=get_confirmation_keyboard()
        )
        return

    # বাকি কোড একই থাকবে...

    # Withdrawal process states
    elif user_state == 'awaiting_bkash_info':
        context.user_data['bkash_number'] = text
        context.user_data['state'] = 'awaiting_name_info'
        await update.message.reply_text(
            "👤 আপনার পুরো নাম দিন:",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    
    elif user_state == 'awaiting_name_info':
        name = text
        amount = context.user_data.get('withdraw_amount')
        bkash_number = context.user_data.get('bkash_number')
        
        success, result = balance_manager.request_withdrawal(user_id, bkash_number, name, amount)
        
        if success:
            # Notify admin
            admin_id = balance_manager.balance_config["admin_id"]
            try:
                await context.bot.send_message(
                    admin_id,
                    f"🔄 নতুন উত্তোলন রিকোয়েস্ট:\n\n"
                    f"👤 User: {user_id}\n"
                    f"📛 Name: {name}\n"
                    f"📱 bKash: {bkash_number}\n"
                    f"💰 Amount: {amount} BDT\n"
                    f"🆔 Request ID: {result}\n\n"
                    f"✅ Approve: /approve {result}\n"
                    f"❌ Reject: /reject {result}"
                )
            except Exception as e:
                logger.error(f"Error notifying admin: {str(e)}")
            
            await update.message.reply_text(
                f"✅ উত্তোলন রিকোয়েস্ট পাঠানো হয়েছে!\n\n"
                f"💰 Amount: {amount} BDT\n"
                f"📱 bKash: {bkash_number}\n"
                f"👤 Name: {name}\n\n"
                f"এডমিন কনফার্ম করলে আপনার টাকা পাঠিয়ে দেব।",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
        else:
            await update.message.reply_text(
                f"❌ উত্তোলন রিকোয়েস্ট ব্যর্থ: {result}",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
        
        context.user_data['state'] = ''
        return

    if user_state == 'confirm_reset_all':
        if text == "Yes":
            success, message = await reset_all(user_id)
            context.user_data.clear()
            await update.message.reply_text(
                message,
                parse_mode='HTML',
                reply_markup=get_main_keyboard(DEFAULT_SELECTED_WEBSITE, user_id)
            )
        
        elif text == "No":
            await update.message.reply_text(
                "✅ রিসেট বাতিল করা হয়েছে।",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
        context.user_data['state'] = ''
        return
    elif user_state == 'awaiting_login':
        if ":" in text:
            await handle_credentials(update, context)
        elif len(text) > 10:
            device_name = str(user_id)
            if not device_manager.exists(device_name):
                await update.message.reply_text(
                    "❌ Please set user agent first using 'Set User Agent'.",
                    reply_markup=get_main_keyboard(selected_website, user_id)
                )
                return
            await save_token(user_id, 'main', text, selected_website)
            context.user_data['state'] = ''
            await update.message.reply_text(
                f"✅ Account login successful for {selected_website}!\nAccount token: <code>{text}...</code>",
                parse_mode='HTML',
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
        else:
            await update.message.reply_text(
                "❌ Invalid input. Please provide a token (longer than 10 characters) or username:password.",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
        return
    elif user_state == 'awaiting_phone':
        await process_phone_number(update, context)
        return
    elif user_state == 'registering':
        website = context.user_data['register_website']
        website_config = WEBSITE_CONFIGS[website]
        account_type = context.user_data.get('register_account_type', 'main')
        device_name = str(user_id)
        if not device_manager.exists(device_name):
            await update.message.reply_text(
                "❌ Please set user agent first using 'Set User Agent'.",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
            context.user_data['state'] = ''
            return
        if 'reg_phone' not in context.user_data:
            context.user_data['reg_phone'] = text
            await update.message.reply_text("🔑 পাসওয়ার্ড দিন:")
            return
        elif 'reg_password' not in context.user_data:
            context.user_data['reg_password'] = text
            await update.message.reply_text("🔄 কনফার্ম পাসওয়ার্ড দিন (ম্যানুয়ালি টাইপ করুন):")
            return
        elif 'reg_confirm_password' not in context.user_data:
            context.user_data['reg_confirm_password'] = text
            await update.message.reply_text("🎁 রেফার কোড দিন (অপশনাল, স্কিপ করতে /skip লিখুন):")
            return
        else:
            invite_code_input = "" if text == "/skip" else text
            phone = context.user_data['reg_phone']
            password = context.user_data['reg_password']
            confirm_password = context.user_data['reg_confirm_password']
            reg_host = website_config['origin'].split('//')[1]
            
            if invite_code_input and len(invite_code_input) < 4:
                await update.message.reply_text(
                    "❌ অবৈধ রেফার কোড। কোডটি কমপক্ষে ৪ অক্ষরের হতে হবে। আবার চেষ্টা করুন বা /skip ব্যবহার করুন।",
                    reply_markup=get_main_keyboard(selected_website, user_id)
                )
                return

            await update.message.reply_text(f"⏳ রেজিস্ট্রেশন চেষ্টা করা হচ্ছে...")
            response_data = await register_account(website_config, phone, password, confirm_password, invite_code_input, device_name, reg_host)
            
            if response_data is None or not isinstance(response_data, dict):
                error_msg = "Server returned no response or invalid response"
                logger.error(f"Registration failed for user {user_id} on {website}: {error_msg}")
                await update.message.reply_text(
                    f"❌ রেজিস্ট্রেশন ব্যর্থ: {error_msg}\n\nআবার চেষ্টা করুন।",
                    reply_markup=get_main_keyboard(selected_website, user_id)
                )
                context.user_data['state'] = ''
                if 'reg_phone' in context.user_data:
                    del context.user_data['reg_phone']
                if 'reg_password' in context.user_data:
                    del context.user_data['reg_password']
                if 'reg_confirm_password' in context.user_data:
                    del context.user_data['reg_confirm_password']
                return

            if response_data.get("code") == 1:
                await update.message.reply_text("✅ রেজিস্ট্রেশন সফল! অটো লগইন চেষ্টা করা হচ্ছে...")
                login_result = await login_with_credentials(phone, password, website_config, device_name)
                if login_result["success"]:
                    await save_token(user_id, account_type, login_result["token"], website)
                    context.user_data['selected_website'] = website
                    # ডায়নামিকভাবে referral_field ব্যবহার করা এবং None চেক
                    referral_field = website_config.get('referral_field', 'invite_code')
                    data = response_data.get("data")
                    invite_code = data.get(referral_field, "N/A") if isinstance(data, dict) else "N/A"
                    bd_time = datetime.now(timezone.utc) + timedelta(hours=6)  # Dhaka is UTC+6
                    formatted_time = bd_time.strftime("%Y-%m-%d %H:%M:%S")
                    number = 1
                    if os.path.exists(REGISTRATION_FILE):
                        with open(REGISTRATION_FILE, 'r') as f:
                            lines = f.readlines()
                            if lines:
                                last_number = 0
                                for line in reversed(lines):
                                    if line.strip() and line.strip()[0].isdigit():
                                        try:
                                            last_number = int(line.split('.')[0])
                                            break
                                        except (ValueError, IndexError):
                                            continue
                                number = last_number + 1
                    os.makedirs(os.path.dirname(REGISTRATION_FILE) or '.', exist_ok=True)
                    with open(REGISTRATION_FILE, 'a') as f:
                        f.write(f"{number}. Date: {bd_time.strftime('%Y-%m-%d')} Time: {bd_time.strftime('%H:%M:%S')}\n")
                        f.write(f"   Website: {website}\n")
                        f.write(f"   Username: {phone}\n")
                        f.write(f"   Password: {password}\n")
                        f.write(f"   Invite Code: {invite_code}\n")
                        f.write(f"   Used: no\n")
                        f.write("\n")
                    logger.info(f"Registration data saved for user {user_id} on {website} in {REGISTRATION_FILE}")
                    await update.message.reply_text(
                        f"✅ অটো লগইন সফল! টোকেন: {login_result['token'][:10]}...\n\n"
                        f"রেজিস্ট্রেশন ডেটা সেভ করা হয়েছে।",
                        reply_markup=get_main_keyboard(context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE), user_id)
                    )
                else:
                    error_msg = login_result.get("error", "Unknown login error")
                    logger.error(f"Auto login failed for user {user_id} on {website}: {error_msg}")
                    await update.message.reply_text(
                        f"❌ অটো লগইন ব্যর্থ। ম্যানুয়াল লগইন করুন: ইউজারনেম:পাসওয়ার্ড বা টোকেন দিন।\n\nError: {error_msg}",
                        reply_markup=get_main_keyboard(selected_website, user_id)
                    )
            else:
                error_msg = response_data.get("msg", "Unknown error")
                logger.error(f"Registration failed for user {user_id} on {website}: {error_msg}")
                await update.message.reply_text(
                    f"❌ রেজিস্ট্রেশন ব্যর্থ: {error_msg}\n\nপ্রতিক্রিয়া: {json.dumps(response_data, indent=2)}\n\nআবার চেষ্টা করুন।",
                    reply_markup=get_main_keyboard(selected_website, user_id)
                )
            context.user_data['state'] = ''
            if 'reg_phone' in context.user_data:
                del context.user_data['reg_phone']
            if 'reg_password' in context.user_data:
                del context.user_data['reg_password']
            if 'reg_confirm_password' in context.user_data:
                del context.user_data['reg_confirm_password']
            return
    else:
        await update.message.reply_text(
            "আমি এই কমান্ড বুঝতে পারিনি। মেনু থেকে একটি অপশন নির্বাচন করুন।",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )

async def process_phone_number(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    phone = update.message.text.strip()
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    account_type = 'main'
    website = selected_website
    website_config = WEBSITE_CONFIGS[website]
    device_name = str(user_id)

    # ✅ ইউজার এজেন্ট চেক
    if not device_manager.exists(device_name):
        await update.message.reply_text(
            "❌ প্রথমে 'Set User Agent' দিয়ে ইউজার এজেন্ট সেট করুন।",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return

    logger.info(f"Processing phone number for user {user_id} on {website}")

    # ✅ নম্বর ক্লিন করা
    phone_clean = re.sub(r'[^\d+]', '', phone)
    if phone_clean.startswith('+'):
        normalized_phone = phone_clean
    elif phone_clean.startswith('1') and len(phone_clean) == 11:
        normalized_phone = '+' + phone_clean
    elif phone_clean.startswith('880') and len(phone_clean) == 13:
        normalized_phone = '+' + phone_clean
    elif len(phone_clean) == 10:
        normalized_phone = '+1' + phone_clean
    else:
        normalized_phone = '+' + phone_clean if phone_clean else None

    if not normalized_phone:
        await update.message.reply_text(
            "❌ অবৈধ ফোন নাম্বার। দয়া করে সঠিক কান্ট্রি কোডসহ নাম্বার দিন, যেমন:\n"
            "+8801XXXXXXXXX (বাংলাদেশ)\n"
            "+1XXXXXXXXXX (USA/Canada)\n\n"
            "অন্য নাম্বার পাঠান অথবা /stop লিখে বের হয়ে যান।",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return

    # ✅ ১ ঘন্টার restriction চেক (শুধুমাত্র successful নাম্বারের জন্য)
    if not number_tracker.can_submit_number(normalized_phone, user_id, website):
        remaining_time = number_tracker.get_remaining_time(normalized_phone, user_id, website)
        hours = remaining_time // 3600
        minutes = (remaining_time % 3600) // 60
        
        await update.message.reply_text(
            f"⏰ **এই নাম্বারটি আবার submit করতে হবে:**\n\n"
            f"📱 নাম্বার: `{normalized_phone}`\n"
            f"🌐 Task: {website}\n"
            f"⏳ বাকি সময়: {hours} ঘন্টা {minutes} মিনিট\n\n"
            f"ℹ️ এই নাম্বারটি ইতিমধ্যে {website} এ successful ভাবে online হয়েছে।\n"
            f"একই নাম্বার 24 ঘন্টার আগে আবার submit করা যাবে না।\n"
            f"✅ কিন্তু অন্য Task-এ submit করতে পারবেন!",
            parse_mode='Markdown',
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        context.user_data['state'] = ''  # Reset state
        return

    # ✅ টোকেন চেক করা
    tokens = load_tokens()
    token = tokens.get(str(user_id), {}).get(website, {}).get(account_type)
    if not token:
        context.user_data.pop('state', None)
        context.user_data['selected_website'] = selected_website
        await update.message.reply_text(
            f"❌ কোনো {website} একাউন্ট লগইন করা নেই। প্রথমে লগইন করুন।",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return

    # ✅ ফোন এনক্রিপ্ট
    phone_encrypted = await encrypt_phone(normalized_phone)

    # ⏳ স্ট্যাটাস দেখানো
    status_msg = await update.message.reply_text("📤 ভেরিফিকেশন কোড পাঠানো হচ্ছে...")

    # ✅ কোড পাঠানো (অটো area_code সহ)
    response = await send_code(token, phone_encrypted, website_config, device_name, phone_plain=normalized_phone)

    # 🔎 রেসপন্স চেক
    if response.get("code") == 1:
        await status_msg.edit_text("✅ ভেরিফিকেশন কোড সফলভাবে পাঠানো হয়েছে! অনুগ্রহ করে অপেক্ষা করুন...")
        await asyncio.sleep(1)
        otp_response = await get_code(token, normalized_phone, website_config, device_name)
        if otp_response and otp_response.get("code") == 1:
            otp = otp_response.get("data", {}).get("code", "N/A")
            
            # ✅ OTP পাওয়ার পর ইউজারকে মেসেজ দিন
            await update.message.reply_text(
                f"📩 **Link কোড!**\n\n"
                f"📱 নাম্বার: `{normalized_phone}`\n"
                f"🔢 Link কোড: `{otp}`\n\n"
                
                f"নাম্বারটি online হলে আপনাকে স্বয়ংক্রিয়ভাবে নোটিফিকেশন দেওয়া হবে।",
                parse_mode='Markdown',
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
            
            # ✅ Context state reset করুন
            context.user_data['state'] = ''
            
            logger.info(f"OTP received for phone {normalized_phone} by user {user_id}")
            
        else:
            error_msg = "কোড পাওয়া যায়নি। সার্ভার থেকে কোনো Link code ফেরত আসেনি।"
            await update.message.reply_text(
                f"❌ {error_msg}",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
            context.user_data['state'] = ''  # Reset state on error
            logger.error(f"No OTP received for phone {normalized_phone} by user {user_id}")
            
    elif response.get("code") == -31:
        # ✅ Area code সাপোর্ট না করলে
        await status_msg.edit_text(
            "❌ এই এরিয়া কোড বর্তমানে সাপোর্টেড নয়। দয়া করে এডমিনের সাথে যোগাযোগ করুন।",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        context.user_data['state'] = ''  # Reset state on error
    else:
        error_msg = response.get('msg', 'অজানা ত্রুটি')
        await status_msg.edit_text(
            f"❌ কোড পাঠাতে ব্যর্থ: {error_msg}",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        context.user_data['state'] = ''  # Reset state on error

async def link_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    logger.info(f"Link command triggered by user {user_id} for {selected_website}")
    tokens = load_tokens()
    device_name = str(user_id)
    if not device_manager.exists(device_name):
        await update.message.reply_text(
            "❌ Please set user agent first using 'Set User Agent'.",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    if str(user_id) not in tokens or selected_website not in tokens[str(user_id)] or 'main' not in tokens[str(user_id)][selected_website]:
        await update.message.reply_text(
            f"❌ {selected_website} account not found. Please login first with 'Log in Account'",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    context.user_data['state'] = 'awaiting_phone'
    await update.message.reply_text(
        "📱 Send your Canada WhatsApp number. Send /stop to exit.",
        reply_markup=get_main_keyboard(selected_website, user_id)
    )

async def phone_list_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    website_config = WEBSITE_CONFIGS[selected_website]
    device_name = str(user_id)
    if not device_manager.exists(device_name):
        await update.message.reply_text("❌ Please set user agent first using 'Set User Agent'.", reply_markup=get_main_keyboard(selected_website, user_id))
        return
    logger.info(f"Phone list command triggered by user {user_id} for {selected_website}")
    tokens = load_tokens()
    if str(user_id) not in tokens or selected_website not in tokens[str(user_id)] or 'main' not in tokens[str(user_id)][selected_website]:
        await update.message.reply_text(
            f"❌ {selected_website} account not found. Please login first with 'Log in Account'",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    token = tokens[str(user_id)][selected_website]['main']
    await update.message.reply_text(f"⏳ Fetching phone list for {selected_website} account...")
    result = await get_phone_list(token, 'main', website_config, device_name, user_id, context)
    await update.message.reply_text(result, reply_markup=get_main_keyboard(selected_website, user_id))

async def get_pagination_keyboard(current_page, total_pages, user_id):
    buttons = []
    if current_page > 1:
        buttons.append(InlineKeyboardButton("⬅️ Previous", callback_data=f"regs_page_{current_page-1}_{user_id}"))
    if current_page < total_pages:
        buttons.append(InlineKeyboardButton("Next ➡️", callback_data=f"regs_page_{current_page+1}_{user_id}"))
    return InlineKeyboardMarkup([buttons]) if buttons else None

async def get_registrations(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    
    if not os.path.exists(REGISTRATION_FILE):
        await update.message.reply_text(
            "কোনো রেজিস্ট্রেশন ডেটা পাওয়া যায়নি।",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return

    with open(REGISTRATION_FILE, 'r') as f:
        content = f.read()

    entries = re.split(r'\n\s*\n', content.strip())
    valid_entries = [entry for entry in entries if entry.strip() and re.match(r'^\d+\.', entry)]
    
    entries_per_page = 10
    total_entries = len(valid_entries)
    total_pages = (total_entries + entries_per_page - 1) // entries_per_page
    current_page = context.user_data.get('regs_page', 1)
    
    if current_page < 1:
        current_page = 1
    elif current_page > total_pages:
        current_page = total_pages
    
    context.user_data['regs_page'] = current_page
    
    start_idx = (current_page - 1) * entries_per_page
    end_idx = min(start_idx + entries_per_page, total_entries)
    
    now = datetime.now(timezone.utc) + timedelta(hours=6)  # Dhaka UTC+6
    output = []
    
    for entry in valid_entries[start_idx:end_idx]:
        lines = entry.split('\n')
        first_line = lines[0].strip()
        match = re.match(r'(\d+)\.\s*Date:\s*(\d{4}-\d{2}-\d{2})\s*Time:\s*(\d{2}:\d{2}:\d{2})', first_line)
        if not match:
            continue
        num = match.group(1)
        date_str = match.group(2)
        time_str = match.group(3)
        try:
            reg_time = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc) + timedelta(hours=6)
        except ValueError:
            continue
        age = now - reg_time
        age_days = age.days
        age_hours = age.seconds // 3600  # দিন + ঘন্টা দেখাচ্ছে
        used = "no"
        for line in lines:
            if line.strip().startswith("Used:"):
                used = line.strip().split(":", 1)[1].strip().lower()
                break
        data_lines = []
        for line in lines:
            if line.strip().startswith("Used:"):
                emoji = "🚫" if used == "no" else "⛔️"
                data_lines.append(f"   Used: {used} {emoji}")
            else:
                data_lines.append(line)
        if used == "no":
            days_emoji = "✅️" if age_days >= 3 else "🔄"
            data_lines.append(f"   {age_days} days {age_hours} hours old {days_emoji}")
        entry_text = '\n'.join(data_lines)
        output.append(f"```{entry_text}```")

    full_output = '\n\n'.join(output) if output else "কোনো বৈধ রেজিস্ট্রেশন ডেটা পাওয়া যায়নি।"
    
    full_output = f"📄 পেজ {current_page}/{total_pages} ({total_entries}টি এন্ট্রি)\n\n{full_output}"
    
    await update.message.reply_text(
        full_output,
        parse_mode='Markdown',
        reply_markup=await get_pagination_keyboard(current_page, total_pages, user_id)
    )

async def handle_callback_query(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()  # Always answer callback queries first
    
    user_id = query.from_user.id
    data = query.data
    
    if data.startswith("regs_page_"):
        try:
            _, _, page_str, query_user_id = data.split("_")
            if int(query_user_id) != user_id:
                await query.answer("এই বাটনটি আপনার জন্য নয়।")
                return
            
            new_page = int(page_str)
            context.user_data['regs_page'] = new_page
            
            # Reuse the same logic from get_registrations
            if not os.path.exists(REGISTRATION_FILE):
                await query.edit_message_text("কোনো রেজিস্ট্রেশন ডেটা পাওয়া যায়নি।")
                return

            with open(REGISTRATION_FILE, 'r', encoding='utf-8') as f:
                content = f.read()

            entries = re.split(r'\n\s*\n', content.strip())
            valid_entries = [entry for entry in entries if entry.strip() and re.match(r'^\d+\.', entry)]
            
            entries_per_page = 10
            total_entries = len(valid_entries)
            total_pages = max(1, (total_entries + entries_per_page - 1) // entries_per_page)
            new_page = min(max(1, new_page), total_pages)
            
            start_idx = (new_page - 1) * entries_per_page
            end_idx = min(start_idx + entries_per_page, total_entries)
            
            now = datetime.now(timezone.utc) + timedelta(hours=6)
            output = []
            
            for entry in valid_entries[start_idx:end_idx]:
                lines = [line.strip() for line in entry.split('\n') if line.strip()]
                if not lines:
                    continue
                    
                first_line = lines[0]
                match = re.match(r'(\d+)\.\s*Date:\s*(\d{4}-\d{2}-\d{2})\s*Time:\s*(\d{2}:\d{2}:\d{2})', first_line)
                if not match:
                    continue
                    
                num = match.group(1)
                date_str = match.group(2)
                time_str = match.group(3)
                
                try:
                    reg_time = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc) + timedelta(hours=6)
                    age = now - reg_time
                    age_days = age.days
                    age_hours = age.seconds // 3600
                except ValueError:
                    continue
                    
                used = "no"
                for line in lines:
                    if line.lower().startswith("used:"):
                        used = line.split(":", 1)[1].strip().lower()
                        break
                        
                entry_text = []
                for line in lines:
                    if not line.lower().startswith("used:"):
                        entry_text.append(line)
                        
                if used == "no":
                    days_text = f"{age_days} দিন {age_hours} ঘন্টা"
                    if age_days >= 3:
                        entry_text.append(f"   Age: {days_text} ✅️")
                    else:
                        entry_text.append(f"   Age: {days_text} 🔄")
                else:
                    entry_text.append("   Used: yes ⛔️")
                    
                # Markdown code block যোগ করুন
                output.append(f"```{'\n'.join(entry_text)}```")

            if not output:
                full_output = "কোনো বৈধ রেজিস্ট্রেশন ডেটা পাওয়া যায়নি।"
            else:
                full_output = f"📄 পেজ {new_page}/{total_pages} ({total_entries}টি এন্ট্রি)\n\n" + "\n\n".join(output)
            
            await query.edit_message_text(
                full_output,
                parse_mode='Markdown',
                reply_markup=await get_pagination_keyboard(new_page, total_pages, user_id))
                
        except Exception as e:
            logger.error(f"Error in callback handler: {str(e)}")
            await query.edit_message_text("❌ পেজ লোড করতে সমস্যা হয়েছে।")

async def mark_used(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    if not context.args:
        await update.message.reply_text("Usage: /markused <entry number>", reply_markup=get_main_keyboard(selected_website, user_id))
        return
    try:
        num = int(context.args[0])
    except ValueError:
        await update.message.reply_text("Invalid number.", reply_markup=get_main_keyboard(selected_website, user_id))
        return
    if not os.path.exists(REGISTRATION_FILE):
        await update.message.reply_text("No registration data.", reply_markup=get_main_keyboard(selected_website, user_id))
        return

    with open(REGISTRATION_FILE, 'r') as f:
        content = f.read()

    entries = re.split(r'\n\s*\n', content.strip())
    found = False
    new_entries = []

    for entry in entries:
        if not entry.strip():
            new_entries.append(entry)
            continue
        lines = entry.split('\n')
        first_line = lines[0].strip()
        match = re.match(r'(\d+)\.', first_line)
        if match and int(match.group(1)) == num:
            found = True
            has_used = False
            for i, line in enumerate(lines):
                if line.strip().startswith("Used:"):
                    lines[i] = "   Used: yes ✅️"
                    has_used = True
                elif line.strip().startswith(f"   {match.group(1)} days old"):
                    lines[i] = ""  # Remove age line if present
            if not has_used:
                lines.append("   Used: yes ✅️")
            new_entries.append('\n'.join([line for line in lines if line.strip()]))
        else:
            new_entries.append(entry)

    if not found:
        await update.message.reply_text(f"No entry found with number {num}.", reply_markup=get_main_keyboard(selected_website, user_id))
        return

    with open(REGISTRATION_FILE, 'w') as f:
        f.write('\n\n'.join(new_entries) + '\n')

    await update.message.reply_text(f"Entry {num} marked as used.", reply_markup=get_main_keyboard(selected_website, user_id))

async def delete_used(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    if not os.path.exists(REGISTRATION_FILE):
        await update.message.reply_text("No registration data.", reply_markup=get_main_keyboard(selected_website, user_id))
        return

    with open(REGISTRATION_FILE, 'r') as f:
        content = f.read()

    entries = re.split(r'\n\s*\n', content.strip())
    kept_entries = []
    count = 0

    for entry in entries:
        if not entry.strip():
            continue
        if "Used: yes" in entry:
            continue
        kept_entries.append(entry)

    if not kept_entries:
        with open(REGISTRATION_FILE, 'w') as f:
            f.write('')
        await update.message.reply_text("All used entries deleted. No entries left.", reply_markup=get_main_keyboard(selected_website, user_id))
        return

    renumbered_entries = []
    for idx, entry in enumerate(kept_entries, 1):
        lines = entry.split('\n')
        first_line = lines[0].strip()
        match = re.match(r'(\d+)\.', first_line)
        if match:
            lines[0] = lines[0].replace(f"{match.group(1)}.", f"{idx}.")
        renumbered_entries.append('\n'.join(lines))

    with open(REGISTRATION_FILE, 'w') as f:
        f.write('\n\n'.join(renumbered_entries) + '\n')

    deleted_count = len(entries) - len(kept_entries)
    await update.message.reply_text(f"{deleted_count} used entries deleted. {len(renumbered_entries)} entries remain.", reply_markup=get_main_keyboard(selected_website, user_id))

async def stop(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    context.user_data.clear()
    context.user_data['selected_website'] = selected_website
    await update.message.reply_text(
        "✅ Process stopped. Select an option to continue.",
        reply_markup=get_main_keyboard(selected_website, user_id)
    )

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
    try:
        # Get the actual error
        error = getattr(context, 'error', None)
        if not error:
            return
            
        error_msg = str(error)
        
        # ✅ CRITICAL FIX: Handle ALL Conflict errors silently
        if "409" in error_msg or "Conflict" in error_msg:
            # Don't log as error, just ignore completely
            return
            
        # Handle other specific errors quietly
        elif isinstance(error, NetworkError):
            logger.warning(f"🌐 Network error")
        elif isinstance(error, BadRequest):
            logger.warning(f"🚫 Bad request")
        elif "RetryAfter" in error_msg:
            logger.warning(f"⏰ Rate limit hit")
        else:
            logger.warning(f"Unexpected error: {error_msg}")
            
    except Exception as e:
        # Silent fail for error handler errors
        pass

# ==============================================
# SIMPLE SOLUTION - BOT PRIORITY
# ==============================================

def main():
    global auto_monitor
    try:
        import psutil, os
        # Stop any existing bot instances first
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.info['cmdline'] and 'python' in proc.info['cmdline'] and 'wslink' in ' '.join(proc.info['cmdline']):
                    if proc.info['pid'] != os.getpid():
                        proc.terminate()
            except:
                pass
        
        app = Application.builder().token(TELEGRAM_TOKEN).build()
        
        # Initialize auto monitor
        auto_monitor = AutoNumberMonitor(app)
        logger.info("✅ Auto Number Monitor initialized")

        # -------------------------
        # Command Handlers
        # -------------------------
        app.add_handler(CommandHandler("start", start))
        app.add_handler(CommandHandler("login", login_command))
        app.add_handler(CommandHandler("link", link_command))
        app.add_handler(CommandHandler("phone_list", phone_list_command))
        app.add_handler(CommandHandler("regs", get_registrations))
        app.add_handler(CommandHandler("markused", mark_used))
        app.add_handler(CommandHandler("deleteused", delete_used))
        app.add_handler(CommandHandler("stop", stop))
        
        # Balance commands
        app.add_handler(CommandHandler("balance", balance_command))
        app.add_handler(CommandHandler("withdraw", withdraw_command))
        
        # Admin commands
        app.add_handler(CommandHandler("admin", admin_command))
        app.add_handler(CommandHandler("setrate", set_balance_rate_command))
        app.add_handler(CommandHandler("userbalance", user_balance_command))
        app.add_handler(CommandHandler("setbalance", set_user_balance_command))
        app.add_handler(CommandHandler("allusers", all_users_command))
        app.add_handler(CommandHandler("todaystats", today_stats_command))
        app.add_handler(CommandHandler("pendingwithdrawals", pending_withdrawals_command))
        app.add_handler(CommandHandler("approve", approve_withdrawal_command))
        app.add_handler(CommandHandler("reject", reject_withdrawal_command))
        app.add_handler(CommandHandler("setincome", set_income_percentage_command))
        
        # ✅ NEW: Monitor status command
        app.add_handler(CommandHandler("monitorstatus", monitor_status))
        
        # ✅ NEW: Stop monitoring command
        app.add_handler(CommandHandler("stopmonitor", stop_monitoring_command))

# Multi-account commands
        app.add_handler(CommandHandler("multiaccount", multi_account_command))

        # Message & callback handlers
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
        app.add_handler(CallbackQueryHandler(handle_callback_query))
        
        # Error handler
        app.add_error_handler(error_handler)

        logger.info("🤖 Bot is starting with MONITOR STATUS and STOP MONITOR commands...")
        print("✅ Bot started successfully!")
        print("🔧 New commands: /monitorstatus, /stopmonitor added")
        
    
        
        # ✅ IMPROVED polling with conflict resolution
        app.run_polling(
            allowed_updates=Update.ALL_TYPES,
            poll_interval=3,
            timeout=60,
            drop_pending_updates=True,
            close_loop=False
        )
        
    except Exception as e:
        logger.error(f"Bot failed to start: {str(e)}")
        print(f"❌ Bot failed: {str(e)}")
        print("🔄 Restarting in 5 seconds...")
        time.sleep(5)
        main()

# ==============================================
# BASIC WEB SERVER FOR RENDER
# ==============================================

from http.server import BaseHTTPRequestHandler, HTTPServer
import threading

class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health' or self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Bot is running!')
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        # Disable access logs
        return

def run_web_server():
    """Run a simple web server in a separate thread"""
    port = int(os.environ.get("PORT", 8080))
    server = HTTPServer(('0.0.0.0', port), HealthHandler)
    print(f"🌐 Web server running on port {port}")
    server.serve_forever()

if __name__ == "__main__":
    # Check if we're on Render
    if "PORT" in os.environ:
        print("🚀 Render.com environment detected - starting bot and web server")
        
        # Start web server in background thread
        web_thread = threading.Thread(target=run_web_server, daemon=True)
        web_thread.start()
        
        # Start bot in main thread
        main()
    else:
        # Local development
        print("🚀 Local development - starting bot only")
        main()
