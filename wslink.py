# --- Realistic Unique Device System যুক্ত করা হয়েছে ---
# Feature:
#   1) reset_all_devices() → সব device profile + cookies ডিলিট করবে
#   2) create_new_device(user_tag) → প্রতিবার নতুন realistic device বানাবে
#   3) মেনুর Reset এবং Set User Agent বাটনের সাথে bind করা হয়েছে

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
class MultiAccountStatus:
    enabled: bool = False
    current_account_index: int = 0
    total_accounts: int = 0
    processing: bool = False
    current_phone: str = ""
    website: str = ""
    last_activity: str = ""
    # নতুন ফিল্ড যোগ করুন
    enabled_websites: List[str] = field(default_factory=list)  # সক্রিয় ওয়েবসাইটের লিস্ট
    current_website_index: int = 0  # বর্তমান ওয়েবসাইটের ইনডেক্স
    round_robin_mode: bool = False  # রাউন্ড-রবিন মোড চালু আছে কিনা
    all_website_accounts: Dict[str, List[Dict[str, str]]] = field(default_factory=dict)  # সব ওয়েবসাইটের একাউন্টস

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
TELEGRAM_TOKEN = "8445698549:AAGcT3wyGecDs3Nbs4UFbjViIABOA5NYw9s"
ADMIN_ID = 5624278091
TOKEN_FILE = "tokens.json"
USER_STATUS_FILE = "user_status.json"
USER_AGENTS_FILE = "user_agents.json"  # Legacy
USED_USER_AGENTS_FILE = "used_user_agents.json"  # Legacy
DEVICE_HISTORY_FILE = "device_history.json"  # Legacy
# Multi-Account System Constants
MULTI_ACCOUNT_FILE = "multi_accounts.json"
MULTI_ACCOUNT_STATUS_FILE = "multi_account_status.json"
REQUEST_TIMEOUT = 8
MAX_RETRIES = 3
MAX_CODE_ATTEMPTS = 10
CODE_CHECK_INTERVAL = 2
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
    "TASKS": {
        "name": "TASKS",
        "api_domain": "https://task33.club/",
        "origin": "https://task33.com",
        "referer": "https://task33.com/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/ws_phone/sendCode",
        "get_code_path": "api/ws_phone/getCode",
        "phone_list_url": "https://task33.club/api/ws_phone/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code"
    },
    "JOB": {
        "name": "JOB",
        "api_domain": "https://job777.club/",
        "origin": "https://job777.me",
        "referer": "https://job777.me/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/ws_phone/sendCode",
        "get_code_path": "api/ws_phone/getCode",
        "phone_list_url": "https://job777.club/api/ws_phone/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code"
    },
    "TG": {
        "name": "TG",
        "api_domain": "https://tg299.online/",
        "origin": "https://tg299.club",
        "referer": "https://tg299.club/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/ws_phone/sendCode",
        "get_code_path": "api/ws_phone/getCode",
        "phone_list_url": "https://tg299.online/api/ws_phone/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code"
    },
    "NEWS": {
        "name": "NEWS",
        "api_domain": "https://mess6.club/",
        "origin": "https://news669.com",
        "referer": "https://news669.com/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/ws_phone/sendCode",
        "get_code_path": "api/ws_phone/getCode",
        "phone_list_url": "https://mess6.club/api/ws_phone/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code"
    },
    "SMS": {
        "name": "SMS",
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
    "OK": {
        "name": "OK",
        "api_domain": "https://ok8job.cc/",
        "origin": "https://www.ok8job.net",
        "referer": "https://www.ok8job.net/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/ws_phone/sendCode",
        "get_code_path": "api/ws_phone/getCode",
        "phone_list_url": "https://ok8job.cc/api/ws_phone/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code"
    },
    "W8": {
        "name": "W8",
        "api_domain": "https://w8job.cyou/",
        "origin": "https://w8job.club",
        "referer": "https://w8job.club/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/ws_phone/sendCode",
        "get_code_path": "api/ws_phone/getCode",
        "phone_list_url": "https://w8job.cyou/api/ws_phone/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code"
    },
     "DEP": {
        "name": "DEP",
        "api_domain": "https://dep6.club/",
        "origin": "https://dep6.com",
        "referer": "https://dep6.com/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/ws_phone/sendCode",
        "get_code_path": "api/ws_phone/getCode",
        "phone_list_url": "https://dep6.club/api/ws_phone/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code"
    },
    "ATM": {
        "name": "ATM",
        "api_domain": "https://atm001.com/",
        "origin": "http://atm8.me",
        "referer": "http://atm8.me/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/ws_phone/sendCode",
        "get_code_path": "api/ws_phone/getCode",
        "phone_list_url": "https://atm001.com/api/ws_phone/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code"
    },
    "MK": {
        "name": "MK",
        "api_domain": "https://mk8ht.com/",
        "origin": "http://mmmmm.cyou",
        "referer": "http://mmmmm.cyou/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/ws_phone/sendCode",
        "get_code_path": "api/ws_phone/getCode",
        "phone_list_url": "https://mk8ht.com/api/ws_phone/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code"
    },
    "TG377": {
        "name": "TG377",
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
    "WA": {
        "name": "WA",
        "api_domain": "https://web.wa2.club/",
        "origin": "http://wa2.club",
        "referer": "http://wa2.club/",
        "login_path": "api/user/signIn",
        "send_code_path": "api/ws_phone/sendCode",
        "get_code_path": "api/ws_phone/getCode",
        "phone_list_url": "https://web.wa2.club/api/ws_phone/phoneList",
        "signup_path": "api/user/signUp",
        "referral_field": "invite_code"
    },
    "AMZN": {
        "name": "AMZ",
        "api_domain": "https://web.amznvip.com/",
        "origin": "https://amznvip.com",
        "referer": "https://amznvip.com/",
        "login_path": "api/user/login",
        "send_code_path": "api/task/send_code",
        "get_code_path": "api/task/get_code",
        "phone_list_url": "https://web.amznvip.com/api/task/phone_list",
        "signup_path": "api/user/register",
        "referral_field": "invitation"
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

class MultiAccountManager:
    def __init__(self):
        self.accounts_file = MULTI_ACCOUNT_FILE
        self.status_file = MULTI_ACCOUNT_STATUS_FILE
    
    async def save_accounts(self, user_id: int, accounts: List[Dict[str, str]], website: str):
        """সব multi accounts সেভ করে (সব ওয়েবসাইটের জন্য)"""
        try:
            if os.path.exists(self.accounts_file):
                async with aiofiles.open(self.accounts_file, 'r') as f:
                    data = json.loads(await f.read())
            else:
                data = {}
            
            user_key = str(user_id)
            if user_key not in data:
                data[user_key] = {}
            
            data[user_key][website] = accounts
            
            async with aiofiles.open(self.accounts_file, 'w') as f:
                await f.write(json.dumps(data, indent=4))
            
            logger.info(f"Saved {len(accounts)} multi-accounts for user {user_id} on {website}")
            
            # status-এও সেভ করুন
            status = await self.load_status(user_id)
            status.all_website_accounts[website] = accounts
            await self.save_status(user_id, status)
            
            return True
        except Exception as e:
            logger.error(f"Error saving multi-accounts: {str(e)}")
            return False
    
    async def load_accounts(self, user_id: int, website: str) -> List[Dict[str, str]]:
        """multi accounts লোড করে (সব ওয়েবসাইটের জন্য)"""
        try:
            if not os.path.exists(self.accounts_file):
                return []
            
            async with aiofiles.open(self.accounts_file, 'r') as f:
                data = json.loads(await f.read())
            
            user_key = str(user_id)
            if user_key in data and website in data[user_key]:
                return data[user_key][website]
            return []
        except Exception as e:
            logger.error(f"Error loading multi-accounts: {str(e)}")
            return []
    
    async def save_status(self, user_id: int, status: MultiAccountStatus):
        """multi account status সেভ করে"""
        try:
            if os.path.exists(self.status_file):
                async with aiofiles.open(self.status_file, 'r') as f:
                    data = json.loads(await f.read())
            else:
                data = {}
            
            data[str(user_id)] = {
                "enabled": status.enabled,
                "current_account_index": status.current_account_index,
                "total_accounts": status.total_accounts,
                "processing": status.processing,
                "current_phone": status.current_phone,
                "website": status.website,
                "last_activity": status.last_activity,
                # নতুন ফিল্ডস
                "enabled_websites": status.enabled_websites,
                "current_website_index": status.current_website_index,
                "round_robin_mode": status.round_robin_mode,
                "all_website_accounts": status.all_website_accounts
            }
            
            async with aiofiles.open(self.status_file, 'w') as f:
                await f.write(json.dumps(data, indent=4))
            
            return True
        except Exception as e:
            logger.error(f"Error saving multi-account status: {str(e)}")
            return False
    
    async def load_status(self, user_id: int) -> MultiAccountStatus:
        """multi account status লোড করে"""
        try:
            if not os.path.exists(self.status_file):
                return MultiAccountStatus()
            
            async with aiofiles.open(self.status_file, 'r') as f:
                data = json.loads(await f.read())
            
            user_data = data.get(str(user_id), {})
            
            # পুরোনো ডেটা কম্প্যাটিবিলিটির জন্য
            all_website_accounts = user_data.get("all_website_accounts", {})
            if not all_website_accounts:
                # পুরোনো ডেটা থেকে কনভার্ট করুন
                try:
                    if os.path.exists(self.accounts_file):
                        async with aiofiles.open(self.accounts_file, 'r') as f:
                            accounts_data = json.loads(await f.read())
                        all_website_accounts = accounts_data.get(str(user_id), {})
                except:
                    all_website_accounts = {}
            
            return MultiAccountStatus(
                enabled=user_data.get("enabled", False),
                current_account_index=user_data.get("current_account_index", 0),
                total_accounts=user_data.get("total_accounts", 0),
                processing=user_data.get("processing", False),
                current_phone=user_data.get("current_phone", ""),
                website=user_data.get("website", ""),
                last_activity=user_data.get("last_activity", ""),
                # নতুন ফিল্ডস
                enabled_websites=user_data.get("enabled_websites", []),
                current_website_index=user_data.get("current_website_index", 0),
                round_robin_mode=user_data.get("round_robin_mode", False),
                all_website_accounts=all_website_accounts
            )
        except Exception as e:
            logger.error(f"Error loading multi-account status: {str(e)}")
            return MultiAccountStatus()
    
    async def clear_accounts(self, user_id: int, website: str = None):
        """multi accounts ক্লিয়ার করে"""
        try:
            if not os.path.exists(self.accounts_file):
                return True
            
            async with aiofiles.open(self.accounts_file, 'r') as f:
                data = json.loads(await f.read())
            
            user_key = str(user_id)
            if user_key in data:
                if website:
                    if website in data[user_key]:
                        del data[user_key][website]
                else:
                    del data[user_key]
            
            async with aiofiles.open(self.accounts_file, 'w') as f:
                await f.write(json.dumps(data, indent=4))
            
            # status-থেকেও ক্লিয়ার করুন
            status = await self.load_status(user_id)
            if website:
                if website in status.all_website_accounts:
                    del status.all_website_accounts[website]
            else:
                status.all_website_accounts = {}
            
            await self.save_status(user_id, status)
            
            logger.info(f"Cleared multi-accounts for user {user_id}")
            return True
        except Exception as e:
            logger.error(f"Error clearing multi-accounts: {str(e)}")
            return False
    
    async def save_website_settings(self, user_id: int, enabled_websites: List[str], round_robin_mode: bool):
        """ওয়েবসাইট সেটিংস সেভ করে"""
        try:
            status = await self.load_status(user_id)
            status.enabled_websites = enabled_websites
            status.round_robin_mode = round_robin_mode
            await self.save_status(user_id, status)
            return True
        except Exception as e:
            logger.error(f"Error saving website settings: {str(e)}")
            return False
    
    async def get_next_website(self, user_id: int) -> Optional[str]:
        """পরবর্তী ওয়েবসাইট রিটার্ন করে"""
        try:
            status = await self.load_status(user_id)
            if not status.round_robin_mode or not status.enabled_websites:
                return None
            
            if status.current_website_index >= len(status.enabled_websites):
                status.current_website_index = 0
            
            next_website = status.enabled_websites[status.current_website_index]
            status.current_website_index += 1
            await self.save_status(user_id, status)
            return next_website
        except Exception as e:
            logger.error(f"Error getting next website: {str(e)}")
            return None
    
    async def reset_website_rotation(self, user_id: int):
        """ওয়েবসাইট রোটেশন রিসেট করে"""
        try:
            status = await self.load_status(user_id)
            status.current_website_index = 0
            await self.save_status(user_id, status)
            return True
        except Exception as e:
            logger.error(f"Error resetting website rotation: {str(e)}")
            return False
    
    async def get_all_websites_with_accounts(self, user_id: int) -> Dict[str, List[Dict[str, str]]]:
        """সব ওয়েবসাইট এবং তাদের একাউন্টস রিটার্ন করে"""
        try:
            status = await self.load_status(user_id)
            return status.all_website_accounts
        except Exception as e:
            logger.error(f"Error getting all websites with accounts: {str(e)}")
            return {}

# Multi Account Manager ইনিশিয়ালাইজ করুন
multi_account_manager = MultiAccountManager()

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
    proxy_set = device_set and device_manager.load(str(user_id)).proxy is not None
    set_proxy_text = f"{'✅ ' if proxy_set else ''}Set Proxy"
    
    # Multi-Account status চেক করুন
    multi_account_text = "Multi-Account"
    round_robin_status = ""
    if user_id:
        try:
            if os.path.exists(MULTI_ACCOUNT_STATUS_FILE):
                with open(MULTI_ACCOUNT_STATUS_FILE, 'r') as f:
                    data = json.load(f)
                user_data = data.get(str(user_id), {})
                if user_data.get("enabled", False):
                    multi_account_text = f"🔄 Multi-Account"
                if user_data.get("round_robin_mode", False):
                    round_robin_status = "🟢"
                else:
                    round_robin_status = "🔴"
        except Exception as e:
            logger.error(f"Error loading multi-account status in get_main_keyboard: {str(e)}")
    
    # বাটন টেক্সট ঠিক করুন
    multi_website_text = "Multi-Website Settings"  # শুধু এই টেক্সট ব্যবহার করুন
    
    keyboard = [
        [KeyboardButton("Log in Account"), KeyboardButton("Register Account")],
        [KeyboardButton(link_text), KeyboardButton(number_list_text)],
        [KeyboardButton("Reset All"), KeyboardButton(set_user_agent_text)],
        [KeyboardButton(set_proxy_text), KeyboardButton(multi_account_text)],
        [KeyboardButton(multi_website_text)]  # শুধু একটিই টেক্সট ব্যবহার করুন
    ]
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
                await asyncio.sleep(0)
                async with asyncio.timeout(REQUEST_TIMEOUT):
                    async with session.post(url, headers=headers, data=data) as response:
                        response_data = await response.json()
                        if response_data.get("code") == 1:
                            token = response_data.get("data", {}).get("token")
                            if not token:
                                token = response_data.get("data", {}).get("userinfo", {}).get("token")
                            if token:
                                return {
                                    "success": True,
                                    "token": token,
                                    "response": response_data
                                }
                            return {
                                "success": False,
                                "error": "Login successful but no token received",
                                "response": response_data
                            }
                        return {
                            "success": False,
                            "error": response_data.get("msg", "Unknown error"),
                            "response": response_data
                        }
            except asyncio.TimeoutError:
                if attempt == MAX_RETRIES - 1:
                    error_msg = f"Request timed out after {REQUEST_TIMEOUT} seconds"
                    logger.error(error_msg)
                    return {
                        "success": False,
                        "error": error_msg,
                        "response": None
                    }
                await asyncio.sleep(0)
            except Exception as e:
                if attempt == MAX_RETRIES - 1:
                    error_msg = f"Connection error: {str(e)}"
                    logger.error(error_msg)
                    return {
                        "success": False,
                        "error": error_msg,
                        "response": None
                    }
                await asyncio.sleep(0)

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
                await asyncio.sleep(0)
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
                            await asyncio.sleep(0)
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
                await asyncio.sleep(0)
            except Exception as e:
                logger.error(f"Error in register_account for {website_config['name']}: {str(e)}")
                if attempt == MAX_RETRIES - 1:
                    return {
                        "code": -1,
                        "msg": f"Registration failed: {str(e)}",
                        "data": None
                    }
                await asyncio.sleep(0)
        logger.error(f"Registration failed after {MAX_RETRIES} attempts for {website_config['name']}")
        return {
            "code": -1,
            "msg": f"Registration failed after {MAX_RETRIES} attempts",
            "data": None
        }

async def send_code(token, phone_encrypted, website_config, device_name):
    async with await device_manager.build_session(device_name) as session:
        for attempt in range(MAX_RETRIES):
            try:
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
                data = {"phone": phone_encrypted, "area_code" : "1"}
                await asyncio.sleep(0)
                async with asyncio.timeout(REQUEST_TIMEOUT):
                    async with session.post(url, headers=headers, data=data) as response:
                        response_data = await response.json()
                        if response_data.get("code") == 0 and response_data.get("msg") == "Frequent requests, please wait!!":
                            logger.info(f"Frequent requests error detected, waiting 2 seconds to retry (attempt {attempt + 1}/{MAX_RETRIES})")
                            await asyncio.sleep(0)
                            continue
                        return response_data
            except asyncio.TimeoutError:
                if attempt == MAX_RETRIES - 1:
                    logger.error(f"Send code timed out after {REQUEST_TIMEOUT} seconds")
                    return {
                        "code": -1,
                        "msg": f"Request timed out after {REQUEST_TIMEOUT} seconds",
                        "time": str(int(time.time())),
                        "data": None
                    }
                await asyncio.sleep(0)
            except Exception as e:
                if attempt == MAX_RETRIES - 1:
                    logger.error(f"Error in send_code after {MAX_RETRIES} attempts: {str(e)}")
                    return {
                        "code": -1,
                        "msg": f"Request failed after {MAX_RETRIES} attempts: {str(e)}",
                        "time": str(int(time.time())),
                        "data": None
                    }
                await asyncio.sleep(0)
        logger.error(f"Send code failed after {MAX_RETRIES} attempts")
        return {
            "code": -1,
            "msg": f"Request failed after {MAX_RETRIES} attempts",
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
                await asyncio.sleep(0)
                async with asyncio.timeout(REQUEST_TIMEOUT):
                    async with session.post(url, headers=headers, data=data) as response:
                        return await response.json()
            except asyncio.TimeoutError:
                if attempt == MAX_RETRIES - 1:
                    logger.error(f"Get code timed out after {REQUEST_TIMEOUT} seconds")
                    raise
                await asyncio.sleep(0)
            except Exception as e:
                if attempt == MAX_RETRIES - 1:
                    logger.error(f"Error in get_code: {str(e)}")
                    raise
                await asyncio.sleep(0)

async def get_phone_list(token, account_type, website_config, device_name):
    async with await device_manager.build_session(device_name) as session:
        if not token or len(token) < 10:
            logger.error(f"Invalid or missing token for {account_type} account")
            return f"❌ Invalid or missing token for {account_type} account. Please login first using 'Log in Account'."
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
        track_file = f"online_durations_{website_config['name'].lower()}.json"
        durations = {}
        if os.path.exists(track_file):
            try:
                async with aiofiles.open(track_file, 'r') as f:
                    content = await f.read()
                    if content:
                        durations = json.loads(content)
            except (json.JSONDecodeError, Exception) as e:
                logger.error(f"Error loading durations for {account_type} ({website_config['name']}): {str(e)}")
                durations = {}

        async def save_durations():
            try:
                async with aiofiles.open(track_file, 'w') as f:
                    await f.write(json.dumps(durations, indent=2))
            except Exception as e:
                logger.error(f"Error saving durations for {account_type} ({website_config['name']}): {str(e)}")

        def format_duration(seconds):
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            seconds = seconds % 60
            return f"{hours}h {minutes}m {seconds}s"

        logger.info(f"Fetching phone list for {account_type} account ({website_config['name']})")
        try:
            await asyncio.sleep(0)
            async with asyncio.timeout(REQUEST_TIMEOUT):
                async with session.post(website_config['phone_list_url'], headers=headers) as response:
                    response.raise_for_status()
                    data = await response.json()
        except aiohttp.ClientResponseError as e:
            if e.status == 401:
                logger.error(f"401 Unauthorized for {account_type} account ({website_config['name']}): {str(e)}")
                return f"❌ Unauthorized access for {account_type} account ({website_config['name']}). Token may be invalid or expired. Please login again using 'Log in Account'."
            logger.error(f"HTTP error for {account_type} account ({website_config['name']}): {str(e)}")
            return f"❌ Error while calling API for {account_type} account ({website_config['name']}): {str(e)}"
        except asyncio.TimeoutError:
            logger.error(f"Phone list request timed out after {REQUEST_TIMEOUT} seconds")
            return f"❌ Request timed out for {account_type} account ({website_config['name']})."
        except Exception as e:
            logger.error(f"Request error for {account_type} account ({website_config['name']}): {str(e)}")
            return f"❌ Error while calling API for {account_type} account ({website_config['name']}): {str(e)}"

        if data.get("code") != 1:
            logger.error(f"API response error for {account_type} ({website_config['name']}): {data.get('msg', 'Unknown error')}")
            return f"❌ Invalid token or no data found for {account_type} account ({website_config['name']}): {data.get('msg', 'Unknown error')}"

        phones = data.get("data", []) or []
        now = datetime.now(timezone.utc)

        for phone_data in phones:
            phone = "+1" + str(phone_data.get("phone", ""))[-10:]
            status = phone_data.get("status", 0)
            
            if phone not in durations:
                durations[phone] = {
                    "online_since": None,
                    "total_online": 0,
                    "last_updated": now.isoformat(),
                    "created_at": phone_data.get("created_at", "unknown")
                }

            try:
                if status == 1:
                    if durations[phone]["online_since"] is None:
                        durations[phone]["online_since"] = now.isoformat()
                else:
                    if durations[phone]["online_since"] is not None:
                        online_since = datetime.fromisoformat(durations[phone]["online_since"])
                        delta = (now - online_since).total_seconds()
                        durations[phone]["total_online"] += int(delta)
                        durations[phone]["online_since"] = None
                durations[phone]["last_updated"] = now.isoformat()
            except ValueError as e:
                logger.error(f"Error processing duration for phone: {str(e)}")
                durations[phone]["online_since"] = None
                durations[phone]["total_online"] = 0

        total = len(phones)
        online = sum(1 for p in phones if p.get("status") == 1)
        offline = total - online

        output = [
            f"🕒 Last Updated: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"🔗 Total Linked: {total}",
            f"🟢 Online: {online}",
            f"🔴 Offline: {offline}\n",
            f"📱 Phone Numbers Status ({website_config['name']}):"
        ]

        for idx, phone_data in enumerate(phones, 1):
            phone = "+1" + str(phone_data.get("phone", ""))[-10:]
            status = phone_data.get("status", 0)
            created = phone_data.get("created_at", "unknown").split(" ")[0]

            total_time = durations[phone]["total_online"]
            if durations[phone]["online_since"]:
                try:
                    online_since = datetime.fromisoformat(durations[phone]["online_since"])
                    total_time += int((now - online_since).total_seconds())
                except ValueError:
                    logger.error(f"Invalid online_since for phone, resetting")
                    durations[phone]["online_since"] = None
                    total_time = durations[phone]["total_online"]

            status_icon = "🟢" if status == 1 else "🔴"
            output.append(
                f"{idx:2d}. {phone} {status_icon} {format_duration(total_time)}"
            )

        await save_durations()
        return "\n".join(output)

async def process_multi_account_login(update: Update, context: ContextTypes.DEFAULT_TYPE, credentials_text: str, website: str):
    """Multi account login প্রসেস করে"""
    user_id = update.message.from_user.id
    device_name = str(user_id)
    
    if not device_manager.exists(device_name):
        await update.message.reply_text(
            "❌ Please set user agent first using 'Set User Agent'.",
            reply_markup=get_main_keyboard(website, user_id)
        )
        return False
    
    # credentials পার্স করুন
    lines = credentials_text.strip().split('\n')
    accounts = []
    
    for line in lines:
        line = line.strip()
        if ':' in line:
            username, password = line.split(':', 1)
            username = username.strip()
            password = password.strip()
            if username and password:
                accounts.append({"username": username, "password": password})
    
    if not accounts:
        await update.message.reply_text(
            "❌ No valid username:password pairs found.",
            reply_markup=get_main_keyboard(website, user_id)
        )
        return False
    
    # accounts সেভ করুন
    await multi_account_manager.save_accounts(user_id, accounts, website)
    
    # status সেটাপ করুন
    status = MultiAccountStatus(
        enabled=True,
        current_account_index=0,
        total_accounts=len(accounts),
        processing=False,
        website=website,
        last_activity=datetime.now().isoformat()
    )
    await multi_account_manager.save_status(user_id, status)
    
    await update.message.reply_text(
        f"✅ Multi-Account System Enabled!\n"
        f"📊 Total Accounts: {len(accounts)}\n"
        f"🌐 Website: {website}\n\n"
        f"Now use 'Link WhatsApp' to start automatic processing.",
        reply_markup=get_main_keyboard(website, user_id)
    )
    
    # প্রথম অ্যাকাউন্ট লগইন করুন
    await auto_login_next_account(update, context, user_id, website)
    return True

async def auto_login_next_account(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int, website: str):
    """পরবর্তী অ্যাকাউন্টে অটো লগইন করে"""
    try:
        status = await multi_account_manager.load_status(user_id)
        if not status.enabled:
            return False
        
        accounts = await multi_account_manager.load_accounts(user_id, website)
        if status.current_account_index >= len(accounts):
            # সব অ্যাকাউন্ট শেষ
            await update.message.reply_text(
                "✅ All accounts processed!\n\n"
                "Multi-Account System completed. You can restart or disable the system.",
                reply_markup=get_main_keyboard(website, user_id)
            )
            status.enabled = False
            await multi_account_manager.save_status(user_id, status)
            return True
        
        current_account = accounts[status.current_account_index]
        website_config = WEBSITE_CONFIGS[website]
        device_name = str(user_id)
        
        await update.message.reply_text(
            f"🔄 Auto-login account {status.current_account_index + 1}/{len(accounts)}\n"
            f"👤 Username: {current_account['username']}\n"
            f"⏳ Please wait..."
        )
        
        # লগইন চেষ্টা করুন
        login_result = await login_with_credentials(
            current_account['username'], 
            current_account['password'], 
            website_config, 
            device_name
        )
        
        if login_result["success"]:
            await save_token(user_id, 'main', login_result["token"], website)
            
            status.current_account_index += 1
            status.last_activity = f"Auto-login successful: {current_account['username']}"
            await multi_account_manager.save_status(user_id, status)
            
            await update.message.reply_text(
                f"✅ Auto-login successful!\n"
                f"📊 Progress: {status.current_account_index}/{len(accounts)}\n"
                f"🔑 Token: {login_result['token'][:10]}...\n\n"
                f"Ready for WhatsApp linking...",
                reply_markup=get_main_keyboard(website, user_id)
            )
            return True
        else:
            # রিট্রাই লজিক
            for retry in range(3):
                await asyncio.sleep(0)
                await update.message.reply_text(f"🔄 Retry login attempt {retry + 1}/3")
                
                login_result = await login_with_credentials(
                    current_account['username'], 
                    current_account['password'], 
                    website_config, 
                    device_name
                )
                
                if login_result["success"]:
                    await save_token(user_id, 'main', login_result["token"], website)
                    
                    status.current_account_index += 1
                    status.last_activity = f"Auto-login successful after retry: {current_account['username']}"
                    await multi_account_manager.save_status(user_id, status)
                    
                    await update.message.reply_text(
                        f"✅ Auto-login successful after retry!\n"
                        f"📊 Progress: {status.current_account_index}/{len(accounts)}",
                        reply_markup=get_main_keyboard(website, user_id)
                    )
                    return True
            
            # সব রিট্রাই ফেল করলে
            await update.message.reply_text(
                f"❌ Auto-login failed after 3 retries\n"
                f"👤 Username: {current_account['username']}\n"
                f"📊 Skipping to next account...",
                reply_markup=get_main_keyboard(website, user_id)
            )
            
            status.current_account_index += 1
            status.last_activity = f"Auto-login failed: {current_account['username']}"
            await multi_account_manager.save_status(user_id, status)
            
            # পরবর্তী অ্যাকাউন্টে চলে যান
            await asyncio.sleep(0)
            await auto_login_next_account(update, context, user_id, website)
            return False
            
    except Exception as e:
        logger.error(f"Error in auto_login_next_account: {str(e)}")
        return False

async def check_phone_in_list_and_continue(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int, phone: str, website: str):
    """ফোন নাম্বার লিস্টে আছে কিনা চেক করে এবং পরবর্তী স্টেপে যায়"""
    try:
        status = await multi_account_manager.load_status(user_id)
        if not status.enabled:
            return False
        
        # ফোন লিস্ট চেক করুন
        tokens = load_tokens()
        token = tokens.get(str(user_id), {}).get(website, {}).get('main')
        website_config = WEBSITE_CONFIGS[website]
        device_name = str(user_id)
        
        if token:
            phone_list_result = await get_phone_list(token, 'main', website_config, device_name)
            
            # ফোন লিস্টে current phone আছে কিনা চেক করুন
            if phone in phone_list_result:
                await update.message.reply_text(
                    f"✅ Phone {phone} found in list!\n"
                    f"🔄 Moving to next account...",
                    reply_markup=get_main_keyboard(website, user_id)
                )
                
                # পরবর্তী অ্যাকাউন্টে যান
                await asyncio.sleep(0)
                await auto_login_next_account(update, context, user_id, website)
                return True
        
        # 10 সেকেন্ড পর আবার চেক করুন
        await asyncio.sleep(5)
        context.application.create_task(
            check_phone_in_list_and_continue(update, context, user_id, phone, website)
        )
        return False
        
    except Exception as e:
        logger.error(f"Error in check_phone_in_list_and_continue: {str(e)}")
        return False

async def multi_account_control_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Multi account control কমান্ড"""
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    
    status = await multi_account_manager.load_status(user_id)
    accounts = await multi_account_manager.load_accounts(user_id, selected_website)
    
    if status.enabled:
        # Disable option
        keyboard = [
            [KeyboardButton("Disable Multi-Account"), KeyboardButton("Next Account")],
            [KeyboardButton("Show Status"), KeyboardButton("Back to Main Menu")]
        ]
        message = (
            f"🔄 Multi-Account System: ENABLED\n"
            f"📊 Progress: {status.current_account_index}/{status.total_accounts}\n"
            f"🌐 Website: {status.website}\n"
            f"⏰ Last Activity: {status.last_activity}"
        )
    else:
        # Enable option
        keyboard = [
            [KeyboardButton("Enable Multi-Account"), KeyboardButton("Show Status")],
            [KeyboardButton("Back to Main Menu")]
        ]
        message = (
            f"🔴 Multi-Account System: DISABLED\n"
            f"📊 Stored Accounts: {len(accounts)}\n"
            f"🌐 Website: {selected_website}"
        )
    
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True, one_time_keyboard=True)
    await update.message.reply_text(message, reply_markup=reply_markup)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    logger.info(f"Start command triggered by user {user_id}")
    tokens = load_tokens()
    context.user_data.clear()
    context.user_data['selected_website'] = DEFAULT_SELECTED_WEBSITE
    logger.info(f"Token cache for user {user_id}: {'Present' if str(user_id) in tokens else 'None'}")

    welcome_message = "👋 Welcome to the WhatsApp Linking Bot!\n\nThis System made by HASAN."
    if str(user_id) in tokens and any(tokens[str(user_id)].get(website, {}).get('main') for website in WEBSITE_CONFIGS):
        selected_website = context.user_data['selected_website']
        message = f"✅ You have accounts setup!\n\n{welcome_message}"
        logger.info(f"User {user_id} has account, showing welcome message")
        await update.message.reply_text(message, reply_markup=get_main_keyboard(selected_website, user_id))
    else:
        logger.info(f"User {user_id} has no account, showing welcome message")
        await update.message.reply_text(
            welcome_message,
            reply_markup=get_main_keyboard(DEFAULT_SELECTED_WEBSITE, user_id)
        )

async def start_round_robin_processing(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int, phone: str):
    """রাউন্ড-রবিন প্রসেসিং শুরু করে"""
    status = await multi_account_manager.load_status(user_id)
    websites = status.enabled_websites
    
    if not websites:
        await update.message.reply_text(
            "❌ No websites enabled for round-robin processing.",
            reply_markup=get_main_keyboard(DEFAULT_SELECTED_WEBSITE, user_id)
        )
        return
    
    # Phone number validation এখানেও করুন
    phone_clean = re.sub(r'[^\d+]', '', phone)
    if phone_clean.startswith('+1') and len(phone_clean) == 12:
        normalized_phone = phone_clean
    elif len(phone_clean) == 10:
        normalized_phone = '+1' + phone_clean
    elif len(phone_clean) == 11 and phone_clean.startswith('1'):
        normalized_phone = '+' + phone_clean
    else:
        normalized_phone = None

    if not normalized_phone or not re.match(r'^\+1\d{10}$', normalized_phone):
        await update.message.reply_text(
            f"❌ Invalid phone format: {phone}\n"
            f"Please use: +1XXXXXXXXXX or XXXXXXXXXX format\n"
            f"Example: +14165551234 or 4165551234",
            reply_markup=get_main_keyboard(DEFAULT_SELECTED_WEBSITE, user_id)
        )
        return
    
    context.user_data['round_robin_phone'] = normalized_phone
    context.user_data['round_robin_websites'] = websites.copy()
    context.user_data['current_round_robin_index'] = 0
    
    await update.message.reply_text(
        f"🔄 Starting Round-Robin Processing\n"
        f"📱 Phone: {normalized_phone} (normalized)\n"
        f"📋 Original: {phone}\n"
        f"🌐 Websites: {', '.join(websites)}\n\n"
        f"Processing will start with {websites[0]}...",
        reply_markup=get_main_keyboard(websites[0], user_id)
    )
    
    await process_next_website_in_round_robin(update, context, user_id)

async def process_next_website_in_round_robin(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int):
    """পরবর্তী ওয়েবসাইট প্রসেস করে"""
    websites = context.user_data.get('round_robin_websites', [])
    current_index = context.user_data.get('current_round_robin_index', 0)
    phone = context.user_data.get('round_robin_phone', '')
    
    if current_index >= len(websites):
        # সব ওয়েবসাইট কমপ্লিট
        await update.message.reply_text(
            f"✅ Round-Robin Complete!\n"
            f"📱 Phone: {phone}\n"
            f"🌐 Processed on all {len(websites)} websites\n\n"
            f"Send another WhatsApp number to continue.",
            reply_markup=get_main_keyboard(websites[0] if websites else DEFAULT_SELECTED_WEBSITE, user_id)
        )
        context.user_data.pop('round_robin_phone', None)
        context.user_data.pop('round_robin_websites', None)
        context.user_data.pop('current_round_robin_index', None)
        return
    
    current_website = websites[current_index]
    await process_phone_for_website_round_robin(update, context, user_id, phone, current_website)

async def process_phone_for_website_round_robin(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int, phone: str, website: str):
    """একটি ওয়েবসাইটের জন্য ফোন প্রসেস করে (রাউন্ড-রবিন মোডে)"""
    website_config = WEBSITE_CONFIGS[website]
    device_name = str(user_id)
    
    # প্রথমে phone number normalize করুন
    phone_clean = re.sub(r'[^\d+]', '', phone)
    if phone_clean.startswith('+1') and len(phone_clean) == 12:
        normalized_phone = phone_clean
    elif len(phone_clean) == 10:
        normalized_phone = '+1' + phone_clean
    elif len(phone_clean) == 11 and phone_clean.startswith('1'):
        normalized_phone = '+' + phone_clean
    else:
        normalized_phone = None

    if not normalized_phone or not re.match(r'^\+1\d{10}$', normalized_phone):
        await update.message.reply_text(
            f"❌ {website}: Invalid phone format: {phone}\n"
            f"Expected: +1XXXXXXXXXX or XXXXXXXXXX\n"
            f"Skipping to next website...",
            reply_markup=get_main_keyboard(website, user_id)
        )
        await move_to_next_website_round_robin(update, context, user_id)
        return
    
    if not device_manager.exists(device_name):
        await update.message.reply_text(
            f"❌ No device set for {website}. Skipping to next website...",
            reply_markup=get_main_keyboard(website, user_id)
        )
        await move_to_next_website_round_robin(update, context, user_id)
        return
    
    tokens = load_tokens()
    token = tokens.get(str(user_id), {}).get(website, {}).get('main')
    
    if not token:
        await update.message.reply_text(
            f"❌ No {website} account found. Skipping to next website...",
            reply_markup=get_main_keyboard(website, user_id)
        )
        await move_to_next_website_round_robin(update, context, user_id)
        return
    
    await update.message.reply_text(
        f"🔄 Processing {normalized_phone} on {website}...\n"
        f"📱 Original input: {phone}",
        reply_markup=get_main_keyboard(website, user_id)
    )
    
    try:
        enc_phone = await encrypt_phone(normalized_phone)
        send_resp = await send_code(token, enc_phone, website_config, device_name)
        
        if send_resp.get("code") != 1:
            error_msg = send_resp.get('msg', 'Unknown error')
            await update.message.reply_text(
                f"❌ {website}: Failed to send code - {error_msg}\n"
                f"Skipping to next website...",
                reply_markup=get_main_keyboard(website, user_id)
            )
            await move_to_next_website_round_robin(update, context, user_id)
            return
        
        # কোড চেকিং লজিক - আপনার existing get_code ফাংশন ব্যবহার করুন
        await update.message.reply_text(f"🔄 {website}: Checking for verification code (this may take 10-30 seconds)...")
        code = None
        code_response_data = None
        
        for attempt in range(MAX_CODE_ATTEMPTS):
            try:
                # get_code ফাংশনে normalized phone পাঠান
                get_resp = await get_code(token, normalized_phone, website_config, device_name)
                logger.debug(f"Get code attempt {attempt + 1} for {website}: {get_resp}")
                
                if isinstance(get_resp, dict):
                    if get_resp.get("code") == 1:
                        code = get_resp.get("data", {}).get("code")
                        code_response_data = get_resp
                        if code:
                            logger.info(f"✅ {website}: Code found: {code}")
                            break
                    else:
                        # API error message লগ করুন
                        error_msg = get_resp.get('msg', 'Unknown error')
                        logger.warning(f"{website}: Get code API error on attempt {attempt + 1}: {error_msg}")
                        
                        # Specific errors এর জন্য early exit
                        if "not found" in error_msg.lower() or "not exist" in error_msg.lower():
                            logger.info(f"{website}: Phone not found in system, stopping retries")
                            break
                
            except Exception as e:
                logger.error(f"{website}: Error in get_code attempt {attempt + 1}: {str(e)}")
            
            if attempt < MAX_CODE_ATTEMPTS - 1:
                await asyncio.sleep(CODE_CHECK_INTERVAL)

        if code:
            await update.message.reply_text(
                f"✅ {website}: Code received!\n\n"
                f"📱 Phone: {normalized_phone}\n"
                f"🔐 Verification Code: <code>{code}</code>\n\n"
                f"Enter this 6-digit code in WhatsApp to complete linking.\n"
                f"📱 Phone will be monitored in list...",
                parse_mode='HTML',
                reply_markup=get_main_keyboard(website, user_id)
            )
            # ফোন লিস্টে ফাউন্ড হওয়ার জন্য মোনিটরিং শুরু করুন
            await monitor_phone_in_list_round_robin(update, context, user_id, normalized_phone, website)
        else:
            # Detailed error message
            error_details = ""
            if code_response_data and isinstance(code_response_data, dict):
                error_details = f"\nAPI Response: {code_response_data.get('msg', 'No details')}"
            
            await update.message.reply_text(
                f"❌ {website}: Failed to get verification code after {MAX_CODE_ATTEMPTS} attempts\n"
                f"📱 Phone: {normalized_phone}\n"
                f"Possible reasons:\n"
                f"• Phone number already linked to another account\n"
                f"• Server temporary issue\n"
                f"• Rate limiting by provider\n"
                f"• Invalid phone number format\n"
                f"{error_details}\n"
                f"Skipping to next website...",
                reply_markup=get_main_keyboard(website, user_id)
            )
            await move_to_next_website_round_robin(update, context, user_id)
        
    except Exception as e:
        logger.error(f"Error processing phone for {website}: {str(e)}")
        await update.message.reply_text(
            f"❌ {website}: Unexpected error - {str(e)}\nSkipping to next website...",
            reply_markup=get_main_keyboard(website, user_id)
        )
        await move_to_next_website_round_robin(update, context, user_id)

async def monitor_phone_in_list_round_robin(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int, phone: str, website: str):
    """ফোন লিস্টে ফাউন্ড হওয়ার জন্য মোনিটর করে"""
    website_config = WEBSITE_CONFIGS[website]
    device_name = str(user_id)
    tokens = load_tokens()
    token = tokens.get(str(user_id), {}).get(website, {}).get('main')
    
    if not token:
        await update.message.reply_text(
            f"❌ {website}: Token not found for monitoring\nSkipping to next website...",
            reply_markup=get_main_keyboard(website, user_id)
        )
        await move_to_next_website_round_robin(update, context, user_id)
        return
    
    #await update.message.reply_text(
        #f"👀 {website}: Monitoring phone list for {phone}...",
        #reply_markup=get_main_keyboard(website, user_id)
    #)
    
    for attempt in range(30):  # 30 বার চেক করুন (প্রতি 5 সেকেন্ডে)
        try:
            phone_list_result = await get_phone_list(token, 'main', website_config, device_name)
            
            # ফোন নাম্বার লিস্টে আছে কিনা চেক করুন
            if phone in str(phone_list_result):
                await update.message.reply_text(
                    f"✅ {website}: Phone {phone} found in list!\n"
                    f"🔄 Moving to next website...",
                    reply_markup=get_main_keyboard(website, user_id)
                )
                await move_to_next_website_round_robin(update, context, user_id)
                return
            
            # যদি প্রথম ৫টি চেকের মধ্যে না থাকে, তাহলে status আপডেট দিন
            if attempt == 5:
                await update.message.reply_text(
                    f"⏳ {website}: Still monitoring... Phone not in list yet",
                    reply_markup=get_main_keyboard(website, user_id)
                )
                
        except Exception as e:
            logger.error(f"Error monitoring phone list for {website}: {str(e)}")
            # monitoring error হলেও চেষ্টা চালিয়ে যান
        
        await asyncio.sleep(1)  # 5 সেকেন্ড অপেক্ষা করুন
    
    # 2.5 মিনিট পরেও না পাওয়া গেলে পরবর্তী ওয়েবসাইটে যান
    await update.message.reply_text(
        f"⏰ {website}: Phone not found in list after 30 seconds\n"
        f"This might be because:\n"
        f"• User didn't enter the code\n"
        f"• Code expired\n"
        f"• Technical issue\n"
        f"Skipping to next website...",
        reply_markup=get_main_keyboard(website, user_id)
    )
    await move_to_next_website_round_robin(update, context, user_id)

async def move_to_next_website_round_robin(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int):
    """পরবর্তী ওয়েবসাইটে移動 করে"""
    current_index = context.user_data.get('current_round_robin_index', 0)
    context.user_data['current_round_robin_index'] = current_index + 1
    await process_next_website_in_round_robin(update, context, user_id)


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
            context.user_data.clear()
            context.user_data['selected_website'] = selected_website
            logger.info(f"User {user_id} saved account token via /login for {selected_website}")
            await update.message.reply_text(
                f"✅ Account login successful for {selected_website}!\nAccount token: <code>{token[:10]}...</code>",
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
            context.user_data.clear()
            context.user_data['selected_website'] = selected_website
            logger.info(f"User {user_id} login successful for {account_type} account on {website}")
            await update.message.reply_text(
                f"✅ Account login successful for {website}!\nAccount token: <code>{login_result['token'][:10]}...</code>",
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
    
    # Multi-Account কন্ট্রোল
    if text == "Multi-Account" or text == "🔄 Multi-Account":
        await multi_account_control_command(update, context)
        return
    
    # নতুন: Multi-Website Settings - শুধু একটি টেক্সট চেক করুন
    if text == "Multi-Website Settings":
        await show_multi_website_settings(update, context)
        return
    
    # ... বাকি existing code ...
    
    # নতুন: Enable Round-Robin
    if text == "🔄 Enable Round-Robin":
        await enable_round_robin_mode(update, context)
        return
    
    # নতুন: Disable Round-Robin  
    if text == "🔴 Disable Round-Robin":
        await disable_round_robin_mode(update, context)
        return
    
    # নতুন: Show All Accounts
    if text == "📊 Show All Accounts":
        await show_all_accounts_summary(update, context)
        return
    
    # নতুন: Save Settings
    if text == "💾 Save Settings":
        user_id = update.message.from_user.id
        selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
        
        status = await multi_account_manager.load_status(user_id)
        
        await update.message.reply_text(
            f"✅ Website Settings Saved!\n"
            f"🌐 Enabled Websites: {', '.join(status.enabled_websites) if status.enabled_websites else 'None'}\n"
            f"🔄 Round-Robin: {'ON' if status.round_robin_mode else 'OFF'}",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    
    # নতুন: ওয়েবসাইট টগল করা
    if text.startswith("✅ ") or text.startswith("❌ "):
        website_name = text[2:].strip()  # প্রথম ২টি ক্যারেক্টর (✅ বা ❌) বাদ দিন
        if website_name in WEBSITE_CONFIGS:
            await toggle_website_selection(update, context, website_name)
        return
    
    # ... existing code ...
    
    # Multi-Account কন্ট্রোল
    if text == "Multi-Account" or text == "🔄 Multi-Account":
        await multi_account_control_command(update, context)
        return
    
    if text == "Enable Multi-Account":
        context.user_data['state'] = 'awaiting_multi_account_credentials'
        await update.message.reply_text(
            f"🔢 Multi-Account System Setup\n\n"
            f"Please send username:password pairs (one per line):\n\n"
            f"Example:\n"
            f"username1:password1\n"
            f"username2:password2\n"
            f"username3:password3\n\n"
            f"Website: {selected_website}",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    
    if text == "Disable Multi-Account":
        status = await multi_account_manager.load_status(user_id)
        status.enabled = False
        await multi_account_manager.save_status(user_id, status)
        
        await update.message.reply_text(
            "🔴 Multi-Account System Disabled",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    
    if text == "Next Account":
        status = await multi_account_manager.load_status(user_id)
        if status.enabled:
            await auto_login_next_account(update, context, user_id, status.website)
        else:
            await update.message.reply_text(
                "❌ Multi-Account System is disabled",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
        return
    
    if text == "Show Status":
        status = await multi_account_manager.load_status(user_id)
        accounts = await multi_account_manager.load_accounts(user_id, selected_website)
        
        message = (
            f"📊 Multi-Account Status\n"
            f"🔧 System: {'🟢 ENABLED' if status.enabled else '🔴 DISABLED'}\n"
            f"📈 Progress: {status.current_account_index}/{status.total_accounts}\n"
            f"🌐 Website: {status.website}\n"
            f"💾 Stored Accounts: {len(accounts)}\n"
            f"⏰ Last Activity: {status.last_activity}"
        )
        
        await update.message.reply_text(
            message,
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    
    # Multi-Account credentials গ্রহণ
    if user_state == 'awaiting_multi_account_credentials':
        success = await process_multi_account_login(update, context, text, selected_website)
        if success:
            context.user_data['state'] = ''
        return
    
    # Multi-Account enabled থাকলে WhatsApp link করার সময় অটো চেক
    if text == f"Link {selected_website} WhatsApp":
        status = await multi_account_manager.load_status(user_id)
        if status.enabled:
            context.user_data['multi_account_linking'] = True
        
        await link_command(update, context)
        return
    
    # আগের existing code এখানে থাকবে...
    # ... বাকি handle_message code

    if text in WEBSITE_CONFIGS.keys() and user_state in ['awaiting_website_selection_login', 'awaiting_website_selection_register']:
        if user_state == 'awaiting_website_selection_login':
            context.user_data['selected_website'] = text
            context.user_data['state'] = 'awaiting_login'
            await update.message.reply_text(
                f"✅ Selected website: {text}\nPlease enter your token or username:password for the {text} account.",
                reply_markup=get_main_keyboard(text, user_id)
            )
        elif user_state == 'awaiting_website_selection_register':
            context.user_data['register_website'] = text
            context.user_data['register_account_type'] = 'main'
            context.user_data['state'] = 'registering'
            await update.message.reply_text(
                f"✅ Selected website: {text}\n📱 ফোন নাম্বার দিন:",
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
            f"🌐 Please select a website for account login:",
            reply_markup=get_website_selection_keyboard()
        )
        return
    elif text == f"Link {selected_website} WhatsApp":
        await link_command(update, context)
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
                f"✅ Account login successful for {selected_website}!\nAccount token: <code>{text[:10]}...</code>",
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

async def show_multi_website_settings(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """মাল্টি-ওয়েবসাইট সেটিংস দেখায়"""
    user_id = update.message.from_user.id
    status = await multi_account_manager.load_status(user_id)
    
    # সব ওয়েবসাইটের একাউন্ট সংখ্যা দেখান
    accounts_info = []
    for website in WEBSITE_CONFIGS.keys():
        account_count = len(status.all_website_accounts.get(website, []))
        is_enabled = website in status.enabled_websites
        status_icon = "✅" if is_enabled else "❌"
        accounts_info.append(f"{status_icon} {website}: {account_count} accounts")
    
    # Side by side বাটন তৈরি করুন - প্রতি লাইনে ২টি বাটন
    keyboard = []
    websites_list = list(WEBSITE_CONFIGS.keys())
    
    for i in range(0, len(websites_list), 2):
        row = []
        # প্রথম বাটন
        website1 = websites_list[i]
        is_enabled1 = website1 in status.enabled_websites
        btn_text1 = f"{'✅' if is_enabled1 else '❌'} {website1}"
        row.append(KeyboardButton(btn_text1))
        
        # দ্বিতীয় বাটন (যদি থাকে)
        if i + 1 < len(websites_list):
            website2 = websites_list[i + 1]
            is_enabled2 = website2 in status.enabled_websites
            btn_text2 = f"{'✅' if is_enabled2 else '❌'} {website2}"
            row.append(KeyboardButton(btn_text2))
        
        keyboard.append(row)
    
    # নিয়ন্ত্রণ বাটনগুলোও side by side
    keyboard.append([KeyboardButton("💾 Save Settings"), KeyboardButton("🔄 Enable Round-Robin")])
    keyboard.append([KeyboardButton("🔴 Disable Round-Robin"), KeyboardButton("📊 Show All Accounts")])
    keyboard.append([KeyboardButton("Back to Main Menu")])
    
    message = (
        "🌐 Multi-Website Round-Robin Settings\n\n"
        "Select websites to enable/disable:\n"
        "✅ = Enabled | ❌ = Disabled\n\n"
        f"🔄 Round-Robin Mode: {'🟢 ON' if status.round_robin_mode else '🔴 OFF'}\n\n"
        "Accounts Summary:\n" + "\n".join(accounts_info)
    )
    
    await update.message.reply_text(
        message,
        reply_markup=ReplyKeyboardMarkup(keyboard, resize_keyboard=True, one_time_keyboard=True)
    )

async def enable_round_robin_mode(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """রাউন্ড-রবিন মোড চালু করে"""
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    
    status = await multi_account_manager.load_status(user_id)
    if not status.enabled_websites:
        await update.message.reply_text(
            "❌ No websites enabled. Please enable at least one website in Multi-Website Settings first.",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    
    # সব enabled ওয়েবসাইটে একাউন্ট আছে কিনা চেক করুন
    missing_accounts = []
    for website in status.enabled_websites:
        if website not in status.all_website_accounts or not status.all_website_accounts[website]:
            missing_accounts.append(website)
    
    if missing_accounts:
        await update.message.reply_text(
            f"❌ No accounts found for: {', '.join(missing_accounts)}\n"
            f"Please login accounts first using 'Log in Account' for these websites.",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    
    status.round_robin_mode = True
    status.current_website_index = 0
    await multi_account_manager.save_status(user_id, status)
    
    # একাউন্ট সামারি তৈরি করুন
    accounts_summary = []
    for website in status.enabled_websites:
        account_count = len(status.all_website_accounts.get(website, []))
        accounts_summary.append(f"{website}: {account_count} accounts")
    
    await update.message.reply_text(
        f"✅ Round-Robin Mode Enabled!\n"
        f"🌐 Active Websites: {', '.join(status.enabled_websites)}\n"
        f"📊 Accounts: {', '.join(accounts_summary)}\n\n"
        f"🔄 Next WhatsApp number will be processed across all enabled websites automatically.",
        reply_markup=get_main_keyboard(selected_website, user_id)
    )

async def disable_round_robin_mode(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """রাউন্ড-রবিন মোড বন্ধ করে"""
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    
    status = await multi_account_manager.load_status(user_id)
    status.round_robin_mode = False
    await multi_account_manager.save_status(user_id, status)
    
    await update.message.reply_text(
        "🔴 Round-Robin Mode Disabled",
        reply_markup=get_main_keyboard(selected_website, user_id)
    )

async def show_all_accounts_summary(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """সব ওয়েবসাইটের একাউন্ট সামারি দেখায়"""
    user_id = update.message.from_user.id
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    
    status = await multi_account_manager.load_status(user_id)
    
    if not status.all_website_accounts:
        await update.message.reply_text(
            "❌ No multi-accounts found for any website.",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return
    
    message = "📊 All Website Accounts Summary:\n\n"
    for website, accounts in status.all_website_accounts.items():
        if accounts:
            message += f"🌐 {website}: {len(accounts)} accounts\n"
            for i, account in enumerate(accounts[:3], 1):  # প্রথম ৩টি একাউন্ট দেখান
                message += f"   {i}. {account['username'][:10]}...\n"
            if len(accounts) > 3:
                message += f"   ... and {len(accounts) - 3} more\n"
            message += "\n"
    
    message += f"🔄 Round-Robin Mode: {'🟢 ON' if status.round_robin_mode else '🔴 OFF'}\n"
    message += f"✅ Enabled Websites: {', '.join(status.enabled_websites) if status.enabled_websites else 'None'}"
    
    await update.message.reply_text(
        message,
        reply_markup=get_main_keyboard(selected_website, user_id)
    )

async def toggle_website_selection(update: Update, context: ContextTypes.DEFAULT_TYPE, website: str):
    """ওয়েবসাইট টগল করে"""
    user_id = update.message.from_user.id
    status = await multi_account_manager.load_status(user_id)
    
    if website in status.enabled_websites:
        status.enabled_websites.remove(website)
    else:
        status.enabled_websites.append(website)
    
    await multi_account_manager.save_status(user_id, status)
    await show_multi_website_settings(update, context)

async def process_multi_account_login(update: Update, context: ContextTypes.DEFAULT_TYPE, credentials_text: str, website: str):
    """Multi account login প্রসেস করে (সব ওয়েবসাইটের জন্য সেভ করে)"""
    user_id = update.message.from_user.id
    device_name = str(user_id)
    
    if not device_manager.exists(device_name):
        await update.message.reply_text(
            "❌ Please set user agent first using 'Set User Agent'.",
            reply_markup=get_main_keyboard(website, user_id)
        )
        return False
    
    # credentials পার্স করুন
    lines = credentials_text.strip().split('\n')
    accounts = []
    
    for line in lines:
        line = line.strip()
        if ':' in line:
            username, password = line.split(':', 1)
            username = username.strip()
            password = password.strip()
            if username and password:
                accounts.append({"username": username, "password": password})
    
    if not accounts:
        await update.message.reply_text(
            "❌ No valid username:password pairs found.",
            reply_markup=get_main_keyboard(website, user_id)
        )
        return False
    
    # accounts সেভ করুন (সব ওয়েবসাইটের জন্য)
    await multi_account_manager.save_accounts(user_id, accounts, website)
    
    # status সেটাপ করুন
    status = await multi_account_manager.load_status(user_id)
    status.enabled = True
    status.current_account_index = 0
    status.total_accounts = len(accounts)
    status.processing = False
    status.website = website
    status.last_activity = datetime.now().isoformat()
    
    # এই ওয়েবসাইটটি enabled websites-এ যোগ করুন যদি না থাকে
    if website not in status.enabled_websites:
        status.enabled_websites.append(website)
    
    await multi_account_manager.save_status(user_id, status)
    
    await update.message.reply_text(
        f"✅ Multi-Account System Enabled!\n"
        f"📊 Total Accounts: {len(accounts)}\n"
        f"🌐 Website: {website}\n\n"
        f"Now use 'Link WhatsApp' to start automatic processing.",
        reply_markup=get_main_keyboard(website, user_id)
    )
    
    # প্রথম অ্যাকাউন্ট লগইন করুন
    await auto_login_next_account(update, context, user_id, website)
    return True


async def process_phone_number(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    phone = update.message.text.strip()
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    account_type = 'main'
    website = selected_website
    website_config = WEBSITE_CONFIGS[website]
    device_name = str(user_id)
    
    # Multi-Account status চেক
    status = await multi_account_manager.load_status(user_id)
    multi_account_linking = context.user_data.get('multi_account_linking', False)
    
    # Multi-Website Round-Robin চেক
    if status.round_robin_mode and status.enabled_websites:
        await start_round_robin_processing(update, context, user_id, phone)
        return
    
    if not device_manager.exists(device_name):
        await update.message.reply_text("❌ Please set user agent first using 'Set User Agent'.", reply_markup=get_main_keyboard(selected_website, user_id))
        return
    logger.info(f"Processing phone number for user {user_id} on {website}")

    phone_clean = re.sub(r'[^\d+]', '', phone)
    if phone_clean.startswith('+1') and len(phone_clean) == 12:
        normalized_phone = phone_clean
    elif len(phone_clean) == 10:
        normalized_phone = '+1' + phone_clean
    else:
        normalized_phone = None

    if not normalized_phone or not re.match(r'^\+1\d{10}$', normalized_phone):
        await update.message.reply_text(
            "❌ Invalid format. Please enter a valid Canada WhatsApp number:\n"
            "- Starts with +1 followed by 10 digits (e.g., +14165551234)\n"
            "- Or 10 digits (e.g., 4165551234)\n"
            "- Or formatted with spaces/parentheses/dashes (e.g., +1 (416) 555-1234)\n\n"
            "Send another number or use /stop to exit.",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return

    tokens = load_tokens()
    token = tokens.get(str(user_id), {}).get(website, {}).get(account_type)

    if not token:
        context.user_data.pop('state', None)
        context.user_data['selected_website'] = selected_website
        await update.message.reply_text(
            f"❌ No {website} account found. Please login first.",
            reply_markup=get_main_keyboard(selected_website, user_id)
        )
        return

    await update.message.reply_text(f"⏳ Processing your request with {website} account...")

    try:
        enc_phone = await encrypt_phone(normalized_phone)
        send_resp = await send_code(token, enc_phone, website_config, device_name)
        logger.debug(f"Send code response for user {user_id} on {website}: {send_resp}")

        if not isinstance(send_resp, dict):
            logger.error(f"Invalid response from send_code for user {user_id} on {website}")
            await update.message.reply_text(
                f"❌ Invalid response from server. Please try again later.\n\n"
                f"Send another number or use /stop to exit.",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
            return

        if send_resp.get("code") != 1:
            error_msg = (
                f"❌ Failed to send verification code\n\n"
                f"Error: {send_resp.get('msg', 'Unknown error')}\n"
                f"Full response: {json.dumps(send_resp, indent=2)}\n\n"
                f"Send another number or use /stop to exit."
            )
            await update.message.reply_text(
                f"<pre>{error_msg}</pre>",
                parse_mode='HTML',
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
            return

        await update.message.reply_text("🔄 Checking for verification code (this may take 10-30 seconds)...")
        code = None
        for attempt in range(MAX_CODE_ATTEMPTS):
            get_resp = await get_code(token, normalized_phone, website_config, device_name)
            logger.debug(f"Get code attempt {attempt + 1} response for user {user_id} on {website}: {get_resp}")
            if isinstance(get_resp, dict) and get_resp.get("code") == 1:
                code = get_resp.get("data", {}).get("code")
                if code:
                    break
            if attempt < MAX_CODE_ATTEMPTS - 1:
                await asyncio.sleep(CODE_CHECK_INTERVAL)

        if code:
            await update.message.reply_text(
                f"✅ Your WhatsApp verification code from {website} account is:\n\n"
                f"<code>{code}</code>\n\n"
                f"Enter this code in WhatsApp to complete linking.\n\n"
                f"Send another number or use /stop to exit.",
                parse_mode='HTML',
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
            
            # Multi-Account enabled থাকলে অটো চেক শুরু করুন
            if status.enabled and multi_account_linking:
                #await update.message.reply_text(
                    #f"🔄 Multi-Account: Monitoring phone list for {normalized_phone}...\n"
                    #f"📊 Progress: {status.current_account_index}/{status.total_accounts}",
                    #reply_markup=get_main_keyboard(selected_website, user_id)
               # )
                
                # Multi-Account status আপডেট করুন
                status.current_phone = normalized_phone
                status.last_activity = f"Processing phone: {normalized_phone}"
                await multi_account_manager.save_status(user_id, status)
                
                # ব্যাকগ্রাউন্ডে ফোন লিস্ট চেক শুরু করুন
                context.application.create_task(
                    check_phone_in_list_and_continue(update, context, user_id, normalized_phone, website)
                )
        else:
            await update.message.reply_text(
                f"❌ Failed to retrieve verification code after {MAX_CODE_ATTEMPTS} attempts. "
                "Please try again later.\n\n"
                "Send another number or use /stop to exit.",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
            
            # Multi-Account enabled থাকলে পরবর্তী অ্যাকাউন্টে যান
            if status.enabled and multi_account_linking:
                await update.message.reply_text(
                    f"🔄 Multi-Account: Moving to next account after failed code retrieval...",
                    reply_markup=get_main_keyboard(selected_website, user_id)
                )
                await asyncio.sleep(0)
                await auto_login_next_account(update, context, user_id, website)
    except Exception as e:
        error_msg = f"❌ An error occurred: {str(e)}\n\nSend another number or use /stop to exit."
        await update.message.reply_text(error_msg, reply_markup=get_main_keyboard(selected_website, user_id))
        logger.error(f"Error in process_phone_number for user {user_id} on {website}: {str(e)}")
        
        # Multi-Account enabled থাকলে পরবর্তী অ্যাকাউন্টে যান
        if status.enabled and multi_account_linking:
            await update.message.reply_text(
                f"🔄 Multi-Account: Moving to next account after error...",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
            await asyncio.sleep(0)
            await auto_login_next_account(update, context, user_id, website)

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
    result = await get_phone_list(token, 'main', website_config, device_name)
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

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id if update.message else "Unknown"
    selected_website = context.user_data.get('selected_website', DEFAULT_SELECTED_WEBSITE)
    try:
        raise context.error
    except NetworkError:
        logger.error(f"Network error for user {user_id}: {context.error}")
        if update.message:
            await update.message.reply_text(
                "❌ Network error occurred. Please try again later.",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
    except BadRequest as e:
        logger.error(f"Bad request error for user {user_id}: {str(e)}")
        if update.message:
            await update.message.reply_text(
                f"❌ Bad request: {str(e)}",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )
    except Exception as e:
        logger.error(f"Unexpected error for user {user_id}: {str(e)}")
        if update.message:
            await update.message.reply_text(
                f"❌ An unexpected error occurred: {str(e)}",
                reply_markup=get_main_keyboard(selected_website, user_id)
            )

from flask import Flask, request
import threading

# Flask app তৈরি করুন
flask_app = Flask(__name__)

@flask_app.route('/')
def home():
    return "Telegram Bot is Running!"

@flask_app.route('/health')
def health():
    return "OK"

def run_flask():
    import os
    port = int(os.environ.get('PORT', 8080))
    flask_app.run(host='0.0.0.0', port=port)

def main():
    app = Application.builder().token(TELEGRAM_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("login", login_command))
    app.add_handler(CommandHandler("regs", get_registrations))
    app.add_handler(CommandHandler("markused", mark_used))
    app.add_handler(CommandHandler("deleteused", delete_used))
    app.add_handler(CommandHandler("stop", stop))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_handler(CallbackQueryHandler(handle_callback_query))
    app.add_error_handler(error_handler)

    logger.info("Bot is starting...")
    
    import os
    if os.environ.get('RENDER'):
        # Render.com এ Flask server এবং bot একসাথে run করবে
        flask_thread = threading.Thread(target=run_flask)
        flask_thread.daemon = True
        flask_thread.start()
    
    # Bot always run in polling mode
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
