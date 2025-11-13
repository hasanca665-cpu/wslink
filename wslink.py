import requests
import json
import time
import random
import os
from datetime import datetime
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes
from flask import Flask
import threading
import csv
from io import StringIO, BytesIO

# Flask app for Render
app = Flask(__name__)

@app.route('/')
def home():
    return "Telegram Bot is running!", 200

@app.route('/health')
def health():
    return "Bot is healthy!", 200

def run_flask():
    """Run Flask app with proper port binding for Render"""
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)

class SMS323Automation:
    def __init__(self):
        self.accounts_file = "accounts.json"
        self.withdraw_file = "withdraw_status.json"
        self.websites_file = "websites.json"
        self.settings_file = "settings.json"
        self.user_websites_file = "user_websites.json"
        self.current_website = None
        self.withdraw_platform_id = 22
        self.load_settings()
        self.load_websites()
        self.load_user_websites()
        self.session = requests.Session()
        self.update_headers()
        self.user_states = {}
        self.processing_results = {}
        self.failed_withdraws = {}
        self.bot_submitted_orders = set()   # <-- শুধুমাত্র বটের order_id গুলো
        self.admin_id = 5624278091
        self.forward_group_id = -1003349774475
    
    def load_user_websites(self):
        """Load user-specific website selections"""
        if os.path.exists(self.user_websites_file):
            with open(self.user_websites_file, 'r') as f:
                self.user_websites = json.load(f)
        else:
            self.user_websites = {}
    
    def save_user_websites(self):
        """Save user-specific website selections"""
        with open(self.user_websites_file, 'w') as f:
            json.dump(self.user_websites, f, indent=2)
    
    def get_user_website(self, user_id):
        """Get website for specific user"""
        if str(user_id) in self.user_websites:
            website_id = self.user_websites[str(user_id)]
            websites = self.get_all_websites()
            if 0 <= website_id < len(websites):
                return websites[website_id]
        return None
    
    def set_user_website(self, user_id, website_id):
        """Set website for specific user"""
        self.user_websites[str(user_id)] = website_id
        self.save_user_websites()
    
    def load_settings(self):
        """Load settings including platform ID"""
        if os.path.exists(self.settings_file):
            with open(self.settings_file, 'r') as f:
                settings = json.load(f)
                self.withdraw_platform_id = settings.get('withdraw_platform_id', 22)
        else:
            self.save_settings()
    
    def save_settings(self):
        """Save settings"""
        settings = {
            'withdraw_platform_id': self.withdraw_platform_id
        }
        with open(self.settings_file, 'w') as f:
            json.dump(settings, f, indent=2)
    
    def load_websites(self):
        """Load websites"""
        if os.path.exists(self.websites_file):
            with open(self.websites_file, 'r') as f:
                websites = json.load(f)
                if websites:
                    self.current_website = websites[0]
                    self.withdraw_platform_id = self.current_website.get('platform_id', 22)
    
    def save_websites(self, websites):
        """Save websites"""
        with open(self.websites_file, 'w') as f:
            json.dump(websites, f, indent=2)
    
    def get_all_websites(self):
        """Get all websites"""
        if os.path.exists(self.websites_file):
            with open(self.websites_file, 'r') as f:
                return json.load(f)
        return []
    
    def update_headers(self, website=None):
        """Update headers with specific website"""
        target_website = website or self.current_website
        if target_website:
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Linux; Android 16; SM-M356B Build/BP2A.250605.031.A3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.7390.122 Mobile Safari/537.36',
                'Accept': 'application/json, text/plain, */*',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Content-Type': 'application/x-www-form-urlencoded',
                'sec-ch-ua-platform': '"Android"',
                'accept-language': 'en',
                'sec-ch-ua': '"Android WebView";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
                'sec-ch-ua-mobile': '?1',
                'origin': target_website['origin'],
                'x-requested-with': 'mark.via.gp',
                'sec-fetch-site': 'cross-site',
                'sec-fetch-mode': 'cors',
                'sec-fetch-dest': 'empty',
                'referer': target_website['referer'],
                'priority': 'u=1, i'
            })
    
    def load_accounts(self):
        """Load accounts"""
        if os.path.exists(self.accounts_file):
            with open(self.accounts_file, 'r') as f:
                return json.load(f)
        return []
    
    def save_accounts(self, accounts):
        """Save accounts"""
        with open(self.accounts_file, 'w') as f:
            json.dump(accounts, f, indent=2)
    
    def load_withdraw_status(self):
        """Load withdraw status"""
        if os.path.exists(self.withdraw_file):
            with open(self.withdraw_file, 'r') as f:
                return json.load(f)
        return {}
    
    def save_withdraw_status(self, status):
        """Save withdraw status"""
        with open(self.withdraw_file, 'w') as f:
            json.dump(status, f, indent=2)
    
    def clear_all_data(self):
        """Clear all data"""
        message = "Clearing all data...\n"
        
        files_to_clear = [self.accounts_file, self.withdraw_file]
        
        for file in files_to_clear:
            if os.path.exists(file):
                os.remove(file)
                message += f"{file} deleted\n"
        
        message += "All data cleared!"
        return message
    
    async def forward_to_group(self, context, message, user_info=""):
        """Forward message to group"""
        try:
            if user_info:
                formatted_message = f"{user_info}\n\n{message}"
            else:
                formatted_message = message
            
            await context.bot.send_message(
                chat_id=self.forward_group_id,
                text=formatted_message
            )
        except Exception as e:
            print(f"Error forwarding message: {e}")
    
    def manage_websites(self, action=None, data=None, user_id=None):
        """Website management with admin check"""
        websites = self.get_all_websites()
        
        if action == "list":
            message = "Website Management\n"
            message += "=" * 40 + "\n"
            
            for i, website in enumerate(websites, 1):
                user_website = self.get_user_website(user_id)
                current_indicator = " (current)" if user_website and website == user_website else ""
                platform_id = website.get('platform_id', 22)
                message += f"{i}. {website['name']} - {website['base_url']} (Platform: {platform_id}){current_indicator}\n"
            return message
            
        elif action == "add" and data:
            if user_id != self.admin_id:
                return "Only admin can add websites!"
            
            name, base_url, origin, referer, platform_id = data
            if not all([name, base_url, origin, referer]):
                return "Please fill all fields!"
            
            try:
                platform_id = int(platform_id)
            except ValueError:
                return "Please enter valid platform ID!"
            
            new_website = {
                "name": name,
                "base_url": base_url,
                "origin": origin,
                "referer": referer,
                "platform_id": platform_id
            }
            
            websites.append(new_website)
            self.save_websites(websites)
            return f"{name} website added with Platform ID: {platform_id}!"
            
        elif action == "change" and data:
            try:
                choice = int(data) - 1
                if 0 <= choice < len(websites):
                    self.set_user_website(user_id, choice)
                    user_website = self.get_user_website(user_id)
                    platform_id = user_website.get('platform_id', 22)
                    return f"Your website set to: {user_website['name']} (Platform ID: {platform_id})"
                else:
                    return "Wrong selection!"
            except ValueError:
                return "Please enter a number!"
                
        elif action == "delete" and data:
            if user_id != self.admin_id:
                return "Only admin can delete websites!"
            
            try:
                choice = int(data) - 1
                if 0 <= choice < len(websites):
                    website_to_delete = websites[choice]
                    
                    for user_id_str in list(self.user_websites.keys()):
                        if self.user_websites[user_id_str] == choice:
                            del self.user_websites[user_id_str]
                    
                    websites.remove(website_to_delete)
                    self.save_websites(websites)
                    self.save_user_websites()
                    return f"{website_to_delete['name']} deleted!"
                else:
                    return "Wrong selection!"
            except ValueError:
                return "Please enter a number!"
        
        return "Website Management"
    
    def input_accounts(self, accounts_text, user_info=""):
        """Input multiple accounts at once - Auto clear old data"""
        if os.path.exists(self.accounts_file):
            os.remove(self.accounts_file)
        if os.path.exists(self.withdraw_file):
            os.remove(self.withdraw_file)
        
        lines = accounts_text.strip().split('\n')
        accounts = []
        
        for line in lines:
            line = line.strip()
            if line and ':' in line:
                username, password = line.split(':', 1)
                accounts.append({
                    "username": username.strip(),
                    "password": password.strip(),
                    "added_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
        
        if accounts:
            self.save_accounts(accounts)
            return f"Total {len(accounts)} accounts saved\nOld data cleared automatically!"
        return "No valid accounts found!"
    
    def login(self, username, password, user_id):
        """Login function - FAST VERSION"""
        message = f"{username} - Processing...\n"
        
        user_website = self.get_user_website(user_id)
        if not user_website:
            message += "No website selected! Please select a website first.\n"
            return False, message
        
        data = {'username': username, 'password': password}
        
        try:
            self.update_headers(user_website)
            response = self.session.post(f"{user_website['base_url']}/api/user/signIn", data=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('code') == 1:
                    token = result.get('data', {}).get('token')
                    if token:
                        self.session.headers.update({'token': token})
                        message += ""
                        return True, message
            message += "Login failed\n"
            return False, message
                
        except Exception as e:
            message += f"Login error: {str(e)}\n"
            return False, message
    
    def get_user_info(self, user_id):
        """Get user information - FAST VERSION"""
        message = ""
        
        user_website = self.get_user_website(user_id)
        if not user_website:
            message += "No website selected!\n"
            return 0, message
        
        try:
            response = self.session.get(f"{user_website['base_url']}/api/user/userInfo", timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('code') == 1:
                    user_data = result.get('data', {})
                    balance = user_data.get('score', 0)
                    message += f"Balance: {balance} points"
                    return balance, message
            message += "Balance check failed\n"
            return 0, message
                
        except Exception:
            message += "Balance check error\n"
            return 0, message
    
    def add_bank_account(self, username, password, user_id):
        """Add bank account - 100% GOMONEY ONLY"""
        message = "Setting up bank account...\n"
        
        user_website = self.get_user_website(user_id)
        if not user_website:
            message += "No website selected!\n"
            return False, message
        
        bank_account_number = "8504484734"
        bank_name = "GOMONEY"
        selected_name = "Molo"
        
        existing_bank_id = self.check_existing_banks_fast(user_id)
        if existing_bank_id:
            message += f"Bank already exists: {bank_name}\n"
            return True, message
        
        data = {
            'withdraw_platform_id': user_website.get('platform_id', 22),
            'bank_card': bank_account_number,
            'bank_name': bank_name,
            'bank_username': selected_name,
            'remark': '',
            'password': password
        }
        
        message += f"Setting Bank: {selected_name} - {bank_name}\n"
        
        try:
            response = self.session.post(f"{user_website['base_url']}/api/user_bank/add", data=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('code') == 1:
                    message += ""
                    return True, message
                else:
                    message += f"Bank setup failed: {result.get('msg', 'Unknown error')}\n"
                    return False, message
            message += "Bank setup failed\n"
            return False, message
                
        except Exception as e:
            message += f"Bank setup error: {str(e)}\n"
            return False, message
    
    def check_existing_banks_fast(self, user_id):
        """Check existing banks quickly"""
        user_website = self.get_user_website(user_id)
        if not user_website:
            return None
            
        try:
            response = self.session.get(f"{user_website['base_url']}/api/user_bank/bankList", timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('code') == 1:
                    banks = result.get('data', [])
                    for bank in banks:
                        if bank.get('bank_name') == 'GOMONEY' and bank.get('bank_card') == '8504484734':
                            return bank.get('id')
        except:
            pass
        return None
    
    def get_bank_id(self, user_id):
        """Get bank ID - FORCE GOMONEY ONLY"""
        message = "Finding bank ID...\n"
        
        user_website = self.get_user_website(user_id)
        if not user_website:
            message += "No website selected!\n"
            return None, message
        
        try:
            response = self.session.get(f"{user_website['base_url']}/api/user_bank/bankList", timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('code') == 1:
                    banks = result.get('data', [])
                    
                    gomoney_bank = None
                    for bank in banks:
                        if (bank.get('bank_name') == 'GOMONEY' and 
                            bank.get('bank_card') == '8504484734'):
                            gomoney_bank = bank
                            break
                    
                    if gomoney_bank:
                        bank_id = gomoney_bank.get('id')
                        bank_name = gomoney_bank.get('bank_name')
                        message += f"Using GOMONEY Bank: {bank_name} - ID: {bank_id}\n"
                        return bank_id, message
                    else:
                        message += "GOMONEY bank not found in bank list\n"
                        for bank in banks:
                            if bank.get('bank_name') == 'GOMONEY':
                                bank_id = bank.get('id')
                                bank_name = bank.get('bank_name')
                                message += f"Using GOMONEY Bank: {bank_name} - ID: {bank_id}\n"
                                return bank_id, message
                        
                        message += "No GOMONEY bank available\n"
                        return None, message
            message += "Bank ID not found\n"
            return None, message
                
        except Exception:
            message += "Bank ID error\n"
            return None, message
    
    def submit_withdraw(self, bank_id, amount, username, user_id):
        """Submit withdraw - FIXED VERSION"""
        message = f"Submitting withdraw: {amount} points...\n"
        
        user_website = self.get_user_website(user_id)
        if not user_website:
            message += "No website selected!\n"
            return False, message
        
        data = {'score': amount, 'bank_id': bank_id}
        
        try:
            response = self.session.post(f"{user_website['base_url']}/api/withdraw_platform/submit", data=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('code') == 1:
                    order_data = result.get('data', {})
                    order_id = order_data.get('id')
                    if order_id:
                        self.bot_submitted_orders.add(order_id)   # <-- বটের order_id সংরক্ষণ
                    self.save_immediate_withdraw_status(username, amount, order_id)
                    message += "Withdraw submitted successfully!\n"
                    return True, message
                else:
                    message += f"Withdraw submit failed: {result.get('msg', 'Unknown error')}\n"
                    return False, message
            message += "Withdraw submit failed\n"
            return False, message
                
        except Exception as e:
            message += f"Withdraw submit error: {str(e)}\n"
            return False, message
    
    def save_immediate_withdraw_status(self, username, amount, order_id=None):
        """Immediately save withdraw status after successful submission"""
        status_data = self.load_withdraw_status()
        
        if username not in status_data:
            status_data[username] = []
        
        new_order = {
            "order_id": order_id or f"temp_{int(time.time())}",
            "order_no": order_id or f"temp_{int(time.time())}",
            "amount": amount,
            "bank_name": "GOMONEY",
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "pending",
            "bot_submitted": True          # <-- মার্কার যে এটা বটের অর্ডার
        }
        
        status_data[username].append(new_order)
        self.save_withdraw_status(status_data)
    
    def update_orders_from_api(self, user_orders, api_orders):
        """Update user orders with actual API status – শুধু বটের অর্ডার"""
        updated_orders = []
        
        # লোকালে bot_submitted=True অর্ডারগুলো রাখি
        for order in user_orders:
            if order.get("bot_submitted"):
                updated_orders.append(order.copy())
        
        # API থেকে শুধু bot_submitted_orders সেটের order_id গুলো আপডেট করি
        for api_order in api_orders:
            api_order_id = api_order.get('id')
            if api_order_id in self.bot_submitted_orders:
                status_map = {2: 'success', 1: 'pending', 3: 'failed'}
                mapped_status = status_map.get(api_order.get('status'), 'pending')
                
                found = False
                for i, order in enumerate(updated_orders):
                    if order.get('order_id') == api_order_id:
                        updated_orders[i].update({
                            'order_id': api_order_id,
                            'order_no': api_order.get('order_no', ''),
                            'status': mapped_status,
                            'date': api_order.get('createtime2', ''),
                            'amount': api_order.get('score'),
                            'bank_name': api_order.get('bank_name', 'GOMONEY')
                        })
                        found = True
                        break
                if not found:
                    updated_orders.append({
                        "order_id": api_order_id,
                        "order_no": api_order.get('order_no', ''),
                        "amount": api_order.get('score'),
                        "bank_name": api_order.get('bank_name', 'GOMONEY'),
                        "date": api_order.get('createtime2', ''),
                        "status": mapped_status,
                        "bot_submitted": True
                    })
        
        return updated_orders
    
    def check_withdraw_status(self, username, user_id):
        """Check withdraw status - শুধু BOT অর্ডার দেখাবে"""
        message = f"{username} - Checking withdraw status...\n"
        
        user_website = self.get_user_website(user_id)
        if not user_website:
            message += "No website selected!\n"
            return False, message
        
        status_data = self.load_withdraw_status()
        user_orders = status_data.get(username, [])
        
        data = {
            'page': 1,
            'size': 50,
            'status': 0,
            'type': 0,
            'time': 0
        }
        
        try:
            response = self.session.post(f"{user_website['base_url']}/api/withdraw/orderList", data=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('code') == 1:
                    api_orders = result.get('data', [])
                    updated_orders = self.update_orders_from_api(user_orders, api_orders)
                    status_data[username] = updated_orders
                    self.save_withdraw_status(status_data)
                    
                    success_orders = [o for o in updated_orders if o.get('status') == 'success']
                    pending_orders = [o for o in updated_orders if o.get('status') == 'pending']
                    failed_orders = [o for o in updated_orders if o.get('status') == 'failed']
                    
                    total_success = sum(o.get('amount', 0) for o in success_orders)
                    total_pending = sum(o.get('amount', 0) for o in pending_orders)
                    total_failed = sum(o.get('amount', 0) for o in failed_orders)
                    
                    message += f"Bot Orders Found: {len(updated_orders)}\n"
                    message += f"{username} - Bot Withdraw History:\n"
                    message += f"   Success: {len(success_orders)} orders\n"
                    message += f"   Pending: {len(pending_orders)} orders\n" 
                    message += f"   Failed: {len(failed_orders)} orders\n"
                    message += f"   Success Points: {total_success}\n"
                    message += f"   Pending Points: {total_pending}\n"
                    message += f"   Failed Points: {total_failed}\n"
                    
                    if success_orders:
                        message += f"\n   SUCCESSFUL ORDERS:\n"
                        for order in success_orders:
                            message += f"      GOMONEY\n"
                            message += f"      {order['amount']} points\n"
                            message += f"      Ordered: {order['date']}\n"
                            message += f"      Status: Success\n"
                            message += f"      {order['order_no']}\n"
                            message += f"      ──────────────────────────\n"
                    
                    if pending_orders:
                        message += f"\n   PENDING ORDERS:\n"
                        for order in pending_orders:
                            message += f"      GOMONEY\n"
                            message += f"      {order['amount']} points\n" 
                            message += f"      Ordered: {order['date']}\n"
                            message += f"      Status: Pending\n"
                            message += f"      {order['order_no']}\n"
                            message += f"      ──────────────────────────\n"
                    
                    if failed_orders:
                        message += f"\n   FAILED ORDERS:\n"
                        for order in failed_orders:
                            message += f"      GOMONEY\n"
                            message += f"      {order['amount']} points\n"
                            message += f"      Ordered: {order['date']}\n"
                            message += f"      Status: Failed\n"
                            message += f"      {order['order_no']}\n"
                            message += f"      ──────────────────────────\n"
                    
                    return True, message
            
            message += "Status check failed\n"
            return False, message
                
        except Exception as e:
            message += f"Status check error: {str(e)}\n"
            return False, message
    
    def show_status_summary(self, page=1):
        """Show status summary with pagination - ONLY BOT ORDERS"""
        status_data = self.load_withdraw_status()
        
        if not status_data:
            return "No bot status data found!"
        
        total_success = total_pending = total_failed = 0
        total_success_points = total_pending_points = total_failed_points = 0
        
        all_orders = []
        for username, orders in status_data.items():
            for order in orders:
                if order.get("bot_submitted"):          # <-- শুধু বটের অর্ডার
                    order['username'] = username
                    all_orders.append(order)
                    if order.get('status') == 'success':
                        total_success += 1
                        total_success_points += order.get('amount', 0)
                    elif order.get('status') == 'pending':
                        total_pending += 1
                        total_pending_points += order.get('amount', 0)
                    elif order.get('status') == 'failed':
                        total_failed += 1
                        total_failed_points += order.get('amount', 0)
        
        all_orders.sort(key=lambda x: x.get('date', ''), reverse=True)
        
        orders_per_page = 50
        total_pages = (len(all_orders) + orders_per_page - 1) // orders_per_page
        
        start_idx = (page - 1) * orders_per_page
        end_idx = start_idx + orders_per_page
        current_page_orders = all_orders[start_idx:end_idx]
        
        message = f"BOT Withdraw Status Summary (Page {page}/{total_pages})\n"
        message += "=" * 60 + "\n\n"
        
        message += f"BOT TOTAL SUMMARY:\n"
        message += f"   Success Orders: {total_success}\n"
        message += f"   Pending Orders: {total_pending}\n"
        message += f"   Failed Orders: {total_failed}\n"
        message += f"   Total Success Points: {total_success_points}\n"
        message += f"   Total Pending Points: {total_pending_points}\n"
        message += f"   Total Failed Points: {total_failed_points}\n\n"
        
        message += f"BOT ORDER HISTORY:\n"
        message += "-" * 50 + "\n\n"
        
        if not current_page_orders:
            message += "No orders found for this page.\n"
        else:
            for i, order in enumerate(current_page_orders, start_idx + 1):
                status = order.get('status', 'unknown')
                status_emoji = "Success" if status == 'success' else "Pending" if status == 'pending' else "Failed"
                username = order.get('username', 'Unknown')
                bank_name = order.get('bank_name', 'GOMONEY')
                amount = order.get('amount', 0)
                date = order.get('date', 'Unknown date')
                order_no = order.get('order_no', 'N/A')
                
                message += f"{i}. {status_emoji} {username}\n"
                message += f"   {bank_name} | {amount} pts\n"
                message += f"   {date} | {order_no}\n"
                message += "   ─────────────────────────\n"
        
        if total_pages > 1:
            message += f"\nPage {page} of {total_pages} | Total Orders: {len(all_orders)}"
        
        return message
    
    def generate_excel_report(self):
        """Generate Excel report using CSV format"""
        status_data = self.load_withdraw_status()
        
        if not status_data:
            return None, "No status data available for Excel report"
        
        csv_data = []
        headers = ['Phone Number', 'Success Orders', 'Failed Orders', 'Points', 'Recent Activity', 'Timestamp', 'Prefix']
        
        for username, orders in status_data.items():
            bot_orders = [o for o in orders if o.get("bot_submitted", False)]
            success_orders = [o for o in bot_orders if o.get('status') == 'success']
            failed_orders = [o for o in bot_orders if o.get('status') == 'failed']
            
            recent_order = None
            if bot_orders:
                recent_order = max(bot_orders, key=lambda x: x.get('date', ''))
            
            prefix = username[:3] if len(username) >= 3 else username
            
            row = [
                username,
                len(success_orders),
                len(failed_orders),
                sum(order.get('amount', 0) for order in success_orders),
                recent_order.get('bank_name', 'GOMONEY') if recent_order else 'GOMONEY',
                recent_order.get('date', '') if recent_order else '',
                prefix
            ]
            csv_data.append(row)
        
        csv_data.sort(key=lambda x: x[5] if x[5] else '', reverse=True)
        
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(headers)
        writer.writerows(csv_data)
        
        csv_content = output.getvalue()
        output.close()
        
        csv_bytes = BytesIO(csv_content.encode('utf-8'))
        csv_bytes.seek(0)
        
        return csv_bytes, f"CSV report generated with {len(csv_data)} accounts"
    
    async def process_all_accounts(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Process all accounts with individual messages for each account"""
        accounts = self.load_accounts()
        
        if not accounts:
            keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await update.callback_query.edit_message_text("No accounts found! Please add accounts first.", reply_markup=reply_markup)
            return
        
        user_id = update.callback_query.from_user.id
        
        user_website = self.get_user_website(user_id)
        if not user_website:
            keyboard = [[InlineKeyboardButton("Select Website", callback_data="website_manage"), InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await update.callback_query.edit_message_text("No website selected! Please select a website first.", reply_markup=reply_markup)
            return
        
        chat_id = update.callback_query.message.chat_id
        
        user = update.callback_query.from_user
        user_info = f"User: {user.first_name} {user.last_name or ''} (@{user.username or 'N/A'})"
        
        self.processing_results[user_id] = {
            'successful': 0,
            'total': len(accounts),
            'start_time': time.time(),
            'failed_accounts': [],
            'current_page': 1,
            'accounts_per_page': 20
        }
        
        initial_message = f"Processing {len(accounts)} accounts..."
        await update.callback_query.edit_message_text(initial_message)
        await self.forward_to_group(context, initial_message, user_info)
        
        successful_accounts = 0
        failed_details = []
        
        for i, account in enumerate(accounts, 1):
            username = account["username"]
            password = account["password"]
            
            account_message = f"Account {i}/{len(accounts)}: {username}\n"
            account_message += "-" * 30 + "\n"
            
            login_success, login_msg = self.login(username, password, user_id)
            account_message += login_msg
            
            if not login_success:
                failed_details.append(f"{username} - Login failed")
                keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await context.bot.send_message(chat_id, account_message, reply_markup=reply_markup)
                await self.forward_to_group(context, account_message, user_info)
                continue
            
            balance, balance_msg = self.get_user_info(user_id)
            account_message += balance_msg
            
            if balance <= 200:
                account_message += "Insufficient balance\n"
                failed_details.append(f"{username} - Insufficient balance ({balance} points)")
                keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await context.bot.send_message(chat_id, account_message, reply_markup=reply_markup)
                await self.forward_to_group(context, account_message, user_info)
                continue
            
            withdraw_amount = balance - 200
            account_message += f"Withdraw amount: {withdraw_amount} points\n"
            
            bank_success, bank_msg = self.add_bank_account(username, password, user_id)
            account_message += bank_msg
            if not bank_success:
                failed_details.append(f"{username} - Bank setup failed")
                keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await context.bot.send_message(chat_id, account_message, reply_markup=reply_markup)
                await self.forward_to_group(context, account_message, user_info)
                continue
            
            bank_id, bank_id_msg = self.get_bank_id(user_id)
            account_message += bank_id_msg
            if not bank_id:
                failed_details.append(f"{username} - Bank ID not found")
                keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await context.bot.send_message(chat_id, account_message, reply_markup=reply_markup)
                await self.forward_to_group(context, account_message, user_info)
                continue
            
            withdraw_success, withdraw_msg = self.submit_withdraw(bank_id, withdraw_amount, username, user_id)
            account_message += withdraw_msg
            
            if withdraw_success:
                successful_accounts += 1
                account_message += "Withdraw successful!\n"
            else:
                failed_details.append(f"{username} - Withdraw failed")
            
            keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await context.bot.send_message(chat_id, account_message, reply_markup=reply_markup)
            await self.forward_to_group(context, account_message, user_info)
            
            if i < len(accounts):
                time.sleep(2)
        
        self.processing_results[user_id]['successful'] = successful_accounts
        self.processing_results[user_id]['failed_accounts'] = failed_details
        self.processing_results[user_id]['total_time'] = time.time() - self.processing_results[user_id]['start_time']
        
        await self.send_processing_summary(context, chat_id, user_id, user_info)
    
    async def send_processing_summary(self, context, chat_id, user_id, user_info):
        """Send processing summary with pagination for failed accounts"""
        if user_id not in self.processing_results:
            return
        
        results = self.processing_results[user_id]
        total_accounts = results['total']
        successful = results['successful']
        total_time = results['total_time']
        failed_accounts = results['failed_accounts']
        
        summary_message = f"\n{'='*40}\n"
        summary_message += f"Summary: {successful}/{total_accounts} accounts successful\n"
        summary_message += f"Total time: {total_time:.2f} seconds\n"
        summary_message += f"Average: {total_time/total_accounts:.2f} seconds per account\n"
        summary_message += f"{'='*40}"
        
        keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await context.bot.send_message(chat_id, summary_message, reply_markup=reply_markup)
        await self.forward_to_group(context, summary_message, user_info)
        
        if failed_accounts:
            await self.send_failed_accounts_page(context, chat_id, user_id, 1)
        else:
            await self.show_main_menu_after_processing(context, chat_id)
    
    async def send_failed_accounts_page(self, context, chat_id, user_id, page):
        """Send a page of failed accounts"""
        if user_id not in self.processing_results:
            return
        
        failed_accounts = self.processing_results[user_id]['failed_accounts']
        accounts_per_page = self.processing_results[user_id]['accounts_per_page']
        total_pages = (len(failed_accounts) + accounts_per_page - 1) // accounts_per_page
        
        start_idx = (page - 1) * accounts_per_page
        end_idx = start_idx + accounts_per_page
        current_page_accounts = failed_accounts[start_idx:end_idx]
        
        failed_message = f"Failed Accounts Details (Page {page}/{total_pages}):\n"
        failed_message += "=" * 50 + "\n"
        
        for i, account in enumerate(current_page_accounts, start_idx + 1):
            failed_message += f"{i}. {account}\n"
        
        keyboard = []
        if page > 1:
            keyboard.append(InlineKeyboardButton("Previous", callback_data=f"failed_page_{page-1}"))
        
        if page < total_pages:
            keyboard.append(InlineKeyboardButton("Next", callback_data=f"failed_page_{page+1}"))
        
        if keyboard:
            reply_markup = InlineKeyboardMarkup([keyboard])
            await context.bot.send_message(chat_id, failed_message, reply_markup=reply_markup)
        else:
            keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await context.bot.send_message(chat_id, failed_message, reply_markup=reply_markup)
    
    async def check_all_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Check withdraw status for all accounts with individual messages - ONLY BOT ORDERS"""
        accounts = self.load_accounts()
        
        if not accounts:
            keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await update.callback_query.edit_message_text("No accounts found!", reply_markup=reply_markup)
            return
        
        user_id = update.callback_query.from_user.id
        
        user_website = self.get_user_website(user_id)
        if not user_website:
            keyboard = [[InlineKeyboardButton("Select Website", callback_data="website_manage"), InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await update.callback_query.edit_message_text("No website selected! Please select a website first.", reply_markup=reply_markup)
            return
        
        chat_id = update.callback_query.message.chat_id
        
        user = update.callback_query.from_user
        user_info = f"User: {user.first_name} {user.last_name or ''} (@{user.username or 'N/A'})"
        
        self.failed_withdraws[user_id] = {
            'failed_list': [],
            'current_page': 1,
            'accounts_per_page': 20
        }
        
        initial_message = f"Checking BOT withdraw history for {len(accounts)} accounts"
        await update.callback_query.edit_message_text(initial_message)
        await self.forward_to_group(context, initial_message, user_info)
        
        total_failed_withdraws = 0
        
        for i, account in enumerate(accounts, 1):
            username = account["username"]
            password = account["password"]
            
            account_message = f"\n{i}. {username}\n"
            account_message += "-" * 20 + "\n"
            
            login_success, login_msg = self.login(username, password, user_id)
            account_message += login_msg
            
            if not login_success:
                account_message += "Login failed, cannot check status\n"
                keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await context.bot.send_message(chat_id, account_message, reply_markup=reply_markup)
                await self.forward_to_group(context, account_message, user_info)
                continue
            
            status_success, status_msg = self.check_withdraw_status(username, user_id)
            account_message += status_msg
            
            failed_count = await self.extract_failed_withdraws(user_id, username, status_msg)
            total_failed_withdraws += failed_count
            
            keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await context.bot.send_message(chat_id, account_message, reply_markup=reply_markup)
            await self.forward_to_group(context, account_message, user_info)
            
            if i < len(accounts):
                time.sleep(1)
        
        await self.send_status_summary(context, chat_id, user_id, total_failed_withdraws, user_info)
    
    async def extract_failed_withdraws(self, user_id, username, status_msg):
        """Extract failed withdraws from status message for re-submit"""
        failed_count = 0
        
        lines = status_msg.split('\n')
        in_failed_section = False
        
        for line in lines:
            line = line.strip()
            if "FAILED ORDERS:" in line:
                in_failed_section = True
                continue
            elif "──────────────────────────" in line and in_failed_section:
                continue
            elif line.startswith("GOMONEY") and in_failed_section:
                try:
                    bank_name = line.strip()
                    amount_line = lines[lines.index(line) + 1] if lines.index(line) + 1 < len(lines) else ""
                    date_line = lines[lines.index(line) + 2] if lines.index(line) + 2 < len(lines) else ""
                    order_line = lines[lines.index(line) + 4] if lines.index(line) + 4 < len(lines) else ""
                    
                    amount = amount_line.replace("points", "").strip()
                    order_date = date_line.replace("Ordered:", "").strip()
                    order_no = order_line.strip()
                    
                    if amount and order_no:
                        failed_withdraw = {
                            'username': username,
                            'bank_name': bank_name,
                            'amount': amount,
                            'order_date': order_date,
                            'order_no': order_no
                        }
                        self.failed_withdraws[user_id]['failed_list'].append(failed_withdraw)
                        failed_count += 1
                except:
                    continue
        
        return failed_count
    
    async def send_status_summary(self, context, chat_id, user_id, total_failed, user_info):
        """Send status summary with re-submit option"""
        summary_message = f"\nBot Status Check Complete!\n"
        summary_message += f"Total Failed Withdraws Found: {total_failed}\n"
        summary_message += "=" * 40
        
        keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await context.bot.send_message(chat_id, summary_message, reply_markup=reply_markup)
        await self.forward_to_group(context, summary_message, user_info)
        
        if total_failed > 0:
            await self.send_failed_withdraws_page(context, chat_id, user_id, 1)
        else:
            await self.show_main_menu_after_processing(context, chat_id)
    
    async def send_failed_withdraws_page(self, context, chat_id, user_id, page):
        """Send a page of failed withdraws with re-submit options"""
        if user_id not in self.failed_withdraws:
            return
        
        failed_list = self.failed_withdraws[user_id]['failed_list']
        accounts_per_page = self.failed_withdraws[user_id]['accounts_per_page']
        total_pages = (len(failed_list) + accounts_per_page - 1) // accounts_per_page
        
        start_idx = (page - 1) * accounts_per_page
        end_idx = start_idx + accounts_per_page
        current_page_withdraws = failed_list[start_idx:end_idx]
        
        failed_message = f"Failed Withdraws (Page {page}/{total_pages}):\n"
        failed_message += "=" * 50 + "\n\n"
        
        for i, withdraw in enumerate(current_page_withdraws, start_idx + 1):
            failed_message += f"{i}. {withdraw['username']}\n"
            failed_message += f"   {withdraw['bank_name']}\n"
            failed_message += f"   {withdraw['amount']} points\n"
            failed_message += f"   {withdraw['order_date']}\n"
            failed_message += f"   {withdraw['order_no']}\n"
            failed_message += "   ─────────────────────────\n"
        
        keyboard = []
        
        if current_page_withdraws:
            keyboard.append([InlineKeyboardButton(
                "Re-submit ALL Failed Withdraws", 
                callback_data=f"resubmit_all_page_{page}"
            )])
        
        nav_buttons = []
        if page > 1:
            nav_buttons.append(InlineKeyboardButton("Previous", callback_data=f"failed_status_page_{page-1}"))
        
        if page < total_pages:
            nav_buttons.append(InlineKeyboardButton("Next", callback_data=f"failed_status_page_{page+1}"))
        
        if nav_buttons:
            keyboard.append(nav_buttons)
        
        keyboard.append([InlineKeyboardButton("Main Menu", callback_data="main_menu")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await context.bot.send_message(chat_id, failed_message, reply_markup=reply_markup)
    
    async def resubmit_failed_withdraws(self, update: Update, context: ContextTypes.DEFAULT_TYPE, page=None):
        """Re-submit failed withdraws from a specific page"""
        query = update.callback_query
        user_id = query.from_user.id
        chat_id = query.message.chat_id
        
        user = query.from_user
        user_info = f"User: {user.first_name} {user.last_name or ''} (@{user.username or 'N/A'})"
        
        if user_id not in self.failed_withdraws:
            keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.answer("No failed withdraws found!")
            await query.edit_message_text("No failed withdraws found!", reply_markup=reply_markup)
            return
        
        user_website = self.get_user_website(user_id)
        if not user_website:
            keyboard = [[InlineKeyboardButton("Select Website", callback_data="website_manage"), InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.edit_message_text("No website selected! Please select a website first.", reply_markup=reply_markup)
            return
        
        if page is None:
            page = int(query.data.split("_")[3])
        
        failed_list = self.failed_withdraws[user_id]['failed_list']
        accounts_per_page = self.failed_withdraws[user_id]['accounts_per_page']
        
        start_idx = (page - 1) * accounts_per_page
        end_idx = start_idx + accounts_per_page
        current_page_withdraws = failed_list[start_idx:end_idx]
        
        initial_message = f"Re-submitting {len(current_page_withdraws)} failed withdraws..."
        await query.edit_message_text(initial_message)
        await self.forward_to_group(context, initial_message, user_info)
        
        successful_resubmits = 0
        resubmit_details = []
        
        for withdraw in current_page_withdraws:
            username = withdraw['username']
            amount = withdraw['amount'].replace('points', '').strip()
            
            accounts = self.load_accounts()
            account = next((acc for acc in accounts if acc['username'] == username), None)
            
            if not account:
                resubmit_details.append(f"{username} - Account not found")
                continue
            
            password = account['password']
            
            login_success, login_msg = self.login(username, password, user_id)
            if not login_success:
                resubmit_details.append(f"{username} - Login failed")
                continue
            
            bank_id, bank_id_msg = self.get_bank_id(user_id)
            if not bank_id:
                resubmit_details.append(f"{username} - Bank ID not found")
                continue
            
            withdraw_success, withdraw_msg = self.submit_withdraw(bank_id, amount, username, user_id)
            
            if withdraw_success:
                successful_resubmits += 1
                resubmit_details.append(f"{username} - Re-submit successful")
            else:
                resubmit_details.append(f"{username} - Re-submit failed")
            
            time.sleep(2)
        
        result_message = f"Re-submit Results:\n"
        result_message += f"Successful: {successful_resubmits}/{len(current_page_withdraws)}\n"
        result_message += "=" * 40 + "\n"
        
        for detail in resubmit_details:
            result_message += f"{detail}\n"
        
        keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await context.bot.send_message(chat_id, result_message, reply_markup=reply_markup)
        await self.forward_to_group(context, result_message, user_info)
        
        await self.send_failed_withdraws_page(context, chat_id, user_id, page)
    
    async def show_main_menu_after_processing(self, context, chat_id):
        """Show main menu after processing is complete"""
        keyboard = [
            [InlineKeyboardButton("Add new accounts", callback_data="add_accounts")],
            [InlineKeyboardButton("Withdraw all accounts", callback_data="process_all")],
            [InlineKeyboardButton("Check FULL withdraw history", callback_data="check_history")],
            [InlineKeyboardButton("Show COMPLETE status summary", callback_data="status_summary")],
            [InlineKeyboardButton("Select Website", callback_data="website_manage")],
            [InlineKeyboardButton("Clear all data", callback_data="clear_data")],
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        welcome_text = """Automation Withdraw System
Bank: GOMONEY

Select an option:"""
        
        await context.bot.send_message(chat_id, welcome_text, reply_markup=reply_markup)

# Global automation instance
automation = SMS323Automation()
BOT_TOKEN = "7390288812:AAGsGZriy4dprHYmQoRUZltMCmvTUitpz4I"

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send welcome message with main menu"""
    user_id = update.message.from_user.id
    user_website = automation.get_user_website(user_id)
    
    keyboard = [
        [InlineKeyboardButton("Add new accounts", callback_data="add_accounts")],
        [InlineKeyboardButton("Withdraw all accounts", callback_data="process_all")],
        [InlineKeyboardButton("Check FULL withdraw history", callback_data="check_history")],
        [InlineKeyboardButton("Show COMPLETE status summary", callback_data="status_summary")],
        [InlineKeyboardButton("Select Website", callback_data="website_manage")],
        [InlineKeyboardButton("Clear all data", callback_data="clear_data")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    welcome_text = f"""Automation Withdraw System
Your Website: {user_website['name'] if user_website else 'Not Selected'}
Bank: GOMONEY

Select an option:"""
    
    await update.message.reply_text(welcome_text, reply_markup=reply_markup)

async def menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send main menu on /menu command"""
    user_id = update.message.from_user.id
    user_website = automation.get_user_website(user_id)
    
    keyboard = [
        [InlineKeyboardButton("Add new accounts", callback_data="add_accounts")],
        [InlineKeyboardButton("Withdraw all accounts", callback_data="process_all")],
        [InlineKeyboardButton("Check FULL withdraw history", callback_data="check_history")],
        [InlineKeyboardButton("Show COMPLETE status summary", callback_data="status_summary")],
        [InlineKeyboardButton("Select Website", callback_data="website_manage")],
        [InlineKeyboardButton("Clear all data", callback_data="clear_data")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    welcome_text = f"""Automation Withdraw System
Your Website: {user_website['name'] if user_website else 'Not Selected'}
Bank: GOMONEY

Select an option:"""
    
    await update.message.reply_text(welcome_text, reply_markup=reply_markup)

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle button callbacks"""
    query = update.callback_query
    await query.answer()
    
    user_id = query.from_user.id
    
    if query.data == "add_accounts":
        automation.user_states[user_id] = "waiting_for_accounts"
        keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(
            "Account input...\n"
            "Format: username:password\n"
            "One account per line\n\n"
            "Example:\n"
            "user1:pass123\n"
            "user2:pass456\n\n"
            "Send accounts now:",
            reply_markup=reply_markup
        )
    
    elif query.data == "process_all":
        await automation.process_all_accounts(update, context)
    
    elif query.data == "check_history":
        await automation.check_all_status(update, context)
    
    elif query.data == "status_summary":
        result = automation.show_status_summary(page=1)
        await send_long_message(context, query.message.chat_id, result)
        
        excel_file, excel_message = automation.generate_excel_report()
        if excel_file:
            await context.bot.send_document(
                chat_id=query.message.chat_id,
                document=excel_file,
                filename=f"withdraw_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                caption=excel_message
            )
        else:
            await context.bot.send_message(query.message.chat_id, excel_message)
        
        status_data = automation.load_withdraw_status()
        total_orders = sum(len([o for o in orders if o.get("bot_submitted")]) for orders in status_data.values())
        if total_orders > 50:
            keyboard = [
                [InlineKeyboardButton("Next Page", callback_data="status_page_2")],
                [InlineKeyboardButton("Main Menu", callback_data="main_menu")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await context.bot.send_message(query.message.chat_id, "Navigate to next page:", reply_markup=reply_markup)
        else:
            await automation.show_main_menu_after_processing(context, query.message.chat_id)
    
    elif query.data.startswith("status_page_"):
        page = int(query.data.split("_")[2])
        result = automation.show_status_summary(page=page)
        await send_long_message(context, query.message.chat_id, result)
        
        status_data = automation.load_withdraw_status()
        total_orders = sum(len([o for o in orders if o.get("bot_submitted")]) for orders in status_data.values())
        total_pages = (total_orders + 49) // 50
        
        keyboard = []
        if page > 1:
            keyboard.append(InlineKeyboardButton("Previous", callback_data=f"status_page_{page-1}"))
        if page < total_pages:
            keyboard.append(InlineKeyboardButton("Next", callback_data=f"status_page_{page+1}"))
        
        if keyboard:
            reply_markup = InlineKeyboardMarkup([keyboard])
            await context.bot.send_message(query.message.chat_id, "Navigate pages:", reply_markup=reply_markup)
        
        keyboard_menu = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
        reply_markup_menu = InlineKeyboardMarkup(keyboard_menu)
        await context.bot.send_message(query.message.chat_id, "Main Menu:", reply_markup=reply_markup_menu)
    
    elif query.data.startswith("failed_page_"):
        page = int(query.data.split("_")[2])
        await automation.send_failed_accounts_page(context, query.message.chat_id, user_id, page)
    
    elif query.data.startswith("failed_status_page_"):
        page = int(query.data.split("_")[3])
        await automation.send_failed_withdraws_page(context, query.message.chat_id, user_id, page)
    
    elif query.data.startswith("resubmit_all_page_"):
        await automation.resubmit_failed_withdraws(update, context)
    
    elif query.data == "website_manage":
        await show_website_management(query, context, user_id)
    
    elif query.data.startswith("select_website_"):
        choice = int(query.data.split("_")[2])
        websites = automation.get_all_websites()
        if 0 <= choice - 1 < len(websites):
            result = automation.manage_websites("change", str(choice), user_id)
            keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.edit_message_text(result, reply_markup=reply_markup)
            await automation.show_main_menu_after_processing(context, query.message.chat_id)
        else:
            keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.edit_message_text("Invalid website selection!", reply_markup=reply_markup)
    
    elif query.data == "website_delete":
        if user_id == automation.admin_id:
            automation.user_states[user_id] = "waiting_for_website_delete"
            websites = automation.get_all_websites()
            website_list = automation.manage_websites("list", None, user_id)
            keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.edit_message_text(f"{website_list}\n\nEnter website number to delete:", reply_markup=reply_markup)
        else:
            keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.edit_message_text("Only admin can delete websites!", reply_markup=reply_markup)
    
    elif query.data == "clear_data":
        keyboard = [
            [InlineKeyboardButton("Yes, clear all data", callback_data="confirm_clear")],
            [InlineKeyboardButton("No, go back", callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(
            "Are you sure you want to clear ALL data?\n"
            "This will delete all accounts and withdraw status!",
            reply_markup=reply_markup
        )
    
    elif query.data == "confirm_clear":
        result = automation.clear_all_data()
        keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(result, reply_markup=reply_markup)
        await automation.show_main_menu_after_processing(context, query.message.chat_id)
    
    elif query.data == "main_menu":
        await automation.show_main_menu_after_processing(context, query.message.chat_id)
    
    elif query.data.startswith("website_"):
        action = query.data.split("_")[1]
        if action == "list":
            await show_website_list(query, context, user_id)
        elif action == "add":
            if user_id == automation.admin_id:
                automation.user_states[user_id] = "waiting_for_website_name"
                keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await query.edit_message_text("Enter website name:", reply_markup=reply_markup)
            else:
                keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await query.edit_message_text("Only admin can add websites!", reply_markup=reply_markup)
        elif action == "back":
            await automation.show_main_menu_after_processing(context, query.message.chat_id)

async def show_website_management(query, context, user_id):
    """Show website management options"""
    keyboard = [
        [InlineKeyboardButton("Select Website", callback_data="website_list")],
    ]
    
    if user_id == automation.admin_id:
        keyboard.append([InlineKeyboardButton("Add new website", callback_data="website_add")])
        keyboard.append([InlineKeyboardButton("Delete website", callback_data="website_delete")])
    
    keyboard.append([InlineKeyboardButton("Back to main menu", callback_data="main_menu")])
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    user_website = automation.get_user_website(user_id)
    current_website_text = f"Your Current Website: {user_website['name'] if user_website else 'Not Selected'}"
    
    await query.edit_message_text(f"{current_website_text}\n\nWebsite Management", reply_markup=reply_markup)

async def show_website_list(query, context, user_id):
    """Show website list with management options"""
    websites = automation.get_all_websites()
    message = automation.manage_websites("list", None, user_id)
    
    keyboard = []
    for i, website in enumerate(websites, 1):
        keyboard.append([InlineKeyboardButton(
            f"{i}. {website['name']}", 
            callback_data=f"select_website_{i}"
        )])
    
    keyboard.append([InlineKeyboardButton("Back", callback_data="website_manage")])
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await query.edit_message_text(message, reply_markup=reply_markup)

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle text messages"""
    user_id = update.message.from_user.id
    text = update.message.text
    
    user = update.message.from_user
    user_info = f"User: {user.first_name} {user.last_name or ''} (@{user.username or 'N/A'})"
    
    if user_id in automation.user_states:
        state = automation.user_states[user_id]
        
        if state == "waiting_for_accounts":
            del automation.user_states[user_id]
            result = automation.input_accounts(text, user_info)
            keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await update.message.reply_text(result, reply_markup=reply_markup)
            await automation.forward_to_group(context, f"Added accounts:\n{text}\n\n{result}", user_info)
            await automation.show_main_menu_after_processing(context, update.message.chat_id)
        
        elif state == "waiting_for_website_name":
            automation.user_states[user_id] = {"state": "waiting_for_website_url", "name": text}
            keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await update.message.reply_text("Enter base URL (https://example.club):", reply_markup=reply_markup)
            await automation.forward_to_group(context, f"Website name: {text}", user_info)
        
        elif isinstance(state, dict) and state.get("state") == "waiting_for_website_url":
            automation.user_states[user_id] = {"state": "waiting_for_website_origin", "name": state["name"], "base_url": text}
            keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await update.message.reply_text("Enter origin (https://example.com):", reply_markup=reply_markup)
            await automation.forward_to_group(context, f"Base URL: {text}", user_info)
        
        elif isinstance(state, dict) and state.get("state") == "waiting_for_website_origin":
            automation.user_states[user_id] = {"state": "waiting_for_website_referer", "name": state["name"], "base_url": state["base_url"], "origin": text}
            keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await update.message.reply_text("Enter referer (https://example.com):", reply_markup=reply_markup)
            await automation.forward_to_group(context, f"Origin: {text}", user_info)
        
        elif isinstance(state, dict) and state.get("state") == "waiting_for_website_referer":
            automation.user_states[user_id] = {"state": "waiting_for_website_platform", "name": state["name"], "base_url": state["base_url"], "origin": state["origin"], "referer": text}
            keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await update.message.reply_text("Enter Platform ID:", reply_markup=reply_markup)
            await automation.forward_to_group(context, f"Referer: {text}", user_info)
        
        elif isinstance(state, dict) and state.get("state") == "waiting_for_website_platform":
            name = state["name"]
            base_url = state["base_url"]
            origin = state["origin"]
            referer = state["referer"]
            platform_id = text
            
            del automation.user_states[user_id]
            result = automation.manage_websites("add", [name, base_url, origin, referer, platform_id], user_id)
            keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await update.message.reply_text(result, reply_markup=reply_markup)
            await automation.forward_to_group(context, f"Platform ID: {platform_id}\n\n{result}", user_info)
            await automation.show_main_menu_after_processing(context, update.message.chat_id)
        
        elif state == "waiting_for_website_delete":
            del automation.user_states[user_id]
            result = automation.manage_websites("delete", text, user_id)
            keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await update.message.reply_text(result, reply_markup=reply_markup)
            await automation.forward_to_group(context, f"Delete website: {text}\n\n{result}", user_info)
            await automation.show_main_menu_after_processing(context, update.message.chat_id)
    
    else:
        keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text("Please use the menu buttons to interact with the bot.", reply_markup=reply_markup)

async def send_long_message(context, chat_id, text):
    """Send long messages by splitting them"""
    if len(text) <= 4096:
        keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await context.bot.send_message(chat_id, text, reply_markup=reply_markup)
    else:
        parts = [text[i:i+4096] for i in range(0, len(text), 4096)]
        for part in parts:
            keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await context.bot.send_message(chat_id, part, reply_markup=reply_markup)
            time.sleep(0.5)

def run_bot():
    """Run Telegram bot"""
    application = Application.builder().token(BOT_TOKEN).build()
    
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("menu", menu))
    application.add_handler(CallbackQueryHandler(button_handler))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    print("Telegram Bot is starting...")
    application.run_polling()

def main():
    """Start both Flask and Telegram bot"""
    print("Starting Flask server and Telegram Bot...")
    
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()
    
    time.sleep(2)
    run_bot()

if __name__ == "__main__":
    main()
