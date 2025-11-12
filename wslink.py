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

# Flask app for Render
app = Flask(__name__)

@app.route('/')
def home():
    return "🤖 Telegram Bot is running!", 200

@app.route('/health')
def health():
    return "✅ Bot is healthy!", 200

def run_flask():
    """Run Flask app with proper port binding for Render"""
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)

# Keep the rest of your existing code exactly the same
class SMS323Automation:
    def __init__(self):
        self.accounts_file = "accounts.json"
        self.withdraw_file = "withdraw_status.json"
        self.websites_file = "websites.json"
        self.settings_file = "settings.json"
        self.current_website = None
        self.withdraw_platform_id = 22  # Default platform ID
        self.load_settings()
        self.load_websites()
        self.session = requests.Session()
        self.update_headers()
        self.user_states = {}
        self.processing_results = {}
        self.failed_withdraws = {}
        self.bot_submitted_orders = set()
        self.admin_id = 5624278091  # Admin user ID
        self.forward_group_id = -1003349774475  # Forward group chat ID
    
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
                    # Set platform ID from current website
                    self.withdraw_platform_id = self.current_website.get('platform_id', 22)
        else:
            # Default website
            self.current_website = {
                "name": "DIY22",
                "base_url": "https://diy22.club",
                "origin": "https://diy22.net",
                "referer": "https://diy22.net",
                "platform_id": 22
            }
            self.save_websites([self.current_website])
    
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
    
    def update_headers(self):
        """Update headers"""
        if self.current_website:
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Linux; Android 16; SM-M356B Build/BP2A.250605.031.A3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.7390.122 Mobile Safari/537.36',
                'Accept': 'application/json, text/plain, */*',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Content-Type': 'application/x-www-form-urlencoded',
                'sec-ch-ua-platform': '"Android"',
                'accept-language': 'en',
                'sec-ch-ua': '"Android WebView";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
                'sec-ch-ua-mobile': '?1',
                'origin': self.current_website['origin'],
                'x-requested-with': 'mark.via.gp',
                'sec-fetch-site': 'cross-site',
                'sec-fetch-mode': 'cors',
                'sec-fetch-dest': 'empty',
                'referer': self.current_website['referer'],
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
        message = "🗑️ Clearing all data...\n"
        
        files_to_clear = [self.accounts_file, self.withdraw_file]
        
        for file in files_to_clear:
            if os.path.exists(file):
                os.remove(file)
                message += f"✅ {file} deleted\n"
        
        message += "🎉 All data cleared!"
        return message
    
    async def forward_to_group(self, context, message, user_info=""):
        """Forward message to group"""
        try:
            if user_info:
                formatted_message = f"👤 {user_info}\n\n{message}"
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
            message = "🌐 Website Management\n"
            message += "=" * 40 + "\n"
            
            for i, website in enumerate(websites, 1):
                current_indicator = " ✅" if website == self.current_website else ""
                platform_id = website.get('platform_id', 22)
                message += f"{i}. {website['name']} - {website['base_url']} (Platform: {platform_id}){current_indicator}\n"
            return message
            
        elif action == "add" and data:
            # Check if user is admin
            if user_id != self.admin_id:
                return "❌ Only admin can add websites!"
            
            name, base_url, origin, referer, platform_id = data
            if not all([name, base_url, origin, referer]):
                return "❌ Please fill all fields!"
            
            try:
                platform_id = int(platform_id)
            except ValueError:
                return "❌ Please enter valid platform ID!"
            
            new_website = {
                "name": name,
                "base_url": base_url,
                "origin": origin,
                "referer": referer,
                "platform_id": platform_id
            }
            
            websites.append(new_website)
            self.save_websites(websites)
            return f"✅ {name} website added with Platform ID: {platform_id}!"
            
        elif action == "change" and data:
            try:
                choice = int(data) - 1
                if 0 <= choice < len(websites):
                    self.current_website = websites[choice]
                    self.withdraw_platform_id = self.current_website.get('platform_id', 22)
                    self.update_headers()
                    platform_id = self.current_website.get('platform_id', 22)
                    return f"✅ Current website: {self.current_website['name']} (Platform ID: {platform_id})"
                else:
                    return "❌ Wrong selection!"
            except ValueError:
                return "❌ Please enter a number!"
                
        elif action == "delete" and data:
            # Check if user is admin
            if user_id != self.admin_id:
                return "❌ Only admin can delete websites!"
            
            try:
                choice = int(data) - 1
                if 0 <= choice < len(websites):
                    website_to_delete = websites[choice]
                    
                    if website_to_delete == self.current_website:
                        return "❌ Cannot delete current website!"
                    
                    websites.remove(website_to_delete)
                    self.save_websites(websites)
                    return f"✅ {website_to_delete['name']} deleted!"
                else:
                    return "❌ Wrong selection!"
            except ValueError:
                return "❌ Please enter a number!"
        
        return "🌐 Website Management"
    
    def input_accounts(self, accounts_text, user_info=""):
        """Input multiple accounts at once - Auto clear old data"""
        # Clear old data automatically when new accounts are added
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
            return f"💾 Total {len(accounts)} accounts saved\n🔄 Old data cleared automatically!"
        return "❌ No valid accounts found!"
    
    def login(self, username, password):
        """Login function - FAST VERSION"""
        message = f"🔐 {username} - Processing...\n"
        
        data = {'username': username, 'password': password}
        
        try:
            response = self.session.post(f"{self.current_website['base_url']}/api/user/signIn", data=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('code') == 1:
                    token = result.get('data', {}).get('token')
                    if token:
                        self.session.headers.update({'token': token})
                        message += ""
                        return True, message
            message += "❌ Login failed\n"
            return False, message
                
        except Exception as e:
            message += f"❌ Login error: {str(e)}\n"
            return False, message
    
    def get_user_info(self):
        """Get user information - FAST VERSION"""
        message = ""
        
        try:
            response = self.session.get(f"{self.current_website['base_url']}/api/user/userInfo", timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('code') == 1:
                    user_data = result.get('data', {})
                    balance = user_data.get('score', 0)
                    user_id = user_data.get('id', 'N/A')
                    message += f"✅ Balance: {balance} points"
                    return balance, message
            message += "❌ Balance check failed\n"
            return 0, message
                
        except Exception:
            message += "❌ Balance check error\n"
            return 0, message
    
    def add_bank_account(self, username, password):
        """Add bank account - 100% GOMONEY ONLY"""
        message = "💳 Setting up bank account...\n"
        
        bank_account_number = "8504484734"
        bank_name = "GOMONEY"
        selected_name = "Molo"
        
        existing_bank_id = self.check_existing_banks_fast()
        if existing_bank_id:
            message += f"✅ Bank already exists: {bank_name}\n"
            return True, message
        
        data = {
            'withdraw_platform_id': self.withdraw_platform_id,
            'bank_card': bank_account_number,
            'bank_name': bank_name,
            'bank_username': selected_name,
            'remark': '',
            'password': password
        }
        
        message += f"📝 Setting Bank: {selected_name} - {bank_name}\n"
        
        try:
            response = self.session.post(f"{self.current_website['base_url']}/api/user_bank/add", data=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('code') == 1:
                    message += ""
                    return True, message
                else:
                    message += f"❌ Bank setup failed: {result.get('msg', 'Unknown error')}\n"
                    return False, message
            message += "❌ Bank setup failed\n"
            return False, message
                
        except Exception as e:
            message += f"❌ Bank setup error: {str(e)}\n"
            return False, message
    
    def check_existing_banks_fast(self):
        """Check existing banks quickly"""
        try:
            response = self.session.get(f"{self.current_website['base_url']}/api/user_bank/bankList", timeout=10)
            
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
    
    def get_bank_id(self):
        """Get bank ID - FAST VERSION"""
        message = "🔍 Finding bank ID...\n"
        
        try:
            response = self.session.get(f"{self.current_website['base_url']}/api/user_bank/bankList", timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('code') == 1:
                    banks = result.get('data', [])
                    if banks:
                        bank = banks[0]
                        bank_id = bank.get('id')
                        bank_name = bank.get('bank_name')
                        bank_number = bank.get('bank_card')
                        message += f"✅ Using Bank: {bank_name} - ID: {bank_id}\n"
                        return bank_id, message
            message += "❌ Bank ID not found\n"
            return None, message
                
        except Exception:
            message += "❌ Bank ID error\n"
            return None, message
    
    def submit_withdraw(self, bank_id, amount, username):
        """Submit withdraw - FAST VERSION"""
        message = f"🚀 Submitting withdraw: {amount} points...\n"
        
        data = {'score': amount, 'bank_id': bank_id}
        
        try:
            response = self.session.post(f"{self.current_website['base_url']}/api/withdraw_platform/submit", data=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('code') == 1:
                    # Store the order ID for tracking
                    order_data = result.get('data', {})
                    order_id = order_data.get('id')
                    if order_id:
                        self.bot_submitted_orders.add(order_id)
                    message += "🎉 Withdraw submitted successfully!\n"
                    return True, message
                else:
                    message += f"❌ Withdraw submit failed: {result.get('msg', 'Unknown error')}\n"
                    return False, message
            message += "❌ Withdraw submit failed\n"
            return False, message
                
        except Exception as e:
            message += f"❌ Withdraw submit error: {str(e)}\n"
            return False, message
    
    def check_withdraw_status(self, username):
        """Check withdraw status - ONLY BOT-SUBMITTED ORDERS"""
        message = f"📊 {username} - Checking withdraw status...\n"
        
        data = {
            'page': 1,
            'size': 50,
            'status': 0,
            'type': 0,
            'time': 0
        }
        
        try:
            response = self.session.post(f"{self.current_website['base_url']}/api/withdraw/orderList", data=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('code') == 1:
                    orders = result.get('data', [])
                    
                    # Filter only bot-submitted orders
                    bot_orders = [order for order in orders if order.get('id') in self.bot_submitted_orders]
                    
                    message += f"📦 Bot Orders Found: {len(bot_orders)}/{len(orders)}\n"
                    
                    success_orders = []
                    pending_orders = []
                    failed_orders = []
                    
                    for order in bot_orders:
                        order_id = order.get('id')
                        amount = order.get('score')
                        status = order.get('status')
                        order_no = order.get('order_no', '')
                        bank_name = order.get('bank_name', 'GOMONEY')
                        create_time = order.get('createtime2', 'Unknown')
                        finish_time = order.get('finishtime', 0)
                        
                        order_date = create_time
                        if finish_time:
                            finish_date = datetime.fromtimestamp(finish_time).strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            finish_date = "Not completed"
                        
                        if status == 2:
                            success_orders.append({
                                'order_id': order_id,
                                'amount': amount,
                                'order_no': order_no,
                                'bank_name': bank_name,
                                'order_date': order_date,
                                'finish_date': finish_date,
                                'status_text': 'success'
                            })
                        elif status == 1:
                            pending_orders.append({
                                'order_id': order_id,
                                'amount': amount,
                                'order_no': order_no,
                                'bank_name': bank_name,
                                'order_date': order_date,
                                'finish_date': finish_date,
                                'status_text': 'pending'
                            })
                        elif status == 3:
                            failed_orders.append({
                                'order_id': order_id,
                                'amount': amount,
                                'order_no': order_no,
                                'bank_name': bank_name,
                                'order_date': order_date,
                                'finish_date': finish_date,
                                'status_text': 'failed'
                            })
                    
                    total_success = sum(order['amount'] for order in success_orders)
                    total_pending = sum(order['amount'] for order in pending_orders)
                    total_failed = sum(order['amount'] for order in failed_orders)
                    
                    message += f"📈 {username} - Bot Withdraw History:\n"
                    message += f"   ✅ Success: {len(success_orders)} orders\n"
                    message += f"   ⏳ Pending: {len(pending_orders)} orders\n" 
                    message += f"   ❌ Failed: {len(failed_orders)} orders\n"
                    message += f"   💰 Success Points: {total_success}\n"
                    message += f"   ⏳ Pending Points: {total_pending}\n"
                    message += f"   💸 Failed Points: {total_failed}\n"
                    
                    if success_orders:
                        message += f"\n   🟢 SUCCESSFUL ORDERS:\n"
                        for order in success_orders:
                            message += f"      💳 {order['bank_name']}\n"
                            message += f"      💰 {order['amount']} points\n"
                            message += f"      📅 Ordered: {order['order_date']}\n"
                            message += f"      ✅ Completed: {order['finish_date']}\n"
                            message += f"      🆔 {order['order_no']}\n"
                            message += f"      ──────────────────────────\n"
                    
                    if pending_orders:
                        message += f"\n   🟡 PENDING ORDERS:\n"
                        for order in pending_orders:
                            message += f"      💳 {order['bank_name']}\n"
                            message += f"      💰 {order['amount']} points\n" 
                            message += f"      📅 Ordered: {order['order_date']}\n"
                            message += f"      ⏳ Status: Pending\n"
                            message += f"      🆔 {order['order_no']}\n"
                            message += f"      ──────────────────────────\n"
                    
                    if failed_orders:
                        message += f"\n   🔴 FAILED ORDERS:\n"
                        for order in failed_orders:
                            message += f"      💳 {order['bank_name']}\n"
                            message += f"      💰 {order['amount']} points\n"
                            message += f"      📅 Ordered: {order['order_date']}\n"
                            message += f"      ❌ Failed: {order['finish_date']}\n"
                            message += f"      🆔 {order['order_no']}\n"
                            message += f"      ──────────────────────────\n"
                    
                    self.update_status_data(username, success_orders + pending_orders + failed_orders)
                    
                    return True, message
            
            message += "❌ Status check failed\n"
            return False, message
                
        except Exception as e:
            message += f"❌ Status check error: {str(e)}\n"
            return False, message
    
    def update_status_data(self, username, orders):
        """Update status data with proper bank_name and status - FIXED DUPLICATE ISSUE"""
        status_data = self.load_withdraw_status()
        
        if username not in status_data:
            status_data[username] = []
        
        latest_orders = {}
        
        for order in orders:
            amount = order['amount']
            order_date = order['order_date']
            
            if amount not in latest_orders or order_date > latest_orders[amount]['order_date']:
                latest_orders[amount] = order
        
        status_data[username] = []
        
        for order in latest_orders.values():
            status_data[username].append({
                "order_id": order['order_id'],
                "order_no": order['order_no'],
                "amount": order['amount'],
                "bank_name": order.get('bank_name', 'GOMONEY'),
                "date": order['order_date'],
                "status": order['status_text']
            })
        
        self.save_withdraw_status(status_data)
    
    async def process_all_accounts(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Process all accounts with individual messages for each account"""
        accounts = self.load_accounts()
        
        if not accounts:
            await update.callback_query.edit_message_text("❌ No accounts found! Please add accounts first.")
            return
        
        user_id = update.callback_query.from_user.id
        chat_id = update.callback_query.message.chat_id
        
        # Get user info for forwarding
        user = update.callback_query.from_user
        user_info = f"User: {user.first_name} {user.last_name or ''} (@{user.username or 'N/A'})"
        
        # Initialize results storage
        self.processing_results[user_id] = {
            'successful': 0,
            'total': len(accounts),
            'start_time': time.time(),
            'failed_accounts': [],
            'current_page': 1,
            'accounts_per_page': 20
        }
        
        initial_message = f"🔄 Processing {len(accounts)} accounts..."
        await update.callback_query.edit_message_text(initial_message)
        await self.forward_to_group(context, initial_message, user_info)
        
        successful_accounts = 0
        failed_details = []
        
        for i, account in enumerate(accounts, 1):
            username = account["username"]
            password = account["password"]
            
            # Send individual account processing message
            account_message = f"⚡ Account {i}/{len(accounts)}: {username}\n"
            account_message += "-" * 30 + "\n"
            
            # Login
            login_success, login_msg = self.login(username, password)
            account_message += login_msg
            
            if not login_success:
                failed_details.append(f"❌ {username} - Login failed")
                await context.bot.send_message(chat_id, account_message)
                await self.forward_to_group(context, account_message, user_info)
                continue
            
            # Balance check
            balance, balance_msg = self.get_user_info()
            account_message += balance_msg
            
            if balance <= 200:
                account_message += "💸 Insufficient balance\n"
                failed_details.append(f"💸 {username} - Insufficient balance ({balance} points)")
                await context.bot.send_message(chat_id, account_message)
                await self.forward_to_group(context, account_message, user_info)
                continue
            
            withdraw_amount = balance - 200
            account_message += f"📊 Withdraw amount: {withdraw_amount} points\n"
            
            # Bank setup
            bank_success, bank_msg = self.add_bank_account(username, password)
            account_message += bank_msg
            if not bank_success:
                failed_details.append(f"🏦 {username} - Bank setup failed")
                await context.bot.send_message(chat_id, account_message)
                await self.forward_to_group(context, account_message, user_info)
                continue
            
            # Get bank ID
            bank_id, bank_id_msg = self.get_bank_id()
            account_message += bank_id_msg
            if not bank_id:
                failed_details.append(f"🏦 {username} - Bank ID not found")
                await context.bot.send_message(chat_id, account_message)
                await self.forward_to_group(context, account_message, user_info)
                continue
            
            # Submit withdraw
            withdraw_success, withdraw_msg = self.submit_withdraw(bank_id, withdraw_amount, username)
            account_message += withdraw_msg
            
            if withdraw_success:
                successful_accounts += 1
                account_message += "✅ Withdraw successful!\n"
            else:
                failed_details.append(f"❌ {username} - Withdraw failed")
            
            await context.bot.send_message(chat_id, account_message)
            await self.forward_to_group(context, account_message, user_info)
            
            # Small delay between accounts
            if i < len(accounts):
                time.sleep(2)
        
        # Store failed accounts for pagination
        self.processing_results[user_id]['successful'] = successful_accounts
        self.processing_results[user_id]['failed_accounts'] = failed_details
        self.processing_results[user_id]['total_time'] = time.time() - self.processing_results[user_id]['start_time']
        
        # Send final summary
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
        
        # Summary message
        summary_message = f"\n🎊 {'='*40}\n"
        summary_message += f"📈 Summary: {successful}/{total_accounts} accounts successful\n"
        summary_message += f"⏱️ Total time: {total_time:.2f} seconds\n"
        summary_message += f"🚀 Average: {total_time/total_accounts:.2f} seconds per account\n"
        summary_message += f"{'='*40}"
        
        await context.bot.send_message(chat_id, summary_message)
        await self.forward_to_group(context, summary_message, user_info)
        
        # Send failed accounts with pagination if any
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
        
        failed_message = f"📋 Failed Accounts Details (Page {page}/{total_pages}):\n"
        failed_message += "=" * 50 + "\n"
        
        for i, account in enumerate(current_page_accounts, start_idx + 1):
            failed_message += f"{i}. {account}\n"
        
        keyboard = []
        if page > 1:
            keyboard.append(InlineKeyboardButton("⬅️ Previous", callback_data=f"failed_page_{page-1}"))
        
        if page < total_pages:
            keyboard.append(InlineKeyboardButton("Next ➡️", callback_data=f"failed_page_{page+1}"))
        
        if keyboard:
            reply_markup = InlineKeyboardMarkup([keyboard])
        else:
            reply_markup = None
        
        # Add main menu button at the end
        menu_button = [InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu")]
        if reply_markup:
            reply_markup.inline_keyboard.append(menu_button)
        else:
            reply_markup = InlineKeyboardMarkup([menu_button])
        
        await context.bot.send_message(chat_id, failed_message, reply_markup=reply_markup)
    
    async def check_all_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Check withdraw status for all accounts with individual messages - ONLY BOT ORDERS"""
        accounts = self.load_accounts()
        
        if not accounts:
            await update.callback_query.edit_message_text("❌ No accounts found!")
            return
        
        user_id = update.callback_query.from_user.id
        chat_id = update.callback_query.message.chat_id
        
        # Get user info for forwarding
        user = update.callback_query.from_user
        user_info = f"User: {user.first_name} {user.last_name or ''} (@{user.username or 'N/A'})"
        
        # Initialize failed withdraws storage
        self.failed_withdraws[user_id] = {
            'failed_list': [],
            'current_page': 1,
            'accounts_per_page': 20
        }
        
        initial_message = f"📊 Checking BOT withdraw history for {len(accounts)} accounts"
        await update.callback_query.edit_message_text(initial_message)
        await self.forward_to_group(context, initial_message, user_info)
        
        total_failed_withdraws = 0
        
        for i, account in enumerate(accounts, 1):
            username = account["username"]
            password = account["password"]
            
            # Send individual account status message
            account_message = f"\n{i}. {username}\n"
            account_message += "-" * 20 + "\n"
            
            login_success, login_msg = self.login(username, password)
            account_message += login_msg
            
            if not login_success:
                account_message += "❌ Login failed, cannot check status\n"
                await context.bot.send_message(chat_id, account_message)
                await self.forward_to_group(context, account_message, user_info)
                continue
            
            status_success, status_msg = self.check_withdraw_status(username)
            account_message += status_msg
            
            # Extract failed withdraws from status message
            failed_count = await self.extract_failed_withdraws(user_id, username, status_msg)
            total_failed_withdraws += failed_count
            
            await context.bot.send_message(chat_id, account_message)
            await self.forward_to_group(context, account_message, user_info)
            
            # Small delay between accounts
            if i < len(accounts):
                time.sleep(1)
        
        # Send final summary with re-submit option if failed withdraws exist
        await self.send_status_summary(context, chat_id, user_id, total_failed_withdraws, user_info)
    
    async def extract_failed_withdraws(self, user_id, username, status_msg):
        """Extract failed withdraws from status message for re-submit"""
        failed_count = 0
        
        # Look for failed orders in the status message
        lines = status_msg.split('\n')
        in_failed_section = False
        
        for line in lines:
            line = line.strip()
            if "🔴 FAILED ORDERS:" in line:
                in_failed_section = True
                continue
            elif "──────────────────────────" in line and in_failed_section:
                continue
            elif line.startswith("💳") and in_failed_section:
                # Extract failed order details
                try:
                    bank_name = line.replace("💳", "").strip()
                    # Get next lines for amount and order details
                    amount_line = lines[lines.index(line) + 1] if lines.index(line) + 1 < len(lines) else ""
                    date_line = lines[lines.index(line) + 2] if lines.index(line) + 2 < len(lines) else ""
                    order_line = lines[lines.index(line) + 4] if lines.index(line) + 4 < len(lines) else ""
                    
                    amount = amount_line.replace("💰", "").replace("points", "").strip()
                    order_date = date_line.replace("📅 Ordered:", "").strip()
                    order_no = order_line.replace("🆔", "").strip()
                    
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
        summary_message = f"\n📋 Bot Status Check Complete!\n"
        summary_message += f"❌ Total Failed Withdraws Found: {total_failed}\n"
        summary_message += "=" * 40
        
        await context.bot.send_message(chat_id, summary_message)
        await self.forward_to_group(context, summary_message, user_info)
        
        # Send failed withdraws with pagination if any
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
        
        failed_message = f"🔴 Failed Withdraws (Page {page}/{total_pages}):\n"
        failed_message += "=" * 50 + "\n\n"
        
        for i, withdraw in enumerate(current_page_withdraws, start_idx + 1):
            failed_message += f"{i}. 👤 {withdraw['username']}\n"
            failed_message += f"   💳 {withdraw['bank_name']}\n"
            failed_message += f"   💰 {withdraw['amount']} points\n"
            failed_message += f"   📅 {withdraw['order_date']}\n"
            failed_message += f"   🆔 {withdraw['order_no']}\n"
            failed_message += "   ─────────────────────────\n"
        
        keyboard = []
        
        # Re-submit all button
        if current_page_withdraws:
            keyboard.append([InlineKeyboardButton(
                "🔄 Re-submit ALL Failed Withdraws", 
                callback_data=f"resubmit_all_page_{page}"
            )])
        
        # Navigation buttons
        nav_buttons = []
        if page > 1:
            nav_buttons.append(InlineKeyboardButton("⬅️ Previous", callback_data=f"failed_status_page_{page-1}"))
        
        if page < total_pages:
            nav_buttons.append(InlineKeyboardButton("Next ➡️", callback_data=f"failed_status_page_{page+1}"))
        
        if nav_buttons:
            keyboard.append(nav_buttons)
        
        # Main menu button
        keyboard.append([InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await context.bot.send_message(chat_id, failed_message, reply_markup=reply_markup)
    
    async def resubmit_failed_withdraws(self, update: Update, context: ContextTypes.DEFAULT_TYPE, page=None):
        """Re-submit failed withdraws from a specific page"""
        query = update.callback_query
        user_id = query.from_user.id
        chat_id = query.message.chat_id
        
        # Get user info for forwarding
        user = query.from_user
        user_info = f"User: {user.first_name} {user.last_name or ''} (@{user.username or 'N/A'})"
        
        if user_id not in self.failed_withdraws:
            await query.answer("❌ No failed withdraws found!")
            return
        
        if page is None:
            # Extract page number from callback data
            page = int(query.data.split("_")[3])
        
        failed_list = self.failed_withdraws[user_id]['failed_list']
        accounts_per_page = self.failed_withdraws[user_id]['accounts_per_page']
        
        start_idx = (page - 1) * accounts_per_page
        end_idx = start_idx + accounts_per_page
        current_page_withdraws = failed_list[start_idx:end_idx]
        
        initial_message = f"🔄 Re-submitting {len(current_page_withdraws)} failed withdraws..."
        await query.edit_message_text(initial_message)
        await self.forward_to_group(context, initial_message, user_info)
        
        successful_resubmits = 0
        resubmit_details = []
        
        for withdraw in current_page_withdraws:
            username = withdraw['username']
            amount = withdraw['amount'].replace('points', '').strip()
            
            # Find account password
            accounts = self.load_accounts()
            account = next((acc for acc in accounts if acc['username'] == username), None)
            
            if not account:
                resubmit_details.append(f"❌ {username} - Account not found")
                continue
            
            password = account['password']
            
            # Login
            login_success, login_msg = self.login(username, password)
            if not login_success:
                resubmit_details.append(f"❌ {username} - Login failed")
                continue
            
            # Get bank ID
            bank_id, bank_id_msg = self.get_bank_id()
            if not bank_id:
                resubmit_details.append(f"❌ {username} - Bank ID not found")
                continue
            
            # Submit withdraw
            withdraw_success, withdraw_msg = self.submit_withdraw(bank_id, amount, username)
            
            if withdraw_success:
                successful_resubmits += 1
                resubmit_details.append(f"✅ {username} - Re-submit successful")
            else:
                resubmit_details.append(f"❌ {username} - Re-submit failed")
            
            # Small delay between re-submits
            time.sleep(2)
        
        # Send re-submit results
        result_message = f"🔄 Re-submit Results:\n"
        result_message += f"✅ Successful: {successful_resubmits}/{len(current_page_withdraws)}\n"
        result_message += "=" * 40 + "\n"
        
        for detail in resubmit_details:
            result_message += f"{detail}\n"
        
        await context.bot.send_message(chat_id, result_message)
        await self.forward_to_group(context, result_message, user_info)
        
        # Show failed withdraws page again
        await self.send_failed_withdraws_page(context, chat_id, user_id, page)
    
    def show_status_summary(self, page=1):
        """Show status summary with pagination - ONLY BOT ORDERS"""
        status_data = self.load_withdraw_status()
        
        if not status_data:
            return "❌ No bot status data found!"
        
        # Calculate totals
        total_success = 0
        total_pending = 0
        total_failed = 0
        total_success_points = 0
        total_pending_points = 0
        total_failed_points = 0
        
        all_orders = []
        for username, orders in status_data.items():
            for order in orders:
                order['username'] = username
                all_orders.append(order)
                
            success_orders = [o for o in orders if o.get('status') == 'success']
            pending_orders = [o for o in orders if o.get('status') == 'pending']
            failed_orders = [o for o in orders if o.get('status') == 'failed']
            
            total_success += len(success_orders)
            total_pending += len(pending_orders)
            total_failed += len(failed_orders)
            total_success_points += sum(o.get('amount', 0) for o in success_orders)
            total_pending_points += sum(o.get('amount', 0) for o in pending_orders)
            total_failed_points += sum(o.get('amount', 0) for o in failed_orders)
        
        # Sort by date (newest first)
        all_orders.sort(key=lambda x: x.get('date', ''), reverse=True)
        
        # Pagination
        orders_per_page = 50
        total_pages = (len(all_orders) + orders_per_page - 1) // orders_per_page
        
        start_idx = (page - 1) * orders_per_page
        end_idx = start_idx + orders_per_page
        current_page_orders = all_orders[start_idx:end_idx]
        
        message = f"📋 BOT Withdraw Status Summary (Page {page}/{total_pages})\n"
        message += "=" * 60 + "\n\n"
        
        # BOT TOTAL SUMMARY at the beginning of each page
        message += f"📊 BOT TOTAL SUMMARY:\n"
        message += f"   ✅ Success Orders: {total_success}\n"
        message += f"   ⏳ Pending Orders: {total_pending}\n"
        message += f"   ❌ Failed Orders: {total_failed}\n"
        message += f"   💰 Total Success Points: {total_success_points}\n"
        message += f"   ⏳ Total Pending Points: {total_pending_points}\n"
        message += f"   💸 Total Failed Points: {total_failed_points}\n\n"
        
        message += f"🎯 BOT ORDER HISTORY:\n"
        message += "-" * 50 + "\n\n"
        
        if not current_page_orders:
            message += "No orders found for this page.\n"
        else:
            for i, order in enumerate(current_page_orders, start_idx + 1):
                status = order.get('status', 'unknown')
                status_emoji = "✅" if status == 'success' else "⏳" if status == 'pending' else "❌"
                username = order.get('username', 'Unknown')
                bank_name = order.get('bank_name', 'GOMONEY')
                amount = order.get('amount', 0)
                date = order.get('date', 'Unknown date')
                order_no = order.get('order_no', 'N/A')
                
                message += f"{i}. {status_emoji} {username}\n"
                message += f"   💳 {bank_name} | 💰 {amount} pts\n"
                message += f"   📅 {date} | 🆔 {order_no}\n"
                message += "   ─────────────────────────\n"
        
        # Add pagination info
        if total_pages > 1:
            message += f"\n📄 Page {page} of {total_pages} | Total Orders: {len(all_orders)}"
        
        return message
    
    async def show_main_menu_after_processing(self, context, chat_id):
        """Show main menu after processing is complete"""
        keyboard = [
            [InlineKeyboardButton("📝 Add new accounts", callback_data="add_accounts")],
            [InlineKeyboardButton("🚀 Withdraw all accounts", callback_data="process_all")],
            [InlineKeyboardButton("📊 Check FULL withdraw history", callback_data="check_history")],
            [InlineKeyboardButton("📋 Show COMPLETE status summary", callback_data="status_summary")],
            [InlineKeyboardButton("🌐 Select Website", callback_data="website_manage")],
            [InlineKeyboardButton("🗑️ Clear all data", callback_data="clear_data")],
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        platform_id = self.current_website.get('platform_id', 22) if self.current_website else 22
        
        welcome_text = f"""🎯 Automation Withdraw System
🌐 Current Website: {self.current_website['name'] if self.current_website else 'N/A'}
🏦 Bank: GOMONEY

Select an option:"""
        
        await context.bot.send_message(chat_id, welcome_text, reply_markup=reply_markup)

# Global automation instance
automation = SMS323Automation()
BOT_TOKEN = "7390288812:AAGsGZriy4dprHYmQoRUZltMCmvTUitpz4I"

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send welcome message with main menu"""
    keyboard = [
        [InlineKeyboardButton("📝 Add new accounts", callback_data="add_accounts")],
        [InlineKeyboardButton("🚀 Withdraw all accounts", callback_data="process_all")],
        [InlineKeyboardButton("📊 Check FULL withdraw history", callback_data="check_history")],
        [InlineKeyboardButton("📋 Show COMPLETE status summary", callback_data="status_summary")],
        [InlineKeyboardButton("🌐 Select Website", callback_data="website_manage")],
        [InlineKeyboardButton("🗑️ Clear all data", callback_data="clear_data")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    platform_id = automation.current_website.get('platform_id', 22) if automation.current_website else 22
    
    welcome_text = f"""🎯 Automation Withdraw System
🌐 Current Website: {automation.current_website['name'] if automation.current_website else 'N/A'}
🏦 Bank: GOMONEY

Select an option:"""
    
    await update.message.reply_text(welcome_text, reply_markup=reply_markup)

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle button callbacks"""
    query = update.callback_query
    await query.answer()
    
    user_id = query.from_user.id
    
    if query.data == "add_accounts":
        automation.user_states[user_id] = "waiting_for_accounts"
        await query.edit_message_text(
            "📝 Account input...\n"
            "Format: username:password\n"
            "One account per line\n\n"
            "Example:\n"
            "user1:pass123\n"
            "user2:pass456\n\n"
            "Send accounts now:"
        )
    
    elif query.data == "process_all":
        await automation.process_all_accounts(update, context)
    
    elif query.data == "check_history":
        await automation.check_all_status(update, context)
    
    elif query.data == "status_summary":
        result = automation.show_status_summary(page=1)
        await send_long_message(context, query.message.chat_id, result)
        
        # Add pagination buttons if needed
        status_data = automation.load_withdraw_status()
        total_orders = sum(len(orders) for orders in status_data.values())
        if total_orders > 50:
            keyboard = [
                [InlineKeyboardButton("Next Page ➡️", callback_data="status_page_2")],
                [InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await context.bot.send_message(query.message.chat_id, "Navigate to next page:", reply_markup=reply_markup)
        else:
            await automation.show_main_menu_after_processing(context, query.message.chat_id)
    
    elif query.data.startswith("status_page_"):
        page = int(query.data.split("_")[2])
        result = automation.show_status_summary(page=page)
        await send_long_message(context, query.message.chat_id, result)
        
        # Pagination buttons
        status_data = automation.load_withdraw_status()
        total_orders = sum(len(orders) for orders in status_data.values())
        total_pages = (total_orders + 49) // 50
        
        keyboard = []
        if page > 1:
            keyboard.append(InlineKeyboardButton("⬅️ Previous", callback_data=f"status_page_{page-1}"))
        if page < total_pages:
            keyboard.append(InlineKeyboardButton("Next ➡️", callback_data=f"status_page_{page+1}"))
        
        if keyboard:
            reply_markup = InlineKeyboardMarkup([keyboard])
            await context.bot.send_message(query.message.chat_id, "Navigate pages:", reply_markup=reply_markup)
        
        await automation.show_main_menu_after_processing(context, query.message.chat_id)
    
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
        # Handle website selection
        choice = int(query.data.split("_")[2])
        websites = automation.get_all_websites()
        if 0 <= choice - 1 < len(websites):
            result = automation.manage_websites("change", str(choice), user_id)
            await query.edit_message_text(result)
            await automation.show_main_menu_after_processing(context, query.message.chat_id)
        else:
            await query.edit_message_text("❌ Invalid website selection!")
    
    elif query.data == "website_delete":
        if user_id == automation.admin_id:
            automation.user_states[user_id] = "waiting_for_website_delete"
            websites = automation.get_all_websites()
            website_list = automation.manage_websites("list", None, user_id)
            await query.edit_message_text(f"{website_list}\n\nEnter website number to delete:")
        else:
            await query.edit_message_text("❌ Only admin can delete websites!")
    
    elif query.data == "clear_data":
        keyboard = [
            [InlineKeyboardButton("✅ Yes, clear all data", callback_data="confirm_clear")],
            [InlineKeyboardButton("❌ No, go back", callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(
            "⚠️ Are you sure you want to clear ALL data?\n"
            "This will delete all accounts and withdraw status!",
            reply_markup=reply_markup
        )
    
    elif query.data == "confirm_clear":
        result = automation.clear_all_data()
        await query.edit_message_text(result)
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
                await query.edit_message_text("Enter website name:")
            else:
                await query.edit_message_text("❌ Only admin can add websites!")
        elif action == "back":
            await automation.show_main_menu_after_processing(context, query.message.chat_id)

async def show_website_management(query, context, user_id):
    """Show website management options"""
    keyboard = [
        [InlineKeyboardButton("📋 Select Website", callback_data="website_list")],
    ]
    
    # Only show add/delete options for admin
    if user_id == automation.admin_id:
        keyboard.append([InlineKeyboardButton("➕ Add new website", callback_data="website_add")])
        keyboard.append([InlineKeyboardButton("❌ Delete website", callback_data="website_delete")])
    
    keyboard.append([InlineKeyboardButton("↩️ Back to main menu", callback_data="main_menu")])
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text("🌐 Website Management", reply_markup=reply_markup)

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
    
    keyboard.append([InlineKeyboardButton("↩️ Back", callback_data="website_manage")])
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await query.edit_message_text(message, reply_markup=reply_markup)

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle text messages"""
    user_id = update.message.from_user.id
    text = update.message.text
    
    # Get user info for forwarding
    user = update.message.from_user
    user_info = f"User: {user.first_name} {user.last_name or ''} (@{user.username or 'N/A'})"
    
    if user_id in automation.user_states:
        state = automation.user_states[user_id]
        
        if state == "waiting_for_accounts":
            del automation.user_states[user_id]
            result = automation.input_accounts(text, user_info)
            await update.message.reply_text(result)
            await automation.forward_to_group(context, f"Added accounts:\n{text}\n\n{result}", user_info)
            await automation.show_main_menu_after_processing(context, update.message.chat_id)
        
        elif state == "waiting_for_website_name":
            automation.user_states[user_id] = {"state": "waiting_for_website_url", "name": text}
            await update.message.reply_text("Enter base URL (https://example.club):")
            await automation.forward_to_group(context, f"Website name: {text}", user_info)
        
        elif isinstance(state, dict) and state.get("state") == "waiting_for_website_url":
            automation.user_states[user_id] = {"state": "waiting_for_website_origin", "name": state["name"], "base_url": text}
            await update.message.reply_text("Enter origin (https://example.com):")
            await automation.forward_to_group(context, f"Base URL: {text}", user_info)
        
        elif isinstance(state, dict) and state.get("state") == "waiting_for_website_origin":
            automation.user_states[user_id] = {"state": "waiting_for_website_referer", "name": state["name"], "base_url": state["base_url"], "origin": text}
            await update.message.reply_text("Enter referer (https://example.com):")
            await automation.forward_to_group(context, f"Origin: {text}", user_info)
        
        elif isinstance(state, dict) and state.get("state") == "waiting_for_website_referer":
            automation.user_states[user_id] = {"state": "waiting_for_website_platform", "name": state["name"], "base_url": state["base_url"], "origin": state["origin"], "referer": text}
            await update.message.reply_text("Enter Platform ID:")
            await automation.forward_to_group(context, f"Referer: {text}", user_info)
        
        elif isinstance(state, dict) and state.get("state") == "waiting_for_website_platform":
            name = state["name"]
            base_url = state["base_url"]
            origin = state["origin"]
            referer = state["referer"]
            platform_id = text
            
            del automation.user_states[user_id]
            result = automation.manage_websites("add", [name, base_url, origin, referer, platform_id], user_id)
            await update.message.reply_text(result)
            await automation.forward_to_group(context, f"Platform ID: {platform_id}\n\n{result}", user_info)
            await automation.show_main_menu_after_processing(context, update.message.chat_id)
        
        elif state == "waiting_for_website_delete":
            del automation.user_states[user_id]
            result = automation.manage_websites("delete", text, user_id)
            await update.message.reply_text(result)
            await automation.forward_to_group(context, f"Delete website: {text}\n\n{result}", user_info)
            await automation.show_main_menu_after_processing(context, update.message.chat_id)
    
    else:
        await update.message.reply_text("Please use the menu buttons to interact with the bot.")

async def send_long_message(context, chat_id, text):
    """Send long messages by splitting them"""
    if len(text) <= 4096:
        await context.bot.send_message(chat_id, text)
    else:
        parts = [text[i:i+4096] for i in range(0, len(text), 4096)]
        for part in parts:
            await context.bot.send_message(chat_id, part)
            time.sleep(0.5)

def run_bot():
    """Run Telegram bot"""
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(button_handler))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    print("🤖 Telegram Bot is starting...")
    application.run_polling()

def main():
    """Start both Flask and Telegram bot"""
    print("🚀 Starting Flask server and Telegram Bot...")
    
    # Start Flask in a separate thread
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()
    
    # Start Telegram bot in main thread
    time.sleep(2)  # Give Flask time to start
    run_bot()

if __name__ == "__main__":
    main()
