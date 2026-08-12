from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
import time
from collections import defaultdict
from datetime import datetime, timedelta
import random
import os
import urllib.parse
import jwt

app = Flask(__name__)

# ==================== KEYS ====================
NORMAL_API_KEY = "SHAPPNO9X"  # ডিফল্ট API Key
ADMIN_KEYS = ["shappno_4444_pro_9xxx"]

# ==================== API KEY STORE ====================
API_KEY_STORE = {
    "current_key": NORMAL_API_KEY,
    "last_updated": None,
    "updated_by": None
}

# ==================== JWT TOKEN API ====================
JWT_API_URLS = [
    "https://super-fast-jwt-shappno.vercel.app/token",
    "https://jwt-2-c4r1.vercel.app/token",
]

TOKEN_CACHE = {}
JWT_ROUND_ROBIN = 0
JWT_API_STATS = {
    "https://super-fast-jwt-shappno.vercel.app/token": {"success": 0, "fail": 0, "last_used": 0},
    "https://jwt-2-c4r1.vercel.app/token": {"success": 0, "fail": 0, "last_used": 0}
}

# ==================== LIMIT & TRACKING ====================
KEY_LIMIT = 1
tracker = defaultdict(lambda: [0, 0])
liked_cache = defaultdict(set)

# Bangladesh timezone offset (UTC+6)
BANGLADESH_OFFSET = 6 * 3600

def get_bangladesh_midnight_timestamp():
    """Get midnight timestamp in Bangladesh time (UTC+6)"""
    now_utc = datetime.utcnow()
    now_bd = now_utc + timedelta(hours=BANGLADESH_OFFSET)
    midnight_bd = datetime(now_bd.year, now_bd.month, now_bd.day)
    midnight_utc = midnight_bd - timedelta(hours=BANGLADESH_OFFSET)
    return midnight_utc.timestamp()

def load_accounts(server_name):
    """Load UID:Password based on server"""
    try:
        if server_name in {"IND", "BR", "US", "SAC", "NA"}:
            filename = "account_ind.txt"
        else:
            filename = "account_bd.txt"
        
        if not os.path.exists(filename):
            print(f"⚠️ {filename} not found!")
            return []
        
        accounts = []
        with open(filename, "r", encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if ':' in line:
                    parts = line.split(':', 1)
                    uid = parts[0].strip()
                    password = parts[1].strip()
                    
                    if uid and password and uid.isdigit():
                        accounts.append({
                            "uid": uid,
                            "password": password
                        })
        
        print(f"✅ Loaded {len(accounts)} accounts from {filename}")
        return accounts
        
    except Exception as e:
        print(f"❌ Error loading accounts: {e}")
        return []

# ==================== JWT TOKEN GENERATION WITH LOAD BALANCING ====================

async def generate_jwt_token(uid, password):
    """
    JWT Token generate - Load Balancing with Round Robin + Failover
    দুইটা API থেকে ভাগ করে টোকেন নেবে
    """
    global JWT_ROUND_ROBIN
    
    encoded_password = urllib.parse.quote(password)
    
    # Round Robin দিয়ে API সিলেক্ট
    selected_api = JWT_API_URLS[JWT_ROUND_ROBIN % len(JWT_API_URLS)]
    JWT_ROUND_ROBIN += 1
    
    # API গুলো shuffle করে ট্রাই করবে
    api_list = JWT_API_URLS.copy()
    api_list.remove(selected_api)
    api_list.insert(0, selected_api)
    
    for jwt_url in api_list:
        try:
            url = f"{jwt_url}?uid={uid}&password={encoded_password}"
            
            print(f"🔄 Trying JWT API: {jwt_url} for UID: {uid}")
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=15) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if isinstance(data, dict):
                            token = None
                            if 'token' in data:
                                token = data['token']
                            elif 'access_token' in data:
                                token = data['access_token']
                            elif 'data' in data and isinstance(data['data'], dict):
                                if 'token' in data['data']:
                                    token = data['data']['token']
                            
                            if token:
                                JWT_API_STATS[jwt_url]["success"] += 1
                                JWT_API_STATS[jwt_url]["last_used"] = time.time()
                                print(f"✅ Token from {jwt_url} for UID: {uid}")
                                return token
                    else:
                        print(f"⚠️ JWT API {jwt_url} status: {response.status}")
                        JWT_API_STATS[jwt_url]["fail"] += 1
        except Exception as e:
            print(f"❌ JWT API {jwt_url} error: {e}")
            JWT_API_STATS[jwt_url]["fail"] += 1
            continue
    
    print(f"❌ All JWT APIs failed for UID: {uid}")
    return None

async def get_valid_token(uid, password):
    """Get valid token from cache or generate new with load balancing"""
    
    # ক্যাশ চেক
    if uid in TOKEN_CACHE:
        cached = TOKEN_CACHE[uid]
        remaining = (cached["expires_at"] - datetime.utcnow()).total_seconds()
        
        if remaining > 1800:
            print(f"♻️ Using cached token for UID: {uid} (expires in {remaining/60:.0f} mins)")
            return cached["token"]
        else:
            print(f"🔄 Token expiring soon for UID: {uid}, refreshing...")
    
    # নতুন টোকেন জেনারেট
    token = await generate_jwt_token(uid, password)
    
    if not token:
        return None
    
    # টোকেন ক্যাশে সেভ
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        exp = payload.get("exp", int(time.time()) + 86400)
        TOKEN_CACHE[uid] = {
            "token": token,
            "expires_at": datetime.utcfromtimestamp(exp)
        }
        print(f"💾 Token cached for UID: {uid}")
    except:
        TOKEN_CACHE[uid] = {
            "token": token,
            "expires_at": datetime.utcnow() + timedelta(hours=24)
        }
        print(f"💾 Token cached for UID: {uid} (default 24h)")
    
    return token

async def get_tokens_for_accounts(accounts):
    """Get tokens for all accounts with load balancing"""
    if not accounts:
        return {}
    
    tokens = {}
    semaphore = asyncio.Semaphore(50)
    
    async def get_token_for_account(acc):
        token = await get_valid_token(acc['uid'], acc['password'])
        if token:
            tokens[acc['uid']] = token
    
    async def limited_get_token(acc):
        async with semaphore:
            await get_token_for_account(acc)
    
    tasks = [limited_get_token(acc) for acc in accounts]
    await asyncio.gather(*tasks, return_exceptions=True)
    
    print(f"✅ Got tokens for {len(tokens)} accounts (Load Balanced)")
    return tokens

# ==================== ENCRYPTION & PROTOBUF ====================

def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return binascii.hexlify(cipher.encrypt(padded_message)).decode('utf-8')

def create_protobuf_message(user_id, region):
    message = like_pb2.like()
    message.uid = int(user_id)
    message.region = region
    return message.SerializeToString()

async def send_like(encrypted_uid, token, url):
    """Send like with token"""
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB54"
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers, timeout=5) as response:
                return response.status
    except:
        return 500

async def process_account(target_uid, encrypted_uid, account, url, semaphore, token):
    """Process single account with token"""
    async with semaphore:
        if not token:
            return 500, account['uid']
        
        status = await send_like(encrypted_uid, token, url)
        
        if status == 200:
            liked_cache[target_uid].add(account['uid'])
            return status, account['uid']
        
        return status, account['uid']

async def send_all_likes(target_uid, server_name, url, accounts, encrypted_uid):
    """Send likes from all accounts"""
    if not accounts: 
        return {'success': 0, 'failed': 0, 'total': 0, 'already_liked': 0}
    
    already_liked = liked_cache.get(target_uid, set())
    fresh_accounts = [acc for acc in accounts if acc['uid'] not in already_liked]
    
    print(f"📊 Total: {len(accounts)}, Fresh: {len(fresh_accounts)}, Already liked: {len(already_liked)}")
    
    if not fresh_accounts:
        return {
            'success': 0, 
            'failed': 0, 
            'total': len(accounts),
            'already_liked': len(already_liked),
            'fresh_used': 0
        }
    
    random.shuffle(fresh_accounts)
    
    print(f"🔄 Generating tokens for {len(fresh_accounts)} accounts...")
    tokens_dict = await get_tokens_for_accounts(fresh_accounts)
    
    token_accounts = [(acc, tokens_dict.get(acc['uid'])) for acc in fresh_accounts if tokens_dict.get(acc['uid'])]
    
    print(f"🔑 Got tokens for {len(token_accounts)} accounts")
    
    if not token_accounts:
        return {'success': 0, 'failed': len(fresh_accounts), 'total': len(accounts)}
    
    semaphore = asyncio.Semaphore(100)
    tasks = []
    for acc, token in token_accounts:
        tasks.append(process_account(target_uid, encrypted_uid, acc, url, semaphore, token))
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    successful = 0
    failed = 0
    for r in results:
        if isinstance(r, tuple):
            status, uid = r
            if status == 200:
                successful += 1
            else:
                failed += 1
    
    return {
        'success': successful,
        'failed': failed,
        'total': len(accounts),
        'already_liked': len(already_liked),
        'fresh_used': len(token_accounts)
    }

def enc(uid):
    message = uid_generator_pb2.uid_generator()
    message.krishna_ = int(uid)
    message.teamXdarks = 1
    return encrypt_message(message.SerializeToString())

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except:
        return None

def get_player_info(encrypted_uid, server_name, token):
    """Get player info with proper URL for each server"""
    if server_name == "IND":
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:
        url = "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"

    edata = bytes.fromhex(encrypted_uid)
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB54"
    }

    try:
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=10)
        return decode_protobuf(response.content)
    except:
        return None

def is_valid_admin_key(key):
    if not key:
        return False
    key = key.strip()
    return key in ADMIN_KEYS

# ==================== CHANGE NORMAL API KEY (ADMIN ONLY) ====================

@app.route('/change-key', methods=['GET'])
def change_api_key():
    """
    Admin key দিয়ে Normal API Key চেঞ্জ করা যায়
    ব্যবহার: /change-key?admin_key=ADMIN_KEY&new_key=NEW_API_KEY
    """
    admin_key = request.args.get("admin_key")
    new_key = request.args.get("new_key")
    
    if not admin_key or admin_key not in ADMIN_KEYS:
        return jsonify({
            "error": "❌ Invalid Admin Key!",
            "status": "failed"
        }), 403
    
    if not new_key or len(new_key) < 6:
        return jsonify({
            "error": "❌ New key must be at least 6 characters long!",
            "status": "failed"
        }), 400
    
    old_key = API_KEY_STORE["current_key"]
    
    global NORMAL_API_KEY
    NORMAL_API_KEY = new_key
    API_KEY_STORE["current_key"] = new_key
    API_KEY_STORE["last_updated"] = datetime.utcnow().isoformat()
    API_KEY_STORE["updated_by"] = admin_key
    
    return jsonify({
        "success": True,
        "message": "✅ API Key updated successfully!",
        "old_key": old_key,
        "new_key": new_key,
        "updated_by": admin_key,
        "updated_at": API_KEY_STORE["last_updated"],
        "status": "success"
    })

# ==================== GET CURRENT API KEY (ADMIN ONLY) ====================

@app.route('/get-key', methods=['GET'])
def get_current_api_key():
    """
    বর্তমান API Key দেখায় (শুধু Admin)
    ব্যবহার: /get-key?admin_key=ADMIN_KEY
    """
    admin_key = request.args.get("admin_key")
    
    if not admin_key or admin_key not in ADMIN_KEYS:
        return jsonify({
            "error": "❌ Invalid Admin Key!",
            "status": "failed"
        }), 403
    
    return jsonify({
        "success": True,
        "current_api_key": API_KEY_STORE["current_key"],
        "last_updated": API_KEY_STORE["last_updated"],
        "updated_by": API_KEY_STORE["updated_by"],
        "default_key": "SHAPPNO9X",
        "status": "success"
    })

# ==================== RESET API KEY TO DEFAULT (ADMIN ONLY) ====================

@app.route('/reset-key', methods=['GET'])
def reset_api_key():
    """
    API Key ডিফল্টে রিসেট করে
    ব্যবহার: /reset-key?admin_key=ADMIN_KEY
    """
    admin_key = request.args.get("admin_key")
    
    if not admin_key or admin_key not in ADMIN_KEYS:
        return jsonify({
            "error": "❌ Invalid Admin Key!",
            "status": "failed"
        }), 403
    
    global NORMAL_API_KEY
    old_key = NORMAL_API_KEY
    NORMAL_API_KEY = "SHAPPNO9X"
    API_KEY_STORE["current_key"] = "SHAPPNO9X"
    API_KEY_STORE["last_updated"] = datetime.utcnow().isoformat()
    API_KEY_STORE["updated_by"] = admin_key
    
    return jsonify({
        "success": True,
        "message": "✅ API Key reset to default!",
        "old_key": old_key,
        "new_key": "SHAPPNO9X",
        "reset_by": admin_key,
        "reset_at": API_KEY_STORE["last_updated"],
        "status": "success"
    })

# ==================== JWT API STATUS (ADMIN ONLY) ====================

@app.route('/jwt-status', methods=['GET'])
def jwt_api_status():
    """
    JWT API গুলোর স্ট্যাটাস দেখায় (শুধু Admin)
    ব্যবহার: /jwt-status?admin_key=ADMIN_KEY
    """
    admin_key = request.args.get("admin_key")
    
    if not admin_key or admin_key not in ADMIN_KEYS:
        return jsonify({
            "error": "❌ Invalid Admin Key!",
            "status": "failed"
        }), 403
    
    return jsonify({
        "success": True,
        "jwt_apis": JWT_API_STATS,
        "total_tokens_cached": len(TOKEN_CACHE),
        "round_robin_counter": JWT_ROUND_ROBIN,
        "status": "success"
    })

# ==================== REFRESH ALL TOKENS (ADMIN ONLY) ====================

@app.route('/refresh-tokens', methods=['GET'])
def refresh_all_tokens():
    """
    সব টোকেন রিফ্রেশ করে (শুধু Admin)
    ব্যবহার: /refresh-tokens?admin_key=ADMIN_KEY
    """
    admin_key = request.args.get("admin_key")
    
    if not admin_key or admin_key not in ADMIN_KEYS:
        return jsonify({
            "error": "❌ Invalid Admin Key!",
            "status": "failed"
        }), 403
    
    global TOKEN_CACHE
    old_count = len(TOKEN_CACHE)
    TOKEN_CACHE.clear()
    
    return jsonify({
        "success": True,
        "message": f"✅ {old_count} tokens cleared! New tokens will be generated on next request.",
        "cleared_count": old_count,
        "cleared_by": admin_key,
        "status": "success"
    })

# ==================== ADMIN ENDPOINTS ====================

@app.route('/set-limit', methods=['GET'])
def set_key_limit():
    admin_key = request.args.get("key")
    new_limit = request.args.get("limit")
    
    if not admin_key or not is_valid_admin_key(admin_key):
        return jsonify({"error": "❌ Invalid Admin Key!"}), 403
    
    if not new_limit:
        return jsonify({"error": "Limit value required"}), 400
    
    try:
        new_limit = int(new_limit)
        if new_limit < 1 or new_limit > 999:
            return jsonify({"error": "Limit must be between 1 and 999"}), 400
        
        global KEY_LIMIT
        KEY_LIMIT = new_limit
        return jsonify({
            "success": True,
            "message": f"✅ Key limit set to {KEY_LIMIT}",
            "new_limit": KEY_LIMIT
        })
    except ValueError:
        return jsonify({"error": "Limit must be a number"}), 400

@app.route('/reset-limit', methods=['GET'])
def reset_limit():
    admin_key = request.args.get("key")
    
    if not admin_key or not is_valid_admin_key(admin_key):
        return jsonify({"error": "❌ Invalid Admin Key!"}), 403
    
    global tracker
    tracker = defaultdict(lambda: [0, 0])
    
    return jsonify({
        "success": True,
        "message": "✅ Limit reset to 0 successfully!"
    })

@app.route('/get-limit', methods=['GET'])
def get_key_limit():
    return jsonify({
        "success": True,
        "current_limit": KEY_LIMIT,
        "reset_time": "4:00 AM Bangladesh Time"
    })

@app.route('/reset-cache', methods=['GET'])
def reset_cache():
    admin_key = request.args.get("key")
    
    if not admin_key or not is_valid_admin_key(admin_key):
        return jsonify({"error": "❌ Invalid Admin Key!"}), 403
    
    global liked_cache
    liked_cache.clear()
    return jsonify({
        "success": True,
        "message": "✅ Cache cleared!"
    })

# ==================== MAIN LIKE ENDPOINT ====================

@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    key = request.args.get("key")
    client_ip = request.remote_addr

    if key != NORMAL_API_KEY:
        return jsonify({"error": "❌ Invalid API Key!"}), 403

    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    valid_servers = ["IND", "BR", "US", "SAC", "NA", "BD", "RU"]
    if server_name not in valid_servers:
        return jsonify({"error": f"Invalid server. Use: {valid_servers}"}), 400

    accounts = load_accounts(server_name)
    if not accounts:
        return jsonify({"error": f"No accounts found for {server_name}"}), 500
    
    bangladesh_midnight = get_bangladesh_midnight_timestamp()
    count, last_reset = tracker[client_ip]

    if last_reset < bangladesh_midnight:
        tracker[client_ip] = [0, time.time()]
        count = 0

    if count >= KEY_LIMIT:
        return jsonify({
            "error": "Your daily limit has been reached",
            "remains": f"(0/{KEY_LIMIT})"
        }), 429

    check_token = None
    for account in accounts[:5]:
        check_token = asyncio.run(get_valid_token(account['uid'], account['password']))
        if check_token:
            break
    
    if not check_token:
        return jsonify({"error": "Token generation failed"}), 500
    
    encrypted_uid = enc(uid)

    before = get_player_info(encrypted_uid, server_name, check_token)
    if before is None:
        return jsonify({"error": "Invalid UID or server", "status": 0}), 200

    try:
        before_data = json.loads(MessageToJson(before))
        before_like = int(before_data['AccountInfo'].get('Likes', 0))
    except:
        return jsonify({"error": "Data parsing failed", "status": 0}), 200

    if server_name == "IND":
        like_url = "https://client.ind.freefiremobile.com/LikeProfile"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        like_url = "https://client.us.freefiremobile.com/LikeProfile"
    else:
        like_url = "https://clientbp.ggpolarbear.com/LikeProfile"

    result = asyncio.run(send_all_likes(uid, server_name, like_url, accounts, encrypted_uid))

    after = get_player_info(encrypted_uid, server_name, check_token)
    if after is None:
        return jsonify({"error": "Could not verify likes", "status": 0}), 200

    try:
        after_data = json.loads(MessageToJson(after))
        after_like = int(after_data['AccountInfo']['Likes'])
        player_id = int(after_data['AccountInfo']['UID'])
        player_name = str(after_data['AccountInfo']['PlayerNickname'])
        
        like_given = after_like - before_like
        
        if like_given > 0:
            tracker[client_ip][0] += 1
            count += 1
            status = 1
        else:
            status = 2
        
        remains = KEY_LIMIT - count

        return jsonify({
            "success": True,
            "LikesGivenByAPI": like_given,
            "LikesafterCommand": after_like,
            "LikesbeforeCommand": before_like,
            "PlayerNickname": player_name,
            "UID": player_id,
            "status": status,
            "remains": f"({remains}/{KEY_LIMIT})"
        })
    except Exception as e:
        return jsonify({"error": str(e), "status": 0}), 500

# ==================== HOME ====================

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "name": "Shappno VIP Like API",
        "version": "2.0",
        "status": "running"
    })