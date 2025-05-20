# website checker using python
# developed by @PRAKASHpv8
# join my tg https://t.me/+LegtLzgLfcliNjRl


from datetime import datetime
from pyrogram import filters, Client
from pyrogram.types import Message, Document
import requests
import re
import os
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Command prefixes
PREFIXES = ["/", "!", "?", "."]

# Bot Configuration
BOT_TOKEN = "7709177882:AAEbp3N9sKyENoQdOO2IzKbfjKV4ZtjN7Zg" # @botfather  
API_ID = "26954601" # my.telegram.org se milega
API_HASH = "d276fb2b026897a91dcf3385683a5f9e" # my.telegram.org se milega

# Initialize the bot
app = Client(
    "url_checker_bot",
    api_id=API_ID,
    api_hash=API_HASH,
    bot_token=BOT_TOKEN
)

@app.on_message(filters.command(["start"]))
async def start_command(client, message):
    await message.reply_text("<b> <i> Hello! I'm a URL checker bot. Send me a URL with /url command to check it.\nExample: /url https://example.com</b></i>")

@app.on_message(filters.command(["url"], PREFIXES))
async def url_checker(client: Client, m: Message):
    try:
        logger.info(f"Received URL check request from user {m.from_user.id}")
        text = m.text[len(m.command[0]) + 2:].strip()

        if not text:
            await m.reply("Please provide a URL to check.", quote=True)
            return

        if not is_valid_url(text):
            await m.reply("Invalid URL format. Please enter a valid URL LIKE THIS /url with http or https.", quote=True)
            return

        await m.reply("Checking URL... Please wait.", quote=True)
        detected_gateways, status_code, captcha_detected, cloudflare_detected, payment_security_type, cvv_cvc_status, inbuilt_status = check_url(text)

        gateways_str = ', '.join(detected_gateways) if detected_gateways else "None"
        response_text = f"""
- - - - - - - -『𝙐𝙍𝙇 𝘾𝙝𝙚𝙘𝙠』- - - - - - - -
━━━━━━━━━━━━━━
[<b><a href="tg://resolve?domain=washitalr">⎒</a></b>]𝙐𝙍𝙇 -» <code>{text}</code>
━━━━━━━━━━━━━━
[<b><a href="tg://resolve?domain=washitalr">零</a></b>]𝙋𝙖𝙮𝙢𝙚𝙣𝙩 𝙂𝙖𝙩𝙚𝙬𝙖𝙮𝙨 -» <code>{gateways_str}</code>
━━━━━━━━━━━━━━
[<b><a href="tg://resolve?domain=washitalr">ᥫ᭡</a></b>]𝘾𝙖𝙥𝙩𝙘𝙝𝙖 𝘿𝙚𝙩𝙚𝙘𝙩𝙚𝙙 -» <code>{captcha_detected}</code>
━━━━━━━━━━━━━━
[<b><a href="tg://resolve?domain=washitalr">ϟ</a></b>]𝘾𝙡𝙤𝙪𝙙𝙛𝙡𝙖𝙧𝙚 𝘿𝙚𝙩𝙚𝙘𝙩𝙚𝙙 -» <code>{cloudflare_detected}</code>
━━━━━━━━━━━━━━
[<b><a href="tg://resolve?domain=washitalr">⌬</a></b>]𝙋𝙖𝙮𝙢𝙚𝙣𝙩 𝙎𝙚𝙘𝙪𝙧𝙞𝙩𝙮 -» <code>{payment_security_type}</code>
━━━━━━━━━━━━━━
[<b><a href="tg://resolve?domain=washitalr">玄</a></b>]𝘾𝙑𝙑/𝘾𝙑𝘾 𝙍𝙚𝙦𝙪𝙞𝙧𝙚𝙢𝙚𝙣𝙩 -» <code>{cvv_cvc_status}</code>
━━━━━━━━━━━━━━
[<b><a href="tg://resolve?domain=washitalr">キ</a></b>]𝙄𝙣-𝙗𝙪𝙞𝙡𝙩 𝙋𝙖𝙮𝙢𝙚𝙣𝙩 -» <code>{inbuilt_status}</code>
━━━━━━━━━━━━━━
[<b><a href="tg://resolve?domain=washitalr">꫟</a></b>]𝙎𝙩𝙖𝙩𝙪𝙨 𝘾𝙤𝙙𝙚 -» <code>{status_code}</code>
[🧑‍💻 <b>DEVELOPED BY :</b> @PRAKASHpv8]
━━━━━━━━━━━━━━
"""
        await m.reply(response_text, quote=True, disable_web_page_preview=True)
    except Exception as e:
        logger.error(f"Error occurred while checking URL: {e}")
        await m.reply("An error occurred while checking the URL. Please try again later.", quote=True)

# URL Validation Function
def is_valid_url(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://'  
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  
        r'localhost|'  
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  
        r'(?::\d+)?'  
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

# URL Checking Function
def check_url(url):
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()  

        detected_gateways = find_payment_gateways(response.text)
        captcha_detected = check_captcha(response.text)
        cloudflare_detected = check_cloudflare(response.headers, response.text)
        is_3d_secure = check_3d_secure(response.text)
        is_otp_required = check_otp_required(response.text)
        cvv_cvc_status = check_payment_info(response.text)
        inbuilt_payment = check_inbuilt_payment_system(response.text)

        payment_security_type = (
            "Both 3D Secure and OTP Required" if is_3d_secure and is_otp_required else
            "3D Secure" if is_3d_secure else
            "OTP Required" if is_otp_required else
            "2D (No extra security)"
        )

        if captcha_detected:
            payment_security_type += " | Captcha Detected"
        if cloudflare_detected:
            payment_security_type += " | Protected by Cloudflare"

        inbuilt_status = "Yes" if inbuilt_payment else "No"

        return detected_gateways, response.status_code, captcha_detected, cloudflare_detected, payment_security_type, cvv_cvc_status, inbuilt_status

    except requests.exceptions.RequestException:
        return [], 500, False, False, "Error", "N/A", "N/A"

# Payment Gateway Detection
def find_payment_gateways(response_text):
    payment_gateways = [ 
        "paypal", "stripe", "razorpay", "paytm", "google pay", "cashapp", "apple pay",
        "amazon pay", "square", "adyen", "authorize.net", "wepay", "skrill", "neteller", "Authnet",
        "braintree", "worldpay", "payoneer", "2checkout", "klarna", "afterpay","shopify ","SHOPING","Shopify","affirm", "authnet", "Authnet",
        "bluepay", "payu", "adyen", "ingenico", "firstdata", "payza", "ccavenue", "mollie",
        "fastspring", "eway", "verifone", "fortumo", "alipay", "wechat pay", "unionpay",
        "mercado pago", "pagseguro", "iyzico", "yandex money", "qiwi", "webmoney",
        "sofort", "giropay", "trustly", "sezzle", "zip pay", "zip money", "openpay",
        "viva wallet", "swish", "vipps", "mobilepay", "paysera", "bluesnap", "billdesk",
        "doku", "paysafecard", "payco", "khipu", "toss", "clip", "ebanx", "mpesa", "pesapal"
    ]
    return [gateway.capitalize() for gateway in payment_gateways if gateway in response_text.lower()]

# Security Check Functions
def check_captcha(response_text):
    return any(keyword in response_text.lower() for keyword in ['captcha', 'robot', 'verification'])

def check_cloudflare(headers, response_text):
    return "server" in headers and headers["server"].lower() == "cloudflare"

def check_3d_secure(response_text):
    return any(keyword in response_text.lower() for keyword in ["3d secure", "verified by visa", "mastercard securecode"])

def check_otp_required(response_text):
    return any(keyword in response_text.lower() for keyword in ["otp", "one-time password", "verification code"])

def check_payment_info(response_text):
    if "cvv" in response_text.lower() and "cvc" in response_text.lower():
        return "Both CVV and CVC Required"
    return "CVV Required" if "cvv" in response_text.lower() else "CVC Required" if "cvc" in response_text.lower() else "No CVV/CVC Required"

def check_inbuilt_payment_system(response_text):
    return any(keyword in response_text.lower() for keyword in ["native payment", "integrated payment", "built-in checkout"])

# Bulk URL Checking from Text File
@app.on_message(filters.command(["urltxt"],PREFIXES) & filters.document)
async def urltxt_checker(client: Client, m: Message):
    try:
        # Check if file is text file
        if not m.document.file_name.endswith('.txt'):
            await m.reply_text("Please send a .txt file containing URLs (one URL per line)", quote=True)
            return

        # Download file
        status_msg = await m.reply_text("⏳ Downloading file...", quote=True)
        file_path = await client.download_media(m.document)
        
        if not file_path:
            await status_msg.edit_text("❌ Failed to download file!")
            return

        # Read URLs from file
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read().strip()
                urls = [line.strip() for line in content.split('\n') if line.strip()]
        except Exception as e:
            await status_msg.edit_text(f"❌ Error reading file: {str(e)}")
            if os.path.exists(file_path):
                os.remove(file_path)
            return

        if not urls:
            await status_msg.edit_text("❌ No URLs found in the file!")
            os.remove(file_path)
            return

        await status_msg.edit_text(f"🔍 Found {len(urls)} URLs. Starting check...")
        
        # Process URLs
        results = []
        for i, url in enumerate(urls, 1):
            try:
                if not is_valid_url(url):
                    results.append(f"URL {i}: {url}\nStatus: ❌ Invalid URL format\n{'='*50}")
                    continue
                
                detected_gateways, status_code, captcha, cloudflare, security, cvv, inbuilt = check_url(url)
                
                result = (
                    f"URL {i}: {url}\n"
                    f"Status Code: {status_code}\n"
                    f"Gateways: {', '.join(detected_gateways) if detected_gateways else 'None'}\n"
                    f"Security: {security}\n"
                    f"Captcha: {'Yes' if captcha else 'No'}\n"
                    f"Cloudflare: {'Yes' if cloudflare else 'No'}\n"
                    f"CVV/CVC: {cvv}\n"
                    f"Inbuilt Payment: {inbuilt}\n"
                    f"{'='*50}\n 🧑‍💻 DEVELOPER :- @PRAKASHpv8"
                    )
                results.append(result)
                
                if i % 5 == 0:
                    await status_msg.edit_text(f"🔍 Checking URLs: {i}/{len(urls)}")
                
            except Exception as e:
                results.append(f"URL {i}: {url}\nError: {str(e)}\n{'='*50}")

        # Save and send results
        result_file = "checked_urls.txt"
        try:
            with open(result_file, 'w', encoding='utf-8') as f:
                f.write("\n".join(results))
            
            await status_msg.edit_text("📤 Sending results...")
            await m.reply_document(
                document=result_file,
                caption=f"✅ URL Check Results\n📝 Total URLs: {len(urls)}\n 🧑‍💻 developed by :- @PRAKASHpv8",
                quote=True
            )
        except Exception as e:
            await status_msg.edit_text(f"❌ Error saving/sending results: {str(e)}")
        
        # Cleanup
        try:
            os.remove(file_path)
            os.remove(result_file)
        except:
            pass
            
    except Exception as e:
        await m.reply_text(f"❌ An error occurred: {str(e)}", quote=True)


# Main execution
if __name__ == "__main__":
    try:
        logger.info("Starting URL Checker Bot...")
        app.run()
    except Exception as e:
        logger.error(f"Error running bot: {str(e)}")