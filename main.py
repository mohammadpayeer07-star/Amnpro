import os
import re
import io
import zipfile
import tldextract
import asyncio # ضفناه مشان delete
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, MessageHandler, CommandHandler, CallbackQueryHandler, filters, ContextTypes
from telegram.error import BadRequest, Forbidden
from telegram.constants import ParseMode

TOKEN = os.getenv("TOKEN")
CHANNEL_ID = "@S1ecurity_Pro"
CHANNEL_LINK = "https://t.me/S1ecurity_Pro"
BOT_NAME = "آمن PRO"

CHECK_MODE = {}
MAX_FILE_SIZE = 25 * 1024 * 1024 # 25MB حد تيليجرام المجاني

# ----------------- تواقيع الملفات الحقيقية Magic Bytes -----------------
FILE_SIGNATURES = {
    b'%PDF-': 'PDF',
    b'PK\x03\x04': 'ZIP/APK/DOCX', # الـ APK هو ZIP
    b'MZ': 'EXE/DLL',
    b'\x7fELF': 'ELF/Linux'
}

# ----------------- دوال المساعدة -----------------
async def is_member(user_id, context):
    try:
        member = await context.bot.get_chat_member(chat_id=CHANNEL_ID, user_id=user_id)
        return member.status in ["member", "administrator", "creator", "owner"]
    except (BadRequest, Forbidden):
        return False

def get_kb(type="main"):
    if type == "main":
        return InlineKeyboardMarkup([
            [InlineKeyboardButton("🏛️ من نحن", callback_data='about')],
            [InlineKeyboardButton("🎯 الرؤية", callback_data='goals')],
            [InlineKeyboardButton("🎓 دورات أمنPRO", callback_data='courses_menu')],
            [InlineKeyboardButton("🔍 فحص الروابط", callback_data='check')],
            [InlineKeyboardButton("🕵️ فحص ملف", callback_data='scan_file')],
            [InlineKeyboardButton("📜 الشهادات", callback_data='cert')],
            [InlineKeyboardButton("🆘 الدعم الفني", callback_data='help')]
        ])
    if type == "back":
        return InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ العودة للرئيسية", callback_data='menu')]])
    if type == "sub":
        return InlineKeyboardMarkup([
            [InlineKeyboardButton("📢 الاشتراك", url=CHANNEL_LINK)],
            [InlineKeyboardButton("✅ تحقق", callback_data='check_sub')]
        ])
    if type == "courses":
        return InlineKeyboardMarkup([
            [InlineKeyboardButton("1️⃣ مستوى أول- مبتدئ", callback_data='course_1')],
            [InlineKeyboardButton("2️⃣ مستوى ثاني- متوسط", callback_data='course_2')],
            [InlineKeyboardButton("3️⃣ مستوى ثالث - محترف", callback_data='course_3')],
            [InlineKeyboardButton("4️⃣ مستوى رابع- PRO", callback_data='course_4')],
            [InlineKeyboardButton("⬅️ رجوع", callback_data='menu')]
        ])

def analyze_link(url):
    url_lower = url.lower()
    threats = []
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"

    if not url_lower.startswith("https://"):
        threats.append("البروتوكول غير مشفر HTTP")
    if "chatid=" in url_lower:
        threats.append("يحتوي على `chatid`")
    if "c.html" in url_lower:
        threats.append("صفحة مزورة `c.html`")
    if "verify=" in url_lower:
        threats.append("يحتوي `verify`")
    if domain == "faceboook.com":
        threats.append("انتحال فيسبوك")

    intro = "🔍 **فحص الرابط**\nيقوم نظام آمن PRO بتحليل الرابط باستخدام عدة طبقات من الفحص للكشف عن المؤشرات الأمنية، بهدف مساعدتك في تقييم الرابط قبل فتحه."

    if threats:
        result = "❌ **غير آمن**"
        description = "تم رصد مؤشرات تدل على أن الرابط قد يكون ضارًا أو يستخدم في التصيد الاحتيالي أو سرقة البيانات.\nنصح بعدم فتح الرابط أو إدخال أي معلومات شخصية داخله حفاظًا على أمنك الرقمي."
    else:
        result = "✅ **آمن**"
        description = "لم يتم رصد أي مؤشرات خطورة معروفة أثناء الفحص.\nملاحظة: يبقى الالتزام بالحذر وعدم مشاركة بياناتك الشخصية أو كلمات المرور في أي موقع غير موثوق."

    footer = "نعمل دائمًا من أجل تعزيز أمنكم الرقمي وتوفير بيئة أكثر أمانًا للجميع.\n\nآمن PRO\nمعًا نحو فضاء رقمي أكثر أمانًا."

    return f"{intro}\n─────────────────────\nنتيجة التحليل: {result}\n{description}\n\n{footer}"

def detect_file_type(file_bytes: bytes, file_name: str) -> str:
    for sig, ftype in FILE_SIGNATURES.items():
        if file_bytes.startswith(sig):
            return ftype
    ext = file_name.lower().split('.')[-1]
    return ext.upper()

# ----------------- معالجات الأوامر - كودك القديم كامل بدون لمس -----------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if await is_member(user_id, context):
        await update.message.reply_text(
            "🛡️ **أهلاً بك في بوت أمن PRO**\nاختر الخدمة التي تريدها من الأزرار أدناه.",
            reply_markup=get_kb("main"),
            parse_mode=ParseMode.MARKDOWN
        )
    else:
        await update.message.reply_text(
            "⚠️ **يجب عليك الاشتراك أولا في القناة للاستفادة من خدمات البوت**",
            reply_markup=get_kb("sub"),
            parse_mode=ParseMode.MARKDOWN
        )

async def buttons(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id = query.from_user.id
    data = query.data

    if data!= 'check_sub' and not await is_member(user_id, context):
        await query.edit_message_text(
            "⚠️ **يجب عليك الاشتراك أولاً للاستفادة من الخدمات.**",
            reply_markup=get_kb("sub"),
            parse_mode=ParseMode.MARKDOWN
        )
        return

    if data == 'check_sub':
        if await is_member(user_id, context):
            await query.edit_message_text(
                "🛡️ **أهلاً بك في بوت أمن PRO**\nاختر الخدمة التي تريدها من الأزرار أدناه.",
                reply_markup=get_kb("main"),
                parse_mode=ParseMode.MARKDOWN
            )
        else:
            await query.edit_message_text(
                "❌ **لم يتم العثور على اشتراك.**\nيرجى الاشتراك ثم الضغط على تحقق.",
                reply_markup=get_kb("sub"),
                parse_mode=ParseMode.MARKDOWN
            )
        return

    if data == 'menu':
        await query.edit_message_text(
            "🛡️ **أهلاً بك في بوت أمن PRO**\nاختر الخدمة التي تريدها من الأزرار أدناه.",
            reply_markup=get_kb("main"),
            parse_mode=ParseMode.MARKDOWN
        )
    elif data == 'about':
        await query.edit_message_text(
            "🏛️ **من نحن**\n\n"
            "آمن PRO فريق متخصص في الأمن السيبراني، يضم خبرات في البرمجة، وتحليل التهديدات الرقمية، "
            "وتصميم الأنظمة، والتوعية الأمنية.\n\n"
            "نعمل على نشر ثقافة الأمن السيبراني، وتطوير أدوات تساعد المستخدمين على استخدام الإنترنت بأمان، "
            "مع تقديم دورات تدريبية ومحتوى احترافي يواكب أحدث التهديدات الإلكترونية.",
            reply_markup=get_kb("back"),
            parse_mode=ParseMode.MARKDOWN
        )
    elif data == 'goals':
        await query.edit_message_text(
            "🎯 **هدف آمن PRO**\n\n"
            "نسعى إلى رفع مستوى الوعي الرقمي، وحماية المستخدمين من الاحتيال والاختراقات والهجمات الإلكترونية، "
            "عبر التدريب، والتوعية، وتوفير أدوات تحقق تساعد على اتخاذ القرار الصحيح قبل التفاعل مع أي رابط أو تطبيق.",
            reply_markup=get_kb("back"),
            parse_mode=ParseMode.MARKDOWN
        )
    elif data == 'courses_menu':
        await query.edit_message_text(
            "📚 **دورات آمن PRO**\nاختر المستوى المناسب لك:",
            reply_markup=get_kb("courses"),
            parse_mode=ParseMode.MARKDOWN
        )
    elif data == 'course_1':
        await query.edit_message_text(
            "**1️⃣ المستوى الأول – المبتدئ**\n\n"
            "يُعد هذا المستوى نقطة البداية لكل من يرغب في تعلم الأمن السيبراني، ويتضمن:\n"
            "• أساسيات الأمن السيبراني.\n"
            "• حماية الهاتف من الاختراق والتجس.\n"
            "• التعامل الآمن مع التطبيقات والروابط.\n"
            "• رفع مستوى الوعي الرقمي وكيفية اكتشاف محاولات الاحتيال والهندسة الاجتماعية.",
            reply_markup=get_kb("courses"),
            parse_mode=ParseMode.MARKDOWN
        )
    elif data == 'course_2':
        await query.edit_message_text(
            "للاشتراك انتظر الإعلان على قنواتنا الرسمية",
            reply_markup=get_kb("courses"),
            parse_mode=ParseMode.MARKDOWN
        )
    elif data == 'course_3':
        await query.edit_message_text(
            "للاشتراك انتظر الإعلان على قنواتنا الرسمية",
            reply_markup=get_kb("courses"),
            parse_mode=ParseMode.MARKDOWN
        )
    elif data == 'course_4':
        await query.edit_message_text(
            "للاشتراك انتظر الإعلان على قنواتنا الرسمية",
            reply_markup=get_kb("courses"),
            parse_mode=ParseMode.MARKDOWN
        )
    elif data == 'cert':
        await query.edit_message_text(
            "نعمل على التطوير من أجل تصديق الشهادات وفق قاعدة بيانات رسمية",
            reply_markup=get_kb("back"),
            parse_mode=ParseMode.MARKDOWN
        )
    elif data == 'help':
        await query.edit_message_text(
            "اطرح سؤالك هنا\nhttps://t.me/+wdWPPmwpg_w5NmU0",
            reply_markup=get_kb("back")
        )
    elif data == 'check':
        CHECK_MODE[user_id] = 'link'
        await query.edit_message_text(
            "🔍 **فحص الروابط**\n\n"
            "أرسل الرابط الذي تريد فحصه، وسيقوم النظام بتحليله وإعلامك بالنتيجة.\n\n"
            "ملاحظة: يفضل إرسال الرابط كرسالة منفصلة.",
            reply_markup=get_kb("back"),
            parse_mode=ParseMode.MARKDOWN
        )
    elif data == 'scan_file':
        CHECK_MODE[user_id] = 'file'
        await query.edit_message_text(
            "🕵️ **فحص ملف جنائي**\n\n"
            "ارسل اي ملف PDF, APK, ZIP, EXE, DLL... الحد 25MB.\n"
            "البوت يكشف التنكر والملفات الملغمة.",
            reply_markup=get_kb("back")
        )

async def messages(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text

    if not await is_member(user_id, context):
        await update.message.reply_text(
            "⚠️ **يجب عليك الاشتراك أولاً للاستفادة من الخدمات.**",
            reply_markup=get_kb("sub"),
            parse_mode=ParseMode.MARKDOWN
        )
        return

    if CHECK_MODE.get(user_id) == 'link':
        if "http" in text:
            urls = re.findall(r'(https?://[^\s]+)', text)
            url_to_check = urls[0] if urls else text
            msg = await update.message.reply_text("⏳ جاري الفحص...")
            result = analyze_link(url_to_check)
            try:
                await msg.delete()
            except:
                pass
            await update.message.reply_text(
                result,
                disable_web_page_preview=True,
                reply_markup=get_kb("back"),
                parse_mode=ParseMode.MARKDOWN
            )
            CHECK_MODE.pop(user_id, None)
        else:
            await update.message.reply_text(
                "⚠️ الرجاء إرسال رابط صحيح يبدأ بـ http:// أو https://",
                reply_markup=get_kb("back")
            )
        return

    if text == "🏛️ من نحن":
        await update.message.reply_text(
            "🏛️ **من نحن**\n\n"
            "آمن PRO فريق متخصص في الأمن السيبراني...",
            reply_markup=get_kb("back"),
            parse_mode=ParseMode.MARKDOWN
        )
        return
    if text == "🎯 الرؤية":
        await update.message.reply_text(
            "🎯 **هدف آمن PRO**\n\nنسعى...",
            reply_markup=get_kb("back"),
            parse_mode=ParseMode.MARKDOWN
        )
        return
    if text == "🎓 دورات أمنPRO":
        await update.message.reply_text(
            "📚 **دورات آمن PRO**\nاختر المستوى المناسب لك:",
            reply_markup=get_kb("courses"),
            parse_mode=ParseMode.MARKDOWN
        )
        return
    if text == "🔍 فحص الروابط":
        CHECK_MODE[user_id] = 'link'
        await update.message.reply_text(
            "🔍 **فحص الروابط**\n\nأرسل الرابط...",
            reply_markup=get_kb("back"),
            parse_mode=ParseMode.MARKDOWN
        )
        return
    if text == "🕵️ فحص ملف":
        CHECK_MODE[user_id] = 'file'
        await update.message.reply_text(
            "🕵️ **فحص ملف جنائي**\n\nارسل اي ملف PDF, APK, ZIP, EXE...",
            reply_markup=get_kb("back")
        )
        return
    if text == "📜 الشهادات":
        await update.message.reply_text(
            "نعمل على التطوير من أجل تصديق الشهادات...",
            reply_markup=get_kb("back"),
            parse_mode=ParseMode.MARKDOWN
        )
        return
    if text == "🆘 الدعم الفني":
        await update.message.reply_text(
            "اطرح سؤالك هنا\nhttps://t.me/+wdWPPmwpg_w5NmU0",
            reply_markup=get_kb("back")
        )
        return

    await update.message.reply_text(
        "⚠️ الرجاء استخدام الأزرار للتنقل.",
        reply_markup=get_kb("main"),
        parse_mode=ParseMode.MARKDOWN
    )

# ----------------- معالج فحص الملفات الجديد - تم تصليح الخطأ هون -----------------
async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if CHECK_MODE.get(user_id)!= 'file': return

    doc = update.message.document
    if doc.file_size > MAX_FILE_SIZE:
        await update.message.reply_text(f"❌ حجم الملف كبير {doc.file_size/1024/1024:.1f}MB. الحد 25MB", reply_markup=get_kb("back"))
        CHECK_MODE.pop(user_id, None) # حطيت None مشان ما يكرش
        return

    msg = await update.message.reply_text("⏳ جاري التحليل الجنائي للملف...")
    file_bytes = await (await doc.get_file()).download_as_bytearray()
    file_name = doc.file_name.lower()

    ftype = detect_file_type(file_bytes, file_name)
    threats = [f"**نوع الملف المكتشف**: {ftype}"]

    # 1. كشف التنكر
    if file_name.endswith('.pdf') and ftype!= 'PDF': threats.append("❌ تنكر خطير: الملف ليس PDF حقي.")
    if file_name.endswith('.apk') and ftype!= 'ZIP/APK/DOCX': threats.append("❌ تنكر خطير: الملف ليس APK حقي.")
    if file_name.endswith('.exe') and ftype!= 'EXE/DLL': threats.append("❌ تنكر خطير: الملف ليس EXE حقي.")

    # 2. فحص PDF
    if ftype == 'PDF':
        raw = file_bytes.decode('latin-1', errors='ignore')
        if '/JS' in raw or '/JavaScript' in raw: threats.append("كشف كود JavaScript مشبوه.")
        if '/Launch' in raw or '/AA' in raw: threats.append("كشف أمر تنفيذ تلقائي عند الفتح.")

    # 3. فحص APK/ZIP
    elif ftype == 'ZIP/APK/DOCX':
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                namelist = z.namelist()
                if any(f.endswith(('.exe', '.bat', '.vbs', '.ps1', '.js')) for f in namelist): threats.append("يحتوي ملف تنفيذي خطير بالداخل.")
                if 'AndroidManifest.xml' in namelist:
                    threats.append("**هذا تطبيق اندرويد APK**")
                    if 'classes.dex' in namelist: threats.append("يحتوي كود تنفيذي Dex.")
                    if any(x in file_name for x in ["gold", "mod", "plus", "pro"]): threats.append("نسخة معدلة = خطر عالي.")
        except zipfile.BadZipFile: threats.append("الملف تالف او ليس ZIP صالح.")

    # 4. فحص EXE
    elif ftype == 'EXE/DLL':
        threats.append("⚠️ ملف تنفيذي Windows. لا تفتحه الا اذا كنت متأكد 100%.")

    result = "❌ **خطير - لا تفتح الملف**" if len(threats) > 1 else "✅ **آمن مبدئياً**"
    final_text = f"{result}\n\n" + "\n".join(threats)

    # --- التعديل المهم هون: مسح + ارسال جديد بدل edit ---
    try:
        await msg.delete()
    except:
        pass
    await update.message.reply_text(final_text, reply_markup=get_kb("back"), parse_mode=ParseMode.MARKDOWN)

    CHECK_MODE.pop(user_id, None) # حطيت None مشان ما يكرش

# ----------------- تشغيل البوت -----------------
app = Application.builder().token(TOKEN).build()
app.add_handler(CommandHandler("start", start))
app.add_handler(CallbackQueryHandler(buttons))
app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, messages))
app.add_handler(MessageHandler(filters.Document.ALL, handle_file))
app.run_polling(drop_pending_updates=True)