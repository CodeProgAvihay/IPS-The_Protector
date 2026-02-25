from email.mime.text import MIMEText
from alert_manager import alert_queue

SYSTEM_GMAIL = "theprotsys@gmail.com"
SYSTEM_APP_PASSWORD = "eykafjfnujcvnfog"

def mail_worker(server):
    while True:
        data = alert_queue.get()
        if data is None:
            #print("[MAIL] shutdown signal received")
            break
        email, ip, attack_type = data
        send_mail_to_user(email, ip, attack_type, server)
        alert_queue.task_done()
    #print("[MAIL] thread exited")

def send_mail_to_user(email, ip, type, server):
    subject = "[IPS] Attack prevented successfully."
    body = ""
    if type == "Port Scan":
        body += f'''שלום,

מערכת ה־IPS זיהתה פעילות חשודה מסוג סריקת פורטים (Port Scan) ברשת.

סריקת פורטים היא פעולה שבה תוקף מנסה לבדוק אילו פורטים פתוחים במערכת,
במטרה לאתר שירותים פעילים ונקודות תורפה אפשריות.

פרטי האירוע:
כתובת מקור (IP): {ip}

רמת חומרה: אזהרה (Warning)

הפעילות נחסמה/נרשמה על־ידי המערכת, ולא זוהתה חדירה בפועל בשלב זה.

המלצות:

לוודא שהמקור אינו חלק ממערכת פנימית לגיטימית

לבדוק לוגים נוספים מאותה כתובת

לוודא שחומת האש והמערכות מעודכנות

במידת הצורך, מומלץ להמשיך במעקב אחר פעילות נוספת מאותו מקור.

בברכה,
מערכת The Protector.'''
    elif type == "SYN Flood":
        body += f'''שלום,

מערכת ה־IPS זיהתה מתקפת מניעת שירות מסוג SYN Flood.

מתקפת SYN Flood היא מתקפה שבה נשלחות בקשות חיבור (SYN) בכמות חריגה,
ללא השלמת תהליך ה־TCP handshake, במטרה להעמיס על השרת
ולמנוע ממשתמשים לגיטימיים להתחבר לשירות.

פרטי האירוע:
- כתובת מקור (IP): {ip}
- רמת חומרה: קריטי (Critical)

המערכת זיהתה עומס חריג ונקטה בפעולות הגנה בהתאם להגדרות,
כולל חסימה זמנית של מקור התעבורה החשודה.

המלצות:
- לוודא שהמקור אינו שירות לגיטימי שנפגע מתקלה
- לבדוק עומסים חריגים על השרתים המותקפים
- לשקול הפעלת מנגנוני הגנה נוספים (Rate Limiting / SYN Cookies)
- להמשיך במעקב אחר תעבורה חריגה

בברכה,  
מערכת The Protector.'''
    elif type == "DNS Spoofing":
        body += f'''שלום,

מערכת ה־IPS זיהתה פעילות זדונית מסוג DNS Spoofing (הרעלת DNS).

מתקפת DNS Spoofing היא מתקפה שבה תוקף מספק תשובות DNS מזויפות,
ובכך גורם למשתמשים להיות מנותבים לכתובות IP שגויות או זדוניות.
מתקפה זו עלולה להוביל לגניבת מידע, התחזות, או הפניית תעבורה לאתרים זדוניים.

פרטי האירוע:
כתובת מקור חשודה (IP): {ip}
רמת חומרה: קריטי (Critical)

המערכת זיהתה אי־התאמה בתשובות DNS ונקטה בפעולות הגנה בהתאם להגדרות,
כולל חסימה/התראה על מקור התעבורה החשודה.

המלצות:
לוודא שה־DNS Servers מוגדרים כמאובטחים ומעודכנים
לבדוק לוגים עבור תשובות DNS חריגות נוספות
לשקול שימוש ב־DNSSEC במידת האפשר
להתריע למשתמשים במידה וקיים חשש לניתוב שגוי

בברכה,  
מערכת ה־IPS'''
    elif type == "ARP Spoofing":
        body += f'''שלום,

מערכת ה־IPS זיהתה פעילות זדונית מסוג ARP Spoofing (הרעלת ARP) ברשת.

מתקפת ARP Spoofing היא מתקפה שבה תוקף מזייף תשובות ARP,
וכך גורם למכשירים ברשת לשייך כתובת IP לגורם שגוי.
מצב זה מאפשר ביצוע מתקפות Man-in-the-Middle, יירוט תעבורה,
שינוי נתונים ואף ניתוק תקשורת.

פרטי האירוע:
כתובת IP חשודה: {ip}
רמת חומרה: קריטי (Critical)

המערכת זיהתה סתירות בטבלאות ARP ונקטה בפעולות הגנה בהתאם להגדרות,
כולל חסימת התעבורה מהמקור החשוד והתראה למנהל המערכת.

המלצות:
לאמת את טבלאות ה־ARP במכשירים הקריטיים
לוודא שהמקור החשוד אינו רכיב לגיטימי ברשת
לשקול הפעלת מנגנוני הגנה כגון Static ARP / DHCP Snooping / ARP Inspection
להמשיך במעקב אחר ניסיונות זיוף נוספים

בברכה,  
מערכת ה־IPS'''
    
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["From"] = SYSTEM_GMAIL
        msg["To"] = email
        msg["Subject"] = subject
        server.sendmail(SYSTEM_GMAIL, email, msg.as_string())
    except Exception as e:
        print("Error sending email: ", e)
    