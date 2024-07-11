import vt
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import os
import hashlib
import time

# VirusTotal API anahtarınızı buraya girin
API_KEY = 'dd36314000b31eaf0e811cc3f636389d90d860c06e27a110188055a0e764be81'

# VirusTotal istemcisini oluştur
client = vt.Client(API_KEY)

# Logo dosyası kontrolü
logo_path = 'logo.png'
expected_hash = '33031400ca1484a2082768f72a85dad0b8a5d317494edb6750aad02f273f4130a16939a142af7c4c1d2113897fca12c28e9ac00881bb3e5ca9da34d1c24d7aaf'

if not os.path.exists(logo_path):
    messagebox.showerror("Hata", "logo.png dosyası bulunamadı!")
    exit()

# Dosyanın hash değerini hesapla ve karşılaştır
def calculate_hash(file_path, hash_type):
    hash_func = None
    if hash_type == 'md5':
        hash_func = hashlib.md5()
    elif hash_type == 'sha1':
        hash_func = hashlib.sha1()
    elif hash_type == 'sha256':
        hash_func = hashlib.sha256()
    elif hash_type == 'sha512':
        hash_func = hashlib.sha512()
    else:
        return None
    
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            hash_func.update(chunk)
    
    return hash_func.hexdigest()

# Hash değerini gösterme işlevi
def show_hash(hash_type):
    global logo_path
    filename = filedialog.askopenfilename()
    if filename:
        hash_value = calculate_hash(filename, hash_type)
        if hash_value:
            messagebox.showinfo(f"{hash_type.upper()} Hash Değeri", f"{hash_type.upper()} hash değeri:\n\n{hash_value}")
        else:
            messagebox.showerror("Hata", "Geçersiz hash türü!")

# Dosya tarama fonksiyonu
def scan_file(file_path):
    with open(file_path, 'rb') as f:
        analysis = client.scan_file(f)
    return analysis.id

# URL tarama fonksiyonu
def scan_url(url):
    analysis = client.scan_url(url)
    return analysis.id

# Dosya raporu alma fonksiyonu
def get_file_report(file_id):
    while True:
        report = client.get_object(f"/analyses/{file_id}")
        if report.status == "completed":
            break
        time.sleep(5)
    return report

# URL raporu alma fonksiyonu
def get_url_report(url_id):
    while True:
        report = client.get_object(f"/analyses/{url_id}")
        if report.status == "completed":
            break
        time.sleep(5)
    return report

# Dosya seçme ve tarama işlemi
def browse_file():
    filename = filedialog.askopenfilename()
    if filename:
        file_id = scan_file(filename)
        messagebox.showinfo("Dosya Tarama", f"Tarama başlatıldı. Tarama ID: {file_id}")
        file_report = get_file_report(file_id)
        show_report(file_report)

# URL tarama işlemi
def scan_entered_url():
    url = url_entry.get()
    if url:
        url_id = scan_url(url)
        messagebox.showinfo("URL Tarama", f"Tarama başlatıldı. Tarama ID: {url_id}")
        url_report = get_url_report(url_id)
        show_report(url_report)

# Tarama sonuçlarını gösterme
def show_report(report):
    result = ""
    attributes = report.to_dict().get('attributes', {})
    stats = attributes.get('stats', {})
    scan_results = attributes.get('results', {})

    detected_count = stats.get('malicious', 0)
    total_count = sum(stats.values())

    result += f"Sonuç: {detected_count}/{total_count} antivirüs virüs tespit etti.\n\n"
    result += "Detaylı Sonuçlar:\n"

    for engine, data in scan_results.items():
        result += f"Antivirüs: {engine}\n"
        result += f"Sonuç: {data.get('category')}\n"
        if data.get('category') == 'malicious':
            result += f"Zararlı Türü: {data.get('result')}\n"
        result += "-"*40 + "\n"

    report_text.config(state=tk.NORMAL)
    report_text.delete(1.0, tk.END)
    report_text.insert(tk.END, result)
    report_text.config(state=tk.DISABLED)

# Tkinter GUI oluşturma
root = tk.Tk()
root.title("NMScanner")

# Logo görüntüleme
img = Image.open(logo_path)
img = img.resize((200, 200), Image.LANCZOS)
logo_img = ImageTk.PhotoImage(img)

logo_label = tk.Label(root, image=logo_img)
logo_label.pack(pady=10)

frame = tk.Frame(root)
frame.pack(pady=20)

file_button = tk.Button(frame, text="Dosya Tara", command=browse_file)
file_button.pack(side=tk.LEFT, padx=10)

url_entry = tk.Entry(frame, width=50)
url_entry.pack(side=tk.LEFT, padx=10)

url_button = tk.Button(frame, text="URL Tara", command=scan_entered_url)
url_button.pack(side=tk.LEFT, padx=10)

# Hash hesaplama butonları
hash_frame = tk.Frame(root)
hash_frame.pack(pady=10)

hash_buttons = []
hash_types = ['md5', 'sha1', 'sha256', 'sha512']
for hash_type in hash_types:
    button = tk.Button(hash_frame, text=f"{hash_type.upper()} Hash", command=lambda h=hash_type: show_hash(h))
    button.pack(side=tk.LEFT, padx=5)
    hash_buttons.append(button)

# Kaydırma çubuğu ve metin alanı oluşturma
scrollbar = tk.Scrollbar(root)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

report_text = tk.Text(root, wrap=tk.WORD, yscrollcommand=scrollbar.set)
report_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
report_text.config(state=tk.DISABLED)

scrollbar.config(command=report_text.yview)

root.mainloop()

# Uygulamayı kapatmadan önce client'ı kapatma
client.close()

