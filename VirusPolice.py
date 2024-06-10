import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from PIL import Image, ImageTk
import requests
import base64

# Function to check URL against VirusTotal
def check_url():
    api_key = 'f45ffae21d2a0047a0653b060c8ecd629927a5665fa56e310fac08d61db11495'
    url = url_entry.get()

    if not url:
        messagebox.showwarning("Input Error", "Please enter a URL")
        return

    headers = {
        "Accept": "application/json",
        "x-apikey": api_key
    }

    params = {"url": url}
    response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, params=params)

    if response.status_code == 200:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        url_report = requests.get(f'https://www.virustotal.com/api/v3/urls/{url_id}', headers=headers)

        if url_report.status_code == 200:
            report_data = url_report.json()
            display_report(report_data)
        else:
            messagebox.showerror("Error", "Failed to retrieve URL report")
    else:
        messagebox.showerror("Error", "Failed to submit URL for analysis")

# Function to display the VirusTotal report
def display_report(report_data):
    analysis_results = report_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
    malicious = analysis_results.get('malicious', 0)
    suspicious = analysis_results.get('suspicious', 0)
    harmless = analysis_results.get('harmless', 0)
    undetected = analysis_results.get('undetected', 0)

    result_text = (
        f"Malicious: {malicious}\n"
        f"Suspicious: {suspicious}\n"
        f"Harmless: {harmless}\n"
        f"Undetected: {undetected}\n"
    )

    result_box.config(state=tk.NORMAL)
    result_box.delete(1.0, tk.END)
    result_box.insert(tk.END, result_text)
    result_box.config(state=tk.DISABLED)

    if malicious == 0 and suspicious == 0:
        safe_message.set("It is safe to open this link.")
    else:
        safe_message.set("This link might be harmful.")

# Function to validate login
def validate_login():
    username = username_entry.get()
    password = password_entry.get()

    if username == "admin" and password == "pass":
        login_frame.pack_forget()
        main_frame.pack(fill='both', expand=True)
    else:
        messagebox.showerror("Login Failed", "Invalid username or password")

# Initialize main Tkinter window
root = tk.Tk()
root.title("Cyber Shield by Msebetsi Solutions")
root.geometry("800x600")

# Load background image
background_image = Image.open("/Users/zazi/Desktop/CyberShield.png")
background_image = background_image.resize((800, 600), Image.Resampling.LANCZOS)
background_photo = ImageTk.PhotoImage(background_image)

# Login Frame
login_frame = tk.Frame(root)
login_frame.pack(fill='both', expand=True)

bg_label_login = tk.Label(login_frame, image=background_photo)
bg_label_login.place(relwidth=1, relheight=1)

login_label = tk.Label(login_frame, text="Login", font=('Helvetica', 18, 'bold'), bg='#000', fg='#fff')
login_label.pack(pady=20)

username_label = tk.Label(login_frame, text="Username", bg='#000', fg='#fff')
username_label.pack(pady=5)
username_entry = ttk.Entry(login_frame)
username_entry.pack(pady=5)

password_label = tk.Label(login_frame, text="Password", bg='#000', fg='#fff')
password_label.pack(pady=5)
password_entry = ttk.Entry(login_frame, show='*')
password_entry.pack(pady=5)

login_button = ttk.Button(login_frame, text="Login", command=validate_login)
login_button.pack(pady=20)

# Main URL Checker Frame
main_frame = tk.Frame(root)

bg_label_main = tk.Label(main_frame, image=background_photo)
bg_label_main.place(relwidth=1, relheight=1)

url_label = tk.Label(main_frame, text="Enter URL:", bg='#000', fg='#fff')
url_label.pack(pady=10)
url_entry = ttk.Entry(main_frame, width=50)
url_entry.pack(pady=5)

check_button = ttk.Button(main_frame, text="Check URL", command=check_url)
check_button.pack(pady=20)

# Result Text Box
result_box = tk.Text(main_frame, height=10, width=50, state=tk.DISABLED)
result_box.pack(pady=10)

# Safety Message Label
safe_message = tk.StringVar()
safe_message_label = tk.Label(main_frame, textvariable=safe_message, font=('Helvetica', 14), bg='#000', fg='#fff')
safe_message_label.pack(pady=10)

# Start the Tkinter loop
root.mainloop()
