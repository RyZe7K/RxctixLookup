import customtkinter as ctk
import requests
import socket
import whois
import subprocess
import platform
from scapy.all import ARP, Ether, srp


def ip_lookup():
    ip_address = entry_input.get()
    if ip_address:
        try:
            response = requests.get(f'https://ipinfo.io/{ip_address}/json')
            data = response.json()
            if 'error' not in data:
                result_label.configure(text=f"IP: {data.get('ip')}\n"
                                             f"City: {data.get('city')}\n"
                                             f"Region: {data.get('region')}\n"
                                             f"Country: {data.get('country')}\n"
                                             f"Location: {data.get('loc')}\n"
                                             f"ISP: {data.get('org')}", text_color="white")
            else:
                result_label.configure(text="Error: Invalid IP address", text_color="white")
        except Exception as e:
            result_label.configure(text=f"Error: {str(e)}", text_color="white")

def search_person():
    person_name = entry_input.get()
    if person_name:
        profiles = [
            f"Facebook: https://facebook.com/{person_name.replace(' ', '').lower()}",
            f"Twitter: https://twitter.com/{person_name.replace(' ', '').lower()}",
            f"LinkedIn: https://linkedin.com/in/{person_name.replace(' ', '-').lower()}"
        ]
        result_label.configure(text="\n".join(profiles), text_color="white")
    else:
        result_label.configure(text="Please enter a name.", text_color="white")

def email_lookup():
    email = entry_input.get()
    if email:
  
        mock_profiles = {
            "example@gmail.com": [
                "Facebook: https://facebook.com/exampleuser",
                "Twitter: https://twitter.com/exampleuser"
            ],
            "test@example.com": [
                "LinkedIn: https://linkedin.com/in/testuser"
            ]
        }
        profiles = mock_profiles.get(email, ["No social media accounts found for this email."])
        result_label.configure(text="\n".join(profiles), text_color="white")
    else:
        result_label.configure(text="Please enter an email address.", text_color="white")

def whois_lookup():
    domain = entry_input.get()
    if domain:
        try:
            w = whois.whois(domain)
            result = f"Domain: {w.domain}\n" \
                     f"Registrar: {w.registrar}\n" \
                     f"Creation Date: {w.creation_date}\n" \
                     f"Expiration Date: {w.expiration_date}\n" \
                     f"Name Servers: {', '.join(w.name_servers) if w.name_servers else 'N/A'}"
            result_label.configure(text=result, text_color="white")
        except Exception as e:
            result_label.configure(text=f"Error: {str(e)}", text_color="white")
    else:
        result_label.configure(text="Please enter a domain.", text_color="white")

def dns_lookup():
    domain = entry_input.get()
    if domain:
        try:
            ip_address = socket.gethostbyname(domain)
            result_label.configure(text=f"IP Address for {domain}: {ip_address}", text_color="white")
        except Exception as e:
            result_label.configure(text=f"Error: {str(e)}", text_color="white")
    else:
        result_label.configure(text="Please enter a domain.", text_color="white")

def ping_host():
    host = entry_input.get()
    if host:
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '4', host] 
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            result_label.configure(text=output, text_color="white")
        except subprocess.CalledProcessError as e:
            result_label.configure(text=f"Error: {e.output}", text_color="white")
        except Exception as e:
            result_label.configure(text=f"Error: {str(e)}", text_color="white")
    else:
        result_label.configure(text="Please enter a host.", text_color="white")

def roblox_account_info():
    username = entry_input.get()
    if username:
        try:
            response = requests.get(f'https://api.roblox.com/users/get-by-username?username={username}')
            if response.status_code == 200:
                data = response.json()
                if 'Id' in data:
                    result_label.configure(text=f"Username: {data['Username']}\n"
                                                 f"User ID: {data['Id']}\n"
                                                 f"Description: {data.get('Description', 'N/A')}\n"
                                                 f"Is Banned: {data.get('IsBanned', 'No')}\n"
                                                 f"Account Age: {data.get('Age', 'N/A')} days", text_color="white")
                else:
                    result_label.configure(text="Error: Username not found", text_color="white")
            else:
                result_label.configure(text="Error: Unable to fetch data", text_color="white")
        except Exception as e:
            result_label.configure(text=f"Error: {str(e)}", text_color="white")
    else:
        result_label.configure(text="Please enter a Roblox username.", text_color="white")

def port_scan():
    host = entry_input.get()
    if host:
        open_ports = []
        for port in range(1, 1025):  # Scan ports 1 to 1024
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)  
                if s.connect_ex((host, port)) == 0:  
                    open_ports.append(port)
        if open_ports:
            result_label.configure(text=f"Open ports on {host}: {', '.join(map(str, open_ports))}", text_color="white")
        else:
            result_label.configure(text=f"No open ports found on {host}.", text_color="white")
    else:
        result_label.configure(text="Please enter a host.", text_color="white")

def traceroute():
    host = entry_input.get()
    if host:
        try:
            command = ['tracert', host] if platform.system().lower() == 'windows' else ['traceroute', host]
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            result_label.configure(text=output, text_color="white")
        except Exception as e:
            result_label.configure(text=f"Error: {str(e)}", text_color="white")
    else:
        result_label.configure(text="Please enter a host.", text_color="white")

def who_is_on_wlan():
    subnet = entry_input.get()
    if subnet:
        try:
            arp = ARP(pdst=subnet)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            result = srp(packet, timeout=3, verbose=False)[0]
            devices = []
            for sent, received in result:
                devices.append((received.psrc, received.hwsrc))
            if devices:
                result_label.configure(text="Devices on WLAN:\n" + "\n".join([f"IP: {ip}, MAC: {mac}" for ip, mac in devices]), text_color="white")
            else:
                result_label.configure(text="No devices found.", text_color="white")
        except Exception as e:
            result_label.configure(text=f"Error: {str(e)}", text_color="white")
    else:
        result_label.configure(text="Please enter a subnet (e.g., 192.168.1.0/24).", text_color="white")

def perform_action(selected_action):
    result_label.configure(text="")
    
    if selected_action == "IP Lookup":
        entry_input.configure(placeholder_text="Enter IP address")
        entry_input.pack(pady=10)
        ip_lookup()
    elif selected_action == "Search Person":
        entry_input.configure(placeholder_text="Enter person name")
        entry_input.pack(pady=10)
        search_person()
    elif selected_action == "Email Lookup":
        entry_input.configure(placeholder_text="Enter email address")
        entry_input.pack(pady=10)
        email_lookup()
    elif selected_action == "WHOIS Lookup":
        entry_input.configure(placeholder_text="Enter domain name")
        entry_input.pack(pady=10)
        whois_lookup()
    elif selected_action == "DNS Lookup":
        entry_input.configure(placeholder_text="Enter domain name")
        entry_input.pack(pady=10)
        dns_lookup()
    elif selected_action == "Ping to Host":
        entry_input.configure(placeholder_text="Enter host/IP")
        entry_input.pack(pady=10)
        ping_host()
    elif selected_action == "Account Info":
        entry_input.configure(placeholder_text="Enter Roblox username")
        entry_input.pack(pady=10)
        roblox_account_info()
    elif selected_action == "Port Scan":
        entry_input.configure(placeholder_text="Enter host/IP for port scan")
        entry_input.pack(pady=10)
        port_scan()
    elif selected_action == "Traceroute":
        entry_input.configure(placeholder_text="Enter host/IP for traceroute")
        entry_input.pack(pady=10)
        traceroute()
    elif selected_action == "Who is on WLAN":
        entry_input.configure(placeholder_text="Enter subnet (e.g., 192.168.1.0/24)")
        entry_input.pack(pady=10)
        who_is_on_wlan()

app = ctk.CTk()
app.geometry("700x600")
app.title("Rxctix")
ctk.set_appearance_mode("dark")
app.configure(fg_color="black")


action_var = ctk.StringVar(value="Select Action")
action_menu = ctk.CTkOptionMenu(app, variable=action_var, values=["IP Lookup", "Search Person", "Email Lookup", "WHOIS Lookup", "DNS Lookup", "Ping to Host", "Account Info", "Port Scan", "Traceroute", "Who is on WLAN"], command=perform_action, fg_color="black", button_color="black")  
action_menu.pack(pady=10, padx=10, anchor="nw")  
# RXCTIX.00 
ascii_text = """
            ;::::;                           
        ;::::; :;                       
    ;:::::'   :;                  
        ;:::::;     ;.                        
       ,:::::'       ;           OOO\         
       ::::::;       ;          OOOOO\        
       ;:::::;       ;         OOOOOOOO       
      ,;::::::;     ;'         / OOOOOOO      
    ;:::::::::`. ,,,;.        /  / DOOOOOO    
  .';:::::::::::::::::;,     /  /     DOOOO   
 ,::::::;::::::;;;;::::;,   /  /        DOOO  
;`::::::`'::::::;;;::::: ,#/  /          DOOO 
:`:::::::`;::::::;;::: ;::#  /            DOOO
::`:::::::`;:::::::: ;::::# /              DOO
`:`:::::::`;:::::: ;::::::#/               DOO
 :::`:::::::`;; ;:::::::::##                OO
 ::::`:::::::`;::::::::;:::#                OO
 `:::::`::::::::::::;'`:;::#                O 
  
^ Your time has come ^      


 _______                    _    _           
|_   __ \                  / |_ (_)          
  | |__) |   _   __  .---.`| |-'__   _   __  
  |  __ /   [ \ [  ]/ /'`\]| | [  | [ \ [  ] 
 _| |  \ \_  > '  < | \__. | |, | |  > '  <  
|____| |___|[__]`\_]'.___.'\__/[___][__]`\_] 
                                             
"""


ascii_label = ctk.CTkLabel(app, text=ascii_text, font=("Courier", 10), fg_color="transparent")
ascii_label.pack(pady=2)


entry_input = ctk.CTkEntry(app, width=300, font=("Arial", 12), placeholder_text="")

result_label = ctk.CTkLabel(app, text="", font=("Arial", 12), text_color="white") 
result_label.pack(pady=20)

app.resizable(False, False)

app.mainloop()
