
# **Packet Sniffer & ARP Spoof Detector** 🛡️  

A **real-time packet sniffer and ARP spoof detector** built using Python with **a user-friendly GUI, real-time alerts, and live packet statistics**. This tool helps network administrators and cybersecurity enthusiasts analyze network traffic and detect potential **Man-in-the-Middle (MITM) attacks**.  

---

## **🔹 Features**  

✅ **Real-time Packet Sniffing** – Captures network packets (TCP, UDP, ARP, DNS, etc.).  
✅ **ARP Spoofing Detection** – Identifies potential MITM attacks based on MAC-IP inconsistencies.  
✅ **Live Packet Statistics** – Graphically represents different packet types.  
✅ **Real-time Alerts Panel** – Displays warnings for suspicious activities.  
✅ **Protocol Filtering** – Allows filtering specific packet types (TCP, UDP, ARP, DNS, HTTP).  
✅ **Start/Stop Sniffing** – User-friendly buttons to control packet capture.  
✅ **GUI-Based Interaction** – Intuitive interface built with Tkinter for ease of use.  

---

## **📌 Installation**  

### **1️⃣ Clone the Repository**  
```sh
git clone https://github.com/ShubhBansal123/Packet-Sniffer.git
cd Packet-Sniffer
```

### **2️⃣ Install Required Dependencies**  
Ensure you have **Python 3.6+** installed. Then install the required libraries:  
```sh
pip install scapy matplotlib
```

### **3️⃣ Run the Packet Sniffer**  
```sh
python packet_sniffer.py
```

---

## **📊 Live Graph & Alerts Panel**  

- **Live Packet Statistics:** Displays a **bar graph** of captured packet types (TCP, UDP, ARP, DNS, etc.).  
- **Real-time Alerts:** Shows alerts in the GUI for **suspicious activity** detected, such as **MITM attacks**.  

### **🚨 How ARP Spoofing is Detected?**  
🔹 The tool maintains an **ARP cache** to monitor IP-MAC mappings.  
🔹 If an IP address is seen with multiple MAC addresses, it **triggers an alert** for a possible MITM attack.  

---

## **🖥️ GUI Overview**  

| Feature | Description |
|---------|------------|
| **Start Sniffing** | Begins capturing packets in real-time |
| **Stop Sniffing** | Stops packet capture |
| **Filter Packets** | Choose to capture only TCP, UDP, DNS, ARP, or HTTP packets |
| **Live Graph** | Displays a real-time bar chart of packet distribution |
| **Alerts Panel** | Shows notifications for potential attacks |

---

## **📌 Future Enhancements**  

🔹 **Export logs** in CSV or JSON format for deeper analysis.  
🔹 **Advanced protocol analysis** (e.g., detecting malicious DNS queries).  
🔹 **Better UI/UX improvements** for better visualization.  
🔹 **Integration with email alerts** for remote monitoring.  

---

## **📜 License**  

This project is **open-source** under the [MIT License](LICENSE).  

---

## **📩 Contributing**  

If you'd like to contribute:  

1. **Fork** this repository.  
2. Create a new **feature branch**.  
3. **Commit** your changes.  
4. Submit a **Pull Request**.  

---

## **📬 Contact**  

For any issues or suggestions, feel free to **open an issue** in the repository or reach out:  
📧 **Email:** shubhbansal1804@gmail.com 
🔗 **GitHub:** [ShubhBansal123](https://github.com/ShubhBansal123)  

---
