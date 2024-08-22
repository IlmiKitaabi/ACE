import time
import csv
import os
import sys
import socks
import socket
import random
import requests
import subprocess
import json
import urllib.request
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from datetime import datetime

# Get the current time
start_time = datetime.now()

# Print the starting time in hh:mm:ss format
print("Time:", start_time.strftime("%H:%M:%S"))

# Function to remove BOM if it exists
def remove_bom(text):
    return text.replace('\ufeff', '')

# List of user agents
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:78.0) Gecko/20100101 Firefox/78.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:76.0) Gecko/20100101 Firefox/76.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:74.0) Gecko/20100101 Firefox/74.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:71.0) Gecko/20100101 Firefox/71.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:60.0) Gecko/20100101 Firefox/60.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36"
]

# Function to set up Selenium WebDriver
def setup_selenium():
  try:	
    chrome_options = Options()
    # chrome_options.add_argument("--headless")  # Uncomment for headless mode
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument(f"user-agent={random.choice(user_agents)}")
    chrome_options.add_argument("--no-sandbox")
    
    # Initialize WebDriver
    service = Service(executable_path='/var/root/chromedriver/chromedriver')
    driver = webdriver.Chrome(service=service, options=chrome_options)

    return driver
  
  except KeyboardInterrupt:
    print("\nProgram terminated")
    sys.exit(0)

def set_socket():
  try:
    # Set up SOCKS5 proxy with Tor
    socks.setdefaultproxy(proxy_type=socks.PROXY_TYPE_SOCKS5, addr="127.0.0.1", port=9050)
    socket.socket = socks.socksocket
  
  except KeyboardInterrupt:
    print("\nProgram terminated")
    sys.exit(0)

def restore_socket():
  try:
    # Restore the original socket settings
    socket.socket = original_socket
  
  except KeyboardInterrupt:
    print("\nProgram terminated")
    sys.exit(0)

# Save the original socket settings
original_socket = socket.socket

# Initialize WebDriver
driver = setup_selenium()
set_socket()

def restart_tor():
  try:
    subprocess.call(["sudo", "pkill", "tor"])
    time.sleep(5)
    return requests.get("http://icanhazip.com").text.strip()

  except KeyboardInterrupt:
    print("\nProgram terminated")
    sys.exit(0)

# List of blocked IPs
blocked_ips = ["185.220.","45.66.35.35","93.90.74.31","109.70.100.1"]
serial = 1

# Get and check new IP
while True:
   ip = restart_tor()
   print(f"Current IP: {ip}")
   
   try:
     if not any(ip.startswith(prefix) for prefix in blocked_ips):
       break  # Exit the loop if the IP is not blocked

   except KeyboardInterrupt:
     print("\nProgram terminated")
     sys.exit(0)

   print(f"Encountered blocked IP {ip}, waiting 10 seconds before retrying...")
   time.sleep(10)
                
# Read IP addresses from the CSV file
try:
 with open('rule31101IPs.csv', mode='r', encoding='utf-8-sig') as file:
    reader = csv.reader(file)
    ip_addresses = [remove_bom(row[0].strip()) for row in reader]  # Remove BOM and strip whitespace

except KeyboardInterrupt:
   print("\nProgram terminated")
   sys.exit(0)

# Initialize counters
counter = 0
restart_threshold = 15
total_ips = len(ip_addresses)

# Define the path to the outout reciever CSV file
csv_file = 'threat_report.csv'

# Check if the file exists to avoid writing headers multiple times
file_exists = os.path.isfile(csv_file)

# Open the CSV file in append mode
try:
  file = open(csv_file, mode='a', newline='')
  writer = csv.writer(file)

  # Write the header if the file is newly created
  if not file_exists:
     writer.writerow(['IP', 'Score', 'Description'])

except KeyboardInterrupt:
   print("\nProgram terminated")
   sys.exit(0)

try:
 while counter < total_ips:
    try:
        # Process the next 20 IP addresses
        for _ in range(min(restart_threshold, total_ips - counter)):
            ip_addr = ip_addresses[counter]
            if not ip_addr:
                counter += 1
                continue
            
            # Go to the specified URL
            url = f"https://www.virustotal.com/gui/ip-address/{ip_addr}"
            driver.get(url)
            
            # Wait additional 2 seconds for the page to load
            time.sleep(2)
            
            try:
                root1 = driver.execute_script("""
                const container = document.querySelector("#view-container > ip-address-view").shadowRoot;
                const report = container.querySelector("#report").shadowRoot;
                const ipCardRoot = container.querySelector("#report > vt-ui-ip-card").shadowRoot;
    
                const positives = report.querySelector("div > div.row.mb-4.d-none.d-lg-flex > div.col-auto > vt-ui-detections-widget")
                .shadowRoot.querySelector("div > div > div.positives")?.textContent || '';
    
                const descriptionContainer = ipCardRoot.querySelector("div > div.card-body.d-flex > div > div.hstack.gap-4 > div.vstack.gap-2.align-self-center.text-truncate.me-auto > div:nth-child(2)");
    
                const description1 = descriptionContainer.querySelector("span > a")?.textContent || '';
                const description2 = descriptionContainer.querySelector("a")?.textContent || '';

                return {
                  positives,
                  description1,
                  description2
                };
                """)

                positives_value = root1['positives']
                description_value1 = root1['description1']
                description_value2 = root1['description2']

                print(serial, "IP:", ip_addr, "Score:", positives_value, "Description:", description_value2 + "  (" + description_value1 + ")")
                
                # Concatenate the descriptions
                description_combined = description_value2 + "  (" + description_value1 + ")"

                # Write the IP address, score, and combined description to the CSV file
                writer.writerow([ip_addr, positives_value, description_combined])

            except Exception as e:
                print(f"An error occurred while fetching or storing data for IP {ip_addr}: {e}")
            
            except KeyboardInterrupt:
                print("\nProgram terminated")
                sys.exit(0)
           
            counter += 1
            serial += 1
 
        # Get and check new IP                         
        while True:
          ip = restart_tor()
          print(f"Current IP: {ip}")
    
          if not any(ip.startswith(prefix) for prefix in blocked_ips):
            break  # Exit the loop if the IP is not blocked
    
          print(f"Encountered blocked IP {ip}, waiting 10 seconds before retrying...")
          time.sleep(10)
        
        # Print the starting time in hh:mm:ss format
        # Get the current time
        start_time = datetime.now()
        print("Time:", start_time.strftime("%H:%M:%S"))
        restore_socket()
        
        # Create a new WebDriver instance with a new random user agent
        driver.quit()
        driver = setup_selenium()
        set_socket()

    except Exception as e:
        print(f"An error occurred: {e}")
        pass

except KeyboardInterrupt:
   print("\nProgram terminated")
   sys.exit(0)

finally:
   # Ensure the file is closed when the script ends
   file.close()
   # Close the browser
   driver.quit()
