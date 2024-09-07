import os
import sys
import shutil
import time
import logging
import requests
import json
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from gvm.errors import GvmError

# Setting up logging to track scan activities 
logging.basicConfig(filename='vulnerability_scan.log', level=logging.INFO)

class OpenVASVulnerabilityManager:
    def __init__(self, host: str, port: int, username: str, password: str):
        # Initialize with connection details to OpenVAS
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.gmp = self.connect_to_openvas()

    # Function to connect and authenticate with OpenVAS
    def connect_to_openvas(self):
        try:
            # Set up a secure connection using TLS
            connection = TLSConnection(host=self.host, port=self.port)
            # Create Gmp object, which is basically how we talk to OpenVAS
            gmp = Gmp(connection=connection, transform=EtreeTransform())
            # Authenticate to OpenVAS using provided credentials
            gmp.authenticate(username=self.username, password=self.password)
            logging.info("Successfully connected and authenticated with OpenVAS.")
            return gmp
        except GvmError as e:
            logging.error(f"Error connecting to OpenVAS: {e}")
            # If something goes wrong, raise an error
            raise RuntimeError("Failed to connect to OpenVAS") from e

    # Function to create a new scan task and kick it off
    def start_scan(self, target_name: str, target_ip: str, scan_config_id: str):
        try:
            # Create a target with the given IP address
            target_response = self.gmp.create_target(name=target_name, hosts=[target_ip])
            # Get the target ID from the response
            target_id = target_response.find('.//target/@id').text

            # Create a task with the specified scan config and target
            task_response = self.gmp.create_task(name=f'Scan for {target_name}',
                                                 config_id=scan_config_id,
                                                 target_id=target_id)
            task_id = task_response.find('.//task/@id').text
            # Start the scan task
            self.gmp.start_task(task_id)
            logging.info(f"Started scan task {task_id} for target {target_ip}.")
            return task_id
        except GvmError as e:
            logging.error(f"Error starting scan: {e}")
            raise RuntimeError("Failed to start the scan") from e

    # Function to wait for scan to complete and then fetch the report
    def fetch_scan_report(self, task_id: str, polling_interval=30, timeout=3600):
        try:
            elapsed_time = 0
            # Check the status of the task
            task_status = self.gmp.get_task(task_id=task_id).find('.//status').text

            # Keep polling until the task is done or timeout is reached
            while task_status != 'Done' and elapsed_time < timeout:
                time.sleep(polling_interval)  # Wait before polling again
                elapsed_time += polling_interval
                task_status = self.gmp.get_task(task_id=task_id).find('.//status').text
                logging.info(f"Task {task_id} status: {task_status}")

            if elapsed_time >= timeout:
                logging.error(f"Scan task {task_id} timed out.")
                raise TimeoutError("Scan task timed out")

            # Once the scan is done, get the report
            report_id = self.gmp.get_task(task_id=task_id).find('.//report/@id').text
            # Fetch the report in XML format
            report = self.gmp.get_report(report_id=report_id, report_format_id="c402cc3e-b531-11e1-9163-406186ea4fc5")
            logging.info(f"Fetched report for task {task_id}.")

            # Save the report to a file
            with open(f'report_{task_id}.xml', 'w') as report_file:
                report_file.write(report)
            logging.info(f"Report saved as report_{task_id}.xml")
        except GvmError as e:
            logging.error(f"Error fetching scan report: {e}")
            raise RuntimeError("Failed to fetch the scan report") from e

    # Function to add a custom vulnerability signature (NVT)
    def add_custom_nvt(self, nvt_name: str, nvt_script: str, nvt_directory: str):
        try:
            # Make sure the NVT script actually exists before proceeding
            if not os.path.isfile(nvt_script):
                logging.error(f"NVT script {nvt_script} not found.")
                raise FileNotFoundError(f"NVT script {nvt_script} not found.")

            # Copy the custom NVT script to the OpenVAS plugins directory
            destination_path = os.path.join(nvt_directory, os.path.basename(nvt_script))
            shutil.copyfile(nvt_script, destination_path)
            logging.info(f"Custom NVT script {nvt_name} copied to {nvt_directory}.")

            # Reload the NVT cache in OpenVAS to recognize the new script
            response = self.gmp.reload_nvt_cache()
            logging.info(f"NVT cache reloaded: {response}")

            logging.info(f"Custom NVT '{nvt_name}' successfully added and NVT cache reloaded.")
        except OSError as e:
            logging.error(f"Error adding custom NVT: {e}")
            raise RuntimeError("Failed to add custom NVT") from e

    # Function to log messages to Splunk through its HTTP Event Collector (HEC)
    def log_to_siem(self, message: str, splunk_hec_url: str, splunk_token: str):
        try:
            # Set headers required for the Splunk HEC API
            headers = {
                'Authorization': f'Splunk {splunk_token}',
                'Content-Type': 'application/json'
            }

            # Format the message as a JSON payload for Splunk
            data = {
                "event": message,
                "sourcetype": "manual",  # You can tweak this based on your Splunk setup
                "index": "main"  # Default index, change if needed
            }

            # Send the event to Splunk
            response = requests.post(splunk_hec_url, headers=headers, data=json.dumps(data))

            # Check if the event was successfully logged
            if 200 <= response.status_code < 300:
                logging.info(f"Successfully logged to Splunk: {message}")
            else:
                logging.error(f"Failed to log to Splunk. Status Code: {response.status_code}, Response: {response.text}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error logging to Splunk: {e}")
            raise RuntimeError("Failed to log to Splunk") from e

# Main function to execute the whole vulnerability management process
def main():
    # Fetch OpenVAS connection details from environment variables
    openvas_host = os.getenv('OPENVAS_HOST', '127.0.0.1')
    openvas_port = int(os.getenv('OPENVAS_PORT', 9390))
    openvas_username = os.getenv('OPENVAS_USERNAME', 'admin')
    openvas_password = os.getenv('OPENVAS_PASSWORD', 'password')

    try:
        # Initialize the OpenVAS manager
        openvas_manager = OpenVASVulnerabilityManager(openvas_host, openvas_port, openvas_username, openvas_password)

        # Define target details
        target_name = 'Test Server'
        target_ip = '192.168.1.100'
        scan_config_id = 'daba56c8-73ec-11df-a475-002264764cea'  # Full and fast scan

        # Start the scan
        task_id = openvas_manager.start_scan(target_name, target_ip, scan_config_id)

        # Fetch the scan report
        openvas_manager.fetch_scan_report(task_id)

        # Add a custom NVT (vulnerability test script)
        nvt_script_path = '/path/to/custom_script.nasl'
        nvt_directory = '/var/lib/openvas/plugins/'
        openvas_manager.add_custom_nvt(nvt_name="Custom Vulnerability", nvt_script=nvt_script_path, nvt_directory=nvt_directory)

        # Send log data to Splunk
        splunk_hec_url = 'https://splunk-server:8088/services/collector'
        splunk_token = os.getenv('SPLUNK_HEC_TOKEN', 'your-splunk-hec-token')
        openvas_manager.log_to_siem("Vulnerability scan completed and report generated.", splunk_hec_url, splunk_token)

    except RuntimeError as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)

# Entry point of the script
if __name__ == "__main__":
    main()
