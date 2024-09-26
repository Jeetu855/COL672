import json
import os
import shutil
import subprocess
import time

import matplotlib.pyplot as plt

# Constants
CONFIG_FILE = "config.json"
BACKUP_CONFIG_FILE = "config_backup.json"
SERVER_EXECUTABLE = "./q4_server"  
CLIENT_EXECUTABLE = "./q4_client"  
MAX_CLIENTS = 32
MIN_CLIENTS = 1
TIMEOUT = 30  


def backup_config():
   
    if not os.path.exists(CONFIG_FILE):
        print(f"Error: {CONFIG_FILE} does not exist.")
        exit(1)
    shutil.copy(CONFIG_FILE, BACKUP_CONFIG_FILE)
    print(f"Backup created: {BACKUP_CONFIG_FILE}")


def restore_config():
    
    if os.path.exists(BACKUP_CONFIG_FILE):
        shutil.copy(BACKUP_CONFIG_FILE, CONFIG_FILE)
        print(f"Configuration restored from {BACKUP_CONFIG_FILE}")
    else:
        print(
            f"Error: {BACKUP_CONFIG_FILE} does not exist. Cannot restore configuration."
        )


def update_num_clients(num_clients):
 
    with open(CONFIG_FILE, "r") as file:
        config = json.load(file)

    config["num_clients"] = num_clients

    with open(CONFIG_FILE, "w") as file:
        json.dump(config, file, indent=4)

    print(f"Updated {CONFIG_FILE}: num_clients = {num_clients}")


def run_server():
    
    try:
        server_process = subprocess.Popen(
            [SERVER_EXECUTABLE], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        print("Server started.")
        # Wait a bit to ensure the server is up
        return server_process
    except Exception as e:
        print(f"Failed to start server: {e}")
        return None


def run_clients(num_clients):
   
    try:
        start_time = time.time()
        # Run the client with the specified number of clients
        client_process = subprocess.Popen(
            [CLIENT_EXECUTABLE], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        try:
            stdout, stderr = client_process.communicate(timeout=TIMEOUT)
            end_time = time.time()
            elapsed_time = end_time - start_time
            print(f"Clients completed in {elapsed_time:.2f} seconds.")
            return elapsed_time
        except subprocess.TimeoutExpired:
            client_process.kill()
            stdout, stderr = client_process.communicate()
            print(f"Clients timed out after {TIMEOUT} seconds.")
            return TIMEOUT
    except Exception as e:
        print(f"Failed to run clients: {e}")
        return None


def main():

    backup_config()


    client_counts = []
    time_taken = []

   
    for num_clients in range(MIN_CLIENTS, MAX_CLIENTS + 1):
        print(f"\n=== Running with {num_clients} client(s) ===")

        
        update_num_clients(num_clients)

      
        server = run_server()
        if server is None:
            print("Skipping this iteration due to server start failure.")
            continue

     
        elapsed = run_clients(num_clients)
        if elapsed is not None:
            client_counts.append(num_clients)
            time_taken.append(elapsed)

 
        server.terminate()
        try:
            server.wait(timeout=5)
            print("Server terminated.")
        except subprocess.TimeoutExpired:
            server.kill()
            print("Server killed after timeout.")

        # Optional: Wait before next iteration


    restore_config()

    
    plt.figure(figsize=(10, 6))
    plt.plot(client_counts, time_taken, marker="o", linestyle="-", color="b")
    plt.title("Time Taken vs Number of Clients")
    plt.xlabel("Number of Clients")
    plt.ylabel("Time Taken (seconds)")
    plt.grid(True)
    plt.xticks(range(MIN_CLIENTS, MAX_CLIENTS + 1, 2))
    plt.savefig("client_time_plot.png")
    plt.show()
    print("\nPlot saved as client_time_plot.png")


if __name__ == "__main__":
    main()
