import json
import os
import shutil
import socket
import subprocess
import time

import matplotlib.pyplot as plt
import numpy as np


CONFIG_FILE = "config.json"
SERVER_EXECUTABLE = "./final_server"  
CLIENT_EXECUTABLE = "./q1_client"  
NUM_ITERATIONS = 10
OUTPUT_PLOT = "completion_time_plot.png"


def read_config():
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)


def write_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)


def backup_config():
    shutil.copy(CONFIG_FILE, CONFIG_FILE + ".bak")


def restore_config():
    if os.path.exists(CONFIG_FILE + ".bak"):
        os.remove(CONFIG_FILE)
        shutil.move(CONFIG_FILE + ".bak", CONFIG_FILE)


def start_server(server_ip):
    """Start the server using the IP from the config file."""
    server_process = subprocess.Popen(
        [SERVER_EXECUTABLE, server_ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return server_process


def stop_server(server_process):
    server_process.terminate()
    try:
        server_process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server_process.kill()
    server_process.wait()  


def is_server_ready(ip, port, timeout=5):
    """Check if the server is ready within a given timeout."""
    start_time = time.time()
    while True:
        if time.time() - start_time > timeout:
            return False
        try:
            with socket.create_connection((ip, port), timeout=0.1):
                return True
        except (ConnectionRefusedError, socket.timeout):
            continue
        except OSError:
            continue


def run_client():
    """Run the client and measure the duration."""
    start_time = time.time()
    try:
        result = subprocess.run(
            [CLIENT_EXECUTABLE],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        print("Client execution failed.")
        print(f"Error: {e.stderr}")
        return None
    end_time = time.time()
    duration = end_time - start_time
    return duration


def main():
    backup_config()
    try:
    
        config = read_config()
        server_ip = config.get("server_ip")
        server_port = config.get("server_port")
        k_value = config.get("k")

      
        if server_ip is None or server_port is None or k_value is None:
            print("Error: Missing server IP, port, or 'k' value in config.json.")
            return

       
        p_values = list(range(1, k_value + 1))
        average_times = []

        for p in p_values:
            print(f"\nRunning experiment for p = {p}")
            config["p"] = p
            write_config(config)
            iteration_times = []

            for i in range(NUM_ITERATIONS):
               
                server_process = start_server(server_ip)

              
                if not is_server_ready(server_ip, server_port):
                    print("Server is not ready. Skipping iteration.")
                    stop_server(server_process)
                    continue

               
                duration = run_client()
                if duration is not None:
                    iteration_times.append(duration)
                else:
                    print("Client run failed.")

            
                stop_server(server_process)

            if iteration_times:
                mean_time = np.mean(iteration_times)
                average_times.append(mean_time)
                print(f"p = {p}, Average Time: {mean_time:.4f} seconds")
            else:
                average_times.append(0)
                print(f"No successful runs for p = {p}")

   
        plt.figure(figsize=(10, 6))
        plt.plot(p_values, average_times, "o-", label="Average Completion Time")
        plt.title("Average Completion Time vs Number of Words per Packet (p)")
        plt.xlabel("Number of Words per Packet (p)")
        plt.ylabel("Average Completion Time (seconds)")
        plt.xticks(p_values)
        plt.grid(True)
        plt.legend()
        plt.savefig(OUTPUT_PLOT)
        plt.show()
        print(f"Plot saved as {OUTPUT_PLOT}")

    finally:
        restore_config()


if __name__ == "__main__":
    main()
