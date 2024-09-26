import json
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

import matplotlib.pyplot as plt


CONFIG_FILE = "config.json"
CONFIG_BACKUP = "config.json.bak"
TIME_LOG = "time.txt"


subprocess.run(["cp", CONFIG_FILE, CONFIG_BACKUP])

with open(CONFIG_BACKUP, "r") as backup_file:
    original_config = json.load(backup_file)

num_clients_list = original_config["num_clients"]
base_server_port = original_config["server_port"]



def log_time(num_clients, start_time, end_time):
    duration = end_time - start_time
    with open(TIME_LOG, "a") as time_log:
        time_log.write(
            f"Number of Clients: {num_clients}, Start: {start_time}, End: {end_time}, Duration: {duration:.4f}\n"
        )



def run_experiment(num_clients, server_port):
    
    modified_config = original_config.copy()
    modified_config["num_clients"] = [num_clients]
    modified_config["server_port"] = server_port

    with open(CONFIG_FILE, "w") as config_file:
        json.dump(modified_config, config_file, indent=4)

    
    server_process = subprocess.Popen(
        ["./q2_server"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    start_time = time.time()  

    def run_client():
        client_process = subprocess.Popen(
            ["./q2_client"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        client_process.wait()

  
    with ThreadPoolExecutor(max_workers=num_clients) as executor:
        executor.map(run_client, range(num_clients))

    end_time = time.time()  

    
    server_process.terminate()
    server_process.wait()


    log_time(num_clients, start_time, end_time)

   
    return end_time - start_time



average_times = []
for idx, num_clients in enumerate(num_clients_list):
    server_port = base_server_port + idx 
    print(f"Running experiment for {num_clients} clients on port {server_port}...")

    
    avg_time = run_experiment(num_clients, server_port)
    average_times.append(avg_time)
    print(f"Average completion time for {num_clients} clients: {avg_time:.4f} seconds")


subprocess.run(["mv", CONFIG_BACKUP, CONFIG_FILE])


plt.figure(figsize=(10, 6))
plt.plot(num_clients_list, average_times, marker="o", linestyle="-", color="b")
plt.title("Average Completion Time vs Number of Clients")
plt.xlabel("Number of Clients")
plt.ylabel("Average Completion Time (seconds)")
plt.grid(True)
plt.savefig("completion_time_plot.png")
plt.show()
