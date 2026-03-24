import requests
import time

GATEWAY_URL = "http://127.0.0.1:8000"

# -------------------- CONFIG --------------------
NUM_REQUESTS = 50


# -------------------- 1. UNAUTHORIZED ACCESS --------------------
def unauthorized_test():
    print("\n[1] Unauthorized Access Test")

    url = f"{GATEWAY_URL}/api/db/users"
    success = 0

    start = time.time()

    for _ in range(NUM_REQUESTS):
        res = requests.get(url)
        if res.status_code == 200:
            success += 1

    end = time.time()

    success_rate = (success / NUM_REQUESTS) * 100
    latency = (end - start) / NUM_REQUESTS

    print(f"Success Rate: {success}/{NUM_REQUESTS} ({success_rate:.2f}%)")
    print(f"Avg Latency: {latency:.4f} sec")

    return success_rate, latency


# -------------------- 2. REPLAY ATTACK --------------------
def replay_test():
    print("\n[2] Replay Attack Test")

    url = f"{GATEWAY_URL}/api/ai/detect-language"
    payload = {"text": "Hello world"}

    success = 0

    start = time.time()

    for _ in range(NUM_REQUESTS):
        res = requests.post(url, json=payload)
        if res.status_code == 200:
            success += 1

    end = time.time()

    success_rate = (success / NUM_REQUESTS) * 100
    latency = (end - start) / NUM_REQUESTS

    print(f"Replay Success: {success}/{NUM_REQUESTS} ({success_rate:.2f}%)")
    print(f"Avg Latency: {latency:.4f} sec")

    return success_rate, latency


# -------------------- 3. FLOOD / DOS TEST --------------------
def flood_test():
    print("\n[3] Flood (DoS) Test")

    url = f"{GATEWAY_URL}/api/db/users"

    success = 0

    start = time.time()

    for _ in range(NUM_REQUESTS):
        try:
            res = requests.get(url)
            if res.status_code == 200:
                success += 1
        except:
            pass

    end = time.time()

    total_time = end - start
    throughput = NUM_REQUESTS / total_time

    print(f"Successful Requests: {success}/{NUM_REQUESTS}")
    print(f"Total Time: {total_time:.2f} sec")
    print(f"Throughput: {throughput:.2f} req/sec")

    return success, throughput


# -------------------- MAIN --------------------
if __name__ == "__main__":
    print("=== ATTACK SIMULATION (SECURED SYSTEM) ===")

    unauth_rate, unauth_latency = unauthorized_test()
    replay_rate, replay_latency = replay_test()
    flood_success, throughput = flood_test()

    print("\n=== SUMMARY ===")
    print(f"Unauthorized Success Rate: {unauth_rate:.2f}%")
    print(f"Replay Success Rate: {replay_rate:.2f}%")
    print(f"Throughput: {throughput:.2f} req/sec")