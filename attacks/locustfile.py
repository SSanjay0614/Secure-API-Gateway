from locust import HttpUser, task, between

class APITestUser(HttpUser):
    host = "http://127.0.0.1:8000"  # IMPORTANT

    wait_time = between(1, 2)

    @task
    def get_users(self):
        self.client.get("/api/db/users")

    @task
    def detect_language(self):
        self.client.post("/api/ai/detect-language", json={
            "text": "Hello world"
        })