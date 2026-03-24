# ai_service/app.py
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from transformers import pipeline

app        = FastAPI(title="AI Language Detection Service")
classifier = pipeline(
    "text-classification",
    model="papluca/xlm-roberta-base-language-detection"
)

class TextInput(BaseModel):
    text: str

# -------------------- UI --------------------
@app.get("/ui", response_class=HTMLResponse)
def get_ui():
    return """
    <!DOCTYPE html><html><head>
        <title>AI Language Detector</title>
        <style>
            body { font-family: 'Segoe UI', sans-serif; margin: 40px; background: #f0f2f5; }
            .container { max-width: 600px; margin: auto; background: white; padding: 30px;
                         border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); }
            h2 { color: #1a73e8; margin-top: 0; }
            textarea { width: 100%; height: 120px; padding: 12px; border: 1px solid #ddd;
                       border-radius: 8px; resize: none; box-sizing: border-box; font-size: 16px; }
            button { width: 100%; padding: 12px; background: #1a73e8; color: white; border: none;
                     border-radius: 8px; font-size: 16px; cursor: pointer; margin-top: 12px; }
            button:hover { background: #1557b0; }
            #result { margin-top: 25px; padding: 15px; border-radius: 8px; display: none;
                      background: #f8f9fa; border: 1px solid #e9ecef; }
            .lang-tag { font-size: 24px; font-weight: bold; color: #1a73e8; margin: 5px 0; }
            .confidence-bar { height: 8px; background: #e0e0e0; border-radius: 4px;
                               margin-top: 8px; overflow: hidden; }
            .confidence-fill { height: 100%; background: #34a853; width: 0%;
                                transition: width 0.5s; }
        </style>
    </head><body>
        <div class="container">
            <h2>Language Detector</h2>
            <p>Enter text below to identify the language using AI.</p>
            <textarea id="textInput" placeholder="Type something… e.g. 'Hola, ¿cómo estás?'"></textarea>
            <button onclick="detectLanguage()" id="btn">Detect Language</button>
            <div id="result">
                <div class="label">Detected Language:</div>
                <div class="lang-tag" id="langRes">--</div>
                <div class="label">Confidence: <span id="confVal">0</span>%</div>
                <div class="confidence-bar">
                    <div id="confFill" class="confidence-fill"></div>
                </div>
            </div>
        </div>
        <script>
            async function detectLanguage() {
                const text = document.getElementById('textInput').value.trim();
                const btn  = document.getElementById('btn');
                if (!text) return alert("Please enter some text");
                btn.innerText = "Analyzing...";
                btn.disabled  = true;
                try {
                    const res  = await fetch('/api/ai/detect-language', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({text})
                    });
                    const data = await res.json();
                    if (res.ok) {
                        document.getElementById('result').style.display = 'block';
                        document.getElementById('langRes').innerText    = data.language.toUpperCase();
                        const pct = (data.confidence * 100).toFixed(1);
                        document.getElementById('confVal').innerText        = pct;
                        document.getElementById('confFill').style.width     = pct + '%';
                    } else {
                        alert("Error: " + data.detail);
                    }
                } catch (e) {
                    alert("Failed to connect: " + e.message);
                } finally {
                    btn.innerText = "Detect Language";
                    btn.disabled  = false;
                }
            }
        </script>
    </body></html>
    """

# -------------------- ROUTES --------------------
@app.get("/")
def home():
    return {"message": "AI Language Detection Service Running. Go to /ui for the interface."}

@app.post("/api/ai/detect-language")
def detect_language(input: TextInput):
    text = input.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Text cannot be empty")
    result = classifier(text)[0]
    return {
        "input_text": text,
        "language":   result["label"],
        "confidence": float(result["score"])
    }

@app.get("/api/ai/health")
def health():
    return {"status": "AI service running", "model_loaded": True}