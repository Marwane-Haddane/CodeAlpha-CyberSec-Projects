import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Basic CSS styles inline for premium modern glassmorphic look
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Vulnerable Login Page (SQL Injection Lab)</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f0c20 0%, #15102a 50%, #201335 100%);
            color: #e0e0e0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 16px;
            padding: 40px;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
            backdrop-filter: blur(8px);
            width: 380px;
            text-align: center;
        }
        h2 {
            margin-bottom: 24px;
            color: #ff3e3e;
            font-size: 24px;
            text-shadow: 0 0 10px rgba(255, 62, 62, 0.3);
        }
        .badge {
            background: rgba(255, 62, 62, 0.2);
            color: #ff3e3e;
            border: 1px solid rgba(255, 62, 62, 0.4);
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            display: inline-block;
            margin-bottom: 20px;
        }
        .form-group {
            margin-bottom: 20px;
            text-align: left;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-size: 14px;
            color: #b0b0c0;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            background: rgba(0, 0, 0, 0.2);
            border-radius: 8px;
            color: #fff;
            box-sizing: border-box;
            outline: none;
            transition: border-color 0.3s;
        }
        input[type="text"]:focus, input[type="password"]:focus {
            border-color: #ff3e3e;
        }
        button {
            width: 100%;
            padding: 12px;
            border: none;
            background: linear-gradient(135deg, #ff3e3e 0%, #d32f2f 100%);
            color: white;
            font-weight: bold;
            border-radius: 8px;
            cursor: pointer;
            transition: box-shadow 0.3s;
            margin-top: 10px;
        }
        button:hover {
            box-shadow: 0 0 15px rgba(255, 62, 62, 0.6);
        }
        .message {
            margin-top: 20px;
            padding: 12px;
            border-radius: 8px;
            font-size: 14px;
        }
        .success {
            background: rgba(76, 175, 80, 0.15);
            color: #4caf50;
            border: 1px solid rgba(76, 175, 80, 0.3);
        }
        .danger {
            background: rgba(244, 67, 54, 0.15);
            color: #f44336;
            border: 1px solid rgba(244, 67, 54, 0.3);
        }
        .query-box {
            background: #000;
            border-radius: 6px;
            padding: 10px;
            font-family: monospace;
            font-size: 11px;
            color: #5cf5ff;
            text-align: left;
            overflow-x: auto;
            margin-top: 15px;
            border: 1px solid rgba(92, 245, 255, 0.2);
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>SQL Injection Lab</h2>
        <span class="badge">SECURITY STATUS: VULNERABLE</span>
        
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" placeholder="e.g. admin or ' OR '1'='1" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" placeholder="Enter password">
            </div>
            <button type="submit">Log In</button>
        </form>

        {% if message %}
            <div class="message {{ 'success' if status == 'success' else 'danger' }}">
                {{ message }}
            </div>
        {% endif %}

        {% if query %}
            <div style="margin-top: 20px; text-align: left;">
                <label style="font-size: 12px; color: #888;">Executed SQL Query:</label>
                <div class="query-box">{{ query }}</div>
            </div>
        {% endif %}
    </div>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    
    # VULNERABLE: Direct string concatenation for SQL query!
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            # Login successful
            message = f"Welcome back, {user[1]}! (User Row: ID={user[0]}, Pass={user[2]})"
            return render_template_string(HTML_TEMPLATE, message=message, status="success", query=query)
        else:
            message = "Invalid credentials."
            return render_template_string(HTML_TEMPLATE, message=message, status="danger", query=query)
            
    except Exception as e:
        # Returning database errors to the client aids SQL Injection exploitation (error-based SQLi)
        message = f"Database Error: {e}"
        return render_template_string(HTML_TEMPLATE, message=message, status="danger", query=query)

if __name__ == "__main__":
    app.run(port=5001, debug=True)
