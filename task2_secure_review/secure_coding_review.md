# Secure Code Review Report: Flask Login Authentication

This code review report evaluates the security posture of the Flask user login feature, identifies a critical SQL Injection (SQLi) vulnerability, and presents remediation strategies following industry-standard secure coding practices.

---

## 1. Vulnerability Analysis: SQL Injection (SQLi)

### Vulnerable Code Snippet (`vulnerable_app.py`)
```python
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    
    # VULNERABLE: Direct string concatenation for SQL query!
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    ...
```

### Vulnerability Mechanism
SQL Injection occurs when user-supplied input is directly concatenated or interpolated into a SQL command string without proper validation or sanitization. This allows an attacker to manipulate the structure of the query and execute arbitrary SQL commands in the database context.

In the snippet above, the parameters `username` and `password` are wrapped inside single quotes (`'{username}'`) and inserted directly into the query string.

### Attack Vector Demonstration
If an attacker inputs the following values in the login form:
- **Username**: `admin' OR '1'='1`
- **Password**: *[Left Blank or Arbitrary]*

The resulting SQL command evaluated by SQLite is:
```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = ''
```
Due to operator precedence:
1. `password = ''` is evaluated (False).
2. `'1'='1'` is evaluated (True).
3. `username = 'admin' OR True` is evaluated as `True` for the table rows.
4. The database engine returns the first row matching the condition, bypassing password verification and authenticating the attacker as the `admin` user.

### Secondary Vulnerability: Error Leakage
```python
except Exception as e:
    message = f"Database Error: {e}"
    return render_template_string(HTML_TEMPLATE, message=message, status="danger", query=query)
```
**Risk**: Printing raw database error messages helps attackers conduct **error-based SQL injection** to discover database schemas, table names, and column types.

---

## 2. Remediation and Secure Coding Solution

### Secure Code Snippet (`secure_app.py`)
```python
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    
    # SECURE: SQL statement with placeholders (parameterization)
    query = "SELECT id, username, password_hash FROM users WHERE username = ?"
    
    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        
        # Execute query passing parameters separately as a tuple
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        conn.close()
        
        # Verify the password hash securely (resilient to timing attacks)
        if user and check_password_hash(user[2], password):
            # ... Login Success ...
```

### Remediation Details
1. **Parameterized Queries (Prepared Statements)**:
   - Instead of inserting variables directly into the query string, we use the `?` placeholder.
   - The database driver treats the parameters passed inside the `execute` tuple purely as **literal values** rather than executable SQL commands.
   - Even if the input is `admin' OR '1'='1`, the database looks for a literal username equal to `admin' OR '1'='1`, rendering the SQL Injection attack completely harmless.

2. **Cryptographic Credential Hashing**:
   - In the vulnerable database, passwords were saved in plaintext. If an attacker dumps the database via SQL Injection, all credentials are stolen.
   - In the secure implementation, passwords are never stored in plaintext. We store the cryptographic hash of the password using `werkzeug.security.generate_password_hash` (which uses secure salts and PBKDF2/bcrypt) and verify matches using `check_password_hash`.

3. **Generic Error Responses & Safe Logging**:
   - Database errors are printed strictly to secure internal logs (`stdout` / files) and never returned to the browser client.
   - Authentication errors return a generic message: `"Invalid username or password"`. This prevents username enumeration attacks (where an attacker can determine valid usernames based on different response messages).

---

## 3. Best Practices Checklist for Secure SQL/Python Development

* **Use ORMs**: Use high-level ORMs like SQLAlchemy or Django ORM, which utilize parameterized queries by default.
* **Never Concatenate SQL**: Avoid using `.format()`, `%`, or f-strings to format queries with external data.
* **Principle of Least Privilege**: Ensure the database connection user has minimal privileges (e.g., read/write permissions only to specific tables, and no administration capabilities).
* **Enable Static Analysis Linting**: Use tools like **Bandit** for Python to scan codebases for SQL Injection and security misconfigurations in CI/CD pipelines. Run it using:
  ```bash
  pip install bandit
  bandit -r path/to/your/code
  ```
