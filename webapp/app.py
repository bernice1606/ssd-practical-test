from flask import Flask, request, render_template, redirect, url_for, flash
import re
import html

app = Flask(__name__)
app.secret_key = 'ssd_practical_test_2302032'

def validate_input(user_input):
    """
    Validate input based on OWASP C5: Validate All Inputs
    Returns: (is_valid, error_type)
    """
    if not user_input or not isinstance(user_input, str):
        return False, "empty"
    
    # Check length (minimum 1, maximum 100 characters)
    if len(user_input) < 1 or len(user_input) > 100:
        return False, "length"
    
    # XSS Detection - Check for script tags and common XSS patterns
    xss_patterns = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'<iframe[^>]*>',
        r'<object[^>]*>',
        r'<embed[^>]*>',
        r'<link[^>]*>',
        r'<meta[^>]*>',
        r'<style[^>]*>.*?</style>',
        r'vbscript:',
        r'data:text/html'
    ]
    
    for pattern in xss_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            return False, "xss"
    
    # SQL Injection Detection - Check for common SQL injection patterns
    sql_patterns = [
        r"('|(\\')|(;)|(--)|(\s*(or|and)\s+))",
        r"\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b",
        r"(\*|%|_)",
        r"(1=1|1=0|'=')",
        r"(\\x[0-9a-f]{2})",
        r"(char\(|ascii\(|substring\(|mid\(|length\()"
    ]
    
    for pattern in sql_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            return False, "sql"
    
    # Allow-list validation: only alphanumeric, spaces, and safe punctuation
    allowed_pattern = r'^[a-zA-Z0-9\s\.\,\!\?\-\_]+$'
    if not re.match(allowed_pattern, user_input):
        return False, "invalid_chars"
    
    return True, None

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        search_term = request.form.get('search_term', '').strip()
        
        # Validate input
        is_valid, error_type = validate_input(search_term)
        
        if not is_valid:
            if error_type == "xss":
                flash("XSS attack detected. Input cleared for security.", "error")
            elif error_type == "sql":
                flash("SQL injection attempt detected. Input cleared for security.", "error")
            else:
                flash("Invalid input detected. Please use only alphanumeric characters, spaces, and basic punctuation.", "error")
            
            return render_template('home.html')
        
        # If input is valid, redirect to results page
        return redirect(url_for('results', term=search_term))
    
    return render_template('home.html')

@app.route('/results')
def results():
    search_term = request.args.get('term', '')
    
    # Re-validate the term (defense in depth)
    is_valid, error_type = validate_input(search_term)
    
    if not is_valid:
        flash("Invalid search term detected.", "error")
        return redirect(url_for('home'))
    
    # HTML escape the term for safe display
    safe_term = html.escape(search_term)
    
    return render_template('results.html', search_term=safe_term)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)