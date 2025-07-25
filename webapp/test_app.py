import pytest
from app import app, validate_input

def test_validate_input_normal():
    """Test normal input validation"""
    is_valid, error = validate_input("hello world")
    assert is_valid == True
    assert error is None

def test_validate_input_xss():
    """Test XSS detection"""
    is_valid, error = validate_input("<script>alert('xss')</script>")
    assert is_valid == False
    assert error == "xss"

def test_validate_input_sql():
    """Test SQL injection detection"""
    is_valid, error = validate_input("'; DROP TABLE users; --")
    assert is_valid == False
    assert error == "sql"

def test_validate_input_empty():
    """Test empty input"""
    is_valid, error = validate_input("")
    assert is_valid == False
    assert error == "empty"

def test_flask_app():
    """Test Flask app creation"""
    assert app is not None
    assert app.config['SECRET_KEY'] is not None