from flask import Flask, request, jsonify
import ast
import ipaddress
import socket


app = Flask(__name__)

@app.route('/')
def hello():
    name = request.args.get('name', 'World')
    if not name.isalnum():
        return jsonify({"error": "Invalid name"}), 400
    return f"Hello, {name}!"

@app.route('/ping')
def ping_exec():
    # Get IP address from URL
    ip = request.args.get('ip')
    if not ip:
        return jsonify({"error": "IP address parameter is required."}), 400
    
    # Check IP address format
    try:
        ip_address = ipaddress.IPv4Address(ip)
    except ValueError as error:
        return jsonify({"error": "Invalid IP address format."}), 400
    
    # Check connectivity
    try:
        with socket.create_connection((str(ip_address), 443), timeout=2) as s:
            return jsonify({"ip": str(ip_address), "reachable": True})
    except Exception as e:
        return jsonify({"ip": str(ip_address), "reachable": False, "error": str(e)}), 500
    

# Insecure use of eval
@app.route('/calculate')
def calculate():
    # Get expression from URL
    expression = request.args.get('expr')
    if not expression:
        return jsonify({"error": "Missing 'expr' parameter."}), 400
    
    # Evaluate expression
    try:
        result = ast.literal_eval(expression)
        return str(result)
    except (ValueError, SyntaxError):
        return jsonify({"error": "Invalid expression"}), 400

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
