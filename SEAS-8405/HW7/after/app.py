from flask import Flask, request, jsonify
import os
import ipaddress
from ping3 import ping
from simpleeval import simple_eval, SimpleEval, FunctionNotDefined


app = Flask(__name__)

@app.route('/')
def hello():
    name = request.args.get('name', 'World')
    if not name.isalnum():
        return jsonify({"error": "Invalid name"}), 400
    return f"Hello, {name}!"

@app.route('/ping')
def ping():
    # Get IP address from URL
    ip = request.args.get('ip')
    if not ip:
        return jsonify({"error": "IP address parameter is required."}), 400
    
    # Check IP address format
    try:
        ip_address = ipaddress.IPv4Address(ip)
    except ValueError as error:
        return jsonify({"error": "Invalid IP address format."}), 400
    
    # Execute ping command
    delay = ping(str(ip_address), timeout=2)
    if delay is None:
        return jsonify({"error": f"Ping failed: {str(e)}"}), 500
    return jsonify({"ip": str(ip_address), "delay_ms": round(delay * 1000, 2)})
    

# Insecure use of eval
@app.route('/calculate')
def calculate():
    # Get expression from URL
    expression = request.args.get('expr')
    if not expression:
        return jsonify({"error": "Missing 'expr' parameter."}), 400
    
    # Evaluate expression
    evaluator = SimpleEval()
    try:
        result = evaluator.eval(expression)
        return jsonify({"result": result})
    except FunctionNotDefined as e:
        return jsonify({"error": "Function not allowed", "details": str(e)}), 400
    except Exception as e:
        return jsonify({"error": "Invalid expression", "details": str(e)}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
