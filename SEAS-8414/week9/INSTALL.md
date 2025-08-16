## Installation Instructions

This project uses Python 3.11. Please follow these steps to create a virtual environment and install the required packages. These steps are for OSX/Linux. There may be minor differences for Windows environments.

1. Ensure you are using python3.11
2. Use the command ```python3.11 -m venv .venv``` to create a virtual environment.
3. Activate the virtual environment with the command ```source .venv/bin/activate```
4. Check that your pip alias is pointed to your virtual environemnt with ```which pip```
5. Install the required dependencies with the command ```pip install -r requirements.txt```
6. Create a ```.env``` file in the project root with your Gemini API key in the following format:
```GEMINI_API_KEY=<YOUR_API_KEY_HERE>```

This concludes the installation instructions. You are now ready to run the program using the syntax:

```python3.11 2_analyze_domain.py --domain google.com```