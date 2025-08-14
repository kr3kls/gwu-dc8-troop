## Setup & Installation

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/kr3kls/gwu-dc8-troop.git
    cd SEAS-8414/week8
    ```

2.  **Configure API Keys**
    This is the most important step. The application reads API keys from a `secrets.toml` file.

    -   Create the directory and file:
        ```bash
        mkdir -p .streamlit
        touch .streamlit/secrets.toml
        ```
    -   Open `.streamlit/secrets.toml` and add your API keys. Use the following template:
        ```toml
        # .streamlit/secrets.toml
        OPENAI_API_KEY = "sk-..."
        GEMINI_API_KEY = "AIza..."
        GROK_API_KEY = "gsk_..."
        ```
        *You only need to provide a key for the service(s) you intend to use.*