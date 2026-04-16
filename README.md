# DevOps Agent (Strands Framework)

An AI-powered DevOps agent built with the [Strands](https://strandsagents.com/) framework.
This agent is designed to manage cloud infrastructure, troubleshoot issues, and provide best practices for AWS and GCP environments.

## Setup
1. Create a virtual environment: `python -m venv venv`
2. Activate it: `.\venv\Scripts\activate` (Windows) or `source venv/bin/activate` (Mac/Linux)
3. Install dependencies: `pip install -r requirements.txt`
4. Set up your AI model API keys (e.g., `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` or `GEMINI_API_KEY`) and cloud credentials (`AWS_PROFILE`, `GOOGLE_APPLICATION_CREDENTIALS`).
5. Run the agent: `python main.py`

## Features
- Custom tools using `@tool` for AWS and GCP.
- Local and Redis-backed session memory.
- MCP Server integration for extended functionality.
