import os
import sys
import asyncio
from strands import Agent
from strands.tools.mcp import MCPClient
from mcp.client.stdio import stdio_client, StdioServerParameters
from memory import get_session_manager
from tools.aws import analyze_aws_infra, check_s3_encryption
from tools.gcp import analyze_gcp_infra, scan_gcp_iam_roles

async def main():
    print("Initializing DevOps Agent...")
    
    session_id = "devops-session-1" # Can be dynamic per user
    
    # 1. Setup Session Manager
    session_manager = get_session_manager(session_id)
    
    # 2. Define tools
    custom_tools = [
        analyze_aws_infra,
        check_s3_encryption,
        analyze_gcp_infra,
        scan_gcp_iam_roles
    ]
    
    # 3. System Prompt setup
    system_prompt = """You are an expert DevOps engineer and cloud security analyst.
You have access to tools to analyze AWS and GCP infrastructure.
Always provide actionable, best-practice recommendations for vulnerabilities found.
Do not invent facts. If a tool fails, explain why and what the user should check (e.g., credentials).
"""
    
    # 4. Initialize MCP and Agent
    print("Connecting to MCP Server (mcp-server-fetch)...")
    mcp_server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_server_fetch"]
    )
    
    mcp_client = MCPClient(transport_callable=lambda: stdio_client(mcp_server_params))
    custom_tools.append(mcp_client)
    
    agent = Agent(
        tools=custom_tools,
        session_manager=session_manager,
        system_prompt=system_prompt
    )
    
    print("\nAgent is ready! (Type 'exit' to quit)")
    
    while True:
        try:
            user_input = input("\nYou: ")
            if user_input.lower() in ['exit', 'quit']:
                break
                
            print("Agent: Thinking...")
            
            # The agent responds by using the memory, system prompt and tools.
            response = await agent(user_input, session_id=session_id)
            print(f"Agent: {response}")
        except EOFError:
            break
        except Exception as e:
            print(f"\nError interacting with agent: {e}")
            
    # Cleanup MCP connection
    if hasattr(mcp_client, 'close'):
        mcp_client.close()

if __name__ == "__main__":
    asyncio.run(main())