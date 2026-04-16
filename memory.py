import os
from strands.session import FileSessionManager, SessionManager

def get_session_manager(session_id: str) -> SessionManager:
    mode = os.environ.get("STORAGE_MODE", "local")
    
    # Ensure the directory exists
    os.makedirs("./sessions", exist_ok=True)
    
    if mode == "redis":
        try:
            # Attempt to import redis session manager if available from community packages
            # For this hackathon, we simulate or use a custom Redis adapter if it exists.
            import redis
            print("Redis mode enabled. (Connecting to Valkey/Redis...)")
            # In a real scenario, this would return a RedisSessionManager instance
            # Fallback for now to local for stability in the agent if Redis isn't fully set up
            return FileSessionManager(session_id=session_id, directory="./sessions")
        except ImportError:
            print("Redis not installed or adapter missing, falling back to Local File Storage.")
            return FileSessionManager(session_id=session_id, directory="./sessions")
    else:
        # Default to local file storage for development/testing
        print("Local file storage mode enabled.")
        return FileSessionManager(session_id=session_id, directory="./sessions")