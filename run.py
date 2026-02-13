import sys
import traceback
import os

try:
    import uvicorn
    # Try importing the app to catch import errors early
    from app.main import app
    
    if __name__ == "__main__":
        port = int(os.environ.get("PORT", 8000))
        uvicorn.run(app, host="0.0.0.0", port=port)

except ImportError as e:
    error_msg = f"MISSING DEPENDENCY: {str(e)}\n\nPlease run: pip install -r requirements.txt"
    print(error_msg)
    with open("startup_error.txt", "w") as f:
        f.write(error_msg)
        
except Exception as e:
    error_msg = f"STARTUP ERROR: {str(e)}\n"
    print(error_msg)
    with open("startup_error.txt", "w") as f:
        f.write(error_msg)
        traceback.print_exc(file=f)
