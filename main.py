
"""
Main entry point for the port scanner web application

This is a fully web-based multithreaded port scanner application.
It uses Flask for the web interface and provides the ability to scan 
networks for open ports using multiple threads for better performance.
"""

# Step 1: Load environment variables from .env file if available
import os
try:
    from dotenv import load_dotenv
    load_dotenv()  # Load environment variables from .env file if it exists
except ImportError:
    print("python-dotenv not installed, skipping .env loading")

# Step 2: Import the Flask app and setup functions from flask_web_interface module
from scanner_tool.flask_web_interface import app, ensure_directories, create_templates, create_css, create_js

# Step 3: Initialize required directories and files before app startup
# This ensures all necessary file structure is in place
ensure_directories()  # Create directory structure for the application
create_templates()    # Generate HTML templates if they don't exist
create_css()          # Generate CSS stylesheets if they don't exist
create_js()           # Generate JavaScript files if they don't exist

# Step 4: Define the application entry point with Flask app run parameters
if __name__ == "__main__":
    # Step 5: Start the Flask web server
    # - host='0.0.0.0' makes the app accessible from any network interface
    # - port=4000 is the standard port for this application
    # - debug mode is determined by environment variable
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    port = int(os.environ.get('PORT', 4000))
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
