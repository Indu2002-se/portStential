"""
Flask Web Interface - Provides a web interface for the port scanner

This module is responsible for:
1. Creating and configuring the Flask web application
2. Handling HTTP requests for scanning and exporting results
3. Managing the web interface templates and static files
4. Coordinating between user input and the scanner engine
"""

# Step 1: Import standard Python libraries
import os              # For file and directory operations
import json            # For JSON serialization/deserialization
import socket          # For network operations
import ipaddress       # For IP address validation
import threading       # For running scans in background threads
import time            # For timing operations
from datetime import datetime  # For timestamping
from typing import Dict, List, Tuple, Optional  # Type hints

# Step 2: Import Flask framework components
from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for, session, flash
from supabase import create_client, Client

# Step 3: Import local modules
# These are the core components of the scanning system
from scanner_tool.auth import auth, login_required
from scanner_tool.scanner_engine import ScannerEngine         # Handles actual port scanning
from scanner_tool.threading_module import ThreadingModule     # Manages multithreaded execution
from scanner_tool.data_export_layer import DataExportLayer    # Handles exporting results

# Step 4: Create and configure Flask app
# The app serves templates from the templates folder and static files from the static folder
app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = os.environ.get("SESSION_SECRET", "scanner_tool_secret_key")  # For session management

# Register custom Jinja2 filter for datetime formatting
@app.template_filter('datetime')
def format_datetime(value):
    """Format ISO datetime string to a more readable format."""
    if not value:
        return ""
    
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            try:
                dt = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f")
            except ValueError:
                return value
    else:
        dt = value
        
    return dt.strftime("%Y-%m-%d %H:%M:%S")

# Register the auth blueprint
app.register_blueprint(auth)

# Supabase setup with environment variables
url: str = os.environ.get('SUPABASE_URL', "https://rcaleqoorgrhnjknlavj.supabase.co")
key: str = os.environ.get('SUPABASE_KEY', "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJjYWxlcW9vcmdyaG5qa25sYXZqIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTAzNzQ0MDUsImV4cCI6MjA2NTk1MDQwNX0.ZVtoEMGEybG25wFJ0524x8q-Mhfi-aXXVyypQdk58QE")
site_url = os.environ.get('SITE_URL', 'http://localhost:4000')
supabase: Client = create_client(url, key)

# Step 5: Initialize core components
# These instances will be used throughout the application
scanner_engine = ScannerEngine()       # Creates scanner engine instance
threading_module = ThreadingModule()   # Creates threading module instance
data_export = DataExportLayer()        # Creates data export layer instance

# Step 6: Define global variables to track scan state
# These dictionaries store information about active scans and their results
active_scans = {}  # Maps scan_id to scan state information
scan_results = {}  # Maps scan_id to final scan results

# Step 7: Define constants
# DEFAULT_PORTS is a list of commonly open ports to scan by default
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 123, 135, 139, 143, 389, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

# Step 8: Define directory setup function
def ensure_directories():
    """
    Step 8.1: Ensure required directories exist.
    This function creates all necessary directories for the application to function properly.
    These directories store templates, static files, and scan results.
    """
    # Create directories for templates
    os.makedirs('scanner_tool/templates', exist_ok=True)
    # Create directories for static files
    os.makedirs('scanner_tool/static', exist_ok=True)
    os.makedirs('scanner_tool/static/css', exist_ok=True)
    os.makedirs('scanner_tool/static/js', exist_ok=True)
    # Create directory for scan results
    os.makedirs('scan_results', exist_ok=True)

# Generate HTML templates
def create_templates():
    """Create HTML templates if they don't exist."""
    # Index template
    index_html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Port Scanner</title>
        <link rel="stylesheet" href="{{ url_for('static', filename='css/styles.css') }}">
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    </head>
    <body>
        <div class="cyber-lines-top"></div>
        <div class="cyber-lines-bottom"></div>
        
        <div class="container">
            <header>
                <div class="cyber-header">
                    <div class="cyber-glitch" data-text="PORT·SCAN·v1.0">PORT·SCAN·v1.0</div>
                    <h1>Multi-Threaded Port Scanner</h1>
                    <p class="subtitle">Discover network services with precision</p>
                    <div class="cyber-scanner"></div>
                </div>
            </header>
            
            <div class="card scan-config tech-card">
                <div class="card-corner top-left"></div>
                <div class="card-corner top-right"></div>
                <div class="card-corner bottom-left"></div>
                <div class="card-corner bottom-right"></div>
                
                <h2><span class="tech-icon">⚙</span> Scan Configuration</h2>
                <div class="form-group">
                    <label for="target">Target Host:</label>
                    <div class="input-group">
                        <input type="text" id="target" name="target" placeholder="Enter IP address or hostname" class="form-control tech-input">
                        <button onclick="useLocalIP()" class="btn btn-secondary tech-btn">
                            <span class="btn-text">Use Local IP</span>
                            <span class="btn-icon">⟲</span>
                        </button>
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="port-range">Port Range:</label>
                    <div class="input-group">
                        <input type="text" id="port-range" name="port-range" placeholder="e.g., 80,443,8000-8100" class="form-control tech-input" value="21,22,23,25,80,443,3306,8080">
                        <div class="checkbox-wrapper tech-checkbox">
                            <input type="checkbox" id="use-predefined" name="use-predefined" checked>
                            <label for="use-predefined">Use Predefined Ports</label>
                        </div>
                    </div>
                </div>
                
                <div class="form-group advanced tech-panel">
                    <label for="threads">Threads:</label>
                    <input type="number" id="threads" name="threads" value="10" min="1" max="100" class="form-control-sm tech-input">
                    <div id="thread-warning" class="warning-message" style="display: none; color: #ff5722; font-size: 0.8rem; margin-top: 5px;">
                        Warning: High thread count may be limited for optimal performance
                    </div>
                    
                    <label for="timeout">Timeout (s):</label>
                    <input type="number" id="timeout" name="timeout" value="1.0" min="0.1" max="10" step="0.1" class="form-control-sm tech-input">
                </div>
                
                <div class="button-group">
                    <button id="scan-button" onclick="startScan()" class="btn btn-primary tech-btn pulse-btn">
                        <span class="btn-text">Start Scan</span>
                        <span class="btn-icon">⚡</span>
                    </button>
                    <button id="stop-button" onclick="stopScan()" class="btn btn-danger tech-btn" disabled>
                        <span class="btn-text">Stop Scan</span>
                        <span class="btn-icon">✕</span>
                    </button>
                    <button id="export-button" onclick="showExportOptions()" class="btn btn-success tech-btn" disabled>
                        <span class="btn-text">Export Results</span>
                        <span class="btn-icon">↓</span>
                    </button>
                    <button onclick="clearResults()" class="btn btn-secondary tech-btn">
                        <span class="btn-text">Clear</span>
                        <span class="btn-icon">⟲</span>
                    </button>
                </div>
            </div>
            
            <div class="progress-section tech-progress">
                <div class="progress-label">Progress:</div>
                <div class="progress tech-progress-bar">
                    <div id="progress-bar" class="progress-bar"></div>
                </div>
                <div id="status-label" class="status-label tech-status">Ready</div>
            </div>
            
            <div class="card results-section tech-card">
                <div class="card-corner top-left"></div>
                <div class="card-corner top-right"></div>
                <div class="card-corner bottom-left"></div>
                <div class="card-corner bottom-right"></div>
                
                <div class="tab-navigation tech-tabs">
                    <button class="tab-button active" onclick="showTab('table-view')">
                        <span class="tab-icon">◉</span> Table View
                    </button>
                    <button class="tab-button" onclick="showTab('log-view')">
                        <span class="tab-icon">⋮</span> Log View
                    </button>
                </div>
                
                <div id="table-view" class="tab-content active">
                    <div class="table-container tech-table">
                        <table id="results-table">
                            <thead>
                                <tr>
                                    <th>Host</th>
                                    <th>Port</th>
                                    <th>Status</th>
                                    <th>Service</th>
                                </tr>
                            </thead>
                            <tbody id="results-body">
                                <!-- Results will be inserted here -->
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <div id="log-view" class="tab-content">
                    <div class="tech-console-header">
                        <div class="console-controls">
                            <span class="console-btn"></span>
                            <span class="console-btn"></span>
                            <span class="console-btn"></span>
                        </div>
                        <div class="console-title">SYSTEM CONSOLE</div>
                    </div>
                    <div id="log-container" class="log-container tech-console">
                        <!-- Logs will be inserted here -->
                    </div>
                </div>
            </div>
            
            <div id="export-modal" class="modal tech-modal">
                <div class="modal-content tech-modal-content">
                    <div class="modal-header">
                        <h2>Export Options</h2>
                        <span class="close-button" onclick="closeExportModal()">&times;</span>
                    </div>
                    <div class="export-options">
                        <button onclick="exportResults('csv')" class="btn btn-primary tech-btn">
                            <span class="btn-text">CSV File</span>
                            <span class="btn-icon">↓</span>
                        </button>
                        <button onclick="exportResults('excel')" class="btn btn-primary tech-btn">
                            <span class="btn-text">Excel File</span>
                            <span class="btn-icon">↓</span>
                        </button>
                        <button onclick="exportResults('pdf')" class="btn btn-primary tech-btn">
                            <span class="btn-text">PDF File</span>
                            <span class="btn-icon">↓</span>
                        </button>
                        <button onclick="closeExportModal()" class="btn btn-secondary tech-btn">
                            <span class="btn-text">Cancel</span>
                            <span class="btn-icon">✕</span>
                        </button>
                    </div>
                </div>
            </div>
            
            <footer class="tech-footer">
                <div class="footer-line"></div>
                <p>PORT SCANNER v1.0.0 | <span id="current-time"></span></p>
                <div class="tech-badge">MULTITHREADED</div>
            </footer>
        </div>
        
        <script src="{{ url_for('static', filename='js/script.js') }}"></script>
    </body>
    </html>
    """
    
    if not os.path.exists('scanner_tool/templates/index.html'):
        with open('scanner_tool/templates/index.html', 'w') as f:
            f.write(index_html)

# Generate CSS styles
def create_css():
    """Create CSS styles if they don't exist."""
    css = """
    /* Variables */
    :root {
        --primary-color: #0a0a0a;
        --secondary-color: #00FF9C;
        --background-color: #0a0a0a;
        --text-color: #00FF9C;
        --success-color: #00FF9C;
        --warning-color: #FFD700;
        --info-color: #00FFFF;
        --card-bg: #0F1F0F;
        --border-color: #00FF9C;
        --highlight-color: #00FF9C;
        --grid-line-color: rgba(0, 255, 156, 0.1);
        --tech-glow: 0 0 15px rgba(0, 255, 156, 0.7);
        --tech-accent: #00FF9C;
        --terminal-bg: #000800;
        --matrix-color: #00FF9C;
    }
    
    /* Base Styles */
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }
    
    /* Cyber elements */
    .cyber-lines-top,
    .cyber-lines-bottom {
        position: fixed;
        left: 0;
        width: 100%;
        height: 4px;
        background: linear-gradient(90deg, transparent 0%, var(--highlight-color) 50%, transparent 100%);
        z-index: 1000;
    }
    
    .cyber-lines-top {
        top: 0;
    }
    
    .cyber-lines-bottom {
        bottom: 0;
    }
    
    .cyber-header {
        position: relative;
        margin-bottom: 20px;
    }
    
    .cyber-glitch {
        font-size: 1rem;
        letter-spacing: 3px;
        color: var(--tech-accent);
        margin-bottom: 10px;
        position: relative;
        display: inline-block;
        text-shadow: var(--tech-glow);
    }
    
    .cyber-glitch::before,
    .cyber-glitch::after {
        content: attr(data-text);
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
    }
    
    .cyber-glitch::before {
        left: 2px;
        text-shadow: -2px 0 var(--secondary-color);
        animation: glitch-1 2s infinite linear alternate-reverse;
    }
    
    .cyber-glitch::after {
        left: -2px;
        text-shadow: 2px 0 var(--highlight-color);
        animation: glitch-2 3s infinite linear alternate-reverse;
    }
    
    @keyframes glitch-1 {
        0%, 100% { clip-path: inset(50% 0 30% 0); }
        20% { clip-path: inset(33% 0 33% 0); }
        40% { clip-path: inset(10% 0 60% 0); }
        60% { clip-path: inset(70% 0 20% 0); }
        80% { clip-path: inset(40% 0 43% 0); }
    }
    
    @keyframes glitch-2 {
        0%, 100% { clip-path: inset(20% 0 50% 0); }
        20% { clip-path: inset(60% 0 20% 0); }
        40% { clip-path: inset(30% 0 40% 0); }
        60% { clip-path: inset(50% 0 30% 0); }
        80% { clip-path: inset(10% 0 60% 0); }
    }
    
    .cyber-scanner {
        position: absolute;
        bottom: -10px;
        left: 50%;
        transform: translateX(-50%);
        width: 50%;
        height: 2px;
        background: var(--highlight-color);
        box-shadow: 0 0 10px var(--highlight-color);
        animation: scanner-move 2s infinite;
    }
    
    @keyframes scanner-move {
        0%, 100% { transform: translateX(-100%); }
        50% { transform: translateX(100%); }
    }
    
    .tech-card {
        position: relative;
        border: 1px solid var(--border-color);
        background: var(--card-bg);
        box-shadow: 0 0 20px rgba(0, 0, 0, 0.3);
        overflow: visible;
    }
    
    .card-corner {
        position: absolute;
        width: 10px;
        height: 10px;
        border: 1px solid var(--highlight-color);
        z-index: 1;
    }
    
    .top-left {
        top: -2px;
        left: -2px;
        border-right: none;
        border-bottom: none;
    }
    
    .top-right {
        top: -2px;
        right: -2px;
        border-left: none;
        border-bottom: none;
    }
    
    .bottom-left {
        bottom: -2px;
        left: -2px;
        border-right: none;
        border-top: none;
    }
    
    .bottom-right {
        bottom: -2px;
        right: -2px;
        border-left: none;
        border-top: none;
    }
    
    .tech-icon {
        color: var(--highlight-color);
        margin-right: 8px;
        text-shadow: var(--tech-glow);
    }
    
    .tech-input {
        background-color: rgba(10, 15, 20, 0.7);
        border: 1px solid var(--border-color);
        color: var(--text-color);
        font-family: 'JetBrains Mono', monospace;
        transition: all 0.3s;
    }
    
    .tech-input:focus {
        border-color: var(--highlight-color);
        box-shadow: var(--tech-glow);
    }
    
    .tech-checkbox {
        display: flex;
        align-items: center;
    }
    
    .tech-panel {
        background-color: rgba(0, 0, 0, 0.3);
        border: 1px solid var(--border-color);
        position: relative;
    }
    
    .tech-panel::before {
        content: "ADVANCED";
        position: absolute;
        top: -8px;
        left: 10px;
        font-size: 0.6rem;
        background-color: var(--card-bg);
        padding: 0 5px;
        color: var(--highlight-color);
    }
    
    .tech-btn {
        background-color: var(--primary-color);
        border: none;
        color: white;
        border-radius: 4px;
        transition: all 0.3s;
        position: relative;
        overflow: hidden;
    }
    
    .tech-btn:after {
        content: "";
        position: absolute;
        top: -50%;
        left: -60%;
        width: 200%;
        height: 200%;
        background: linear-gradient(60deg, transparent, rgba(255, 255, 255, 0.1), transparent);
        transform: rotate(30deg);
        transition: all 0.6s;
    }
    
    .tech-btn:hover:after {
        left: 100%;
    }
    
    .tech-btn:hover {
        box-shadow: 0 0 10px rgba(2, 179, 228, 0.5);
    }
    
    .btn-text, .btn-icon {
        position: relative;
        z-index: 2;
    }
    
    .pulse-btn {
        animation: pulse 2s infinite;
    }
    
    @keyframes pulse {
        0% {
            box-shadow: 0 0 0 0 rgba(2, 179, 228, 0.4);
        }
        70% {
            box-shadow: 0 0 0 10px rgba(2, 179, 228, 0);
        }
        100% {
            box-shadow: 0 0 0 0 rgba(2, 179, 228, 0);
        }
    }
    
    .tech-progress {
        position: relative;
        border: 1px solid var(--border-color);
    }
    
    .tech-progress::before {
        content: "";
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: linear-gradient(90deg, 
            transparent 0%, 
            rgba(2, 179, 228, 0.05) 50%, 
            transparent 100%);
        animation: progress-bg 2s infinite;
        z-index: 0;
    }
    
    @keyframes progress-bg {
        0% { background-position: -100% 0; }
        100% { background-position: 100% 0; }
    }
    
    .tech-progress-bar {
        height: 12px;
        background-color: rgba(0, 0, 0, 0.3);
        border-radius: 6px;
        overflow: hidden;
        position: relative;
    }
    
    .tech-status {
        font-size: 0.7rem;
        text-transform: uppercase;
        letter-spacing: 1px;
        background-color: rgba(0, 0, 0, 0.3);
        border: 1px solid var(--border-color);
    }
    
    .tech-tabs {
        background-color: rgba(0, 0, 0, 0.2);
        padding: 5px;
        border-radius: 4px;
    }
    
    .tab-icon {
        color: var(--highlight-color);
        margin-right: 5px;
    }
    
    .tech-table {
        border: 1px solid var(--border-color);
    }
    
    .tech-table th {
        background-color: rgba(0, 0, 0, 0.3);
        color: var(--highlight-color);
        text-transform: uppercase;
        font-size: 0.7rem;
        letter-spacing: 1px;
    }
    
    .tech-console-header {
        display: flex;
        align-items: center;
        background-color: rgba(0, 0, 0, 0.3);
        padding: 5px 10px;
        border-top-left-radius: 6px;
        border-top-right-radius: 6px;
    }
    
    .console-controls {
        display: flex;
        gap: 5px;
    }
    
    .console-btn {
        width: 10px;
        height: 10px;
        border-radius: 50%;
        background-color: #555;
    }
    
    .console-btn:nth-child(1) {
        background-color: #FF5F56;
    }
    
    .console-btn:nth-child(2) {
        background-color: #FFBD2E;
    }
    
    .console-btn:nth-child(3) {
        background-color: #27C93F;
    }
    
    .console-title {
        margin-left: auto;
        margin-right: auto;
        font-size: 0.7rem;
        color: #999;
    }
    
    .tech-console {
        background-color: var(--terminal-bg);
        border: 1px solid var(--border-color);
        border-top: none;
        border-bottom-left-radius: 6px;
        border-bottom-right-radius: 6px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
        line-height: 1.4;
        padding: 10px;
        height: 350px;
        box-shadow: inset 0 0 20px rgba(0, 255, 156, 0.1);
        position: relative;
        overflow: auto;
    }
    
    .tech-console::before {
        content: "";
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: repeating-linear-gradient(
            0deg,
            transparent,
            transparent 2px,
            rgba(0, 255, 156, 0.03) 3px,
            rgba(0, 255, 156, 0.03) 3px
        );
        pointer-events: none;
    }
    
    .tech-modal {
        background-color: rgba(0, 0, 0, 0.8);
        backdrop-filter: blur(5px);
    }
    
    .tech-modal-content {
        background-color: var(--card-bg);
        border: 1px solid var(--border-color);
        box-shadow: 0 0 30px rgba(0, 0, 0, 0.5);
        position: relative;
    }
    
    .tech-modal-content::before {
        content: "";
        position: absolute;
        top: -2px;
        left: -2px;
        right: -2px;
        bottom: -2px;
        border: 1px solid var(--highlight-color);
        opacity: 0.3;
        pointer-events: none;
    }
    
    .modal-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        border-bottom: 1px solid var(--border-color);
        padding-bottom: 15px;
        margin-bottom: 20px;
    }
    
    .tech-footer {
        position: relative;
        text-align: center;
        padding: 20px 0;
        color: #718096;
        font-size: 0.8rem;
    }
    
    .footer-line {
        position: absolute;
        top: 0;
        left: 50%;
        transform: translateX(-50%);
        width: 100px;
        height: 1px;
        background: linear-gradient(90deg, transparent, var(--highlight-color), transparent);
    }
    
    .tech-badge {
        display: inline-block;
        margin-top: 10px;
        padding: 3px 10px;
        background-color: rgba(0, 0, 0, 0.3);
        border: 1px solid var(--border-color);
        border-radius: 15px;
        font-size: 0.7rem;
        color: var(--highlight-color);
        letter-spacing: 1px;
    }
    
    body {
        font-family: 'JetBrains Mono', 'Source Code Pro', monospace;
        background-color: var(--background-color);
        color: var(--text-color);
        line-height: 1.6;
        position: relative;
        overflow-x: hidden;
    }
    
    body::before {
        content: "";
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background-image: 
            linear-gradient(var(--grid-line-color) 1px, transparent 1px),
            linear-gradient(90deg, var(--grid-line-color) 1px, transparent 1px);
        background-size: 20px 20px;
        z-index: -1;
    }
    
    /* Matrix rain effect in the background */
    body::after {
        content: "";
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: linear-gradient(0deg, 
            rgba(0, 255, 156, 0.03) 25%, 
            rgba(0, 255, 156, 0.01) 50%, 
            transparent 75%);
        opacity: 0.5;
        z-index: -1;
        animation: matrix-rain 20s linear infinite;
    }
    
    @keyframes matrix-rain {
        0% { background-position: 0% 0%; }
        100% { background-position: 0% 1000%; }
    }
    
    .container {
        max-width: 1000px;
        margin: 0 auto;
        padding: 20px;
    }
    
    /* Header */
    header {
        text-align: center;
        margin-bottom: 30px;
        position: relative;
        padding: 20px 0;
    }
    
    header::before {
        content: "";
        position: absolute;
        top: 0;
        left: 50%;
        transform: translateX(-50%);
        width: 100px;
        height: 3px;
        background: linear-gradient(90deg, var(--highlight-color), var(--secondary-color));
        border-radius: 3px;
    }
    
    h1 {
        color: var(--highlight-color);
        margin-bottom: 10px;
        font-size: 2.2rem;
        letter-spacing: 1px;
        text-shadow: 0 0 10px rgba(2, 179, 228, 0.3);
    }
    
    .subtitle {
        color: var(--secondary-color);
        font-style: italic;
        font-size: 1rem;
        opacity: 0.9;
    }
    
    /* Cards */
    .card {
        background: var(--card-bg);
        border-radius: 8px;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
        padding: 25px;
        margin-bottom: 25px;
        border: 1px solid var(--border-color);
        transition: transform 0.3s ease, box-shadow 0.3s ease;
        position: relative;
        overflow: hidden;
    }
    
    .card::before {
        content: "";
        position: absolute;
        top: 0;
        left: 0;
        width: 3px;
        height: 100%;
        background: linear-gradient(to bottom, var(--highlight-color), var(--secondary-color));
    }
    
    .card:hover {
        transform: translateY(-3px);
        box-shadow: 0 6px 20px rgba(0, 0, 0, 0.3);
    }
    
    h2 {
        color: var(--text-color);
        margin-bottom: 20px;
        border-bottom: 1px solid var(--border-color);
        padding-bottom: 15px;
        position: relative;
        font-size: 1.4rem;
    }
    
    h2::after {
        content: "";
        position: absolute;
        bottom: -1px;
        left: 0;
        width: 80px;
        height: 3px;
        background: linear-gradient(90deg, var(--highlight-color), transparent);
    }
    
    /* Form Elements */
    .form-group {
        margin-bottom: 20px;
    }
    
    label {
        display: block;
        margin-bottom: 8px;
        font-weight: bold;
        color: var(--highlight-color);
        font-size: 0.9rem;
        letter-spacing: 0.5px;
    }
    
    .input-group {
        display: flex;
        gap: 10px;
    }
    
    .form-control {
        width: 100%;
        padding: 10px 15px;
        border: 1px solid var(--border-color);
        border-radius: 6px;
        font-family: inherit;
        background-color: rgba(17, 24, 39, 0.7);
        color: var(--text-color);
        transition: all 0.3s;
    }
    
    .form-control:focus {
        outline: none;
        border-color: var(--highlight-color);
        box-shadow: 0 0 0 2px rgba(2, 179, 228, 0.2);
    }
    
    .form-control-sm {
        width: 80px;
        padding: 8px 10px;
        border: 1px solid var(--border-color);
        border-radius: 6px;
        font-family: inherit;
        background-color: rgba(17, 24, 39, 0.7);
        color: var(--text-color);
    }
    
    .checkbox-wrapper {
        display: flex;
        align-items: center;
        gap: 8px;
    }
    
    .checkbox-wrapper input[type="checkbox"] {
        appearance: none;
        width: 18px;
        height: 18px;
        border: 1px solid var(--border-color);
        border-radius: 4px;
        background-color: rgba(17, 24, 39, 0.7);
        position: relative;
        cursor: pointer;
    }
    
    .checkbox-wrapper input[type="checkbox"]:checked::before {
        content: "✓";
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        font-size: 12px;
        color: var(--highlight-color);
    }
    
    .advanced {
        display: flex;
        gap: 20px;
        align-items: center;
        padding: 15px;
        background-color: rgba(0, 0, 0, 0.2);
        border-radius: 6px;
        margin-top: 15px;
    }
    
    /* Buttons */
    .button-group {
        display: flex;
        gap: 12px;
        margin-top: 25px;
    }
    
    .btn {
        padding: 10px 18px;
        border: none;
        border-radius: 6px;
        cursor: pointer;
        font-family: inherit;
        font-weight: bold;
        letter-spacing: 0.5px;
        text-transform: uppercase;
        font-size: 0.8rem;
        transition: all 0.3s;
        position: relative;
        overflow: hidden;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
    }
    
    .btn::before {
        content: "";
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.1), transparent);
        transition: left 0.7s;
    }
    
    .btn:hover::before {
        left: 100%;
    }
    
    .btn-primary {
        background-color: var(--primary-color);
        color: white;
        box-shadow: 0 4px 6px rgba(44, 62, 80, 0.3);
    }
    
    .btn-danger {
        background-color: var(--secondary-color);
        color: white;
        box-shadow: 0 4px 6px rgba(231, 76, 60, 0.3);
    }
    
    .btn-success {
        background-color: var(--success-color);
        color: white;
        box-shadow: 0 4px 6px rgba(39, 174, 96, 0.3);
    }
    
    .btn-secondary {
        background-color: #34495e;
        color: white;
        box-shadow: 0 4px 6px rgba(52, 73, 94, 0.3);
    }
    
    .btn:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 10px rgba(0, 0, 0, 0.3);
    }
    
    .btn:active {
        transform: translateY(1px);
    }
    
    .btn:disabled {
        background-color: #4a5568;
        color: #a0aec0;
        cursor: not-allowed;
        box-shadow: none;
    }
    
    .btn:disabled:hover {
        transform: none;
    }
    
    /* Icon styles for buttons */
    .btn::after {
        font-family: monospace;
        font-size: 1rem;
    }
    
    .btn-primary::after {
        content: "⚡";
    }
    
    .btn-danger::after {
        content: "✕";
    }
    
    .btn-success::after {
        content: "↓";
    }
    
    /* Progress Bar */
    .progress-section {
        display: flex;
        align-items: center;
        margin-bottom: 25px;
        gap: 15px;
        background-color: var(--card-bg);
        padding: 15px;
        border-radius: 8px;
        border: 1px solid var(--border-color);
    }
    
    .progress-label {
        flex: 0 0 auto;
        font-weight: bold;
        color: var(--highlight-color);
    }
    
    .progress {
        flex: 1;
        height: 10px;
        background-color: rgba(0, 0, 0, 0.3);
        border-radius: 10px;
        overflow: hidden;
        position: relative;
    }
    
    .progress-bar {
        height: 100%;
        background: linear-gradient(90deg, var(--highlight-color), var(--info-color));
        transition: width 0.3s ease;
        border-radius: 10px;
        position: relative;
    }
    
    .progress-bar::after {
        content: "";
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: linear-gradient(
            90deg,
            transparent,
            rgba(255, 255, 255, 0.3),
            transparent
        );
        animation: progress-shine 2s infinite;
    }
    
    @keyframes progress-shine {
        0% {
            transform: translateX(-100%);
        }
        100% {
            transform: translateX(100%);
        }
    }
    
    .status-label {
        flex: 0 0 auto;
        font-weight: bold;
        padding: 5px 10px;
        border-radius: 20px;
        background-color: rgba(0, 0, 0, 0.2);
        font-size: 0.8rem;
        min-width: 100px;
        text-align: center;
    }
    
    /* Tabs */
    .tab-navigation {
        display: flex;
        border-bottom: 1px solid var(--border-color);
        margin-bottom: 20px;
        gap: 5px;
    }
    
    .tab-button {
        padding: 10px 20px;
        background: none;
        border: none;
        cursor: pointer;
        opacity: 0.7;
        border-bottom: 2px solid transparent;
        color: var(--text-color);
        transition: all 0.3s;
        position: relative;
        font-weight: bold;
    }
    
    .tab-button:hover {
        opacity: 0.9;
        background-color: rgba(255, 255, 255, 0.05);
    }
    
    .tab-button.active {
        opacity: 1;
        border-bottom: 2px solid var(--highlight-color);
        color: var(--highlight-color);
    }
    
    .tab-button.active::before {
        content: "";
        position: absolute;
        bottom: -2px;
        left: 0;
        width: 100%;
        height: 2px;
        background: var(--highlight-color);
        box-shadow: 0 0 10px var(--highlight-color);
    }
    
    .tab-content {
        display: none;
        animation: fadeIn 0.5s ease;
    }
    
    @keyframes fadeIn {
        from {
            opacity: 0;
            transform: translateY(10px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    .tab-content.active {
        display: block;
    }
    
    /* Table */
    .table-container {
        overflow-x: auto;
        border-radius: 6px;
        border: 1px solid var(--border-color);
    }
    
    table {
        width: 100%;
        border-collapse: collapse;
    }
    
    th, td {
        padding: 12px 15px;
        text-align: left;
        border-bottom: 1px solid var(--border-color);
    }
    
    th {
        background-color: rgba(0, 0, 0, 0.2);
        font-weight: bold;
        color: var(--highlight-color);
        position: sticky;
        top: 0;
    }
    
    tbody tr {
        transition: background-color 0.2s;
    }
    
    tbody tr:hover {
        background-color: rgba(255, 255, 255, 0.05);
    }
    
    /* Alternating row colors */
    tbody tr:nth-child(even) {
        background-color: rgba(0, 0, 0, 0.1);
    }
    
    /* Log Container */
    .log-container {
        height: 350px;
        overflow-y: auto;
        padding: 15px;
        background-color: rgba(0, 0, 0, 0.3);
        border-radius: 6px;
        font-size: 0.9rem;
        font-family: 'JetBrains Mono', monospace;
        border: 1px solid var(--border-color);
    }
    
    .log-entry {
        margin-bottom: 8px;
        padding: 8px;
        border-radius: 4px;
        position: relative;
        animation: logFadeIn 0.3s ease;
    }
    
    @keyframes logFadeIn {
        from {
            opacity: 0;
            transform: translateX(-10px);
        }
        to {
            opacity: 1;
            transform: translateX(0);
        }
    }
    
    .log-info {
        color: var(--info-color);
        border-left: 2px solid var(--info-color);
        padding-left: 8px;
        background-color: rgba(52, 152, 219, 0.1);
    }
    
    .log-success {
        color: var(--success-color);
        border-left: 2px solid var(--success-color);
        padding-left: 8px;
        background-color: rgba(39, 174, 96, 0.1);
    }
    
    .log-warning {
        color: var(--warning-color);
        border-left: 2px solid var(--warning-color);
        padding-left: 8px;
        background-color: rgba(243, 156, 18, 0.1);
    }
    
    .log-error {
        color: var(--secondary-color);
        border-left: 2px solid var(--secondary-color);
        padding-left: 8px;
        background-color: rgba(231, 76, 60, 0.1);
    }
    
    /* Modal */
    .modal {
        display: none;
        position: fixed;
        z-index: 1000;
        left: 0;
        top: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(0, 0, 0, 0.7);
        backdrop-filter: blur(5px);
        animation: fadeIn 0.3s ease;
    }
    
    .modal-content {
        background-color: var(--card-bg);
        margin: 10% auto;
        padding: 25px;
        border-radius: 8px;
        width: 400px;
        max-width: 90%;
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);
        border: 1px solid var(--border-color);
        position: relative;
        animation: modalSlideIn 0.4s ease;
    }
    
    @keyframes modalSlideIn {
        from {
            opacity: 0;
            transform: translateY(-50px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    .close-button {
        position: absolute;
        top: 15px;
        right: 15px;
        font-size: 24px;
        cursor: pointer;
        width: 30px;
        height: 30px;
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: 50%;
        background-color: rgba(0, 0, 0, 0.2);
        transition: all 0.3s;
    }
    
    .close-button:hover {
        background-color: var(--secondary-color);
        color: white;
        transform: rotate(90deg);
    }
    
    .export-options {
        display: flex;
        flex-direction: column;
        gap: 15px;
        margin-top: 25px;
    }
    
    /* Footer */
    footer {
        text-align: center;
        margin-top: 40px;
        color: #718096;
        font-size: 0.9rem;
        padding: 20px 0;
        position: relative;
    }
    
    footer::before {
        content: "";
        position: absolute;
        top: 0;
        left: 50%;
        transform: translateX(-50%);
        width: 50px;
        height: 2px;
        background: linear-gradient(90deg, transparent, var(--highlight-color), transparent);
    }
    
    /* Matrix-like background animation */
    @keyframes matrix-effect {
        0% {
            background-position: 0% 0%;
        }
        100% {
            background-position: 0% 100%;
        }
    }
    
    /* Typing effect */
    .typing-effect {
        overflow: hidden;
        border-right: 2px solid var(--highlight-color);
        white-space: nowrap;
        margin: 0 auto;
        letter-spacing: 0.1em;
        animation: 
            typing 3.5s steps(30, end),
            blink-caret 0.75s step-end infinite;
    }
    
    @keyframes typing {
        from { width: 0 }
        to { width: 100% }
    }
    
    @keyframes blink-caret {
        from, to { border-color: transparent }
        50% { border-color: var(--highlight-color) }
    }
    
    /* Responsive Design */
    @media (max-width: 768px) {
        .input-group {
            flex-direction: column;
        }
        
        .button-group {
            flex-wrap: wrap;
        }
        
        .advanced {
            flex-direction: column;
            align-items: flex-start;
        }
        
        .progress-section {
            flex-direction: column;
            align-items: stretch;
        }
        
        .status-label {
            align-self: flex-end;
        }
    }
    
    /* Custom Scrollbar */
    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }
    
    ::-webkit-scrollbar-track {
        background: rgba(0, 0, 0, 0.2);
        border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb {
        background: var(--highlight-color);
        border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: var(--secondary-color);
    }
    """  
    
    if not os.path.exists('scanner_tool/static/css/styles.css'):
        with open('scanner_tool/static/css/styles.css', 'w') as f:
            f.write(css)

# Generate JavaScript
def create_js():
    """Create JavaScript code if it doesn't exist."""
    js = """
    // Global variables
    let scanActive = false;
    let scanId = null;
    let updateInterval = null;
    let resultCount = 0;
    let typingEffect = false;
    
    // DOM Elements
    const targetInput = document.getElementById('target');
    const portRangeInput = document.getElementById('port-range');
    const threadsInput = document.getElementById('threads');
    const timeoutInput = document.getElementById('timeout');
    const usePredefinedCheck = document.getElementById('use-predefined');
    const scanButton = document.getElementById('scan-button');
    const stopButton = document.getElementById('stop-button');
    const exportButton = document.getElementById('export-button');
    const progressBar = document.getElementById('progress-bar');
    const statusLabel = document.getElementById('status-label');
    const resultsBody = document.getElementById('results-body');
    const logContainer = document.getElementById('log-container');
    const exportModal = document.getElementById('export-modal');
    const currentTimeElem = document.getElementById('current-time');
    
    // Update current time
    function updateTime() {
        const now = new Date();
        currentTimeElem.textContent = now.toLocaleString();
    }
    
    // Initialize
    document.addEventListener('DOMContentLoaded', function() {
        updateTime();
        setInterval(updateTime, 1000);
        
        // Event listeners
        usePredefinedCheck.addEventListener('change', togglePortInput);
        
        // Add terminal typing effect to the header
        const header = document.querySelector('h1');
        applyTypingEffect(header);
        
        // Add some initial tech logs
        setTimeout(() => {
            addLogEntry('System initialized', 'info');
            addLogEntry('Scanner engine loaded', 'info');
            addLogEntry('Multithreading enabled', 'success');
            addLogEntry('Ready to scan network targets', 'info');
        }, 500);
        
        // Add input event listeners for "tech feeling"
        targetInput.addEventListener('focus', () => {
            addLogEntry(`Target input focused`, 'info');
        });
        
        // Add port range visual feedback
        portRangeInput.addEventListener('input', () => {
            validatePortsVisually();
        });
        
        // Add thread count visual feedback
        threadsInput.addEventListener('input', () => {
            const threads = parseInt(threadsInput.value);
            if (!isNaN(threads)) {
                if (threads > 20) {
                    addLogEntry(`Warning: High thread count may impact system performance`, 'warning');
                }
            }
        });
    });
    
    // Apply typing effect to an element
    function applyTypingEffect(element) {
        if (!element || typingEffect) return;
        
        typingEffect = true;
        const text = element.textContent;
        element.textContent = '';
        element.classList.add('typing-effect');
        
        let i = 0;
        const typeInterval = setInterval(() => {
            if (i < text.length) {
                element.textContent += text.charAt(i);
                i++;
            } else {
                clearInterval(typeInterval);
                setTimeout(() => {
                    element.classList.remove('typing-effect');
                }, 1000);
            }
        }, 80);
    }
    
    // Validate ports visually
    function validatePortsVisually() {
        try {
            const portRangeText = portRangeInput.value.trim();
            if (!portRangeText) return;
            
            // Count total ports
            let portCount = 0;
            const sections = portRangeText.split(',');
            
            for (const section of sections) {
                if (section.includes('-')) {
                    const [start, end] = section.split('-').map(p => parseInt(p.trim()));
                    if (!isNaN(start) && !isNaN(end) && start <= end) {
                        portCount += (end - start + 1);
                    }
                } else {
                    if (!isNaN(parseInt(section.trim()))) {
                        portCount++;
                    }
                }
            }
            
            if (portCount > 100) {
                addLogEntry(`Scan configuration: ${portCount} ports selected`, 'warning');
            } else if (portCount > 0) {
                addLogEntry(`Scan configuration: ${portCount} ports selected`, 'info');
            }
        } catch (e) {
            // Silently fail
        }
    }
    
    // Tab navigation
    function showTab(tabId) {
        // Add tech sound effect
        playTechSound('switch');
        
        // Hide all tab content
        document.querySelectorAll('.tab-content').forEach(tab => {
            tab.classList.remove('active');
        });
        
        // Remove active class from all tab buttons
        document.querySelectorAll('.tab-button').forEach(button => {
            button.classList.remove('active');
        });
        
        // Show selected tab
        document.getElementById(tabId).classList.add('active');
        
        // Set active class on clicked button
        event.currentTarget.classList.add('active');
        
        addLogEntry(`View switched to ${tabId.replace('-', ' ')}`, 'info');
    }
    
    // Toggle port input based on checkbox
    function togglePortInput() {
        if (usePredefinedCheck.checked) {
            portRangeInput.value = '21,22,23,25,80,443,3306,8080';
            addLogEntry('Using predefined ports', 'info');
        } else {
            portRangeInput.value = '';
            addLogEntry('Custom port configuration enabled', 'info');
        }
        
        // Add tech sound effect
        playTechSound('toggle');
    }
    
    // Get local IP address
    function useLocalIP() {
        // Add tech sound effect
        playTechSound('process');
        
        addLogEntry('Detecting local IP address...', 'info');
        
        fetch('/api/local-ip')
            .then(response => response.json())
            .then(data => {
                if (data.ip) {
                    targetInput.value = data.ip;
                    addLogEntry(`Local IP detected: ${data.ip}`, 'success');
                    
                    // Visual feedback
                    targetInput.classList.add('highlight-success');
                    setTimeout(() => {
                        targetInput.classList.remove('highlight-success');
                    }, 1000);
                }
            })
            .catch(error => {
                addLogEntry(`Error detecting local IP: ${error}`, 'error');
            });
    }
    
    // Play tech sound effect
    function playTechSound(type) {
        // This could be implemented with actual sounds if desired
        // For now we'll just add a visual effect
        const body = document.body;
        
        switch(type) {
            case 'process':
                body.classList.add('processing');
                setTimeout(() => body.classList.remove('processing'), 300);
                break;
            case 'success':
                body.classList.add('success-flash');
                setTimeout(() => body.classList.remove('success-flash'), 300);
                break;
            case 'error':
                body.classList.add('error-flash');
                setTimeout(() => body.classList.remove('error-flash'), 300);
                break;
            case 'switch':
            case 'toggle':
                // Just visual feedback in the log
                break;
        }
    }
    
    // Validate input before starting scan
    function validateInput() {
        const target = targetInput.value.trim();
        const portRange = portRangeInput.value.trim();
        const threads = parseInt(threadsInput.value);
        const timeout = parseFloat(timeoutInput.value);
        
        if (!target) {
            addLogEntry('Error: Target host required', 'error');
            playTechSound('error');
            targetInput.classList.add('highlight-error');
            setTimeout(() => targetInput.classList.remove('highlight-error'), 1000);
            return false;
        }
        
        if (!portRange) {
            addLogEntry('Error: Port range required', 'error');
            playTechSound('error');
            portRangeInput.classList.add('highlight-error');
            setTimeout(() => portRangeInput.classList.remove('highlight-error'), 1000);
            return false;
        }
        
        if (isNaN(threads) || threads < 1) {
            addLogEntry('Error: Thread count must be at least 1', 'error');
            playTechSound('error');
            threadsInput.classList.add('highlight-error');
            setTimeout(() => threadsInput.classList.remove('highlight-error'), 1000);
            return false;
        }
        
        if (isNaN(timeout) || timeout <= 0) {
            addLogEntry('Error: Timeout must be greater than 0', 'error');
            playTechSound('error');
            timeoutInput.classList.add('highlight-error');
            setTimeout(() => timeoutInput.classList.remove('highlight-error'), 1000);
            return false;
        }
        
        return true;
    }
    
    // Start scan
    function startScan() {
        if (!validateInput()) return;
        
        // Add tech sound effect
        playTechSound('process');
        
        const scanData = {
            target: targetInput.value.trim(),
            port_range: portRangeInput.value.trim(),
            threads: parseInt(threadsInput.value),
            timeout: parseFloat(timeoutInput.value)
        };
        
        // Update UI
        scanButton.disabled = true;
        stopButton.disabled = false;
        exportButton.disabled = true;
        statusLabel.textContent = 'Scanning...';
        progressBar.style.width = '0%';
        
        // Clear previous results
        clearResults(false);
        
        // Matrix-like visual effect during scan
        document.body.classList.add('scanning-mode');
        
        // Log scan start
        addLogEntry(`Initializing scan engine...`, 'info');
        addLogEntry(`Target: ${scanData.target}`, 'info');
        addLogEntry(`Preparing ${scanData.threads} scanner threads`, 'info');
        addLogEntry(`Timeout set to ${scanData.timeout} seconds`, 'info');
        addLogEntry(`Scan initiated - connecting to target system`, 'success');
        
        // Start scan
        fetch('/api/scan/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(scanData)
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                addLogEntry(`Error: ${data.error}`, 'error');
                playTechSound('error');
                resetScanUI();
                return;
            }
            
            scanId = data.scan_id;
            scanActive = true;
            
            // Add scanning indicator to status
            statusLabel.innerHTML = 'Scanning <span class="scan-pulse">⚡</span>';
            
            // Start polling for updates
            updateInterval = setInterval(updateScanProgress, 500);
        })
        .catch(error => {
            addLogEntry(`Connection error: ${error}`, 'error');
            playTechSound('error');
            resetScanUI();
        });
    }
    
    // Stop scan
    function stopScan() {
        if (!scanActive || !scanId) return;
        
        // Add tech sound effect
        playTechSound('process');
        
        addLogEntry('User interrupt signal received', 'warning');
        addLogEntry('Terminating scanner threads...', 'warning');
        
        fetch(`/api/scan/${scanId}/stop`, {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            addLogEntry('Scan process terminated by user', 'warning');
            document.body.classList.remove('scanning-mode');
            resetScanUI();
        })
        .catch(error => {
            addLogEntry(`Error stopping scan: ${error}`, 'error');
        });
        
        clearInterval(updateInterval);
        scanActive = false;
    }
    
    // Update scan progress
    function updateScanProgress() {
        if (!scanActive || !scanId) return;
        
        fetch(`/api/scan/${scanId}/status`)
            .then(response => response.json())
            .then(data => {
                // Update progress bar
                progressBar.style.width = `${data.progress}%`;
                
                // Add new log entries
                if (data.logs && data.logs.length > 0) {
                    data.logs.forEach(log => {
                        addLogEntry(log.message, log.level);
                    });
                }
                
                // Update results table
                if (data.results) {
                    updateResultsTable(data.results);
                }
                
                // Check if scan is complete
                if (data.status === 'completed' || data.status === 'failed' || data.status === 'stopped') {
                    clearInterval(updateInterval);
                    scanActive = false;
                    document.body.classList.remove('scanning-mode');
                    
                    if (data.status === 'completed') {
                        statusLabel.textContent = `Completed in ${data.duration.toFixed(2)}s`;
                        progressBar.style.width = '100%';
                        
                        // Play success sound
                        playTechSound('success');
                        
                        addLogEntry(`Scan completed in ${data.duration.toFixed(2)} seconds`, 'success');
                        addLogEntry(`Found ${resultCount} open ports`, 'success');
                        
                        // Enable export button if we have results
                        if (data.results && Object.keys(data.results).length > 0) {
                            exportButton.disabled = false;
                            addLogEntry('Export functionality enabled', 'info');
                        }
                    } else if (data.status === 'failed') {
                        statusLabel.textContent = 'Scan Failed';
                        addLogEntry('Scan process failed', 'error');
                        playTechSound('error');
                    } else {
                        statusLabel.textContent = 'Stopped';
                    }
                    
                    scanButton.disabled = false;
                    stopButton.disabled = true;
                }
            })
            .catch(error => {
                addLogEntry(`Connection error: ${error}`, 'error');
                clearInterval(updateInterval);
                document.body.classList.remove('scanning-mode');
                resetScanUI();
            });
    }
    
    // Update results table
    function updateResultsTable(results) {
        const host = targetInput.value.trim();
        const currentPortCount = Object.keys(results).length;
        
        // Only update if we have new results
        if (currentPortCount > resultCount) {
            const newPorts = currentPortCount - resultCount;
            playTechSound('success');
            addLogEntry(`Discovered ${newPorts} new open port${newPorts > 1 ? 's' : ''}`, 'success');
            
            // Clear and rebuild the table for animation effect
            resultsBody.innerHTML = '';
            
            // Update with new result count
            resultCount = currentPortCount;
            
            // Populate table with animation delay
            let delay = 0;
            for (const port in results) {
                const service = results[port];
                
                const row = document.createElement('tr');
                row.style.animation = `fadeIn 0.3s ease ${delay}s both`;
                row.innerHTML = `
                    <td>${host}</td>
                    <td>${port}</td>
                    <td><span class="status-badge">Open</span></td>
                    <td>${service}</td>
                `;
                
                resultsBody.appendChild(row);
                delay += 0.05;
            }
        }
    }
    
    // Add log entry
    function addLogEntry(message, level) {
        const timestamp = new Date().toLocaleTimeString();
        const logEntry = document.createElement('div');
        logEntry.className = `log-entry log-${level}`;
        
        // Add console-like prefix based on log level
        let prefix = '>';
        switch(level) {
            case 'info': prefix = 'ℹ'; break;
            case 'success': prefix = '✓'; break;
            case 'warning': prefix = '⚠'; break;
            case 'error': prefix = '✗'; break;
        }
        
        logEntry.innerHTML = `<span class="log-time">[${timestamp}]</span> <span class="log-prefix">${prefix}</span> ${message}`;
        
        logContainer.appendChild(logEntry);
        logContainer.scrollTop = logContainer.scrollHeight; // Auto-scroll to bottom
    }
    
    // Reset scan UI
    function resetScanUI() {
        scanButton.disabled = false;
        stopButton.disabled = true;
        scanActive = false;
        clearInterval(updateInterval);
        document.body.classList.remove('scanning-mode');
    }
    
    // Clear results
    function clearResults(clearLogs = true) {
        // Add tech sound effect
        playTechSound('process');
        
        // Clear table
        resultsBody.innerHTML = '';
        resultCount = 0;
        
        // Reset progress
        progressBar.style.width = '0%';
        
        // Disable export button
        exportButton.disabled = true;
        
        // Clear logs if requested
        if (clearLogs) {
            logContainer.innerHTML = '';
            addLogEntry('System reset: Results and logs cleared', 'info');
        }
        
        // Update status
        statusLabel.textContent = 'Ready';
    }
    
    // Show export options modal
    function showExportOptions() {
        if (resultsBody.innerHTML === '') {
            addLogEntry('Error: No results to export', 'error');
            playTechSound('error');
            return;
        }
        
        // Add tech sound effect
        playTechSound('process');
        addLogEntry('Preparing export options...', 'info');
        
        exportModal.style.display = 'block';
    }
    
    // Close export modal
    function closeExportModal() {
        // Add tech sound effect
        playTechSound('toggle');
        exportModal.style.display = 'none';
    }
    
    // Export results
    function exportResults(format) {
        // Add tech sound effect
        playTechSound('process');
        
        addLogEntry(`Preparing ${format.toUpperCase()} export...`, 'info');
        
        fetch(`/api/export/${format}?scan_id=${scanId}`)
            .then(response => {
                if (response.ok) {
                    return response.blob();
                }
                throw new Error('Export failed');
            })
            .then(blob => {
                // Create file name
                const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
                const host = targetInput.value.trim();
                const fileName = `${host}_scan_${timestamp}.${format}`;
                
                // Create download link
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = fileName;
                document.body.appendChild(a);
                a.click();
                
                // Clean up
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
                
                playTechSound('success');
                addLogEntry(`Export successful: ${fileName}`, 'success');
                closeExportModal();
            })
            .catch(error => {
                addLogEntry(`Export error: ${error}`, 'error');
                playTechSound('error');
            });
    }
    
    // Add some CSS classes for the tech effects
    document.head.insertAdjacentHTML('beforeend', `
        <style>
            .scanning-mode {
                animation: scanner-pulse 2s infinite;
            }
            
            @keyframes scanner-pulse {
                0% { background-color: var(--background-color); }
                50% { background-color: #111827; }
                100% { background-color: var(--background-color); }
            }
            
            .processing {
                animation: processing-flash 0.3s;
            }
            
            @keyframes processing-flash {
                0% { background-color: var(--background-color); }
                50% { background-color: rgba(2, 179, 228, 0.1); }
                100% { background-color: var(--background-color); }
            }
            
            .success-flash {
                animation: success-flash 0.3s;
            }
            
            @keyframes success-flash {
                0% { background-color: var(--background-color); }
                50% { background-color: rgba(39, 174, 96, 0.1); }
                100% { background-color: var(--background-color); }
            }
            
            .error-flash {
                animation: error-flash 0.3s;
            }
            
            @keyframes error-flash {
                0% { background-color: var(--background-color); }
                50% { background-color: rgba(231, 76, 60, 0.1); }
                100% { background-color: var(--background-color); }
            }
            
            .highlight-error {
                animation: highlight-error 1s;
            }
            
            @keyframes highlight-error {
                0% { border-color: var(--border-color); }
                50% { border-color: var(--secondary-color); box-shadow: 0 0 10px rgba(231, 76, 60, 0.5); }
                100% { border-color: var(--border-color); }
            }
            
            .highlight-success {
                animation: highlight-success 1s;
            }
            
            @keyframes highlight-success {
                0% { border-color: var(--border-color); }
                50% { border-color: var(--success-color); box-shadow: 0 0 10px rgba(39, 174, 96, 0.5); }
                100% { border-color: var(--border-color); }
            }
            
            .scan-pulse {
                display: inline-block;
                animation: scan-pulse 1s infinite;
            }
            
            @keyframes scan-pulse {
                0% { opacity: 0.5; transform: scale(1); }
                50% { opacity: 1; transform: scale(1.2); }
                100% { opacity: 0.5; transform: scale(1); }
            }
            
            .status-badge {
                display: inline-block;
                padding: 2px 8px;
                border-radius: 12px;
                background-color: var(--success-color);
                color: white;
                font-size: 0.8rem;
                font-weight: bold;
            }
            
            .log-time {
                color: #718096;
            }
            
            .log-prefix {
                display: inline-block;
                width: 20px;
                text-align: center;
                margin-right: 5px;
            }
        </style>
    `);
    
    // Close modal when clicking outside of it
    window.onclick = function(event) {
        if (event.target === exportModal) {
            closeExportModal();
        }
    };
    """
    
    if not os.path.exists('scanner_tool/static/js/script.js'):
        with open('scanner_tool/static/js/script.js', 'w') as f:
            f.write(js)

def parse_port_range(port_range: str) -> List[int]:
    """
    Parse port range string into a list of port numbers.
    
    Args:
        port_range: String representing port range (e.g., "80,443,8000-8100")
        
    Returns:
        List[int]: List of port numbers to scan
    """
    ports = []
    if not port_range:
        return DEFAULT_PORTS
        
    sections = port_range.split(',')
    for section in sections:
        if '-' in section:
            start, end = map(int, section.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(section))
    
    return sorted(list(set(ports)))

def scan_worker(scan_id: str, target: str, ports: List[int], thread_count: int, timeout: float):
    """
    Step 11: Worker function to execute a scan in a separate thread.
    This function runs in the background and performs the actual port scanning.
    
    Args:
        scan_id: Unique ID for this scan
        target: Target host to scan
        ports: List of ports to scan
        thread_count: Number of threads to use
        timeout: Socket timeout in seconds
    """
    try:
        # Step 11.1: Initialize scan state
        active_scans[scan_id] = {
            'status': 'running',     # Scan is now running
            'progress': 0,           # 0% progress initially
            'start_time': datetime.now(),  # Record start time
            'logs': [],              # Empty log list
            'results': {}            # Empty results dict
        }
        
        # Step 11.2: Resolve target hostname to IP address
        try:
            ip_address = socket.gethostbyname(target)
            if ip_address != target:
                # Log hostname resolution if successful
                add_log(scan_id, f"Resolved {target} to {ip_address}", "info")
        except Exception as e:
            # Log and exit if hostname resolution fails
            add_log(scan_id, f"Failed to resolve {target}: {e}", "error")
            complete_scan(scan_id, 'failed')
            return
        
        # Step 11.3: Configure scanner timeout
        scanner_engine.timeout = timeout
        
        # Step 11.4: Set up progress tracking
        total_ports = len(ports)
        completed_ports = 0
        
        # Step 11.5: Define progress callback function
        def update_progress(port_number, status):
            nonlocal completed_ports
            completed_ports += 1
            # Calculate percentage progress
            progress = int((completed_ports / total_ports) * 100)
            
            # Update progress in scan state
            active_scans[scan_id]['progress'] = progress
            
            # Log status for open ports
            if status:
                service = scanner_engine.fetch_service_info(port_number)
                add_log(scan_id, f"Port {port_number} is open: {service}", "success")
        
        # Step 11.6: Execute the scan using the scanner engine
        # This is where the ScannerEngine and ThreadingModule work together
        scan_results = scanner_engine.scan_ports(
            target,                     # Target host
            ports,                      # Ports to scan
            threading_module,           # Threading module for parallel scanning
            thread_count,               # Number of threads to use
            progress_callback=update_progress  # Callback for progress updates
        )
        
        # Step 11.7: Store scan results
        active_scans[scan_id]['results'] = scan_results
        
        # Step 11.8: Log completion status
        if scan_results:
            add_log(scan_id, f"Scan completed. Found {len(scan_results)} open ports.", "info")
        else:
            add_log(scan_id, "Scan completed. No open ports found.", "warning")
        
        # Step 11.9: Mark scan as completed
        complete_scan(scan_id, 'completed')
        
    except Exception as e:
        # Step 11.10: Handle any unexpected errors
        add_log(scan_id, f"Error during scan: {e}", "error")
        complete_scan(scan_id, 'failed')

def add_log(scan_id: str, message: str, level: str = "info"):
    """
    Step 12: Add a log message to the scan state.
    This function is used to track progress and provide feedback to the user.
    
    Args:
        scan_id: Unique ID for the scan
        message: Log message
        level: Log level (info, success, warning, error)
    """
    if scan_id in active_scans:
        # Create log entry with timestamp
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'message': message,
            'level': level
        }
        # Add to scan's log list
        active_scans[scan_id]['logs'].append(log_entry)

def complete_scan(scan_id: str, status: str):
    """
    Step 13: Mark a scan as completed.
    This updates the scan status and stores results for later retrieval.
    
    Args:
        scan_id: Unique ID for the scan
        status: Final status (completed, failed, stopped)
    """
    if scan_id in active_scans:
        # Update scan status
        active_scans[scan_id]['status'] = status
        # Record end time
        active_scans[scan_id]['end_time'] = datetime.now()
        
        # Store results in the global results dictionary for later access
        scan_results[scan_id] = active_scans[scan_id]['results']

# Step 14: Define Flask routes
@app.route('/')
def index():
    """Render the landing page."""
    # Get approved feedback to display
    try:
        res = supabase.table('feedback').select('*').eq('is_approved', 1).order('created_at', desc=True).limit(6).execute()
        approved_feedback = res.data
    except Exception as e:
        flash(f'Error fetching feedback: {e}', 'error')
        approved_feedback = []
    
    return render_template('landing.html', approved_feedback=approved_feedback)

@app.route('/api/feedback/submit', methods=['POST'])
def submit_feedback():
    """Submit user feedback."""
    data = request.get_json()
    name = data.get('name')
    message = data.get('message')
    rating = data.get('rating', 5)

    if not name or not message:
        return jsonify({"status": "error", "message": "Name and message are required"}), 400

    try:
        feedback_data = {
            'name': name,
            'message': message,
            'rating': rating,
            'is_approved': 0  # Default to not approved
        }
        res = supabase.table('feedback').insert(feedback_data).execute()
        
        if res.data:
            new_feedback = res.data[0]
            return jsonify({
                "success": True, 
                "message": "Feedback submitted successfully",
                "feedback": new_feedback
            })
        else:
            return jsonify({"success": False, "message": "Failed to submit feedback"}), 500
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/admin/feedback')
@login_required
def admin_feedback():
    """Admin page to manage feedback."""
    try:
        res = supabase.table('feedback').select('*').order('created_at', desc=True).execute()
        feedback_list = res.data
        return render_template('admin/feedback.html', feedback=feedback_list)
    except Exception as e:
        flash(f'Error fetching feedback: {e}', 'error')
        return render_template('admin/feedback.html', feedback=[])

@app.route('/api/feedback/approve/<int:feedback_id>', methods=['POST'])
@login_required
def approve_feedback(feedback_id):
    """Approve a feedback item."""
    try:
        res = supabase.table('feedback').update({'is_approved': 1}).eq('id', feedback_id).execute()
        if res.data:
            return jsonify({"status": "success"})
        return jsonify({"status": "error", "message": "Feedback not found or error updating"}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/feedback/delete/<int:feedback_id>', methods=['POST'])
@login_required
def delete_feedback(feedback_id):
    """Delete a feedback item."""
    try:
        res = supabase.table('feedback').delete().eq('id', feedback_id).execute()
        if res.data:
            return jsonify({"status": "success"})
        return jsonify({"status": "error", "message": "Feedback not found or error deleting"}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/feedback/approved', methods=['GET'])
def get_approved_feedback():
    """Get all approved feedback for real-time updates."""
    try:
        res = supabase.table('feedback').select('*').eq('is_approved', 1).order('created_at', desc=True).limit(6).execute()
        return jsonify(res.data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/export-history', methods=['GET', 'POST'])
@login_required
def export_history():
    """
    Render page with history of exported scan results.
    Can also show results for a specific, recent scan.
    """
    user_id = session.get('user_id')
    scan_results = None
    scan_id = None
    target_host = None
    debug_info = {}  # Debug information to help diagnose issues
    
    # Add debug info
    debug_info['user_id'] = user_id
    
    if request.method == 'POST':
        try:
            scan_results_json = request.form.get('scan_results')
            if scan_results_json:
                scan_results = json.loads(scan_results_json)
            scan_id = request.form.get('scan_id')
            target_host = request.form.get('target_host')
        except (json.JSONDecodeError, TypeError) as e:
            flash(f"Could not display the scan results due to a data error: {str(e)}", "error")
            debug_info['post_error'] = str(e)
            scan_results = None

    try:
        # Get all exports regardless of user ID first to check if any exports exist at all
        check_all_exports = supabase.table('scan_exports').select('count').execute()
        debug_info['total_exports_count'] = check_all_exports.count if hasattr(check_all_exports, 'count') else 0
        
        # Define order condition based on whether created_at column exists
        try:
            # First try using created_at for ordering
            response = supabase.table('scan_exports').select('*').order('created_at', desc=True).execute()
            order_column = 'created_at'
        except Exception:
            # Fall back to export_date if created_at doesn't exist
            try:
                response = supabase.table('scan_exports').select('*').order('export_date', desc=True).execute()
                order_column = 'export_date'
            except Exception as e:
                # If both fail, just get the data without ordering
                response = supabase.table('scan_exports').select('*').execute()
                order_column = None
                debug_info['ordering_error'] = str(e)
        
        debug_info['order_column'] = order_column
        debug_info['response_data'] = bool(response.data)  # True if data exists, False otherwise
        debug_info['response_data_length'] = len(response.data) if response.data else 0
        
        # Process exports to ensure they have consistent date fields
        all_exports = response.data if response.data else []
        for export in all_exports:
            # Ensure created_at exists (use export_date as fallback)
            if not export.get('created_at') and export.get('export_date'):
                export['created_at'] = export['export_date']
            # Ensure export_date exists (use created_at as fallback)
            if not export.get('export_date') and export.get('created_at'):
                export['export_date'] = export['created_at']
        
        # Now filter by user_id if needed
        if user_id and all_exports:
            exports = [export for export in all_exports if export.get('user_id') == user_id]
            debug_info['filtered_exports_count'] = len(exports)
        else:
            # For testing/debugging, use all exports when no user_id filter is applied
            exports = all_exports
            debug_info['using_all_exports'] = True
        
        # Debug: Add details about the first few exports if available
        if exports and len(exports) > 0:
            debug_info['first_export_keys'] = list(exports[0].keys()) if exports else []
            debug_info['export_example'] = {k: str(v)[:100] for k, v in exports[0].items()} if exports else {}
            
    except Exception as e:
        app.logger.error(f"Error fetching export history: {str(e)}")
        flash(f"Error fetching export history: {str(e)}", 'error')
        exports = []
        debug_info['fetch_error'] = str(e)
    
    app.logger.info(f"Export history debug info: {json.dumps(debug_info)}")
    
    return render_template('export_history.html', 
                           exports=exports, 
                           scan_results=scan_results,
                           scan_id=scan_id,
                           target_host=target_host,
                           debug_info=debug_info)

@app.route('/api/exports', methods=['GET'])
@login_required
def api_export_history():
    """API endpoint to get export history data."""
    user_id = session.get('user_id')
    debug_info = {'route': 'api_export_history', 'user_id': user_id}
    
    if not user_id:
        debug_info['error'] = 'User not logged in'
        app.logger.warning("API exports request without valid user_id")
        return jsonify({"error": "User not logged in", "debug": debug_info}), 401

    try:
        # First, try to get all exports to see if there's any data in the table
        all_exports_check = supabase.table('scan_exports').select('count').execute()
        debug_info['total_exports_count'] = all_exports_check.count if hasattr(all_exports_check, 'count') else 0
        
        # Try different ordering columns
        try:
            # First try with created_at
            all_exports = supabase.table('scan_exports').select('*').order('created_at', desc=True).execute()
            order_column = 'created_at'
        except Exception:
            try:
                # Fall back to export_date
                all_exports = supabase.table('scan_exports').select('*').order('export_date', desc=True).execute()
                order_column = 'export_date'
            except Exception as e:
                # If both fail, just get the data without ordering
                all_exports = supabase.table('scan_exports').select('*').execute()
                order_column = None
                debug_info['ordering_error'] = str(e)
        
        debug_info['order_column'] = order_column
        debug_info['all_exports_count'] = len(all_exports.data) if all_exports.data else 0
        
        # Process all exports to ensure date fields are consistent
        all_export_data = all_exports.data if all_exports.data else []
        for export in all_export_data:
            # Ensure created_at exists (use export_date as fallback)
            if not export.get('created_at') and export.get('export_date'):
                export['created_at'] = export['export_date']
            # Ensure export_date exists (use created_at as fallback)
            if not export.get('export_date') and export.get('created_at'):
                export['export_date'] = export['created_at']
        
        # Then filter for the specific user
        if user_id and all_export_data:
            exports = [export for export in all_export_data if export.get('user_id') == user_id]
            debug_info['exports_found'] = len(exports)
            
            # For debugging, add the first export data
            if exports:
                debug_info['first_export'] = {k: str(v)[:50] for k, v in exports[0].items()}
        else:
            # For testing purposes, if no data is found for this user, return all exports
            exports = all_export_data
            debug_info['using_all_exports'] = True
            debug_info['reason'] = 'No exports found for user_id'
        
        app.logger.info(f"API export history: {json.dumps(debug_info)}")
        
        # Return both exports and debug info
        return jsonify({
            "exports": exports,
            "debug_info": debug_info
        })
    except Exception as e:
        error_details = str(e)
        app.logger.error(f"Error fetching export history API: {error_details}")
        debug_info['exception'] = error_details
        debug_info['exception_type'] = type(e).__name__
        
        return jsonify({"error": str(e), "debug": debug_info}), 500

@app.route('/api/export/<int:export_id>/download', methods=['GET'])
@login_required
def download_export(export_id):
    """Download a previously exported file."""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "User not logged in"}), 401

    try:
        res = supabase.table('scan_exports').select('file_path').eq('id', export_id).eq('user_id', user_id).execute()
        if res.data:
            file_path = res.data[0]['file_path']
            directory = os.path.dirname(file_path)
            filename = os.path.basename(file_path)
            return send_from_directory(directory, filename, as_attachment=True)
        return "File not found or access denied", 404
    except Exception as e:
        return str(e), 500

@app.route('/scanner')
@login_required
def scanner_page():
    """Render the main scanner page."""
    return render_template('scanner.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Render the main dashboard page."""
    return render_template('index_dash.html')

@app.route('/api/local-ip', methods=['GET'])
def api_local_ip():
    """
    Get the local IP address of the machine.
    This helps users quickly scan their own machine.
    """
    try:
        # Create a dummy socket to get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Connect to Google's DNS (doesn't actually send data)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return jsonify({'ip': local_ip})
    except Exception:
        # Return localhost if unable to determine IP
        return jsonify({'ip': "127.0.0.1"})

@app.route('/api/scan/start', methods=['POST'])
def api_start_scan():
    """
    Step 14.3: API endpoint to start a scan.
    This is the main entry point for initiating a scan from the web interface.
    """
    # Step 14.3.1: Get JSON data from request
    data = request.json
    import multiprocessing
    
    # Step 14.3.2: Validate input
    if not data or 'target' not in data:
        return jsonify({'error': 'Missing target host'}), 400
    
    # Step 14.3.3: Extract scan parameters
    target = data.get('target', '').strip()
    port_range = data.get('port_range', '').strip()
    thread_count = int(data.get('threads', 10))
    timeout = float(data.get('timeout', 1.0))
    
    # Step 14.3.4: Validate and limit thread count based on CPU resources
    # This prevents excessive resource usage
    cpu_count = multiprocessing.cpu_count()
    max_recommended_threads = cpu_count * 2
    
    # Define the warning function outside the condition to ensure it's always available
    def add_thread_warning(scan_id, original_count, max_count):
        warning_msg = f"Thread count {original_count} exceeds recommended maximum of {max_count}"
        add_log(
            scan_id=scan_id,
            message=f"WARNING: {warning_msg}. Using {max_count} threads for optimal performance.",
            level="warning"
        )
    
    # Store original thread count for warning message
    original_thread_count = thread_count
    should_warn = thread_count > max_recommended_threads
    
    if should_warn:
        # Log warning about thread count being capped
        warning_msg = f"Thread count {thread_count} exceeds recommended maximum of {max_recommended_threads}"
        app.logger.warning(warning_msg)
        
        # Limit thread count to the recommended maximum
        thread_count = max_recommended_threads
    
    # Step 14.3.5: Parse and validate ports
    try:
        ports = parse_port_range(port_range)
        if not ports:
            return jsonify({'error': 'No valid ports specified'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid port range'}), 400
    
    # Step 14.3.6: Generate unique scan ID using timestamp and target
    scan_id = f"{int(time.time())}_{target}"
    
    # Step 14.3.7: Show thread warning if needed
    if should_warn:
        add_thread_warning(scan_id, original_thread_count, max_recommended_threads)
    
    # Step 14.3.8: Start scan in a separate thread
    # This allows the web interface to remain responsive during scanning
    scan_thread = threading.Thread(
        target=scan_worker,
        args=(scan_id, target, ports, thread_count, timeout),
        daemon=True  # Daemon thread will be terminated when main thread exits
    )
    scan_thread.start()
    
    # Step 14.3.9: Return scan ID to client for status tracking
    return jsonify({'scan_id': scan_id})

@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def api_scan_status(scan_id):
    """
    Step 14.4: API endpoint to get scan status.
    This allows the client to poll for updates on an ongoing scan.
    """
    # Step 14.4.1: Check if scan exists
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Step 14.4.2: Get scan data
    scan_data = active_scans[scan_id]
    
    # Step 14.4.3: Add CPU core information if not already present
    if 'cpu_cores' not in scan_data:
        import multiprocessing
        scan_data['cpu_cores'] = multiprocessing.cpu_count()
        scan_data['max_recommended_threads'] = scan_data['cpu_cores'] * 2
    
    # Step 14.4.4: Calculate scan duration if scan is complete
    duration = 0
    if 'end_time' in scan_data and scan_data['start_time']:
        duration = (scan_data['end_time'] - scan_data['start_time']).total_seconds()
    
    # Step 14.4.5: Get new logs since last fetch (for incremental updates)
    logs_index = int(request.args.get('logs_index', 0))
    new_logs = scan_data['logs'][logs_index:] if logs_index < len(scan_data['logs']) else []
    
    # Calculate real-time statistics for open ports and vulnerabilities
    current_results = scan_data.get('results', [])
    open_ports_count = 0
    vulnerabilities_count = 0
    
    # Process current results for statistics
    if isinstance(current_results, list):
        if all(isinstance(r, dict) for r in current_results):
            open_ports_count = len([r for r in current_results if r.get('status') == 'open'])
            # Check for vulnerable services
            vulnerabilities_count = len([r for r in current_results if r.get('service', '').lower() in ['telnet', 'ftp']])
        else:
            open_ports_count = len(current_results)  # If it's a list of port numbers
            # Check for vulnerable ports
            vulnerabilities_count = len([p for p in current_results if p in [21, 23]])  # FTP and Telnet ports
    
    # Step 14.4.6: Prepare response with current status
    response = {
        'status': scan_data['status'],       # running, completed, failed, or stopped
        'progress': scan_data['progress'],   # percentage complete (0-100)
        'logs': new_logs,                    # new log entries since last fetch
        'logs_index': len(scan_data['logs']), # current log index for next update
        'duration': duration,                # scan duration in seconds
        'real_time_stats': {
            'open_ports': open_ports_count,
            'vulnerabilities': vulnerabilities_count
        }
    }
    
    # Step 14.4.7: Include results if scan is complete
    if scan_data['status'] in ['completed', 'failed', 'stopped']:
        response['results'] = scan_data['results']
    
    # Step 14.4.8: Return JSON response to client
    return jsonify(response)

@app.route('/api/scan/<scan_id>/stop', methods=['POST'])
def api_stop_scan(scan_id):
    """
    Step 14.5: API endpoint to stop a scan.
    This allows users to cancel an ongoing scan.
    """
    # Step 14.5.1: Check if scan exists
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Step 14.5.2: Mark the scan as stopped
    complete_scan(scan_id, 'stopped')
    
    # Step 14.5.3: Return stopped status to client
    return jsonify({'status': 'stopped'})

@app.route('/api/export/<format_type>', methods=['GET'])
@login_required
def api_export_results(format_type):
    """
    API endpoint to export scan results.
    This allows users to download scan results in various formats.
    """
    # Get scan ID from request parameters
    scan_id = request.args.get('scan_id')
    debug_info = {'route': 'api_export_results', 'format': format_type, 'scan_id': scan_id}
    
    # Get current user ID if available
    user_id = session.get('user_id')
    # We should use the numeric user_id from session, not the UUID
    debug_info['user_id'] = user_id
    
    # Validate scan ID and check for results
    if not scan_id or scan_id not in scan_results:
        debug_info['error'] = 'Invalid scan ID'
        app.logger.warning(f"Export attempt with invalid scan_id: {scan_id}")
        return jsonify({'error': 'Invalid scan ID', 'debug': debug_info}), 400
    
    results = scan_results[scan_id]
    if not results:
        debug_info['error'] = 'No results to export'
        return jsonify({'error': 'No results to export', 'debug': debug_info}), 400
    
    # Extract host from scan_id
    host = scan_id.split('_', 1)[1] if '_' in scan_id else 'localhost'
    debug_info['host'] = host
    
    try:
        # Handle different export formats
        filepath = None
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format_type == 'csv':
            # Export to CSV with enhanced banner information
            filename = f"{host}_scan_{timestamp}.csv"
            filepath = data_export.export_to_csv(results, host, filename)
            
        elif format_type == 'excel':
            # Export to Excel with enhanced banner information
            filename = f"{host}_scan_{timestamp}.xlsx"
            filepath = data_export.export_to_excel(results, host, filename)
            
        elif format_type == 'pdf':
            # Export to PDF with enhanced banner information
            filename = f"{host}_scan_{timestamp}.pdf"
            filepath = data_export.export_to_pdf(results, host, filename)
            
        else:
            # Handle unsupported format
            debug_info['error'] = f'Unsupported export format: {format_type}'
            return jsonify({'error': 'Unsupported export format', 'debug': debug_info}), 400
        
        debug_info['filepath'] = filepath
        
        # Store export information in database
        if filepath and os.path.exists(filepath):
            # Get file size
            file_size = os.path.getsize(filepath)
            debug_info['file_size'] = file_size
            
            # Calculate open port count
            open_port_count = 0
            port_count = 0
            
            if isinstance(results, dict):
                port_count = len(results)
                open_port_count = sum(1 for port_data in results.values() if port_data.get('status') == 'open')
            elif isinstance(results, list):
                port_count = len(results)
                if all(isinstance(item, dict) for item in results):
                    open_port_count = sum(1 for item in results if item.get('status') == 'open')
                else:
                    open_port_count = port_count  # If the list contains port numbers, all are open
            
            debug_info['port_count'] = port_count
            debug_info['open_port_count'] = open_port_count
            
            # Create summary text
            summary = f"Scan of {host} found {open_port_count} open ports out of {port_count} scanned"
            debug_info['summary'] = summary
            
            # Get scan date from active_scans
            scan_date = None
            if scan_id in active_scans and 'start_time' in active_scans[scan_id]:
                scan_date = active_scans[scan_id]['start_time']
            
            # Prepare export data for database - use export_date instead of created_at
            current_time = datetime.now().isoformat()
            
            # Ensure user_id is a valid bigint or null
            # If the user_id is a UUID (string), we need to get the numeric ID from session
            user_id_for_db = user_id  # This should now be the bigint ID from session
            
            export_data = {
                'scan_id': scan_id,
                'target_host': host,
                'export_format': format_type,
                'file_path': filepath,
                'file_size': file_size,
                'user_id': user_id_for_db,  # This is now the bigint ID
                'scan_date': scan_date.isoformat() if scan_date else current_time,
                'port_count': port_count,
                'open_port_count': open_port_count,
                'summary': summary,
                'export_date': current_time  # Use export_date instead of created_at
            }
            debug_info['export_data'] = {k: str(v)[:50] for k, v in export_data.items()}
            
            # Store in database
            try:
                # Add a more descriptive insert
                insert_result = supabase.table('scan_exports').insert(export_data).execute()
                debug_info['db_insert_success'] = True
                debug_info['db_insert_result'] = str(insert_result.data)[:100] if insert_result.data else None
                
                app.logger.info(f"Successfully stored export in database: {json.dumps(debug_info)}")
            except Exception as db_error:
                # Handle database error but still return the file
                error_msg = f"Database storage error: {str(db_error)}"
                debug_info['db_error'] = error_msg
                app.logger.error(error_msg)
                
                # Try a simplified insert as a fallback, making sure user_id is a bigint
                try:
                    minimal_data = {
                        'target_host': host,
                        'export_format': format_type,
                        'file_path': filepath,
                        'file_size': file_size,
                        'user_id': user_id_for_db,  # Use the bigint ID
                        'summary': summary,
                        'export_date': current_time  # Use export_date instead of created_at
                    }
                    fallback_insert = supabase.table('scan_exports').insert(minimal_data).execute()
                    debug_info['fallback_insert_success'] = True
                except Exception as fallback_error:
                    debug_info['fallback_insert_error'] = str(fallback_error)
            
            # Send file to client as download attachment
            if os.path.exists(filepath):
                # Log success but don't include in response
                app.logger.info(f"Export completed successfully: {json.dumps(debug_info)}")
                return send_from_directory(os.path.dirname(os.path.abspath(filepath)), 
                                          os.path.basename(filepath), 
                                          as_attachment=True)
            else:
                raise FileNotFoundError(f"Export file not found: {filepath}")
            
    except Exception as e:
        # Handle export errors
        import traceback
        error_details = traceback.format_exc()
        app.logger.error(f"Export error: {str(e)}\n{error_details}")
        
        debug_info['exception'] = str(e)
        debug_info['traceback'] = error_details
        
        return jsonify({
            'error': f'Export failed: {str(e)}', 
            'debug': debug_info
        }), 500

@app.route('/api/dashboard/scans')
@login_required
def api_dashboard_data():
    """
    API endpoint to get dashboard data including all scans, statistics, and security issues.
    This provides data for the real-time dashboard.
    """
    # Collect all completed scans (from both active_scans and scan_results)
    all_scans = []
    
    # Add completed scans from scan_results
    for scan_id, results in scan_results.items():
        if scan_id in active_scans:
            scan_data = active_scans[scan_id]
            
            # Extract target from scan_id (format: timestamp_target)
            target = scan_id.split('_', 1)[1] if '_' in scan_id else 'unknown'
            
            # Count open ports - safely handle different result formats
            try:
                # Check if results is a list of dictionaries with 'status' key
                if isinstance(results, list) and all(isinstance(r, dict) for r in results):
                    open_ports_count = len([r for r in results if r.get('status') == 'open'])
                # If results is a simple list of port numbers
                elif isinstance(results, list) and all(isinstance(r, int) for r in results):
                    open_ports_count = len(results)  # All ports in this list are considered open
                else:
                    # For any other format, default to 0
                    app.logger.warning(f"Unexpected scan results format for scan_id {scan_id}: {type(results)}")
                    open_ports_count = 0
            except Exception as e:
                app.logger.error(f"Error processing scan results for {scan_id}: {str(e)}")
                open_ports_count = 0
            
            # Extract services - safely handle different result formats
            services = []
            try:
                if isinstance(results, list) and all(isinstance(r, dict) for r in results):
                    for result in results:
                        if result.get('service') and result.get('service') not in services:
                            services.append(result.get('service'))
                # If we have a custom service mapping based on port numbers
                elif isinstance(results, list) and all(isinstance(r, int) for r in results):
                    # Common port to service mappings
                    port_services = {
                        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 
                        53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL',
                        3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Proxy'
                    }
                    for port in results:
                        if port in port_services and port_services[port] not in services:
                            services.append(port_services[port])
            except Exception as e:
                app.logger.error(f"Error extracting services for {scan_id}: {str(e)}")
            
            # Identify potential vulnerabilities - safely handle different result formats
            vulnerabilities = []
            try:
                common_vulnerable_services = ['telnet', 'ftp']
                common_vulnerable_ports = {23: 'telnet', 21: 'ftp'}
                
                if isinstance(results, list) and all(isinstance(r, dict) for r in results):
                    # Process dictionary-based results
                    for result in results:
                        service = result.get('service', '').lower()
                        if service in common_vulnerable_services:
                            vulnerabilities.append({
                                'port': result.get('port'),
                                'service': service,
                                'severity': 'high'
                            })
                elif isinstance(results, list) and all(isinstance(r, int) for r in results):
                    # Process port number list results
                    for port in results:
                        if port in common_vulnerable_ports:
                            vulnerabilities.append({
                                'port': port,
                                'service': common_vulnerable_ports[port],
                                'severity': 'high'
                            })
            except Exception as e:
                app.logger.error(f"Error identifying vulnerabilities for {scan_id}: {str(e)}")
            
            # Create scan entry
            scan_info = {
                'scan_id': scan_id,
                'target': target,
                'timestamp': scan_data.get('start_time').isoformat() if scan_data.get('start_time') else None,
                'status': scan_data.get('status', 'unknown'),
                'open_ports_count': open_ports_count,
                'services': services[:3],  # Limit to 3 services for display
                'vulnerabilities': vulnerabilities
            }
            
            all_scans.append(scan_info)
    
    # Also include running scans that might not have results yet
    for scan_id, scan_data in active_scans.items():
        if scan_id not in scan_results and scan_data.get('status') == 'running':
            # Extract target from scan_id
            target = scan_id.split('_', 1)[1] if '_' in scan_id else 'unknown'
            
            # Create scan entry for running scan
            scan_info = {
                'scan_id': scan_id,
                'target': target,
                'timestamp': scan_data.get('start_time').isoformat() if scan_data.get('start_time') else None,
                'status': 'running',
                'open_ports_count': 0,
                'services': [],
                'vulnerabilities': []
            }
            
            all_scans.append(scan_info)
    
    # Calculate statistics
    total_scans = len(all_scans)
    active_hosts = len(set([scan['target'] for scan in all_scans]))
    
    # Count total open ports across all scans
    open_ports = sum([scan['open_ports_count'] for scan in all_scans])
    
    # Count total vulnerabilities
    vulnerabilities = sum([len(scan.get('vulnerabilities', [])) for scan in all_scans])
    
    # Generate security recommendations based on scan results
    security_issues = []
    
    # Add default recommendations if there are no scans
    if not all_scans:
        security_issues = [
            {
                'title': 'Welcome to PortSentinel',
                'description': 'Start by running a scan on your local network to identify open ports and potential vulnerabilities.'
            },
            {
                'title': 'Security Best Practice',
                'description': 'Regular scanning helps maintain network security. Use the "New Scan" button to begin.'
            }
        ]
    else:
        # Check for hosts with many open ports
        for scan in all_scans:
            if scan['open_ports_count'] > 10:
                security_issues.append({
                    'title': f'Open Port Alert for {scan["target"]}',
                    'description': f'Host {scan["target"]} has {scan["open_ports_count"]} open ports. Consider closing unnecessary services and implementing firewall rules.'
                })
        
        # Check for common vulnerable services
        vulnerable_services = {}
        for scan in all_scans:
            for vuln in scan.get('vulnerabilities', []):
                service = vuln.get('service')
                if service:
                    if service not in vulnerable_services:
                        vulnerable_services[service] = []
                    vulnerable_services[service].append(scan['target'])
        
        for service, hosts in vulnerable_services.items():
            if service == 'telnet':
                security_issues.append({
                    'title': 'Telnet Security Risk',
                    'description': f'Telnet (unencrypted protocol) found on {len(hosts)} host(s). Consider replacing with SSH for secure remote access.'
                })
            elif service == 'ftp':
                security_issues.append({
                    'title': 'FTP Security Risk',
                    'description': f'FTP (unencrypted protocol) found on {len(hosts)} host(s). Consider using SFTP or FTPS for secure file transfers.'
                })
        
        # Check for hosts with SSH
        ssh_hosts = []
        for scan in all_scans:
            if 'SSH' in scan.get('services', []):
                ssh_hosts.append(scan['target'])
        
        if ssh_hosts:
            security_issues.append({
                'title': 'SSH Security',
                'description': f'{len(ssh_hosts)} host(s) have SSH (port 22) open. Ensure key-based authentication is enabled and password auth is disabled.'
            })
    
    response = {
        'scans': all_scans,
        'statistics': {
            'total_scans': total_scans,
            'active_hosts': active_hosts,
            'open_ports': open_ports,
            'vulnerabilities': vulnerabilities
        },
        'security_issues': security_issues
    }
    
    return jsonify(response)

@app.route('/api/scan/<scan_id>/details')
@login_required
def api_scan_details(scan_id):
    """
    API endpoint to get detailed information about a specific scan.
    This provides data for the scan details modal.
    """
    # Check if scan exists
    if scan_id not in active_scans:
        # Return a helpful error message instead of just "Scan not found"
        return jsonify({
            'error': 'Scan not found. The scan may have been deleted or has not been started.',
            'scan_id': scan_id
        }), 404
    
    scan_data = active_scans[scan_id]
    
    # Calculate scan duration
    duration = 0
    if 'end_time' in scan_data and scan_data['start_time']:
        try:
            duration = (scan_data['end_time'] - scan_data['start_time']).total_seconds()
        except Exception as e:
            app.logger.error(f"Error calculating duration: {str(e)}")
    
    # Extract target from scan_id
    target = scan_id.split('_', 1)[1] if '_' in scan_id else 'unknown'
    
    # Get results, defaulting to empty list if not available
    raw_results = scan_data.get('results', [])
    
    # Process results to ensure they're in a consistent format for the client
    processed_results = []
    try:
        # Common port to service mappings
        port_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 
            53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL',
            3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Proxy'
        }
        
        # Check if results is a list of dictionaries
        if isinstance(raw_results, list) and all(isinstance(r, dict) for r in raw_results):
            processed_results = raw_results
        
        # Check if results is a list of port numbers
        elif isinstance(raw_results, list) and all(isinstance(r, int) for r in raw_results):
            for port in raw_results:
                result = {
                    'port': port,
                    'status': 'open',
                    'service': port_services.get(port, 'Unknown'),
                    'banner': None
                }
                processed_results.append(result)
        
        # Handle any other format
        else:
            app.logger.warning(f"Unexpected results format for scan_id {scan_id}: {type(raw_results)}")
    except Exception as e:
        app.logger.error(f"Error processing scan details for {scan_id}: {str(e)}")
    
    # Create response with detailed scan information
    response = {
        'scan_id': scan_id,
        'target': target,
        'timestamp': scan_data.get('start_time').isoformat() if scan_data.get('start_time') else None,
        'duration': duration,
        'status': scan_data.get('status', 'unknown'),
        'results': processed_results
    }
    
    return jsonify(response)

# Step 15: Run setup on import
# These functions create necessary directories and files when the module is imported
ensure_directories()   # Create required directories
create_templates()     # Generate HTML templates
create_css()           # Generate CSS styles
create_js()            # Generate JavaScript code

def run():
    """
    Run the Flask web application.
    This function is called when the application is started.
    """
    # Step 18.1: Ensure all required directories exist
    ensure_directories()
    
    # Step 18.2: Create template files if they don't exist
    # create_templates()
    # create_css()
    # create_js()
    
    # Step 18.3: Set host to 0.0.0.0 to listen on all interfaces
    # This allows access from other computers on the network
    app.run(host='0.0.0.0', port=5000, debug=True)

if __name__ == "__main__":
    print("Starting PortScanner Web Interface...")
    run()