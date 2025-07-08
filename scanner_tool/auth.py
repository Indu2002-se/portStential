from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from supabase import create_client, Client
import os
from functools import wraps

auth = Blueprint('auth', __name__)

# Supabase setup with environment variables
url: str = os.environ.get('SUPABASE_URL', "https://rcaleqoorgrhnjknlavj.supabase.co")
key: str = os.environ.get('SUPABASE_KEY', "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJjYWxlcW9vcmdyaG5qa25sYXZqIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTAzNzQ0MDUsImV4cCI6MjA2NTk1MDQwNX0.ZVtoEMGEybG25wFJ0524x8q-Mhfi-aXXVyypQdk58QE")
site_url = os.environ.get('SITE_URL', 'http://localhost:4000')
supabase: Client = create_client(url, key)

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        privacy_agree = request.form.get('privacy_agree')

        if not all([username, email, password]):
            flash('All fields are required', 'error')
            return redirect(url_for('auth.signup'))
        
        if not privacy_agree:
            flash('You must agree to the Privacy Policy', 'error')
            return redirect(url_for('auth.signup'))

        try:
            # Check if username already exists in the old system for backward compatibility
            res = supabase.table('users').select("id").eq('username', username).execute()
            if res.data:
                flash('Username already exists', 'error')
                return redirect(url_for('auth.signup'))

            # Use site_url for email redirect instead of url_for
            # Use the root URL as the redirect target - we'll handle all paths in our 404 handler
            redirect_url = site_url
            
            # Sign up the user with Supabase Auth
            auth_response = supabase.auth.sign_up({
                "email": email,
                "password": password,
                "options": {
                    "data": {
                        "username": username
                    },
                    "email_redirect_to": https://portstential-production.up.railway.app/login
                }
            })

            # After successful Supabase Auth sign-up, create a record in the public 'users' table
            if auth_response.user:
                try:
                    # Note: We are inserting a placeholder for the password as it's managed by Supabase Auth
                    # The 'password' column in the 'users' table has a NOT NULL constraint.
                    supabase.table('users').insert({
                        "username": username,
                        "email": email,
                        "password": "managed-by-supabase-auth"
                    }).execute()
                except Exception as db_error:
                    # This is a critical error. The user exists in Supabase Auth but not in our public users table.
                    # This can lead to login issues. For now, we flash an error.
                    # A more robust solution would be to either delete the Supabase Auth user or retry the insert.
                    flash(f"An error occurred while creating your user profile: {db_error}. Please contact support.", 'error')
                    return redirect(url_for('auth.signup'))

            # The user is signed up but needs to confirm their email
            # Supabase sends the confirmation email automatically
            flash('Registration successful! Please check your email to confirm your account.', 'success')
            return redirect(url_for('auth.login'))

        except Exception as e:
            # Supabase client raises an error for existing email, so we can catch it
            flash(f'An error occurred: {e}', 'error')
            return redirect(url_for('auth.signup'))
            
    return render_template('auth/signup.html')

@auth.route('/confirm')
def confirm_email():
    """Handle email confirmation redirects from Supabase"""
    # Get token parameters from query string
    token_hash = request.args.get('token_hash')
    type_param = request.args.get('type')
    
    # Log all received parameters for debugging
    print(f"Email confirmation received with params: {request.args}")
    
    # Show success message regardless of parameters
    # The actual verification is handled by Supabase before redirecting here
    flash('Email confirmed successfully! You can now log in.', 'success')
    return redirect(url_for('auth.login'))

# Add a catch-all route for other confirmation formats
@auth.route('/auth/v1/verify', methods=['GET'])
def verify_redirect():
    """Handle alternative verification URL format"""
    flash('Email confirmed successfully! You can now log in.', 'success')
    return redirect(url_for('auth.login'))

# Add a catch-all route for the callback format
@auth.route('/callback')
def callback_redirect():
    """Handle callback format for verification"""
    flash('Email confirmed successfully! You can now log in.', 'success')
    return redirect(url_for('auth.login'))

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Please fill in all fields', 'error')
            return redirect(url_for('auth.login'))
            
        try:
            auth_data = supabase.auth.sign_in_with_password({"email": email, "password": password})
            
            # Fetch the user profile from the public 'users' table to get the bigint ID
            profile_res = supabase.table('users').select("id").eq('email', email).single().execute()
            
            if not profile_res.data:
                # This case can happen if the user was created in Supabase Auth but not in the public.users table
                flash('User profile not found. Please contact support.', 'error')
                return redirect(url_for('auth.login'))

            session['user_id'] = profile_res.data['id'] # This is the bigint ID
            session['auth_user_id'] = auth_data.user.id # This is the UUID
            session['username'] = auth_data.user.user_metadata.get('username', 'N/A')
            flash('Welcome back!', 'success')
            return redirect(url_for('dashboard'))
        
        except Exception as e:
            error_message = str(e).lower()
            if "email not confirmed" in error_message:
                flash('Please confirm your email address before logging in. Check your inbox for the confirmation link.', 'error')
            else:
                flash(f'Invalid email or password: {e}', 'error')
            return redirect(url_for('auth.login'))
            
    return render_template('auth/login.html')

@auth.route('/privacy-policy')
def privacy_policy():
    return render_template('auth/privacy_policy.html')
    
@auth.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index')) 