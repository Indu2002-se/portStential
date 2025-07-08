# Railway Deployment Guide for Portsentinal

This guide will help you properly deploy the Portsentinal application on Railway with working email confirmation.

## Email Confirmation Issue Fix

If you're experiencing issues with email confirmation not working after deployment, follow these steps:

### 1. Configure Supabase Site URL

1. Log into your [Supabase Dashboard](https://supabase.com/dashboard)
2. Select your project
3. Go to Authentication → URL Configuration
4. Add your Railway domain (e.g., `https://portstential-production.up.railway.app`) to:
   - Site URL list
   - Redirect URLs list (add both `/login` and `/auth/confirm` paths)
5. Save changes

### 2. Set Environment Variables in Railway

In your Railway project dashboard, add the following environment variables:

```
SITE_URL=https://portstential-production.up.railway.app
SUPABASE_URL=https://rcaleqoorgrhnjknlavj.supabase.co
SUPABASE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJjYWxlcW9vcmdyaG5qa25sYXZqIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTAzNzQ0MDUsImV4cCI6MjA2NTk1MDQwNX0.ZVtoEMGEybG25wFJ0524x8q-Mhfi-aXXVyypQdk58QE
SESSION_SECRET=your_secure_random_string
FLASK_ENV=production
```

Replace:
- `https://portstential-production.up.railway.app` with your actual Railway app URL
- `your_secure_random_string` with a secure random string for session encryption

### 3. Deploy the Updated Code

The code has been updated to:
- Use environment variables for configuration
- Properly handle email confirmation redirects with a dedicated `/auth/confirm` route
- Provide better error messages for unconfirmed emails
- Handle invalid paths gracefully

After pushing these changes and setting the environment variables, redeploy your application on Railway.

### 4. Testing Email Confirmation

1. Register a new user
2. Check your email for the confirmation link
3. Click the confirmation link - it should now redirect to the login page with a success message
4. Log in with your confirmed credentials

## Troubleshooting

If you're still experiencing issues:

1. **Check Logs**: Review Railway logs for any errors
2. **Email Delivery**: Ensure emails are being delivered (check spam folder)
3. **URL Configuration**: Double-check that your Railway URL matches exactly what's in Supabase settings
4. **Environment Variables**: Verify all environment variables are set correctly
5. **Clear Browser Cache**: Sometimes old redirects or cookies can cause issues

### Common Issues and Solutions:

#### "Requested path is invalid" Error
This usually happens when the confirmation link is trying to redirect to a path that doesn't exist. Make sure:
- You've added the `/auth/confirm` route to your application
- Your SITE_URL environment variable is correctly set
- The redirect URL in Supabase settings matches your application URL

#### Email Still Shows as Unconfirmed
If Supabase shows the email as confirmed but your app still says it's unconfirmed:
- Try clearing your browser cookies and cache
- Try logging in with incognito/private browsing
- Check if there are multiple user records with the same email

## Local Development

For local development:
1. Copy `env.example` to `.env`
2. Adjust values as needed
3. Run `pip install -r requirements.txt`
4. Run `python main.py` 