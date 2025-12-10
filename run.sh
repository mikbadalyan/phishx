#!/bin/bash

# Run script for Phishing Detection Platform

echo "Starting Phishing Detection Platform..."

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Set environment variables
echo "Setting environment variables..."
export FLASK_APP=app.py
export FLASK_ENV=development

# Run the application
echo "Starting Flask application..."
flask run