#!/bin/bash

# Setup script for Phishing Detection Platform

echo "Setting up Phishing Detection Platform..."

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install required packages
echo "Installing required packages..."
pip install -r requirements.txt

# Create uploads directory if it doesn't exist
echo "Creating uploads directory..."
mkdir -p uploads

echo "Setup complete!"
echo ""
echo "To run the application:"
echo "1. Activate the virtual environment: source venv/bin/activate"
echo "2. Set environment variables:"
echo "   export FLASK_APP=app.py"
echo "   export FLASK_ENV=development"
echo "3. Run the application: flask run"
echo ""
echo "Then open http://127.0.0.1:5000/ in your browser."