Cyber Shield URL Checker - README
Overview
Cyber Shield is a Python application that checks URLs against VirusTotal's database to determine if they are safe or potentially harmful. The application features a login system and a user-friendly interface built with Tkinter.

Features
Secure login system

URL safety checking using VirusTotal API

Detailed analysis report display

Visual indication of URL safety status

Attractive graphical interface

Prerequisites
Before running this application, ensure you have the following installed:

Python 3.6 or higher

Required Python packages:

tkinter (usually comes with Python)

Pillow (PIL)

requests

Installation
Step 1: Install Python
Download Python from python.org

Run the installer

Check "Add Python to PATH" during installation

Complete the installation

Step 2: Install Required Packages
Open a command prompt or terminal and run:
pip install pillow requests

Step 3: Get a VirusTotal API Key
Go to VirusTotal

Create an account if you don't have one

Get your API key from your account settings

Replace the placeholder API key in the code with your actual key:
api_key = 'your-actual-api-key-here'

Step 4: Prepare the Background Image
Create an image named "CyberShield.png"

Place it in a known directory

Update the image path in the code:
background_image = Image.open("/path/to/your/CyberShield.png")

How to Run the Application
Step 1: Save the Code
Copy the provided Python code

Save it as cyber_shield.py

Step 2: Run the Application
Open a command prompt or terminal, navigate to the directory containing the file, and run:
python cyber_shield.py

Usage Instructions
Step 1: Login
When the application starts, you'll see a login screen

Use the following credentials (you can change these in the code):

Username: admin

Password: pass

Click the "Login" button

Step 2: Check a URL
After successful login, you'll see the main interface

Enter the URL you want to check in the input field

Click the "Check URL" button

Step 3: View Results
The application will display:

Number of security vendors that flagged the URL as:

Malicious

Suspicious

Harmless

Undetected

A safety message indicating whether the URL is safe or potentially harmful

Customization Options
Changing Login Credentials
To change the login credentials, modify this section in the code:
if username == "admin" and password == "pass":

Replace "admin" and "pass" with your desired username and password.

Changing the Appearance
To change colors, modify the bg (background) and fg (foreground) parameters

To change fonts, modify the font parameters

To change the window size, modify the geometry parameter:
root.geometry("800x600")

Using a Different Background Image
Prepare your image (PNG format recommended)

Update the image path in the code

Ensure the image dimensions match the window size or adjust the resize parameters

Troubleshooting
Common Issues and Solutions
1. Module Not Found Error

Symptom: Error message about missing modules

Solution: Ensure all required packages are installed:
pip install pillow requests

2. API Key Not Working

Symptom: Error messages when checking URLs

Solution:

Verify your VirusTotal API key is correct

Check your VirusTotal account for any restrictions

Ensure you have internet connectivity

3. Image Not Loading

Symptom: Blank background or error message

Solution:

Verify the image path is correct

Ensure the image exists at the specified location

Check the image file is not corrupted

4. Login Not Working

Symptom: "Invalid username or password" message with correct credentials

Solution:

Check the login validation code for hardcoded credentials

Ensure no extra spaces in the input fields

Security Notes
API Key Security:

The API key is currently hardcoded in the application

For production use, consider:

Using environment variables

Implementing a configuration file

Adding user input for the API key

Login Security:

The current login system is basic

For serious use, consider:

Password hashing

Account lockout after failed attempts

Secure credential storage

Future Enhancements
Add URL scanning history

Implement API key rotation

Add more detailed report information

Include screenshot of the website

Add multi-user support with different permission levels

Implement scheduled URL checks

Add export functionality for reports

License
This project is provided by Msebetsi Solutions for educational purposes. You're free to modify and distribute it, but please include attribution to the original creator.

Support
For any questions or issues, please contact:
Msebetsi Solutions Support
