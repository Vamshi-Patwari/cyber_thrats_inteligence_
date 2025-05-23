# Cyber Threats Intelligence Dashboard

## Overview
The Cyber Threats Intelligence Dashboard is a web application designed to provide insights into various cyber threats. It aggregates threat intelligence data and presents it in an interactive dashboard format, allowing users to monitor and analyze threats effectively.

## Features
- **IP Threats Display**: View a list of IP addresses that pose security threats
- **Threat Details**: Get detailed information about each threat
- **Traffic Analysis**: Monitor network traffic and identify suspicious patterns
- **Interactive UI**: Easy-to-use interface with tabs and dynamic content

## Installation and Setup

### Prerequisites
- Python 3.6 or higher
- pip (Python package installer)

### Installation Steps

1. Clone the repository:
   ```
   git clone <repository-url>
   ```

2. Navigate to the project directory:
   ```
   cd cyber-threats-intelligence-dashboard
   ```

3. Create a virtual environment (recommended):
   ```
   python -m venv venv
   ```

4. Activate the virtual environment:
   - On Windows:
     ```
     venv\Scripts\activate
     ```
   - On macOS/Linux:
     ```
     source venv/bin/activate
     ```

5. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

## Running the Application

1. Make sure your virtual environment is activated

2. Start the Flask application:
   ```
   python app.py
   ```

3. Open your web browser and navigate to:
   ```
   http://127.0.0.1:5000/
   ```

## Usagegit st
- The dashboard will display IP threats by default
- Click on any threat to view detailed information
- Use the tabs to switch between IP threats and traffic analysis views

## Project Structure
- `app.py`: Main Flask application
- `data/`: Contains JSON files with threat and traffic data
- `static/`: Static files (CSS, JavaScript)
- `templates/`: HTML templates

## Customization
You can modify the sample data in `app.py` to include your own threat intelligence data.

## License
This project is licensed under the MIT License. See the LICENSE file for more details.#   c y b e r _ t h r a t s _ i n t e l i g e n c e _ 
 
 