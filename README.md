# Snyk API Integration

This project provides a Python-based integration with the Snyk API, allowing users to interact with Snyk's services for exporting reports and checking export statuses.

## Features

- Initiate and download Snyk export reports in CSV format.
- Check the status of export jobs.

## Requirements

- Python 3.10.14 or above

## Setup

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/snyk-api-integration.git
   cd snyk-api-integration
   ```

2. **Install dependencies:**

   Use `pip` to install the required Python packages:

   ```bash
   pip install -r requirements.txt
   ```

3. **Configure API Tokens:**

   Ensure that your API tokens are set as environment variables:

   - `SNYK_TOKEN`: Your Snyk API token.

   These tokens are validated and retrieved using functions in `utils/helper.py`.

## Usage

To use the application, refer to the help menu provided by the Typer tool. You can access it by running:
```bash
python index.py --help
```

This will display all available commands and options for interacting with the Snyk API.
