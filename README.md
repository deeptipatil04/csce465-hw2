# CSCE 465 Homework 2

## Setup

Create and activate a Python virtual environment:

python3 -m venv .venv
source .venv/bin/activate

Install the required dependencies:

pip install -r requirements.txt

## Running the Tests

Run the test suite with:

pytest -v

Individual tests can also be run with:

python3 test_handshake.py
python3 test_secure_record.py
python3 test_secure_channel.py

## Files

- `baseline_ctr.py` - baseline CTR implementation
- `handshake.py` - authenticated handshake implementation
- `secure_record.py` - secure record implementation
- `secure_channel.py` - secure channel implementation
- `tamper_demo.py` - demonstrates tampering behavior
- `ffdhe3072.pem` - Diffie-Hellman group parameters
- `tests/` - additional tests
