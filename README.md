# GitguardSecretScanner
Scans files for secrets with Gitguardian API 

Many secrets, like API keys or credentials, are hidden in our local files or project directories sometimes so to remedy this issue gitguardian from github  helps  automate this and detect secrets.This python script scans files within the given directory and detect potential secrets, hardcoded values using the GitGuardian API and an API python wrapper.

NOTE: you will need gitguardian API key to run the scan

The script will:

Detect secrets and other potential policy breakages to and from the file path / directory, print filenames, policy breaks and matches for all policy breaks found.

# Dependencies from python:

pygitguardian, python-dotenv.

