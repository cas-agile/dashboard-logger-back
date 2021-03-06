# install virtual environment
virtualenv -p python3 innometricsenv

# pip requirements
source innometricsenv/bin/activate
pip install -r requirements.txt

echo "Add next lines to your ~/.bashrc file"
echo "export INNOMETRICS_BACKEND_PATH=\"/srv/innometrics-backend\" # where srv is the directory you cloned the code"
echo "export PYTHONPATH=\"$INNOMETRICS_BACKEND_PATH:$INNOMETRICS_BACKEND_PATH/api:$INNOMETRICS_BACKEND_PATH/db\""
