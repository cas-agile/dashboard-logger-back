# Logger-backend
This is a backend implementation of innometrics. In order to run it, please, follow the steps.
# Run depoyment.sh
This script will make an environment for the project and install requirements. It will also print environment variables you would need to add to your system.

# Activate virtual environment
`source $INNOMETRICS_BACKEND_PATH/innometricsenv/bin/activate`

# Run Flask server
`python api/app.py`

# Run with Production environment
In order to run the app in production environment, please:
1. Add `config_proudction.ini` with production config settings
2. Set INNOMETRICS_PRODUCTION environment variable to True
3. Add INNOMETRICS_PRODUCTION_KEYFILE and INNOMETRICS_PRODUCTION_CERTFILE enviroment variables,
which should point to location of SSL certificate files


# REST API docs
The documentation for rest api is stored in `documentation.yaml`.
You can render it using <https://editor.swagger.io/>
