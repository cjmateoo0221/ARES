from dependencies import *
import os
from dotenv import load_dotenv

load_dotenv()

oaikey = os.getenv('OPENAI_APIKEY')
gitkey = os.getenv('GITHUB_APIKEY')
oaiendpoint = os.getenv('OPEN_AIENDPOINT')
vtkey = os.getenv('VT_APIKEY')