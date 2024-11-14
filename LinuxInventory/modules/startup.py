from fastapi import FastAPI, Response, Depends, HTTPException, status, Query
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets
from typing import Optional
from pydantic import BaseModel
import sys
import os
sys.path.append(rf'{os.getcwd()}/modules')
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.responses import PlainTextResponse
from fastapi.openapi.docs import get_swagger_ui_html
import subprocess
import httpx
from threading import Thread