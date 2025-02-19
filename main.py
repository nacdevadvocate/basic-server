from fastapi import FastAPI, HTTPException, Header, Depends, Form
from pydantic import BaseModel
from fastapi.responses import JSONResponse
import secrets
import base64
import httpx
import os
from dotenv import load_dotenv

# Load environment variables from a .env file (if available)
load_dotenv()

app = FastAPI()


# Define the model for the incoming request body
class UEIdRequest(BaseModel):
    ueId: dict  # In this case, the ueId is expected to be a dictionary


# Simulated client database (In a real-world scenario, you'd query this from a database)
valid_client_id = os.getenv("VALID_CLIENT_ID")
valid_client_secret = os.getenv("VALID_CLIENT_SECRET")

client_id = os.getenv("CLIENT_ID")  # Load client_id from environment
client_secret = os.getenv("CLIENT_SECRET")  # Load client_secret from environment
valid_access_tokens = set()


@app.get("/test/ping-api")
def read_root():
    return {"message": "API works as expected"}

def generate_basic_auth_header(client_id: str, client_secret: str) -> str:
    """
    Generates a Base64 encoded Basic Auth header.
    """
    auth_string = f"{client_id}:{client_secret}"
    base64_encoded = base64.b64encode(auth_string.encode()).decode()
    return f"Basic {base64_encoded}"

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    scope: str


def generate_access_token(client_id: str, client_secret: str) -> TokenResponse:
    """
    Simulate the process of generating an OAuth2 access token.
    """
    if client_id == valid_client_id and client_secret == valid_client_secret:
        access_token = secrets.token_urlsafe(32)
        valid_access_tokens.add(access_token)  # Save the generated token (for demo purposes)
        return TokenResponse(
            access_token=access_token,
            token_type="Bearer",
            expires_in=3600,  # 1 hour
            scope="your_desired_scope",
        )
    else:
        raise HTTPException(status_code=401, detail="Invalid client_id or client_secret")


@app.post("/oauth2/token", response_model=TokenResponse)
async def oauth2_token(
    client_id: str = Form(...),
    client_secret: str = Form(...),
    grant_type: str = Form("client_credentials"),  # Default to "client_credentials"
):
    """
    Endpoint to generate an access token using client credentials.
    """
    if grant_type != "client_credentials":
        raise HTTPException(status_code=400, detail="Invalid grant_type")

    return generate_access_token(client_id, client_secret)




@app.post("/device-status/v0/roaming")
async def process_request(
    request_body: UEIdRequest,  # Request body with ueId
    authorization: str = Header(...)  # Authorization header
):
    """
    Endpoint that processes the provided access token and UEId request to complete the API flow.
    """
    # Step 1: Validate the access token in the header
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=400, detail="Invalid token format. Expected 'Bearer <token>'")
    
    access_token = authorization[len("Bearer "):]  # Extract the token part
    basic_auth_header = generate_basic_auth_header(client_id, client_secret)
    print("access_token: ", access_token)
    print("request_body: ", request_body)

    # In a real-world scenario, here you would validate the access token against a database or auth service

    # Step 2: Send the request to the first API endpoint (AUTH_GATEWAY_URL)
    try:
        async with httpx.AsyncClient() as client:
            auth_gateway_url = os.getenv("GATEWAY_URL") + "/bc-authorize"  # Get URL from env variable
            print("auth_gateway_url: ", auth_gateway_url)
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
               "Authorization": basic_auth_header
            }
            data = {
                "login_hint": "tel:" + request_body.ueId["msisdn"],
                "scope": os.getenv("SCOPE")
            }
            print("data: ", data)
            response = await client.post(auth_gateway_url, headers=headers, data=data)
            # Handle HTTP errors gracefully
            if response.status_code >= 400:
                return JSONResponse(
                    status_code=response.status_code,
                    content={
                        "error": "Failed to authorize",
                        "details": response.json()  
                    }
                )

            response_data = response.json()
            print("bc_response: ", response_data)
            auth_req_id = response_data["auth_req_id"]
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"Error in first API request: {str(e)}")

    # Step 3: Send the second request to get the token 
    try:
        async with httpx.AsyncClient() as client:
            token_url = os.getenv("GATEWAY_URL") + "/token"  # Get URL from env variable
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": basic_auth_header
            }
            data = {
                "grant_type": "urn:openid:params:grant-type:ciba",
                "auth_req_id": auth_req_id
            }
            response = await client.post(token_url, headers=headers, data=data)
            # Handle HTTP errors gracefully
            if response.status_code >= 400:
                return JSONResponse(
                    status_code=response.status_code,
                    content={
                        "error": "Failed to get token",
                        "details": response.json()  
                    }
                )
            response_data = response.json()
            print("token_response: ", response_data)
            token = response_data["access_token"]
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"Error in second API request: {str(e)}")

    # Step 4: Send the third request using the access token 
    try:
        async with httpx.AsyncClient() as client:
            device_status_url = os.getenv("GATEWAY_URL") + "/device-status/v0/roaming"  # Get URL from env variable
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}"
            }
            data = {
                "ueId": request_body.ueId
            }
            response = await client.post(device_status_url, headers=headers, json=data)
             # Handle HTTP errors gracefully
            if response.status_code >= 400:
                return JSONResponse(
                    status_code=response.status_code,
                    content={
                        "error": "Failed to retrieve roaming",
                        "details": response.json()  
                    }
                )
            final_data = response.json()
            print("final_data: ", final_data)
            return final_data
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"Error in third API request: {str(e)}")

