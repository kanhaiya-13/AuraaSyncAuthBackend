from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import firebase_admin
from firebase_admin import credentials, auth
from supabase import create_client, Client
import os
from datetime import datetime
from typing import Optional
import logging
from dotenv import load_dotenv

load_dotenv() 

# Initialize FastAPI app
app = FastAPI()

# Security scheme for Bearer token
security = HTTPBearer()

# Initialize Firebase Admin SDK
# You'll need to download your Firebase service account key JSON file
# and set the path in environment variable or directly here
try:
    # Option 1: Using environment variable for service account key file
    firebase_cred_path = os.getenv("FIREBASE_SERVICE_ACCOUNT_KEY_PATH")
    if firebase_cred_path:
        cred = credentials.Certificate(firebase_cred_path)
    else:
        # Option 2: Using environment variables for service account details
        firebase_config = {
            "type": "service_account",
            "project_id": os.getenv("FIREBASE_PROJECT_ID"),
            "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
            "private_key": os.getenv("FIREBASE_PRIVATE_KEY").replace('\\n', '\n') if os.getenv("FIREBASE_PRIVATE_KEY") else None,
            "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
            "client_id": os.getenv("FIREBASE_CLIENT_ID"),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
        cred = credentials.Certificate(firebase_config)
    
    firebase_admin.initialize_app(cred)
except Exception as e:
    logging.error(f"Failed to initialize Firebase: {e}")

# Initialize Supabase client
supabase_url = os.getenv("SUPABASE_URL")
supabase_key = os.getenv("SUPABASE_ANON_KEY")  # or service role key for server-side operations
supabase: Client = create_client(supabase_url, supabase_key)

# Pydantic models
class UserCreate(BaseModel):
    email: str
    name: Optional[str] = None
    profile_picture: Optional[str] = None

class UserResponse(BaseModel):
    id: str
    email: str
    name: Optional[str]
    profile_picture: Optional[str]
    created_at: datetime
    is_new_user: bool

# Dependency to verify Firebase token and get user info
async def verify_firebase_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Verify Firebase ID token and return decoded token
    """
    try:
        # Remove 'Bearer ' prefix if present
        id_token = credentials.credentials
        
        # Verify the ID token
        decoded_token = auth.verify_id_token(id_token)
        return decoded_token
    
    except auth.InvalidIdTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Firebase ID token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except auth.ExpiredIdTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Expired Firebase ID token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token verification failed: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Function to check if user exists in Supabase
async def get_user_from_supabase(firebase_uid: str):
    """
    Check if user exists in Supabase users table
    """
    try:
        result = supabase.table("users").select("*").eq("firebase_uid", firebase_uid).execute()
        
        if result.data:
            return result.data[0]
        return None
    
    except Exception as e:
        logging.error(f"Error fetching user from Supabase: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error occurred"
        )

# Function to create new user in Supabase
async def create_user_in_supabase(firebase_uid: str, email: str, name: Optional[str] = None, profile_picture: Optional[str] = None):
    """
    Create new user in Supabase users table
    """
    try:
        user_data = {
            "firebase_uid": firebase_uid,
            "email": email,
            "name": name,
            "profile_picture": profile_picture,
            "created_at": datetime.utcnow().isoformat(),
        }
        
        result = supabase.table("users").insert(user_data).execute()
        
        if result.data:
            return result.data[0]
        else:
            raise Exception("Failed to create user")
    
    except Exception as e:
        logging.error(f"Error creating user in Supabase: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user in database"
        )

# Main route for user authentication and registration
@app.post("/auth/verify-user", response_model=UserResponse)
async def verify_and_register_user(
    user_data: Optional[UserCreate] = None,
    firebase_token: dict = Depends(verify_firebase_token)
):
    """
    1. Verify Firebase authentication token
    2. Check if user exists in Supabase database
    3. If new user, add them to the users table
    4. Return user information with is_new_user flag
    """
    
    # Extract user info from Firebase token
    firebase_uid = firebase_token["uid"]
    email = firebase_token.get("email")
    name = firebase_token.get("name")
    profile_picture = firebase_token.get("picture")
    
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email not found in Firebase token"
        )
    
    # Check if user exists in Supabase
    existing_user = await get_user_from_supabase(firebase_uid)
    
    if existing_user:
        # User exists, return existing user data
        return UserResponse(
            id=existing_user["id"],
            email=existing_user["email"],
            name=existing_user["name"],
            profile_picture=existing_user["profile_picture"],
            created_at=existing_user["created_at"],
            is_new_user=False
        )
    else:
        # New user, create in Supabase
        # Use data from request body if provided, otherwise use Firebase token data
        if user_data:
            final_name = user_data.name or name
            final_profile_picture = user_data.profile_picture or profile_picture
        else:
            final_name = name
            final_profile_picture = profile_picture
        
        new_user = await create_user_in_supabase(
            firebase_uid=firebase_uid,
            email=email,
            name=final_name,
            profile_picture=final_profile_picture
        )
        
        return UserResponse(
            id=new_user["id"],
            email=new_user["email"],
            name=new_user["name"],
            profile_picture=new_user["profile_picture"],
            created_at=new_user["created_at"],
            is_new_user=True
        )

# Additional route to get current user info (protected)
@app.get("/auth/me", response_model=UserResponse)
async def get_current_user(firebase_token: dict = Depends(verify_firebase_token)):
    """
    Get current authenticated user information
    """
    firebase_uid = firebase_token["uid"]
    
    user = await get_user_from_supabase(firebase_uid)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found in database"
        )
    
    return UserResponse(
        id=user["id"],
        email=user["email"],
        name=user["name"],
        profile_picture=user["profile_picture"],
        created_at=user["created_at"],
        is_new_user=False
    )

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "message": "FastAPI server is running"}

# Example of a protected route that requires authentication
@app.get("/protected")
async def protected_route(firebase_token: dict = Depends(verify_firebase_token)):
    """
    Example of a protected route that requires Firebase authentication
    """
    return {
        "message": "You have access to this protected route!",
        "user_id": firebase_token["uid"],
        "email": firebase_token.get("email")
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)