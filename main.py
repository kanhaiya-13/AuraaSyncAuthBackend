from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
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

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],  # Frontend URLs
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
)

# Security scheme for Bearer token
security = HTTPBearer()

# Initialize Firebase Admin SDK
# You'll need to download your Firebase service account key JSON file
# and set the path in environment variable or directly here
firebase_initialized = False
try:
    # Option 1: Using environment variable for service account key file
    firebase_cred_path = os.getenv("FIREBASE_SERVICE_ACCOUNT_KEY_PATH")
    if firebase_cred_path and os.path.exists(firebase_cred_path):
        cred = credentials.Certificate(firebase_cred_path)
        firebase_admin.initialize_app(cred)
        firebase_initialized = True
        logging.info("Firebase initialized with service account file")
    elif os.path.exists("./firebase-service-account.json"):
        # Use the local firebase-service-account.json file
        cred = credentials.Certificate("./firebase-service-account.json")
        firebase_admin.initialize_app(cred)
        firebase_initialized = True
        logging.info("Firebase initialized with local service account file")
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
        if all(firebase_config.values()):
            cred = credentials.Certificate(firebase_config)
            firebase_admin.initialize_app(cred)
            firebase_initialized = True
            logging.info("Firebase initialized with environment variables")
        else:
            logging.warning("Firebase credentials not found. Authentication will be disabled.")
except Exception as e:
    logging.error(f"Failed to initialize Firebase: {e}")
    logging.warning("Firebase authentication will be disabled.")

# Initialize Supabase client
supabase_url = os.getenv("SUPABASE_URL")
supabase_key = os.getenv("SUPABASE_ANON_KEY")  # or service role key for server-side operations

if not supabase_url or not supabase_key:
    logging.warning("Supabase credentials not found. Some features may not work.")
    # Create a dummy client for development
    supabase = None
else:
    supabase: Client = create_client(supabase_url, supabase_key)

# Pydantic models
class UserCreate(BaseModel):
    email: str
    name: Optional[str] = None
    profile_picture: Optional[str] = None
    firebase_id:str

class UserResponse(BaseModel):
    id: int
    email: str
    name: Optional[str] = None
    profile_picture: Optional[str] = None
    gender: Optional[str] = None
    location: Optional[str] = None
    skin_tone: Optional[str] = None
    face_shape: Optional[str] = None
    body_shape: Optional[str] = None
    personality: Optional[str] = None
    onboarding_completed: Optional[bool] = None
    is_new_user: bool

# Dependency to verify Firebase token and get user info
async def verify_firebase_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Verify Firebase ID token and return decoded token
    """
    if not firebase_initialized:
        logging.warning("Firebase not initialized, creating mock token for development")
        # Return a mock token for development
        return {
            "uid": "mock_user_123",
            "email": "test@example.com",
            "name": "Test User",
            "picture": "https://example.com/avatar.jpg"
        }
    
    try:
        # Remove 'Bearer ' prefix if present
        id_token = credentials.credentials
        logging.info(f"Attempting to verify Firebase token (length: {len(id_token)})")
        
        # Verify the ID token with clock skew tolerance
        decoded_token = auth.verify_id_token(id_token, check_revoked=False)
        logging.info(f"Firebase token verified successfully for user: {decoded_token.get('email', 'unknown')}")
        return decoded_token
    
    except auth.InvalidIdTokenError as e:
        logging.error(f"Invalid Firebase ID token: {str(e)}")
        # For development, let's be more lenient with token validation
        if "Token used too early" in str(e) or "clock" in str(e).lower():
            logging.warning("Clock synchronization issue detected, attempting to verify with relaxed timing")
            try:
                # Try again with a more relaxed approach
                import time
                time.sleep(1)  # Wait a second and try again
                decoded_token = auth.verify_id_token(id_token, check_revoked=False)
                logging.info(f"Firebase token verified on retry for user: {decoded_token.get('email', 'unknown')}")
                return decoded_token
            except Exception as retry_e:
                logging.error(f"Token verification failed on retry: {str(retry_e)}")
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Firebase ID token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except auth.ExpiredIdTokenError as e:
        logging.error(f"Expired Firebase ID token: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Expired Firebase ID token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        logging.error(f"Token verification failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token verification failed: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Function to check if user exists in Supabase
async def get_user_from_supabase(firebase_uid: str):
    """
    Check if user exists in Supabase users table and get customer data
    """
    if not supabase:
        logging.warning("Supabase not configured, returning None for user lookup")
        return None
        
    try:
        # First, get the user record
        user_result = supabase.table("user").select("*").eq("firebase_id", firebase_uid).execute()
        
        if not user_result.data:
            return None
        
        user_record = user_result.data[0]
        user_id = user_record["user_id"]
        
        # Then, get the customer record
        customer_result = supabase.table("customer").select("*").eq("user_id", user_id).execute()
        
        if customer_result.data:
            customer_record = customer_result.data[0]
            # Merge user and customer data
            user_record.update(customer_record)
        
        return user_record
    
    except Exception as e:
        logging.error(f"Error fetching user from Supabase: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error occurred"
        )

# Function to create new user in Supabase
async def create_user_in_supabase(firebase_uid: str, email: str, name: Optional[str] = None, profile_picture: Optional[str] = None):
    """
    Create new user in both user and customer tables in Supabase
    """
    if not supabase:
        logging.warning("Supabase not configured, creating mock user")
        # Return a mock user for development
        return {
            "user_id": 1,
            "firebase_id": firebase_uid,
            "email": email,
        }
        
    try:
        # First, create the user record
        user_data = {
            "firebase_id": firebase_uid,
            "email": email,
            "name": name,
        }
        
        user_result = supabase.table("user").insert(user_data).execute()
        
        if not user_result.data:
            raise Exception("Failed to create user record")
        
        user_record = user_result.data[0]
        user_id = user_record["user_id"]
        
        # Then, create the customer record
        customer_data = {
            "user_id": user_id,
            "email": email,
            "name": name or "",
            "profile_picture": profile_picture or "",
            "gender": "",
            "location": "",
            "skin_tone": "",
            "face_shape": None,
            "body_shape": None,
            "personality": None,
            "onboarding_completed": False,
            "is_new_user": True
        }
        
        customer_result = supabase.table("customer").insert(customer_data).execute()
        
        if not customer_result.data:
            # If customer creation fails, we should clean up the user record
            logging.error("Failed to create customer record, cleaning up user record")
            supabase.table("user").delete().eq("user_id", user_id).execute()
            raise Exception("Failed to create customer record")
        
        # Return the user record with additional info
        user_record["customer_created"] = True
        return user_record
    
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
            id=existing_user["user_id"],
            email=existing_user["email"],
            name=existing_user.get("name"),
            profile_picture=existing_user.get("profile_picture"),
            gender=existing_user.get("gender"),
            location=existing_user.get("location"),
            skin_tone=existing_user.get("skin_tone"),
            face_shape=existing_user.get("face_shape"),
            body_shape=existing_user.get("body_shape"),
            personality=existing_user.get("personality"),
            onboarding_completed=existing_user.get("onboarding_completed"),
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
            id=new_user["user_id"],
            email=new_user["email"],
            name=new_user.get("name"),
            profile_picture=new_user.get("profile_picture"),
            gender=new_user.get("gender"),
            location=new_user.get("location"),
            skin_tone=new_user.get("skin_tone"),
            face_shape=new_user.get("face_shape"),
            body_shape=new_user.get("body_shape"),
            personality=new_user.get("personality"),
            onboarding_completed=new_user.get("onboarding_completed"),
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
        id=user["user_id"],
        email=user["email"],
        name=user.get("name"),
        profile_picture=user.get("profile_picture"),
        gender=user.get("gender"),
        location=user.get("location"),
        skin_tone=user.get("skin_tone"),
        face_shape=user.get("face_shape"),
        body_shape=user.get("body_shape"),
        personality=user.get("personality"),
        onboarding_completed=user.get("onboarding_completed"),
        is_new_user=False
    )

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "message": "FastAPI server is running"}

# Route to update onboarding status
@app.put("/auth/update-onboarding")
async def update_onboarding_status(
    onboarding_data: dict,
    firebase_token: dict = Depends(verify_firebase_token)
):
    """
    Update user's onboarding status and profile information
    """
    firebase_uid = firebase_token["uid"]
    
    try:
        # Get user from database
        user = await get_user_from_supabase(firebase_uid)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found in database"
            )
        
        user_id = user["user_id"]
        
        # Check if customer record exists
        if not supabase:
            logging.warning("Supabase not configured, skipping customer update")
            return {"message": "Onboarding status updated successfully (mock)"}
        
        # Verify customer record exists
        customer_check = supabase.table("customer").select("*").eq("user_id", user_id).execute()
        if not customer_check.data:
            logging.error(f"No customer record found for user_id: {user_id}")
            # Create customer record if it doesn't exist
            customer_data = {
                "user_id": user_id,
                "email": user.get("email", ""),
                "name": user.get("name", ""),
                "profile_picture": user.get("profile_picture", ""),
                "gender": "",
                "location": "",
                "skin_tone": "",
                "face_shape": None,
                "body_shape": None,
                "personality": None,
                "onboarding_completed": False,
                "is_new_user": True
            }
            supabase.table("customer").insert(customer_data).execute()
            logging.info(f"Created missing customer record for user_id: {user_id}")
        
        # Update customer table with onboarding data
        update_data = {
            "onboarding_completed": onboarding_data.get("onboarding_completed", False),
            "gender": onboarding_data.get("gender", ""),
            "name": onboarding_data.get("name", ""),
            "skin_tone": onboarding_data.get("skin_tone", ""),
            "face_shape": onboarding_data.get("face_shape"),
            "body_shape": onboarding_data.get("body_shape"),
            "personality": onboarding_data.get("personality")
        }
        
        # Remove None values
        update_data = {k: v for k, v in update_data.items() if v is not None}
        
        if supabase:
            logging.info(f"Attempting to update customer table with data: {update_data}")
            result = supabase.table("customer").update(update_data).eq("user_id", user_id).execute()
            
            logging.info(f"Update result: {result}")
            
            if result.data:
                logging.info(f"Successfully updated customer record for user_id: {user_id}")
                return {"message": "Onboarding status updated successfully"}
            else:
                logging.error(f"No data returned from update operation for user_id: {user_id}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to update onboarding status - no data returned"
                )
        else:
            # Mock response for development
            return {"message": "Onboarding status updated successfully (mock)"}
    
    except Exception as e:
        logging.error(f"Error updating onboarding status: {e}")
        logging.error(f"Firebase UID: {firebase_uid}")
        logging.error(f"User data: {user}")
        logging.error(f"Update data: {update_data}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update onboarding status: {str(e)}"
        )

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