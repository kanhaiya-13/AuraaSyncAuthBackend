# version 7
# main.py - Complete FastAPI with Firebase Auth + Supabase
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import firebase_admin
from firebase_admin import credentials, auth
from supabase import create_client, Client
import os
from dotenv import load_dotenv
import logging
from typing import Optional
from datetime import datetime

# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Firebase Auth + Supabase API",
    description="Complete authentication system with Firebase and Supabase",
    version="1.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Firebase Admin SDK setup
firebase_initialized = False
try:
    # Check if service account file exists
    if os.path.exists("firebase-service-account.json"):
        cred = credentials.Certificate("firebase-service-account.json")
        firebase_admin.initialize_app(cred)
        firebase_initialized = True
        logger.info("✅ Firebase Admin initialized successfully")
    else:
        logger.warning("⚠️  Firebase service account file not found: firebase-service-account.json")
        logger.info("ℹ️  Download from Firebase Console > Project Settings > Service Accounts")
except Exception as e:
    logger.error(f"❌ Failed to initialize Firebase: {e}")
    logger.info("ℹ️  Make sure firebase-service-account.json is valid and in project root")

# Supabase setup
supabase = None
supabase_initialized = False
try:
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_ANON_KEY")
    
    if not supabase_url:
        logger.warning("⚠️  SUPABASE_URL not found in environment variables")
    elif not supabase_key:
        logger.warning("⚠️  SUPABASE_ANON_KEY not found in environment variables")
    else:
        supabase: Client = create_client(supabase_url, supabase_key)
        supabase_initialized = True
        logger.info("✅ Supabase client initialized successfully")
        
except Exception as e:
    logger.error(f"❌ Failed to initialize Supabase: {e}")

# Log setup status
if not os.path.exists(".env"):
    logger.warning("⚠️  .env file not found - create one with SUPABASE_URL and SUPABASE_ANON_KEY")

print("=" * 60)
print(f"🔥 Setup Status:")
print(f"   Firebase: {'✅ Ready' if firebase_initialized else '❌ Not configured'}")
print(f"   Supabase: {'✅ Ready' if supabase_initialized else '❌ Not configured'}")
print(f"   Server: ✅ Running")
print("=" * 60)

# ============================================================================
# PYDANTIC MODELS (Data Structure Definitions)
# ============================================================================

class TokenRequest(BaseModel):
    """Request model for Firebase ID token verification"""
    idToken: str
    
    class Config:
        schema_extra = {
            "example": {
                "idToken": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE2NzAyN..."
            }
        }

class UserProfile(BaseModel):
    """User profile data structure"""
    uid: str
    email: str
    name: Optional[str] = ""
    picture: Optional[str] = ""
    provider: str  # "email" or "google.com"
    email_verified: bool
    created_at: Optional[str] = None
    last_login: Optional[str] = None

class AuthResponse(BaseModel):
    """Response for successful authentication"""
    success: bool
    message: str
    user: UserProfile
    is_new_user: bool  # True if user was just created, False if existing user

class ErrorResponse(BaseModel):
    """Error response model"""
    success: bool
    error: str
    details: Optional[str] = None

class UserUpdateRequest(BaseModel):
    """Request model for updating user profile"""
    name: Optional[str] = None
    picture: Optional[str] = None

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

async def verify_firebase_token(id_token: str) -> dict:
    """
    Verify Firebase ID token and return decoded user data
    
    Args:
        id_token (str): Firebase ID token from client
        
    Returns:
        dict: Decoded token data with user info
        
    Raises:
        HTTPException: If token is invalid or expired
    """
    if not firebase_initialized:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Firebase service is not configured. Please set up firebase-service-account.json"
        )
    
    try:
        # Verify token with Firebase Admin SDK
        decoded_token = auth.verify_id_token(id_token)
        logger.info(f"✅ Token verified for user: {decoded_token.get('email')}")
        return decoded_token
    except Exception as e:
        logger.error(f"❌ Token verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired Firebase token"
        )

async def get_user_from_supabase(firebase_uid: str) -> Optional[dict]:
    """
    Get user from Supabase database by Firebase UID
    
    Args:
        firebase_uid (str): Firebase user ID
        
    Returns:
        dict or None: User data if found, None if not found
    """
    if not supabase_initialized or not supabase:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Supabase service is not configured. Please set up .env file with Supabase credentials"
        )
    
    try:
        result = supabase.table('users').select('*').eq('firebase_uid', firebase_uid).execute()
        if result.data:
            logger.info(f"✅ Found existing user in Supabase: {firebase_uid}")
            return result.data[0]
        else:
            logger.info(f"ℹ️  User not found in Supabase: {firebase_uid}")
            return None
    except Exception as e:
        logger.error(f"❌ Error querying Supabase: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database query failed"
        )

async def create_user_in_supabase(user_data: dict) -> dict:
    """
    Create new user in Supabase database
    
    Args:
        user_data (dict): Firebase user data
        
    Returns:
        dict: Created user data
        
    Raises:
        HTTPException: If user creation fails
    """
    if not supabase_initialized or not supabase:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Supabase service is not configured. Please set up .env file with Supabase credentials"
        )
    
    try:
        # Extract data from Firebase token
        user_record = {
            'firebase_uid': user_data.get('uid'),
            'email': user_data.get('email'),
            'name': user_data.get('name', ''),
            'picture': user_data.get('picture', ''),
            'provider': user_data.get('firebase', {}).get('sign_in_provider', 'email'),
            'email_verified': user_data.get('email_verified', False),
            'created_at': datetime.utcnow().isoformat(),
            'last_login': datetime.utcnow().isoformat()
        }
        
        # Insert new user
        result = supabase.table('users').insert(user_record).execute()
        
        if result.data:
            logger.info(f"✅ Created new user in Supabase: {user_data.get('email')}")
            return result.data[0]
        else:
            raise Exception("No data returned from insert operation")
            
    except Exception as e:
        logger.error(f"❌ Failed to create user in Supabase: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create user in database: {str(e)}"
        )

async def update_user_last_login(firebase_uid: str) -> dict:
    """
    Update user's last login timestamp
    
    Args:
        firebase_uid (str): Firebase user ID
        
    Returns:
        dict: Updated user data
    """
    if not supabase_initialized or not supabase:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Supabase service is not configured. Please set up .env file with Supabase credentials"
        )
    
    try:
        result = supabase.table('users').update({
            'last_login': datetime.utcnow().isoformat()
        }).eq('firebase_uid', firebase_uid).execute()
        
        if result.data:
            logger.info(f"✅ Updated last login for user: {firebase_uid}")
            return result.data[0]
        else:
            raise Exception("User not found for login update")
            
    except Exception as e:
        logger.error(f"❌ Failed to update last login: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user login time"
        )

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "message": "Firebase Auth + Supabase API",
        "status": "running",
        "endpoints": {
            "docs": "/docs",
            "health": "/health",
            "auth": {
                "login_signup": "/auth/login",
                "user_profile": "/auth/user/{firebase_uid}",
                "update_profile": "/auth/user/{firebase_uid}"
            }
        },
        "version": "1.0.0"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    
    # Check Firebase connection safely
    firebase_status = "disconnected"
    try:
        firebase_admin.get_app()
        firebase_status = "connected"
    except ValueError:
        firebase_status = "not_initialized"
    except Exception as e:
        firebase_status = f"error: {str(e)}"
    
    # Check Supabase connection safely
    supabase_status = "disconnected"
    try:
        if 'supabase' in globals() and supabase:
            # Try a simple query to test connection
            supabase.table('users').select('count').limit(1).execute()
            supabase_status = "connected"
        else:
            supabase_status = "not_initialized"
    except Exception as e:
        supabase_status = f"error: {str(e)[:50]}"
    
    return {
        "status": "healthy",
        "message": "Server is running correctly",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "firebase": firebase_status,
            "supabase": supabase_status
        },
        "setup_status": {
            "firebase_service_account": "✅ Found" if os.path.exists("firebase-service-account.json") else "❌ Missing firebase-service-account.json",
            "env_file": "✅ Found" if os.path.exists(".env") else "❌ Missing .env file",
            "supabase_url": "✅ Set" if os.getenv("SUPABASE_URL") else "❌ Missing SUPABASE_URL in .env",
            "supabase_key": "✅ Set" if os.getenv("SUPABASE_ANON_KEY") else "❌ Missing SUPABASE_ANON_KEY in .env"
        }
    }

@app.post(
    "/auth/login",
    response_model=AuthResponse,
    summary="Handle Firebase Authentication (Email/Password & Google)",
    description="""
    This endpoint handles BOTH Firebase email/password and Google sign-in authentication.
    
    **How it works:**
    1. Client authenticates with Firebase (frontend) - either email/password or Google
    2. Client receives Firebase ID token
    3. Client sends ID token to this endpoint
    4. Server verifies token with Firebase Admin SDK
    5. Server creates/updates user in Supabase database
    6. Server returns user profile data
    
    **Supports:**
    - Firebase Email/Password authentication
    - Firebase Google sign-in authentication
    - Automatic user creation in Supabase
    - Existing user login tracking
    """
)
async def firebase_auth_handler(token_request: TokenRequest):
    """
    Handle Firebase authentication and Supabase user management
    
    This single endpoint handles both:
    - Email/password authentication
    - Google sign-in authentication
    
    The flow is the same for both since Firebase handles the actual authentication
    """
    try:
        # Step 1: Verify Firebase ID token
        firebase_user_data = await verify_firebase_token(token_request.idToken)
        firebase_uid = firebase_user_data.get('uid')
        
        # Step 2: Check if user exists in Supabase
        existing_user = await get_user_from_supabase(firebase_uid)
        
        if existing_user:
            # Step 3a: Existing user - update last login
            updated_user = await update_user_last_login(firebase_uid)
            is_new_user = False
            user_data = updated_user
            message = "User logged in successfully"
            logger.info(f"🔄 Existing user logged in: {firebase_user_data.get('email')}")
        else:
            # Step 3b: New user - create in Supabase
            user_data = await create_user_in_supabase(firebase_user_data)
            is_new_user = True
            message = "User registered and logged in successfully"
            logger.info(f"🆕 New user created: {firebase_user_data.get('email')}")
        
        # Step 4: Create response with user profile
        user_profile = UserProfile(
            uid=user_data['firebase_uid'],
            email=user_data['email'],
            name=user_data.get('name', ''),
            picture=user_data.get('picture', ''),
            provider=user_data.get('provider', 'email'),
            email_verified=user_data.get('email_verified', False),
            created_at=user_data.get('created_at'),
            last_login=user_data.get('last_login')
        )
        
        return AuthResponse(
            success=True,
            message=message,
            user=user_profile,
            is_new_user=is_new_user
        )
        
    except HTTPException:
        # Re-raise HTTP exceptions (already properly formatted)
        raise
    except Exception as e:
        logger.error(f"❌ Unexpected error in auth handler: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during authentication"
        )

@app.get(
    "/auth/user/{firebase_uid}",
    response_model=UserProfile,
    summary="Get User Profile",
    description="Get user profile data from Supabase database using Firebase UID"
)
async def get_user_profile(firebase_uid: str):
    """
    Get user profile from Supabase database
    
    Args:
        firebase_uid (str): Firebase user ID from URL path
        
    Returns:
        UserProfile: User profile data
    """
    try:
        user_data = await get_user_from_supabase(firebase_uid)
        
        if not user_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return UserProfile(
            uid=user_data['firebase_uid'],
            email=user_data['email'],
            name=user_data.get('name', ''),
            picture=user_data.get('picture', ''),
            provider=user_data.get('provider', 'email'),
            email_verified=user_data.get('email_verified', False),
            created_at=user_data.get('created_at'),
            last_login=user_data.get('last_login')
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error fetching user profile: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch user profile"
        )

@app.put(
    "/auth/user/{firebase_uid}",
    response_model=UserProfile,
    summary="Update User Profile",
    description="Update user profile information (name, picture, etc.)"
)
async def update_user_profile(firebase_uid: str, update_data: UserUpdateRequest):
    """
    Update user profile information
    
    Args:
        firebase_uid (str): Firebase user ID
        update_data (UserUpdateRequest): Data to update
        
    Returns:
        UserProfile: Updated user profile
    """
    if not supabase_initialized or not supabase:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Supabase service is not configured. Please set up .env file with Supabase credentials"
        )
    
    try:
        # Check if user exists
        existing_user = await get_user_from_supabase(firebase_uid)
        if not existing_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Prepare update data (only include non-None values)
        update_fields = {}
        if update_data.name is not None:
            update_fields['name'] = update_data.name
        if update_data.picture is not None:
            update_fields['picture'] = update_data.picture
        
        if not update_fields:
            # No fields to update
            return UserProfile(**existing_user)
        
        # Update user in Supabase
        result = supabase.table('users').update(update_fields).eq('firebase_uid', firebase_uid).execute()
        
        if result.data:
            updated_user = result.data[0]
            logger.info(f"✅ Updated profile for user: {firebase_uid}")
            
            return UserProfile(
                uid=updated_user['firebase_uid'],
                email=updated_user['email'],
                name=updated_user.get('name', ''),
                picture=updated_user.get('picture', ''),
                provider=updated_user.get('provider', 'email'),
                email_verified=updated_user.get('email_verified', False),
                created_at=updated_user.get('created_at'),
                last_login=updated_user.get('last_login')
            )
        else:
            raise Exception("Update operation returned no data")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error updating user profile: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user profile"
        )

@app.delete(
    "/auth/user/{firebase_uid}",
    summary="Delete User",
    description="Delete user from Supabase database (Firebase user deletion should be handled on frontend)"
)
async def delete_user(firebase_uid: str):
    """
    Delete user from Supabase database
    
    Note: This only deletes the user from Supabase. 
    Firebase user deletion should be handled on the frontend.
    """
    if not supabase_initialized or not supabase:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Supabase service is not configured. Please set up .env file with Supabase credentials"
        )
    
    try:
        # Check if user exists
        existing_user = await get_user_from_supabase(firebase_uid)
        if not existing_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Delete user from Supabase
        result = supabase.table('users').delete().eq('firebase_uid', firebase_uid).execute()
        
        logger.info(f"✅ Deleted user from Supabase: {firebase_uid}")
        
        return {
            "success": True,
            "message": "User deleted from database successfully",
            "note": "Remember to also delete the user from Firebase on the frontend"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error deleting user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user"
        )

# ============================================================================
# EVENT HANDLERS
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    logger.info("🚀 FastAPI server starting up...")
    print("=" * 60)
    print("🔥 Firebase + Supabase Authentication API")
    print("=" * 60)
    print("📖 API Documentation: http://localhost:8000/docs")
    print("🏥 Health Check: http://localhost:8000/health")
    print("🔐 Authentication: http://localhost:8000/auth/login")
    print("=" * 60)
    
    if not firebase_initialized:
        print("⚠️  SETUP NEEDED: Firebase not configured")
        print("   1. Download service account key from Firebase Console")
        print("   2. Save as 'firebase-service-account.json' in project root")
        print("")
    
    if not supabase_initialized:
        print("⚠️  SETUP NEEDED: Supabase not configured")
        print("   1. Create .env file in project root")
        print("   2. Add SUPABASE_URL=your_project_url")
        print("   3. Add SUPABASE_ANON_KEY=your_anon_key")
        print("")
    
    if firebase_initialized and supabase_initialized:
        print("✅ All services configured and ready!")
        print("")
    
    print("=" * 60)

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("🛑 FastAPI server shutting down...")

# Run server directly
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)