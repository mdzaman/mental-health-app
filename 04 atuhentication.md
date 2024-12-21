import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Separator } from "@/components/ui/separator";
import { 
  LogIn, Mail, Phone, Key, Shield, WhatsappLogo, Github, 
  Google, Facebook, Twitter, ArrowRight, Smartphone,
  AlertCircle 
} from 'lucide-react';

const AdvancedAuth = () => {
  // Authentication states
  const [authMethod, setAuthMethod] = useState('email');
  const [step, setStep] = useState('initial');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  
  // Form states
  const [identifier, setIdentifier] = useState(''); // email or phone
  const [password, setPassword] = useState('');
  const [otp, setOtp] = useState('');
  const [mfaCode, setMfaCode] = useState('');

  // Helper to validate email/phone
  const validateIdentifier = (value) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const phoneRegex = /^\+?[\d\s-]{10,}$/;
    return emailRegex.test(value) || phoneRegex.test(value);
  };

  // Handle initial identifier submit
  const handleIdentifierSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    if (!validateIdentifier(identifier)) {
      setError('Please enter a valid email or phone number');
      setLoading(false);
      return;
    }

    try {
      // API call to check if user exists and their auth methods
      const response = await fetch('/api/auth/check-identifier', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier })
      });
      
      if (!response.ok) throw new Error('Failed to verify identifier');
      
      const data = await response.json();
      if (data.hasMFA) {
        setStep('mfa');
      } else if (data.hasPassword) {
        setStep('password');
      } else {
        setStep('otp');
        // Automatically send OTP
        await sendOTP();
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Handle password-based login
  const handlePasswordLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await fetch('/api/auth/password-login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier, password })
      });
      
      if (!response.ok) throw new Error('Invalid credentials');
      
      const data = await response.json();
      handleAuthSuccess(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Handle OTP verification
  const handleOTPVerify = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await fetch('/api/auth/verify-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier, otp })
      });
      
      if (!response.ok) throw new Error('Invalid OTP');
      
      const data = await response.json();
      handleAuthSuccess(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Handle MFA verification
  const handleMFAVerify = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await fetch('/api/auth/verify-mfa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier, mfaCode })
      });
      
      if (!response.ok) throw new Error('Invalid MFA code');
      
      const data = await response.json();
      handleAuthSuccess(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Send OTP via email/SMS/WhatsApp
  const sendOTP = async () => {
    setLoading(true);
    setError('');

    try {
      const response = await fetch('/api/auth/send-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          identifier,
          method: authMethod // email/sms/whatsapp
        })
      });
      
      if (!response.ok) throw new Error('Failed to send OTP');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Send magic link
  const sendMagicLink = async () => {
    setLoading(true);
    setError('');

    try {
      const response = await fetch('/api/auth/magic-link', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier })
      });
      
      if (!response.ok) throw new Error('Failed to send magic link');
      
      setStep('magic-link-sent');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Handle social login
  const handleSocialLogin = async (provider) => {
    try {
      window.location.href = `/api/auth/${provider}`;
    } catch (err) {
      setError('Failed to initiate social login');
    }
  };

  // Handle successful authentication
  const handleAuthSuccess = (data) => {
    localStorage.setItem('token', data.token);
    // Additional success handling (e.g., redirect)
  };

  return (
    <div className="w-full max-w-md mx-auto p-4">
      {error && (
        <Alert variant="destructive" className="mb-4">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <LogIn className="h-5 w-5" />
            Sign In
          </CardTitle>
          <CardDescription>
            Choose your preferred way to sign in
          </CardDescription>
        </CardHeader>

        <CardContent>
          {step === 'initial' && (
            <>
              <form onSubmit={handleIdentifierSubmit} className="space-y-4">
                <div className="space-y-2">
                  <Label>Email or Phone Number</Label>
                  <div className="flex gap-2">
                    <Input
                      value={identifier}
                      onChange={(e) => setIdentifier(e.target.value)}
                      placeholder="Enter email or phone number"
                      required
                    />
                    <Button type="submit" disabled={loading}>
                      <ArrowRight className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </form>

              <div className="my-6">
                <Separator />
                <p className="text-center text-sm text-gray-500 my-4">or continue with</p>
                
                <div className="grid grid-cols-2 gap-4">
                  <Button 
                    variant="outline" 
                    onClick={() => handleSocialLogin('google')}
                    className="w-full"
                  >
                    <Google className="h-4 w-4 mr-2" />
                    Google
                  </Button>
                  
                  <Button 
                    variant="outline" 
                    onClick={() => handleSocialLogin('facebook')}
                    className="w-full"
                  >
                    <Facebook className="h-4 w-4 mr-2" />
                    Facebook
                  </Button>
                  
                  <Button 
                    variant="outline" 
                    onClick={() => handleSocialLogin('github')}
                    className="w-full"
                  >
                    <Github className="h-4 w-4 mr-2" />
                    GitHub
                  </Button>
                  
                  <Button 
                    variant="outline"
                    onClick={() => handleSocialLogin('twitter')}
                    className="w-full"
                  >
                    <Twitter className="h-4 w-4 mr-2" />
                    Twitter
                  </Button>
                </div>
              </div>
            </>
          )}

          {step === 'password' && (
            <form onSubmit={handlePasswordLogin} className="space-y-4">
              <div className="space-y-2">
                <Label>Password</Label>
                <Input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>
              <Button type="submit" className="w-full" disabled={loading}>
                {loading ? 'Signing in...' : 'Sign In'}
              </Button>
              <Button
                type="button"
                variant="ghost"
                className="w-full"
                onClick={() => setStep('otp')}
              >
                Use OTP instead
              </Button>
            </form>
          )}

          {step === 'otp' && (
            <div className="space-y-4">
              <div className="flex gap-2 mb-4">
                <Button
                  variant={authMethod === 'email' ? 'default' : 'outline'}
                  onClick={() => setAuthMethod('email')}
                  className="flex-1"
                >
                  <Mail className="h-4 w-4 mr-2" />
                  Email
                </Button>
                <Button
                  variant={authMethod === 'sms' ? 'default' : 'outline'}
                  onClick={() => setAuthMethod('sms')}
                  className="flex-1"
                >
                  <Smartphone className="h-4 w-4 mr-2" />
                  SMS
                </Button>
                <Button
                  variant={authMethod === 'whatsapp' ? 'default' : 'outline'}
                  onClick={() => setAuthMethod('whatsapp')}
                  className="flex-1"
                >
                  <WhatsappLogo className="h-4 w-4 mr-2" />
                  WhatsApp
                </Button>
              </div>

              <form onSubmit={handleOTPVerify} className="space-y-4">
                <div className="space-y-2">
                  <Label>Enter OTP</Label>
                  <Input
                    value={otp}
                    onChange={(e) => setOtp(e.target.value)}
                    placeholder="Enter OTP"
                    required
                  />
                </div>
                <Button type="submit" className="w-full" disabled={loading}>
                  Verify OTP
                </Button>
              </form>

              <Button
                type="button"
                variant="ghost"
                className="w-full"
                onClick={sendOTP}
                disabled={loading}
              >
                Resend OTP
              </Button>
            </div>
          )}

          {step === 'mfa' && (
            <form onSubmit={handleMFAVerify} className="space-y-4">
              <div className="space-y-2">
                <Label>Enter MFA Code</Label>
                <Input
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value)}
                  placeholder="Enter MFA code"
                  required
                />
              </div>
              <Button type="submit" className="w-full" disabled={loading}>
                Verify MFA
              </Button>
            </form>
          )}

          {step === 'magic-link-sent' && (
            <div className="text-center space-y-4">
              <Mail className="h-12 w-12 mx-auto text-primary" />
              <h3 className="text-lg font-semibold">Check your inbox</h3>
              <p className="text-sm text-gray-500">
                We've sent a magic link to your email address. Click the link to sign in.
              </p>
              <Button
                type="button"
                variant="ghost"
                className="w-full"
                onClick={sendMagicLink}
                disabled={loading}
              >
                Resend magic link
              </Button>
            </div>
          )}
        </CardContent>

        {step === 'initial' && (
          <CardFooter>
            <Button
              type="button"
              variant="ghost"
              className="w-full"
              onClick={sendMagicLink}
              disabled={loading}
            >
              <Key className="h-4 w-4 mr-2" />
              Send Magic Link
            </Button>
          </CardFooter>
        )}
      </Card>
    </div>
  );
};

export default AdvancedAuth;



from fastapi import FastAPI, HTTPException, Depends, Security, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr, constr
from typing import Optional, Union, Dict
import boto3
from datetime import datetime, timedelta
import jwt
import pyotp
import uuid
import json
from twilio.rest import Client
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import requests

app = FastAPI(title="Mental Health Platform - Advanced Authentication Service")

# AWS Services
dynamodb = boto3.resource('dynamodb')
ses = boto3.client('ses')
user_table = dynamodb.Table('users')
otp_table = dynamodb.Table('otps')
mfa_table = dynamodb.Table('mfa_secrets')

# Configuration (In production, use AWS Secrets Manager)
CONFIG = {
    'JWT_SECRET': 'your-secret-key',
    'JWT_ALGORITHM': 'HS256',
    'JWT_EXPIRES_IN': 30,  # minutes
    'TWILIO_ACCOUNT_SID': 'your-twilio-sid',
    'TWILIO_AUTH_TOKEN': 'your-twilio-token',
    'SENDGRID_API_KEY': 'your-sendgrid-key',
    'WHATSAPP_API_KEY': 'your-whatsapp-key',
    'OTP_EXPIRES_IN': 10,  # minutes
    'MAGIC_LINK_EXPIRES_IN': 15,  # minutes
    'ALLOWED_ORIGINS': ['http://localhost:3000']
}

# Models
class UserIdentifier(BaseModel):
    identifier: str  # Email or phone number

class OTPRequest(BaseModel):
    identifier: str
    method: str  # email/sms/whatsapp

class OTPVerify(BaseModel):
    identifier: str
    otp: str

class PasswordLogin(BaseModel):
    identifier: str
    password: str

class MFAVerify(BaseModel):
    identifier: str
    code: str

class SocialLoginCallback(BaseModel):
    code: str
    state: str

# Helper Functions
def generate_otp() -> str:
    return pyotp.random_base32()[:6]

def generate_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=CONFIG['JWT_EXPIRES_IN'])
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, CONFIG['JWT_SECRET'], algorithm=CONFIG['JWT_ALGORITHM'])

def verify_token(token: str) -> dict:
    try:
        return jwt.decode(token, CONFIG['JWT_SECRET'], algorithms=[CONFIG['JWT_ALGORITHM']])
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def is_valid_phone(phone: str) -> bool:
    # Basic phone validation - enhance as needed
    return phone.startswith('+') and len(phone) >= 10

def is_valid_email(email: str) -> bool:
    try:
        EmailStr.validate(email)
        return True
    except:
        return False

async def send_email_otp(email: str, otp: str):
    try:
        message = Mail(
            from_email='noreply@yourapp.com',
            to_emails=email,
            subject='Your OTP Code',
            html_content=f'Your OTP code is: <strong>{otp}</strong>')
        
        sg = SendGridAPIClient(CONFIG['SENDGRID_API_KEY'])
        response = sg.send(message)
        return response.status_code == 202
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send email: {str(e)}")

async def send_sms_otp(phone: str, otp: str):
    try:
        client = Client(CONFIG['TWILIO_ACCOUNT_SID'], CONFIG['TWILIO_AUTH_TOKEN'])
        message = client.messages.create(
            body=f'Your OTP code is: {otp}',
            from_='+1234567890',  # Your Twilio number
            to=phone
        )
        return True
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send SMS: {str(e)}")

async def send_whatsapp_otp(phone: str, otp: str):
    try:
        # Using WhatsApp Business API
        url = 'https://graph.facebook.com/v13.0/YOUR_PHONE_NUMBER_ID/messages'
        headers = {
            'Authorization': f'Bearer {CONFIG["WHATSAPP_API_KEY"]}',
            'Content-Type': 'application/json'
        }
        data = {
            'messaging_product': 'whatsapp',
            'to': phone,
            'type': 'template',
            'template': {
                'name': 'otp_message',
                'language': {'code': 'en'},
                'components': [
                    {
                        'type': 'body',
                        'parameters': [{'type': 'text', 'text': otp}]
                    }
                ]
            }
        }
        response = requests.post(url, headers=headers, json=data)
        return response.status_code == 200
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send WhatsApp message: {str(e)}")

# API Endpoints
@app.post("/api/auth/check-identifier")
async def check_identifier(user_data: UserIdentifier):
    try:
        # Check if identifier is email or phone
        identifier = user_data.identifier
        is_email = is_valid_email(identifier)
        is_phone = is_valid_phone(identifier)
        
        if not (is_email or is_phone):
            raise HTTPException(status_code=400, detail="Invalid identifier format")

        # Query user table
        response = user_table.query(
            IndexName='identifier-index',
            KeyConditionExpression='identifier = :id',
            ExpressionAttributeValues={':id': identifier}
        )

        user = response.get('Items', [None])[0]
        if not user:
            return {
                "exists": False,
                "authMethods": ["otp", "magic-link"]
            }

        return {
            "exists": True,
            "hasPassword": bool(user.get('has_password')),
            "hasMFA": bool(user.get('mfa_enabled')),
            "authMethods": user.get('auth_methods', ["otp", "magic-link"])
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/auth/send-otp")
async def send_otp(otp_request: OTPRequest, background_tasks: BackgroundTasks):
    try:
        identifier = otp_request.identifier
        method = otp_request.method
        
        # Generate OTP
        otp = generate_otp()
        expires_at = datetime.utcnow() + timedelta(minutes=CONFIG['OTP_EXPIRES_IN'])
        
        # Store OTP
        otp_table.put_item(Item={
            'identifier': identifier,
            'otp': otp,
            'expires_at': expires_at.isoformat(),
            'created_at': datetime.utcnow().isoformat()
        })
        
        # Send OTP based on method
        if method == 'email' and is_valid_email(identifier):
            background_tasks.add_task(send_email_otp, identifier, otp)
        elif method == 'sms' and is_valid_phone(identifier):
            background_tasks.add_task(send_sms_otp, identifier, otp)
        elif method == 'whatsapp' and is_valid_phone(identifier):
            background_tasks.add_task(send_whatsapp_otp, identifier, otp)
        else:
            raise HTTPException(status_code=400, detail="Invalid method for identifier")
        
        return {"message": "OTP sent successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/auth/verify-otp")
async def verify_otp(verification: OTPVerify):
    try:
        # Get stored OTP
        response = otp_table.get_item(Key={
            'identifier': verification.identifier
        })
        
        stored_otp = response.get('Item')
        if not stored_otp:
            raise HTTPException(status_code=400, detail="Invalid OTP")
        
        # Check expiration
        expires_at = datetime.fromisoformat(stored_otp['expires_at'])
        if datetime.utcnow() > expires_at:
            raise HTTPException(status_code=400, detail="OTP expired")
        
        # Verify OTP
        if stored_otp['otp'] != verification.otp:
            raise HTTPException(status_code=400, detail="Invalid OTP")
        
        # Generate token
        token = generate_token({"sub": verification.identifier})
        
        # Delete used OTP
        otp_table.delete_item(Key={'identifier': verification.identifier})
        
        return {"token": token}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/auth/magic-link")
async def send_magic_link(user_data: UserIdentifier, background_tasks: BackgroundTasks):
    try:
        if not is_valid_email(user_data.identifier):
            raise HTTPException(status_code=400, detail="Magic links require email")
        
        # Generate token for magic link
        token = generate_token({
            "sub": user_data.identifier,
            "type": "magic_link"
        })
        
        # Create magic link
        magic_link = f"https://yourapp.com/auth/verify-magic-link?token={token}"
        
        # Send email with magic link
        message = Mail(
            from_email='noreply@yourapp.com',
            to_emails=user_data.identifier,
            subject='Your Magic Link',
            html_content=f'Click <a href="{magic_link}">here</a> to sign in.')
        
        sg = SendGridAPIClient(CONFIG['SENDGRID_API_KEY'])
        background_tasks.add_task(sg.send, message)
        
        return {"message": "Magic link sent successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/auth/verify-mfa")
async def verify_mfa(verification: MFAVerify):
    try:
        # Get user's MFA secret
        response = mfa_table.get_item(Key={
            'identifier': verification.identifier
        })
        
        mfa_secret = response.get('Item', {}).get('secret')
        if not mfa_secret:
            raise HTTPException(status_code=400, detail="MFA not set up")
        
        # Verify MFA code
        totp = pyotp.TOTP(mfa_secret)
        if not totp.verify(verification.code):
            raise HTTPException(status_code=400, detail="Invalid MFA code")
        
        # Generate token
        token = generate_token({"sub": verification.identifier})
        
        return {"token": token}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Social Login Endpoints
@app.get("/api/auth/{provider}/login")
async def social_login(provider: str):
    providers = {
        'google': {
            'url': 'https://accounts.google.com/o/oauth2/v2/auth',
            'client_id': 'your-google-client-id',
            'scope': 'email profile'
        },
        'facebook': {
            'url': 'https://www.facebook.com/v13.0/dialog/oauth',
            'client_id': 'your-facebook-client-id',
            'scope': 'email'
        },
        'github': {
            'url': 'https://github.com/login/oauth/authorize',
            'client_id': 'your-github-client-id',
            'scope': 'user:email'
        }
    }
    
    if provider not in providers:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    
    config = providers[provider]
    state = str(uuid.uuid4())
    
    params = {
        'client_id': config['client_id'],
        'redirect_uri': f'https://yourapp.com/auth/{provider}/callback',
        'scope': config['scope'],
        'state': state,
        'response_type': 'code'
    }
    
    # Store state for verification
    # Implement state storage logic
    
    auth_url = f"{config['url']}?" + "&".join(f"{k}={v}" for k, v in params.items())
    return {"url": auth_url}

@app.post("/api/auth/{provider}/callback")
async def social_login_callback(provider: str, callback_data: SocialLoginCallback):
    try:
        # Verify state to prevent CSRF
        # Implement state verification logic
        
        # Exchange code for access token
        # Implement provider-specific token exchange
        
        # Get user info from provider
        # Implement provider-specific user info retrieval
        
        # Create or update user in your system
        # Generate token
        token = generate_token({"sub": "user_id"})
        
        return {"token": token}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))





import * as aws from '@aws-sdk/client-dynamodb';
import * as cdk from 'aws-cdk-lib';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as subscriptions from 'aws-cdk-lib/aws-sns-subscriptions';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import { Duration } from 'aws-cdk-lib';

export class AuthInfrastructureStack extends cdk.Stack {
  constructor(scope: cdk.App, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // DynamoDB Tables
    const usersTable = new dynamodb.Table(this, 'Users', {
      partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      stream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
    });

    // Add GSI for email lookup
    usersTable.addGlobalSecondaryIndex({
      indexName: 'email-index',
      partitionKey: { name: 'email', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Add GSI for phone lookup
    usersTable.addGlobalSecondaryIndex({
      indexName: 'phone-index',
      partitionKey: { name: 'phone', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    const otpTable = new dynamodb.Table(this, 'OTP', {
      partitionKey: { name: 'identifier', type: dynamodb.AttributeType.STRING },
      timeToLiveAttribute: 'ttl',
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const mfaTable = new dynamodb.Table(this, 'MFASecrets', {
      partitionKey: { name: 'user_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
    });

    const sessionTable = new dynamodb.Table(this, 'Sessions', {
      partitionKey: { name: 'session_id', type: dynamodb.AttributeType.STRING },
      timeToLiveAttribute: 'ttl',
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Cognito User Pool
    const userPool = new cognito.UserPool(this, 'UserPool', {
      userPoolName: 'mental-health-app-users',
      selfSignUpEnabled: true,
      signInAliases: {
        email: true,
        phone: true,
        username: true,
      },
      standardAttributes: {
        email: {
          required: true,
          mutable: true,
        },
        phoneNumber: {
          required: false,
          mutable: true,
        },
      },
      customAttributes: {
        'lastLogin': new cognito.StringAttribute({ mutable: true }),
        'authMethod': new cognito.StringAttribute({ mutable: true }),
        'mfaEnabled': new cognito.StringAttribute({ mutable: true }),
      },
      passwordPolicy: {
        minLength: 8,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // Add social providers
    const userPoolIdentityProviderGoogle = new cognito.UserPoolIdentityProviderGoogle(this, 'Google', {
      userPool,
      clientId: 'GOOGLE_CLIENT_ID', // Replace with actual client ID
      clientSecret: 'GOOGLE_CLIENT_SECRET', // Replace with actual client secret
      attributeMapping: {
        email: cognito.ProviderAttribute.GOOGLE_EMAIL,
        givenName: cognito.ProviderAttribute.GOOGLE_GIVEN_NAME,
        familyName: cognito.ProviderAttribute.GOOGLE_FAMILY_NAME,
        profilePicture: cognito.ProviderAttribute.GOOGLE_PICTURE,
      },
      scopes: ['profile', 'email', 'openid'],
    });

    const userPoolIdentityProviderFacebook = new cognito.UserPoolIdentityProviderFacebook(this, 'Facebook', {
      userPool,
      clientId: 'FACEBOOK_CLIENT_ID', // Replace with actual client ID
      clientSecret: 'FACEBOOK_CLIENT_SECRET', // Replace with actual client secret
      attributeMapping: {
        email: cognito.ProviderAttribute.FACEBOOK_EMAIL,
        givenName: cognito.ProviderAttribute.FACEBOOK_FIRST_NAME,
        familyName: cognito.ProviderAttribute.FACEBOOK_LAST_NAME,
      },
      scopes: ['public_profile', 'email'],
    });

    // Secrets Manager for API Keys
    const apiSecrets = new secretsmanager.Secret(this, 'APISecrets', {
      secretName: 'mental-health-app/api-secrets',
      generateSecretString: {
        secretStringTemplate: JSON.stringify({
          TWILIO_ACCOUNT_SID: 'placeholder',
          TWILIO_AUTH_TOKEN: 'placeholder',
          SENDGRID_API_KEY: 'placeholder',
          WHATSAPP_API_KEY: 'placeholder',
        }),
        generateStringKey: 'JWT_SECRET',
      },
    });

    // SNS Topics for notifications
    const notificationTopic = new sns.Topic(this, 'NotificationTopic', {
      displayName: 'Auth Notifications',
    });

    // SQS Dead Letter Queue
    const dlq = new sqs.Queue(this, 'NotificationDLQ', {
      queueName: 'auth-notification-dlq',
      retentionPeriod: Duration.days(14),
    });

    // SQS Queue for notification processing
    const notificationQueue = new sqs.Queue(this, 'NotificationQueue', {
      queueName: 'auth-notification-queue',
      visibilityTimeout: Duration.seconds(300),
      deadLetterQueue: {
        queue: dlq,
        maxReceiveCount: 3,
      },
    });

    // Subscribe SQS to SNS
    notificationTopic.addSubscription(
      new subscriptions.SqsSubscription(notificationQueue)
    );

    // Lambda for notification processing
    const notificationHandler = new lambda.Function(this, 'NotificationHandler', {
      runtime: lambda.Runtime.PYTHON_3_9,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda/notification'),
      environment: {
        SECRETS_ARN: apiSecrets.secretArn,
      },
    });

    // Grant permissions
    apiSecrets.grantRead(notificationHandler);
    notificationQueue.grantConsumeMessages(notificationHandler);
    
    // API Gateway
    const api = new apigateway.RestApi(this, 'AuthAPI', {
      restApiName: 'Authentication Service',
      description: 'API for authentication services',
      defaultCorsPreflightOptions: {
        allowOrigins: apigateway.Cors.ALL_ORIGINS,
        allowMethods: apigateway.Cors.ALL_METHODS,
      },
    });

    // Outputs
    new cdk.CfnOutput(this, 'UserPoolId', {
      value: userPool.userPoolId,
      description: 'The ID of the Cognito User Pool',
    });

    new cdk.CfnOutput(this, 'UserTableName', {
      value: usersTable.tableName,
      description: 'The name of the Users table',
    });

    new cdk.CfnOutput(this, 'ApiUrl', {
      value: api.url,
      description: 'The URL of the API Gateway',
    });
  }
}

// DynamoDB table schemas
const UserTableSchema = {
  id: 'string', // Primary key
  email: 'string',
  phone: 'string',
  full_name: 'string',
  password_hash: 'string',
  mfa_enabled: 'boolean',
  auth_methods: 'string[]',
  created_at: 'string',
  updated_at: 'string',
  last_login: 'string',
  status: 'string',
  social_providers: 'map',
  preferences: 'map',
  metadata: 'map',
};

const OTPTableSchema = {
  identifier: 'string', // Primary key
  otp: 'string',
  type: 'string', // email/sms/whatsapp
  created_at: 'string',
  ttl: 'number',
  attempts: 'number',
};

const MFATableSchema = {
  user_id: 'string', // Primary key
  secret: 'string',
  backup_codes: 'string[]',
  created_at: 'string',
  last_used: 'string',
};

const SessionTableSchema = {
  session_id: 'string', // Primary key
  user_id: 'string',
  created_at: 'string',
  expires_at: 'string',
  ttl: 'number',
  device_info: 'map',
  ip_address: 'string',
  last_activity: 'string',
};

import json
import boto3
import os
from botocore.exceptions import ClientError
from twilio.rest import Client
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import requests
from typing import Dict, Any

# Initialize AWS clients
secrets = boto3.client('secretsmanager')
sns = boto3.client('sns')
dynamodb = boto3.resource('dynamodb')

def get_secrets() -> Dict[str, str]:
    """Retrieve secrets from AWS Secrets Manager"""
    try:
        secret_response = secrets.get_secret_value(
            SecretId=os.environ['SECRETS_ARN']
        )
        return json.loads(secret_response['SecretString'])
    except ClientError as e:
        print(f"Error retrieving secrets: {str(e)}")
        raise

def send_email(to_email: str, subject: str, content: str, secrets_dict: Dict[str, str]) -> bool:
    """Send email using SendGrid"""
    try:
        sg = SendGridAPIClient(secrets_dict['SENDGRID_API_KEY'])
        message = Mail(
            from_email='noreply@yourapp.com',
            to_emails=to_email,
            subject=subject,
            html_content=content
        )
        response = sg.send(message)
        return response.status_code == 202
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False

def send_sms(to_number: str, message: str, secrets_dict: Dict[str, str]) -> bool:
    """Send SMS using Twilio"""
    try:
        client = Client(
            secrets_dict['TWILIO_ACCOUNT_SID'],
            secrets_dict['TWILIO_AUTH_TOKEN']
        )
        message = client.messages.create(
            body=message,
            from_='+1234567890',  # Your Twilio number
            to=to_number
        )
        return True
    except Exception as e:
        print(f"Error sending SMS: {str(e)}")
        return False

def send_whatsapp(to_number: str, message: str, secrets_dict: Dict[str, str]) -> bool:
    """Send WhatsApp message using WhatsApp Business API"""
    try:
        url = 'https://graph.facebook.com/v13.0/YOUR_PHONE_NUMBER_ID/messages'
        headers = {
            'Authorization': f'Bearer {secrets_dict["WHATSAPP_API_KEY"]}',
            'Content-Type': 'application/json'
        }
        data = {
            'messaging_product': 'whatsapp',
            'to': to_number,
            'type': 'template',
            'template': {
                'name': 'auth_notification',
                'language': {'code': 'en'},
                'components': [
                    {
                        'type': 'body',
                        'parameters': [{'type': 'text', 'text': message}]
                    }
                ]
            }
        }
        response = requests.post(url, headers=headers, json=data)
        return response.status_code == 200
    except Exception as e:
        print(f"Error sending WhatsApp message: {str(e)}")
        return False

def process_notification(event: Dict[str, Any], secrets_dict: Dict[str, str]) -> bool:
    """Process notification based on type and channel"""
    try:
        notification_type = event['type']
        channel = event['channel']
        recipient = event['recipient']
        content = event['content']

        if notification_type == 'otp':
            subject = 'Your OTP Code'
        elif notification_type == 'magic_link':
            subject = 'Your Magic Link'
        elif notification_type == 'security_alert':
            subject = 'Security Alert'
        else:
            subject = 'Authentication Notification'

        if channel == 'email':
            return send_email(recipient, subject, content, secrets_dict)
        elif channel == 'sms':
            return send_sms(recipient, content, secrets_dict)
        elif channel == 'whatsapp':
            return send_whatsapp(recipient, content, secrets_dict)
        else:
            print(f"Unsupported channel: {channel}")
            return False

    except KeyError as e:
        print(f"Missing required field: {str(e)}")
        return False
    except Exception as e:
        print(f"Error processing notification: {str(e)}")
        return False

def handle_security_event(event: Dict[str, Any]) -> None:
    """Handle security-related events and alerts"""
    try:
        event_type = event.get('securityEventType')
        user_id = event.get('userId')
        metadata = event.get('metadata', {})

        # Log security event
        security_log_table = dynamodb.Table('SecurityEvents')
        security_log_table.put_item(Item={
            'user_id': user_id,
            'timestamp': event['timestamp'],
            'event_type': event_type,
            'metadata': metadata,
            'ip_address': event.get('ipAddress'),
            'user_agent': event.get('userAgent'),
            'location': event.get('location'),
            'risk_score': event.get('riskScore', 0)
        })

        # Check if immediate action is needed
        if event.get('riskScore', 0) > 80:
            # Trigger immediate security measures
            user_table = dynamodb.Table('Users')
            user_table.update_item(
                Key={'id': user_id},
                UpdateExpression='SET account_status = :status, security_flag = :flag',
                ExpressionAttributeValues={
                    ':status': 'LOCKED',
                    ':flag': 'HIGH_RISK'
                }
            )

            # Notify security team
            sns.publish(
                TopicArn=os.environ['SECURITY_ALERT_TOPIC'],
                Message=json.dumps({
                    'type': 'HIGH_RISK_ACTIVITY',
                    'userId': user_id,
                    'eventType': event_type,
                    'riskScore': event.get('riskScore', 0),
                    'timestamp': event['timestamp']
                })
            )

    except Exception as e:
        print(f"Error handling security event: {str(e)}")
        raise

def handler(event, context):
    """Main Lambda handler"""
    try:
        # Get secrets
        secrets_dict = get_secrets()
        
        # Process SQS batch
        if 'Records' in event:
            failed_messages = []
            for record in event['Records']:
                try:
                    message_body = json.loads(record['body'])
                    
                    # Handle security events
                    if message_body.get('type') == 'SECURITY_EVENT':
                        handle_security_event(message_body)
                    else:
                        # Process normal notification
                        success = process_notification(message_body, secrets_dict)
                        if not success:
                            failed_messages.append({
                                'itemIdentifier': record['messageId'],
                                'reason': 'ProcessingFailed'
                            })
                
                except Exception as e:
                    print(f"Error processing record: {str(e)}")
                    failed_messages.append({
                        'itemIdentifier': record['messageId'],
                        'reason': str(e)
                    })
            
            return {
                'batchItemFailures': failed_messages
            }
        
        else:
            # Direct invocation
            success = process_notification(event, secrets_dict)
            return {
                'statusCode': 200 if success else 500,
                'body': json.dumps({
                    'success': success,
                    'message': 'Notification processed successfully' if success else 'Failed to process notification'
                })
            }

    except Exception as e:
        print(f"Error in handler: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'success': False,
                'message': str(e)
            })
        }


from fastapi import Request, HTTPException
from typing import Dict, Optional, List
import boto3
import time
import json
from datetime import datetime, timedelta
import ipaddress
import geoip2.database
import hashlib
from redis import Redis
from user_agents import parse

class SecurityLayer:
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb')
        self.redis = Redis(host='localhost', port=6379, db=0)  # Configure for your Redis instance
        self.security_events_table = self.dynamodb.Table('SecurityEvents')
        self.rate_limits = {
            'login_attempts': {'count': 5, 'window': 300},  # 5 attempts per 5 minutes
            'otp_requests': {'count': 3, 'window': 600},    # 3 OTP requests per 10 minutes
            'password_reset': {'count': 2, 'window': 3600}, # 2 reset requests per hour
        }

    async def analyze_request(self, request: Request, action_type: str) -> Dict:
        """Analyze incoming request for security risks"""
        client_ip = request.client.host
        user_agent = request.headers.get('user-agent', '')
        
        # Basic risk assessment
        risk_factors = []
        risk_score = 0
        
        # Check for rate limiting
        if await self.is_rate_limited(client_ip, action_type):
            raise HTTPException(status_code=429, detail="Too many requests")

        # Analyze IP reputation
        ip_risk = await self.check_ip_reputation(client_ip)
        if ip_risk['is_risky']:
            risk_factors.append('suspicious_ip')
            risk_score += 30

        # Check for suspicious user agent
        ua_risk = self.analyze_user_agent(user_agent)
        if ua_risk['is_suspicious']:
            risk_factors.append('suspicious_user_agent')
            risk_score += 20

        # Velocity check
        velocity_risk = await self.check_velocity(client_ip, action_type)
        if velocity_risk['is_suspicious']:
            risk_factors.append('suspicious_velocity')
            risk_score += 25

        return {
            'risk_score': risk_score,
            'risk_factors': risk_factors,
            'metadata': {
                'ip_address': client_ip,
                'user_agent': user_agent,
                'geo_location': ip_risk.get('location'),
                'timestamp': datetime.utcnow().isoformat()
            }
        }

    async def is_rate_limited(self, identifier: str, action_type: str) -> bool:
        """Check if the request should be rate limited"""
        if action_type not in self.rate_limits:
            return False

        key = f"rate_limit:{action_type}:{identifier}"
        current_time = int(time.time())
        window = self.rate_limits[action_type]['window']
        max_requests = self.rate_limits[action_type]['count']

        # Use Redis sorted set for rate limiting
        self.redis.zadd(key, {str(current_time): current_time})
        self.redis.zremrangebyscore(key, 0, current_time - window)
        
        # Count requests in the current window
        request_count = self.redis.zcard(key)
        self.redis.expire(key, window)  # Set expiry for cleanup

        return request_count > max_requests

    async def check_ip_reputation(self, ip: str) -> Dict:
        """Check IP reputation using various sources"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check if IP is in known bad IP ranges
            if self.is_ip_in_blocklist(ip):
                return {'is_risky': True, 'reason': 'blocked_ip'}

            # GeoIP lookup
            with geoip2.database.Reader('path/to/GeoLite2-City.mmdb') as reader:
                response = reader.city(ip)
                location = {
                    'country': response.country.name,
                    'city': response.city.name,
                    'latitude': response.location.latitude,
                    'longitude': response.location.longitude
                }

            # Check if location is high-risk
            if response.country.name in self.get_high_risk_countries():
                return {
                    'is_risky': True,
                    'reason': 'high_risk_location',
                    'location': location
                }

            return {
                'is_risky': False,
                'location': location
            }

        except Exception as e:
            print(f"Error checking IP reputation: {str(e)}")
            return {'is_risky': True, 'reason': 'verification_failed'}

    def analyze_user_agent(self, user_agent_string: str) -> Dict:
        """Analyze user agent for suspicious patterns"""
        try:
            ua = parse(user_agent_string)
            
            suspicious_factors = []
            
            # Check for known bot patterns
            if 'bot' in user_agent_string.lower() or 'crawler' in user_agent_string.lower():
                suspicious_factors.append('bot_pattern')

            # Check for suspicious browser/OS combinations
            if ua.browser.family == 'IE' and ua.os.family == 'Linux':
                suspicious_factors.append('inconsistent_browser_os')

            # Check for missing or suspicious browser details
            if not ua.browser.family or not ua.os.family:
                suspicious_factors.append('incomplete_user_agent')

            return {
                'is_suspicious': len(suspicious_factors) > 0,
                'factors': suspicious_factors,
                'metadata': {
                    'browser': ua.browser.family,
                    'os': ua.os.family,
                    'device': ua.device.family
                }
            }

        except Exception as e:
            print(f"Error analyzing user agent: {str(e)}")
            return {'is_suspicious': True, 'factors': ['parsing_failed']}

    async def check_velocity(self, identifier: str, action_type: str) -> Dict:
        """Check for suspicious velocity of actions"""
        try:
            key = f"velocity:{action_type}:{identifier}"
            current_time = int(time.time())
            window = 3600  # 1 hour window

            # Record the action
            self.redis.zadd(key, {str(current_time): current_time})
            self.redis.zremrangebyscore(key, 0, current_time - window)
            self.redis.expire(key, window)

            # Get action counts
            action_count = self.redis.zcard(key)
            
            # Define velocity thresholds
            thresholds = {
                'login_attempts': 10,
                'password_reset': 3,
                'profile_updates': 5
            }

            is_suspicious = action_count > thresholds.get(action_type, 10)

            return {
                'is_suspicious': is_suspicious,
                'action_count': action_count,
                'window_size': window
            }

        except Exception as e:
            print(f"Error checking velocity: {str(e)}")
            return {'is_suspicious': True, 'reason': 'check_failed'}

    def log_security_event(self, event_type: str, user_id: Optional[str], metadata: Dict) -> None:
        """Log security events for analysis"""
        try:
            self.security_events_table.put_item(Item={
                'event_id': hashlib.sha256(f"{time.time()}{user_id}".encode()).hexdigest(),
                'user_id': user_id,
                'event_type': event_type,
                'timestamp': datetime.utcnow().isoformat(),
                'metadata': metadata
            })
        except Exception as e:
            print(f"Error logging security event: {str(e)}")

    def get_high_risk_countries(self) -> List[str]:
        """Get list of high-risk countries"""
        # This should be maintained based on your security requirements
        return [
            # Add countries based on your risk assessment
        ]

    def is_ip_in_blocklist(self, ip: str) -> bool:
        """Check if IP is in blocklist"""
        try:
            key = f"ip_blocklist:{ip}"
            return bool(self.redis.get(key))
        except Exception as e:
            print(f"Error checking IP blocklist: {str(e)}")
            return False

# Initialize security layer
security = SecurityLayer()

# FastAPI middleware for security checks
async def security_middleware(request: Request, call_next):
    """Middleware to perform security checks on all requests"""
    try:
        # Skip security checks for certain paths
        if request.url.path in ['/health', '/metrics']:
            return await call_next(request)

        # Perform security analysis
        security_analysis = await security.analyze_request(
            request,
            action_type=request.url.path.split('/')[-1]
        )

        # Add security analysis to request state
        request.state.security_analysis = security_analysis

        # Block high-risk requests
        if security_analysis['risk_score'] > 80:
            security.log_security_event(
                'high_risk_request_blocked',
                user_id=None,
                metadata=security_analysis['metadata']
            )
            raise HTTPException(status_code=403, detail="Request blocked for security reasons")

        # Proceed with the request
        response = await call_next(request)

        # Log security event for successful requests
        security.log_security_event(
            'successful_request',
            user_id=getattr(request.state, 'user_id', None),
            metadata=security_analysis['metadata']
        )

        return response

    except HTTPException as e:
        raise e
    except Exception as e:
        print(f"Error in security middleware: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal security error")


        
