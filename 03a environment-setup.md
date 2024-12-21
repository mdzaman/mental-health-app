# Complete Setup Guide for Mental Health Application Development
## A Non-Technical Person's Guide to Getting Started

### Table of Contents
1. Essential Tools Installation
2. Code Development Setup
3. Cloud Services Setup
4. Database Setup
5. Mobile Development Setup
6. Testing Tools Setup
7. Monitoring Tools Setup

### 1. Essential Tools Installation

#### 1.1. Git Installation
Git is used for code version control.

**For Windows:**
1. Download Git from: https://git-scm.com/download/windows
2. Run the installer
3. During installation:
   - Accept default options
   - For "Adjusting your PATH environment", select "Git from the command line and also from 3rd-party software"
   - For line ending conversions, select "Checkout Windows-style, commit Unix-style line endings"

**For Mac:**
1. Open Terminal
2. Install Homebrew (package manager) by pasting:
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```
3. Install Git:
   ```bash
   brew install git
   ```

#### 1.2. Visual Studio Code Installation
VS Code is your main code editor.

**For Both Windows and Mac:**
1. Download from: https://code.visualstudio.com/
2. Run the installer
3. Install recommended extensions:
   - Python
   - React
   - Flutter
   - GitLens
   - Docker
   - AWS Toolkit

#### 1.3. Node.js Installation
Required for React development.

**For Windows:**
1. Download from: https://nodejs.org/
2. Choose LTS version
3. Run installer with default options

**For Mac:**
```bash
brew install node
```

#### 1.4. Python Installation
Required for backend development.

**For Windows:**
1. Download from: https://www.python.org/downloads/
2. Run installer
3. Check "Add Python to PATH"
4. Choose "Customize installation"
5. Select all optional features
6. Install for all users

**For Mac:**
```bash
brew install python
```

#### 1.5. Docker Desktop Installation
For containerization and local development.

**For Windows:**
1. Enable WSL2 (Windows Subsystem for Linux):
   - Open PowerShell as Administrator
   - Run: `wsl --install`
   - Restart computer
2. Download Docker Desktop from: https://www.docker.com/products/docker-desktop
3. Run installer

**For Mac:**
1. Download Docker Desktop from: https://www.docker.com/products/docker-desktop
2. Install the application
3. Start Docker Desktop

### 2. Code Development Setup

#### 2.1. Create Project Directory
**For Windows (Command Prompt):**
```bash
mkdir C:\Projects\mental-health-app
cd C:\Projects\mental-health-app
```

**For Mac (Terminal):**
```bash
mkdir ~/Projects/mental-health-app
cd ~/Projects/mental-health-app
```

#### 2.2. Initialize Git Repository
```bash
git init
```

#### 2.3. Set Up Backend Environment
```bash
# Create Python virtual environment
python -m venv venv

# Activate virtual environment
# For Windows:
venv\Scripts\activate
# For Mac:
source venv/bin/activate

# Install required Python packages
pip install fastapi uvicorn python-dotenv boto3 pytest
```

#### 2.4. Set Up Frontend Environment
```bash
# Create React application
npx create-react-app frontend
cd frontend
npm install @aws-amplify/ui-react @emotion/react @chakra-ui/react axios
```

### 3. Cloud Services Setup

#### 3.1. AWS Account Setup
1. Go to https://aws.amazon.com/
2. Click "Create an AWS Account"
3. Follow sign-up process
4. Set up billing alerts:
   - Go to AWS Console
   - Search for "Budgets"
   - Create a budget with your desired limit

#### 3.2. AWS CLI Installation

**For Windows:**
1. Download AWS CLI MSI installer from: https://aws.amazon.com/cli/
2. Run installer
3. Open Command Prompt
4. Run: `aws --version` to verify installation

**For Mac:**
```bash
brew install awscli
```

#### 3.3. Configure AWS CLI
```bash
aws configure
```
Enter your AWS access key, secret key, region (e.g., us-east-1), and output format (json)

### 4. Database Setup

#### 4.1. PostgreSQL Installation

**For Windows:**
1. Download from: https://www.postgresql.org/download/windows/
2. Run installer
3. Remember the password you set for the postgres user

**For Mac:**
```bash
brew install postgresql
brew services start postgresql
```

#### 4.2. MongoDB Installation (Optional)

**For Windows:**
1. Download from: https://www.mongodb.com/try/download/community
2. Run installer
3. Install MongoDB Compass (GUI tool)

**For Mac:**
```bash
brew tap mongodb/brew
brew install mongodb-community
brew services start mongodb-community
```

### 5. Mobile Development Setup

#### 5.1. Flutter Installation

**For Windows:**
1. Download Flutter SDK from: https://flutter.dev/docs/get-started/install/windows
2. Extract ZIP to C:\src\flutter
3. Add Flutter to PATH
4. Run: `flutter doctor` to check setup

**For Mac:**
```bash
brew install flutter
flutter doctor
```

#### 5.2. Android Studio Installation
1. Download from: https://developer.android.com/studio
2. Run installer
3. During setup, ensure you install:
   - Android SDK
   - Android SDK Platform
   - Android Virtual Device

### 6. Testing Tools Setup

#### 6.1. Postman Installation
For API testing:
1. Download from: https://www.postman.com/downloads/
2. Install and create a free account

#### 6.2. Jest Setup (Frontend Testing)
In your frontend directory:
```bash
npm install --save-dev jest @testing-library/react
```

### 7. Monitoring Tools Setup

#### 7.1. Install AWS CloudWatch Agent
This will be done through AWS CLI:
```bash
aws cloudwatch help
```

### 8. Verification Steps

Run these commands to verify your setup:

```bash
# Check Git
git --version

# Check Node.js
node --version
npm --version

# Check Python
python --version
pip --version

# Check AWS CLI
aws --version

# Check Flutter
flutter doctor

# Check Docker
docker --version
docker-compose --version
```

### 9. Common Issues and Solutions

#### Issue 1: Path Not Found
- Windows: Add to Path through System Properties > Environment Variables
- Mac: Add to PATH in ~/.zshrc or ~/.bash_profile

#### Issue 2: Permission Denied
- Windows: Run as Administrator
- Mac: Use sudo (carefully!)

#### Issue 3: Port Already in Use
```bash
# Windows
netstat -ano | findstr :[PORT]
taskkill /PID [PID] /F

# Mac
lsof -i :[PORT]
kill -9 [PID]
```

### 10. Next Steps

After completing the setup:
1. Test each component
2. Clone the project repository
3. Set up your IDE preferences
4. Configure git user:
```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

### 11. Maintenance

Regular updates:
```bash
# Update Node packages
npm update

# Update Python packages
pip install --upgrade -r requirements.txt

# Update Flutter
flutter upgrade

# Update AWS CLI
# Windows: Download new installer
# Mac:
brew upgrade awscli
```
