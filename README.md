##jwt-refresh-api

###This project implements a secure and robust authentication system utilizing JSON Web Tokens (JWTs) with a two-token approach:
a short-lived Access Token and a long-lived Refresh Token. 
The primary goal is to enhance application security by minimizing the exposure window of the primary authentication token, while maintaining a seamless user experience
The system is designed to automatically detect an expired Access Token and securely exchange the Refresh Token for a new pair, preventing constant re-login prompts. 
The Refresh Token is stored in a secure, HTTP-Only cookie and validated against a server-side database whitelist to enable immediate token revocation upon logout or security breach, significantly improving session management and protection against common web vulnerabilities like XSS.




##Features
1   User Registration →	Allows new users to create an account
2	  User Login →	Registered users can log in securely using valid credentials.
3   Protected Routes →	Only authenticated users with valid access tokens can access restricted pages
4  	JWT Token-Based Authentication →	    Implements JSON Web Tokens (JWT) to securely verify user identity without storing sessions on the server.
5  	Refresh Token Mechanism →   When an access token expires, the frontend automatically requests a new token using
6  	Real-Time Input Validation →    Form validation dynamically checks
7  	Error & Validation Handling →   Displays clear error messages for invalid inputs

##Final Project Structure

/jwt-refresh-demo
|
├── server.js 
|
├── client.html
|
└── package.json


##Author 
    KRISHNAKUMAR R


  
