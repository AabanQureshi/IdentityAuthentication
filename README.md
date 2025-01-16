<h1>Two-Factor Authentication (2FA) with QR Code and Email in ASP.NET Core</h1>

<h2>Description</h2>
    <p>
        This project demonstrates the implementation of Two-Factor Authentication (2FA) in an ASP.NET Core application. 
        It supports both QR code-based 2FA (for use with authenticator apps like Google Authenticator or Microsoft Authenticator) 
        and Email-based 2FA, providing users with a secure and flexible authentication experience.
    </p>

  <h2>Key Features</h2>
    <ul>
        <li><strong>User Authentication:</strong> Secure user login using ASP.NET Identity.</li>
        <li><strong>Two-Factor Authentication (2FA):</strong>
            <ul>
                <li><strong>QR Code-Based 2FA:</strong> Dynamically generates QR codes for setting up 2FA with authenticator apps.</li>
                <li><strong>Email-Based 2FA:</strong> Sends time-based one-time passwords (TOTP) to the user's email address.</li>
            </ul>
        </li>
        <li><strong>ASP.NET Core Identity Integration:</strong> Seamless integration with Identity for token generation and validation.</li>
        <li><strong>Email Configuration:</strong> Built-in SMTP email service for sending authentication codes.</li>
        <li><strong>Scalable and Secure:</strong> Implements best practices for authentication and user management.</li>
    </ul>

  <h2>Technologies Used</h2>
    <ul>
        <li>ASP.NET Core 6/7</li>
        <li>ASP.NET Core Identity</li>
        <li>QRCoder Library for QR Code Generation</li>
        <li>C#</li>
        <li>SMTP Email Service</li>
    </ul>

  <h2>Setup Instructions</h2>
    <ol>
        <li>Clone the repository:
            <pre><code>git clone &lt;repository-link&gt;</code></pre>
        </li>
        <li>Configure the database connection string and email settings in <code>appsettings.json</code>.
            <pre><code>
              "EmailSettings": {  
    "SMTPServer": "smtp.example.com",  
    "Port": 587,  
    "SenderEmail": "your-email@example.com",  
    "SenderPassword": "your-email-password"  
}
            </code></pre>
        </li>
        <li>Run migrations to set up the database:
            <pre><code>dotnet ef database update</code></pre>
        </li>
        <li>Launch the application:
            <pre><code>dotnet run</code></pre>
        </li>
    </ol>

  <h2>How to Use</h2>
    <ol>
        <li>Sign up or log in to the application.</li>
        <li>Enable Two-Factor Authentication from your account settings.</li>
        <li>For <strong>QR Code-Based 2FA</strong>:
            <ul>
                <li>Scan the generated QR code with an authenticator app.</li>
                <li>Use the TOTP code from the app for secure login.</li>
            </ul>
        </li>
        <li>For <strong>Email-Based 2FA</strong>:
            <ul>
                <li>Receive a one-time password (OTP) in your email.</li>
                <li>Enter the OTP during login to complete authentication.</li>
            </ul>
        </li>
    </ol>

  <h2>Future Enhancements</h2>
    <ul>
        <li>Support for push notifications as an additional 2FA method.</li>
        <li>Enhanced UI for managing 2FA preferences.</li>
    </ul>

  <h2>Contribution</h2>
    <p>
        You can fix the repository, raise issues, or contribute by submitting pull requests. 
        Suggestions for improvements are welcome!
    </p>
