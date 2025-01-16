using IdentityProject2.Models;
using IdentityProject2.Servicies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using QRCoder;

namespace IdentityProject2.Controllers
{
    /// <summary>
    /// Negative Programing approch is used here as it is easy to understand and faster to code also it is recommened to code like this.
    /// 
    /// All the Authentication Related Actions and Methods are defined here.
    /// 
    /// No repos are used here as it would have been difficult to for some beginers to understand the flow.
    /// 
    /// This Controller is responsible for all the Authentication Related Actions no Authorization is done here.
    /// 
    /// Some Servicies are defined in the Services Folder.
    /// 
    /// You have to Setup the SMTP Service in the App.settings file (u have to provide the email, password and host. Everything Else is already Done).
    /// 
    /// You also have to setup the Connection String in the App.settings file (ServerName and(or) Db Name as well everything else is already defined).
    /// 
    /// Use Breakpoints to understand the flow of the code.
    /// 
    /// Nothing out of Context is done here.
    /// 
    /// Simple forms are used to get the data from the user.
    /// </summary>
    public class AuthController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ISMTPService _sMTPService;


        public AuthController(
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            ISMTPService sMTPService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _sMTPService = sMTPService;
        }
        /// <summary>
        /// This is the Index Action (Login Form) of the Auth Controller,
        /// which has the LoginCredentialsVM as the Model. (Press f12 on the model to see its definition)
        /// </summary>
        /// <returns>
        ///     View
        /// </returns>
        public IActionResult Index()
        {
            var model = new LoginCredentialsVM();
            return View(model);
        }


        /// <summary>
        /// This is the Post method of Index Action (Login Form) of the Auth Controller,
        /// 
        /// Credentials are validated and then the user is signed in.
        /// 
        /// if the email is not confirmed then the user is redirected to the EmailNotConfirmed Action.
        /// </summary>
        /// <param name="model"></param>
        /// <returns>
        ///     if Email Confrmed then to main page(here Privacy page is considered as the main page)
        ///     else to EmailNotConfirmed Action
        /// </returns>
        [HttpPost]
        public async Task<IActionResult> Index(LoginCredentialsVM model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false);

            if (!result.Succeeded || result == null)
            {
                ModelState.AddModelError("LoginError", "User not found");
                return View(model);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (!await _userManager.IsEmailConfirmedAsync(user))
            {
                return RedirectToAction("EmailNotConfirmed", user);
            }
            return RedirectToAction("Privacy", "home");

        }

        /// <summary>
        /// This is the Signup Action of the Auth Controller,
        /// which has SignupCredentialsVM as the Model. (Press f12 on the model to see its definition)
        /// </summary>
        /// <returns>
        ///     View (SignUp/ Registration Form)
        /// </returns>
        public IActionResult Signup()
        {
            var model = new SignupCredentialsVM();
            return View(model);
        }


        /// <summary>
        /// This is the Post method of Signup Action of the Auth Controller,
        /// model is validated and then the user is created.
        /// 
        /// and then the user is redirected to the Index Action.
        /// 
        /// An email confirmation is sent to the user as well.
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost]
        public async Task<IActionResult> Signup(SignupCredentialsVM model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError("SignupError", "Provide the Following Details");
                return View(model);
            }

            var user = new IdentityUser
            {
                UserName = model.Email,
                Email = model.Email
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("SignupError", error.Description);
                }
                await SendEmailConfirmation(user);
                return View(model);
            }



            return RedirectToAction("Index");


        }

        /// <summary>
        /// This is the ConfirmEmail Action of the Auth Controller,
        /// 
        /// User is redirected to this Action when the user clicks on the Email Confirmation Link.
        /// 
        /// user is first found by the UserID and then the Token is Confirmed.
        /// 
        /// User is Confirmed and then the user is redirected to the ConfirmEmail View.
        /// </summary>
        /// <param name="UserID"></param>
        /// <param name="Token"></param>
        /// <returns></returns>
        public async Task<IActionResult> ConfirmEmail(string UserID, string Token)
        {
            var user = await _userManager.FindByIdAsync(UserID);
            if (user == null)
            {
                return BadRequest();
            }

            var result = await _userManager.ConfirmEmailAsync(user, Token);

            var message = result.Succeeded ? "Email Confirmed Successfully" : "Error Confirming Email";

            return View("ConfirmEmail", message);
        }


        /// <summary>
        /// This is the EmailNotConfirmed Action of the Auth Controller,
        /// When the user is not confirmed then the user is redirected to this Action.
        /// An email confirmation is sent to the user (again as the first time was when he registered).
        /// </summary>
        /// <param name="User"></param>
        /// <returns></returns>
        public async Task<IActionResult> EmailNotConfirmed(IdentityUser User)
        {
            await SendEmailConfirmation(User);
            return View();

        }


        /// <summary>
        /// This is the SendEmailConfirmation Method of the Auth Controller (Good Approch is to make these type of function outside the Controller in seprate class/file),
        /// 
        /// Token is generated and then the Confirmation Link is generated.
        /// 
        /// An Email Confirmation is sent to the user.
        /// 
        /// </summary>
        /// <param name="user"></param>
        /// <returns>
        ///     Nothing is returned (you can chnage it to your needs)
        /// </returns>
        private async Task SendEmailConfirmation(IdentityUser user)
        {
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var confirmationLink = Url.Action("ConfirmEmail", "Auth", new { UserID = user.Id, Token = token }, Request.Scheme);
            var message = $"<a href=\"{confirmationLink}\">Click here to confirm your email</a>";
            await _sMTPService.SendEmailAsync(user.Email, "Email Confirmation", message);
        }



        /// <summary>
        /// This is the 2Factor Authentication Action of the Auth Controller by Email,
        /// 
        /// an OTP is generated and sent to the user's email.
        /// </summary>
        /// <returns></returns>
        public async Task<IActionResult> Email2FA()
        {
            var user = await _userManager.GetUserAsync(User);

            if (user == null || user.Email == null)
            {
                return RedirectToAction("Index");
            }


            var Email2FAToken = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");


            await _sMTPService.SendEmailAsync(user.Email, "2FA OTP", $"Please Use this OTP: {Email2FAToken ?? string.Empty}");

            return View();
        }

        /// <summary>
        /// This is the Post method of the 2Factor Authentication Action of the Auth Controller by Email,
        /// 
        /// the OTP is validated and Two Factor is enabled then the user is signed in.
        /// </summary>
        /// <param name="SecurityCode"></param>
        /// <returns>
        /// 
        /// Redirects to the Privacy Page (Main Page)
        /// 
        /// </returns>
        [HttpPost]
        public async Task<IActionResult> Email2FA(string SecurityCode)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError("", "Provide the Code sent to your email");
                return View();
            }

            var user = await _userManager.GetUserAsync(User);

            if (user == null)
            {
                return RedirectToAction("Index");
            }

            var res = await _userManager.VerifyTwoFactorTokenAsync(user, "Email", SecurityCode);

            if (!res)
            {
                ModelState.AddModelError("", "Invalid Code");
                return View();
            }
            await _userManager.SetTwoFactorEnabledAsync(user, true);
            await _signInManager.SignInAsync(user, false);
            return RedirectToAction("Privacy", "Home");


        }

        /// <summary>
        /// This is the 2Factor Authentication Action of the Auth Controller by App (Any Authenticator App can be used),
        /// 
        /// Token is generated and then the QR Code is generated.
        /// 
        /// </summary>
        /// <returns>
        /// 
        ///     View with the QR Code, which then have to be scanned by the Authenticator App.
        /// </returns>
        public async Task<IActionResult> App2FA()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null || user.Email == null)
            {
                return RedirectToAction("index");
            }

            await _userManager.ResetAuthenticatorKeyAsync(user);
            var App2FAToken = await _userManager.GetAuthenticatorKeyAsync(user);

            var qr = QRCodeAuthenticator("IdentityProject2", user.Email, App2FAToken ?? string.Empty);
            return View(qr);
        }


        /// <summary>
        /// This is the Post method of the 2Factor Authentication Action of the Auth Controller by App (Any Authenticator App can be used),
        /// 
        /// The Code is validated and then the Two Factor is enabled and the user is signed in.
        /// </summary>
        /// <param name="SecurityCode"></param>
        /// <returns></returns>
        [HttpPost]
        public async Task<IActionResult> App2FA(string SecurityCode)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError("", "Provide the Code displayed on the app");
                return View();
            }
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToAction("Index");
            }
            var res = await _userManager.VerifyTwoFactorTokenAsync(user, "Authenticator", SecurityCode);
            if (!res)
            {
                ModelState.AddModelError("", "Invalid Code");
                return View();
            }
            await _userManager.SetTwoFactorEnabledAsync(user, true);
            await _signInManager.SignInAsync(user, false);
            return RedirectToAction("Privacy", "Home");
        }


        /// <summary>
        /// 
        /// Generates a QR code for configuring two-factor authentication (2FA) with an authenticator app.
        /// 
        /// </summary>
        /// <param name="provider">
        ///     The name of the application or service providing 2FA (e.g., "MyApp").
        /// </param>
        /// 
        /// <param name="email">
        ///     The user's email address, used to identify the account in the authenticator app.
        /// </param>
        /// <param name="key">
        ///     The secret key shared between the server and the authenticator app for generating TOTP (Time-based OTP) codes.
        /// </param>
        /// <returns>
        ///     A byte array representing the QR code image in PNG format.
        /// </returns>
        public Byte[] QRCodeAuthenticator(string provider, string email, string key)
        {
            var qr = new QRCodeGenerator();
            var qrData = qr.CreateQrCode(
                $"otpauth://totp/{provider}:{email}?secret={key}&issuer={provider}",
                QRCodeGenerator.ECCLevel.Q);
            var qrCode = new PngByteQRCode(qrData);
            return qrCode.GetGraphic(25);
        }


        /// <summary>
        /// Simple Logout Action of the Auth Controller,
        /// </summary>
        /// <returns></returns>
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index");
        }
    }
}
