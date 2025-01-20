using System.ComponentModel.DataAnnotations;

namespace IdentityProject2.Models
{
    public class LoginCredentialsVM
    {
        [Required]
        [EmailAddress(ErrorMessage = "Please Provide Authentic Email")]
        [Display(Name = "Email Address")]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; } = null!;

        [Required]
        [Display(Name = "Password")]
        [DataType(DataType.Password)]
        [MinLength(6, ErrorMessage = "Password must be at least 6 characters long")]
        [MaxLength(15, ErrorMessage = "Password must be at most 15 characters long")]
        public string Password { get; set; } = null!;

        [Display(Name = "Remember Me")]
        public bool RememberMe { get; set; }
    }

    public class SignupCredentialsVM
    {
        [Required]
        [EmailAddress(ErrorMessage = "Please Provide Authentic Email")]
        [Display(Name = "Email Address")]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; } = null!;


        [Required]
        [Display(Name = "Password")]
        [DataType(DataType.Password)]
        [MinLength(6, ErrorMessage = "Password must be at least 6 characters long")]
        [MaxLength(15, ErrorMessage = "Password must be at most 15 characters long")]
        public string Password { get; set; } = null!;

        [Required]
        [Display(Name = "Confirm Password")]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Password and Confirm Password must match")]
        [MinLength(6, ErrorMessage = "Password must be at least 6 characters long")]
        [MaxLength(15, ErrorMessage = "Password must be at most 15 characters long")]
        public string ConfirmPassword { get; set; } = null!;

    }

    public class OTPVM
    {
        [Required]
        [Display(Name = "Security Code")]
        [Length(6, 6, ErrorMessage = "Security Code must be 6 characters long")]
        public string OTP { get; set; } = null!;

        public bool rememerMe { get; set; }
    }

    public class ForgotPasswordVM
    {
        [Required]
        [EmailAddress(ErrorMessage = "Please Provide Authentic Email")]
        [Display(Name = "Email Address")]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; } = null!;

        public string? Token { get; set; }


    }

    public class ResetPasswordVM : SignupCredentialsVM
    {
        [Required]
        public string Token { get; set; } = null!;
    }




}
