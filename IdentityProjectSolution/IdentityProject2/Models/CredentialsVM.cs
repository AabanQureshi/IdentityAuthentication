using System.ComponentModel.DataAnnotations;

namespace IdentityProject2.Models
{
    public class LoginCredentialsVM
    {
        [Required]
        [EmailAddress(ErrorMessage = "Please Provide Authentic Email")]
        [Display(Name = "Email Address")]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }

        [Required]
        [Display(Name = "Password")]
        [DataType(DataType.Password)]
        [MinLength(6, ErrorMessage = "Password must be at least 6 characters long")]
        [MaxLength(15, ErrorMessage = "Password must be at most 15 characters long")]
        public string Password { get; set; }

        [Display(Name = "Remember Me")]
        public bool RememberMe { get; set; }
    }

    public class SignupCredentialsVM
    {
        [Required]
        [EmailAddress(ErrorMessage = "Please Provide Authentic Email")]
        [Display(Name = "Email Address")]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }

        [Required]
        [Display(Name = "Password")]
        [DataType(DataType.Password)]
        [MinLength(6, ErrorMessage = "Password must be at least 6 characters long")]
        [MaxLength(15, ErrorMessage = "Password must be at most 15 characters long")]
        public string Password { get; set; }

        [Required]
        [Display(Name = "Confirm Password")]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Password and Confirm Password must match")]
        [MinLength(6, ErrorMessage = "Password must be at least 6 characters long")]
        [MaxLength(15, ErrorMessage = "Password must be at most 15 characters long")]
        public string ConfirmPassword { get; set; }
    }


}
