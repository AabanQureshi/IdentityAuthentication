namespace IdentityProject2.Servicies
{
    public interface ISMTPService
    {
        Task<bool> SendEmailAsync(string toEmail, string subject, string body);
    }
}
