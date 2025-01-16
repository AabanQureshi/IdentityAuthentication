using IdentityProject2.Models;
using System.Net.Mail;
using System.Net;
using Microsoft.Extensions.Options;

namespace IdentityProject2.Servicies
{
    public class SMTPService : ISMTPService
    {
        private readonly EmailSettings _emailSettings;

        public SMTPService(IOptions<EmailSettings> emailSettings)
        {
            _emailSettings = emailSettings.Value;
        }
        public async Task<bool> SendEmailAsync(string toEmail, string subject, string body)
        {
            try
            {
                var mailMessage = new MailMessage();
                mailMessage.From = new MailAddress(_emailSettings.FromEmail);
                mailMessage.To.Add(toEmail);
                mailMessage.Subject = subject;
                mailMessage.Body = body;
                mailMessage.IsBodyHtml = false;



                using var smtpClient = new SmtpClient(_emailSettings.SmtpServer, _emailSettings.Port)
                {
                    DeliveryMethod = SmtpDeliveryMethod.Network,
                    UseDefaultCredentials = false,
                    Credentials = new NetworkCredential(_emailSettings.FromEmail, _emailSettings.Password),
                    EnableSsl = true
                };

                await smtpClient.SendMailAsync(mailMessage);
            }
            catch (Exception ex)
            {
                // Log error or rethrow
                return false;
            }
            return true;
        }
    }
}
