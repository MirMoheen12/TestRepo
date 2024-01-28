using Microsoft.AspNetCore.Authentication;
using System.ComponentModel.DataAnnotations;

namespace BizDevSearch.Models
{
    public class LoginViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }
        public bool Rememberme { get; set; }
        public string ReturnUrl { get; set; }
        public IList<AuthenticationScheme> Externallogin { get; set; }
    }
}
