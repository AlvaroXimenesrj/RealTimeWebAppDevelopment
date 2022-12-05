using System.ComponentModel.DataAnnotations;
using System.Xml.Linq;

namespace ASC.WebApi.Models
{
    public class LoginViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }        
        public bool RememberMe { get; set; }
    }
}
