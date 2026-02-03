using System.ComponentModel.DataAnnotations;

namespace JwtCleanArch.Application.DTOs
{
    public class AuthenticationRequestDto
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}
