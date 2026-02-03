using System.ComponentModel.DataAnnotations.Schema;

namespace JwtCleanArch.Domain.Entities
{
    public class ApplicationUser
    {
        public int Id { get; set; }
        public string FullName { get; set; }
        public string Email { get; set; }
        public string? Address { get; set; }

        [ForeignKey("UserId")]
        public string IdentityUserId { get; set; }
    }
}
