namespace JwtCleanArch.Domain.Entities
{
    public class UserRefreshToken
    {
        public int Id { get; set; }
        public string UserId { get; set; }  // IdentityUser Id
        public string Token { get; set; }
        public DateTime Expires { get; set; }
        public bool IsRevoked { get; set; } = false;
    }
}
