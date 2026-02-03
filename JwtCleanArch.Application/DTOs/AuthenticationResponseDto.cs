namespace JwtCleanArch.Application.DTOs
{
    public class AuthenticationResponseDto
    {
        public string Token { get; set; }
        public string RefreshToken { get; set; }
        public DateTime Expires { get; set; }
    }
}
