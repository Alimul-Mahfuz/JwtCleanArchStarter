using JwtCleanArch.Application.DTOs;

namespace JwtCleanArch.Application.Interfaces
{
    public interface IAuthService
    {
        Task<AuthenticationResponseDto> RegisterAsync(string email, string password);
        Task<AuthenticationResponseDto> LoginAsync(string email, string password);
        Task<AuthenticationResponseDto> RefreshTokenAsync(string refreshToken);
    }
}
