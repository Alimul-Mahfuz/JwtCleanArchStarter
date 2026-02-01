using JwtCleanArch.Application.Common;
using JwtCleanArch.Application.DTOs;

namespace JwtCleanArch.Application.Interfaces
{
    public interface IAuthService
    {
        Task<Result<AuthenticationResponseDto>> RegisterAsync(string email, string password);
        Task<Result<AuthenticationResponseDto>> LoginAsync(string email, string password);
        Task<Result<AuthenticationResponseDto>> RefreshTokenAsync(string refreshToken);
        Task<Result<object>> LogoutAsync(string refreshToken);
    }
}
