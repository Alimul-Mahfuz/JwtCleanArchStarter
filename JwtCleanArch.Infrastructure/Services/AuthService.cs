using JwtCleanArch.Application.DTOs;
using JwtCleanArch.Application.Interfaces;
using JwtCleanArch.Domain.Entities;
using JwtCleanArch.Infrastructure.Data;
using JwtCleanArch.Infrastructure.Settings;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtCleanArch.Infrastructure.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ApplicationDbContext _context;
        private readonly JwtSettings _jwtSettings;

        public AuthService(UserManager<IdentityUser> userManager, ApplicationDbContext context, IOptions<JwtSettings> jwtSettings)
        {
            _userManager = userManager;
            _context = context;
            _jwtSettings = jwtSettings.Value;
        }

        async Task<AuthenticationResponseDto> IAuthService.RegisterAsync(string email, string password)
        {
            var existingUser = await _userManager.FindByEmailAsync(email);
            if (existingUser != null)
                throw new Exception("User already exists");

            var user = new IdentityUser
            {
                UserName = email,
                Email = email
            };

            var result = await _userManager.CreateAsync(user, password);
            if (!result.Succeeded)
                throw new Exception(string.Join(", ", result.Errors.Select(e => e.Description)));

            return await GenerateTokensAsync(user);
        }

        async Task<AuthenticationResponseDto> IAuthService.LoginAsync(string email, string password)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, password))
                throw new Exception("Invalid credentials");

            return await GenerateTokensAsync(user);
        }

        async Task<AuthenticationResponseDto> IAuthService.RefreshTokenAsync(string refreshToken)
        {
            var existingToken = await _context.UserRefreshTokens.FirstOrDefaultAsync(t => t.Token == refreshToken && !t.IsRevoked);
            if (existingToken == null || existingToken.Expires < DateTime.UtcNow)
            {
                throw new Exception("Invalid refresh token");
            }

            var user = await _userManager.FindByIdAsync(existingToken.UserId);

            if (user == null)
            {
                throw new Exception("Invalid user");
            }

            existingToken.IsRevoked = true;
            await _context.SaveChangesAsync();

            return await GenerateTokensAsync(user);


        }

        private async Task<AuthenticationResponseDto> GenerateTokensAsync(IdentityUser user)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            // Use JwtSecurityToken directly instead of SecurityTokenDescriptor
            var jwtToken = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_jwtSettings.TokenLifetimeMinutes),
                signingCredentials: creds
            );

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenString = tokenHandler.WriteToken(jwtToken);

            // Refresh Token (still custom, as ASP.NET Core doesn’t provide built-in refresh tokens)
            var refreshToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
            var userRefreshToken = new UserRefreshToken
            {
                UserId = user.Id,
                Token = refreshToken,
                Expires = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenLifetimeDays)
            };

            _context.UserRefreshTokens.Add(userRefreshToken);
            await _context.SaveChangesAsync();

            return new AuthenticationResponseDto
            {
                Token = tokenString,
                RefreshToken = refreshToken,
                Expires = jwtToken.ValidTo
            };
        }


    }
}
