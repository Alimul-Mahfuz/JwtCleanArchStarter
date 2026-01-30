using JwtCleanArch.Application.DTOs;
using JwtCleanArch.Application.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace JwtCleanArch.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthenticationController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] AuthenticationRequestDto requestDto)
        {
            var result = await _authService.RegisterAsync(requestDto.Email, requestDto.Password);
            return Ok(result);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] AuthenticationRequestDto request)
        {
            var result = await _authService.LoginAsync(request.Email, request.Password);
            return Ok(result);
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] AuthenticationResponseDto request)
        {
            try
            {
                var response = await _authService.RefreshTokenAsync(request.RefreshToken);
                return Ok(response);
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new ProblemDetails
                {
                    Title = "Invalid refresh token",
                    Detail = ex.Message,
                    Status = StatusCodes.Status400BadRequest
                });
            }
        }
    }
}
