using JwtCleanArch.Application.Common;
using JwtCleanArch.Application.Interfaces;
using JwtCleanArch.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace JwtCleanArch.Infrastructure.Services
{
    public class UserService : IUserService
    {
        private readonly ApplicationDbContext _context;

        public UserService(ApplicationDbContext context)
        {
            _context = context;
        }


        public async Task<Result<object>> UserInfoByIdentityUserIdAsync(string IdentityUserId)
        {
            var user = await _context.ApplicationUsers
                .FirstOrDefaultAsync(x => x.IdentityUserId == IdentityUserId);

            if (user == null)
                return Result<object>.Failure("Invalid user");

            var userDto = new
            {
                user.Id,
                user.FullName,
                user.Email
            };

            return Result<object>.SuccessResult(userDto);
        }

    }
}
