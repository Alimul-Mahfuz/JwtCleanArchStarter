using JwtCleanArch.Application.Common;

namespace JwtCleanArch.Application.Interfaces
{
    public interface IUserService
    {
        Task<Result<object>> UserInfoByIdentityUserIdAsync(string IdentityUserId);
    }
}
