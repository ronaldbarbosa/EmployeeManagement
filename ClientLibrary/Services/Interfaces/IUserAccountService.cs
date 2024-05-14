using BaseLibrary.DTOs;
using BaseLibrary.Responses;

namespace ClientLibrary.Services.Interfaces
{
    public interface IUserAccountService
    {
        Task<GeneralResponse> CreateAsync(RegisterDTO user);
        Task<LoginResponse> SignInAsync(LoginDTO user);
        Task<LoginResponse> RefreshTokenAsync(RefreshTokenDTO token);

    }
}
