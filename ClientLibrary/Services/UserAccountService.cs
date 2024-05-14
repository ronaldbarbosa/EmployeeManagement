using BaseLibrary.DTOs;
using BaseLibrary.Responses;
using ClientLibrary.Helpers;
using ClientLibrary.Services.Interfaces;
using System.Net.Http.Json;

namespace ClientLibrary.Services
{
    public class UserAccountService(GetHttpClient getHttpClient) : IUserAccountService
    {
        public const string AuthUrl = "api/Authentication";

        public async Task<GeneralResponse> CreateAsync(RegisterDTO user)
        {
            var httpClient = getHttpClient.GetPublicHttpClient();
            var result = await httpClient.PostAsJsonAsync($"{AuthUrl}/Register", user);
            if (!result.IsSuccessStatusCode) return new GeneralResponse(false, "Error occured");

            return await result.Content.ReadFromJsonAsync<GeneralResponse>()!;
        }

        public async Task<LoginResponse> RefreshTokenAsync(RefreshTokenDTO token)
        {
            throw new NotImplementedException();
        }

        public async Task<LoginResponse> SignInAsync(LoginDTO user)
        {
            var httpClient = getHttpClient.GetPublicHttpClient();
            var result = await httpClient.PostAsJsonAsync($"{AuthUrl}/Login", user);
            if (!result.IsSuccessStatusCode) return new LoginResponse(false, "Error occured");

            return await result.Content.ReadFromJsonAsync<LoginResponse>()!;
        }
    }
}
