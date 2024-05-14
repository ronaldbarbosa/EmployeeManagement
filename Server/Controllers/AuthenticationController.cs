using BaseLibrary.DTOs;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ServerLibrary.Repositories.Interfaces;

namespace Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController(IUserAccountRepository userAccountRepository) : ControllerBase
    {
        [HttpPost("Register")]
        public async Task<IActionResult> CreateAsync(RegisterDTO user)
        {
            if (user is null) return BadRequest("Model is empty");
            var result = await userAccountRepository.CreateAsync(user);
            return Ok(result);
        }

        [HttpPost("Login")]
        public async Task<IActionResult> SignInAsync(LoginDTO user)
        {
            if (user == null) return BadRequest("Model is empty");
            var result = await userAccountRepository.SignInAsync(user);
            return Ok(result);
        }

        [HttpPost("Refresh-Token")]
        public async Task<IActionResult> RefreshTokenAsync(RefreshTokenDTO token)
        {
            if (token == null) return BadRequest("Model is empty");
            var result = await userAccountRepository.RefreshTokenAsync(token);
            return Ok(result);
        }
    }
}
