using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace TokenAPI.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class StreamTokenController : Controller
    {
        private readonly string _apiKey = "9puabwjb5p2p";
        private readonly string _apiSecret = "xs93ftx87nujrm35z6eat7uzge5jky74hcby9umye2g4sdcdurkc25hmj8jf3gak";

        [HttpGet]
        [Route("generate")]
        public IActionResult GenerateToken(string userId)
        {
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest("userId is required");
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_apiSecret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("user_id", userId),
                    new Claim("role", "user")
                }),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);
            return Ok(new { token = tokenString });
        }
    }
}
