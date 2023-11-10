using JWTCourse.DTO;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
namespace JWTCourse.Controllers
{
    public class AuthController : Controller
    {
        public static User user = new User();
        protected readonly IConfiguration _configuration;
        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> UserRegister(UserRegisterDTO res)
        {
            CreatePasswordHash(res.Password, out byte[] passwordHash, out byte[] passwordSalt);
            user.PasswordSalt = passwordSalt;
            user.PasswordHash = passwordHash;
            user.Username = res.Username;
            user.TypeOfUser = res.TypeOfUser;
            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> LogInMethod(UserRegisterDTO userLog)
        {
            if(userLog.Username != user.Username)
            {
                return BadRequest();
            }

            if (VerifyPasswordHash(userLog.Password, user.PasswordHash, user.PasswordSalt)!= true) { 
                return BadRequest();
            }
            
            string token = CreateToken(user);
            var refreshToken = GenerateRefreshToken();
            SetRefreshToken(refreshToken);

            return Ok(token);
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<string>> RefreshToken()
        {
            var refreshToken = Request.Cookies["refresh-token"];

            if (!user.RefreshToken.Equals(refreshToken)) 
            {
                return Unauthorized("Invalid refresh Token.");
            }
            else if(user.TokenExpires < DateTime.Now) {
                return Unauthorized("Token Expires");
            }
            string token = CreateToken(user);
            var newRefreshToken = GenerateRefreshToken();
            SetRefreshToken(newRefreshToken);

            return Ok(token);
        }


        private RefreshToken GenerateRefreshToken()
        {
            var refreshToken = new RefreshToken()
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.UtcNow.AddDays(7),
                Created = DateTime.Now
            };
            return refreshToken;
        }

        private void SetRefreshToken(RefreshToken refreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = refreshToken.Expires,

            };
            Response.Cookies.Append("RefreshToken", refreshToken.Token, cookieOptions);

            user.RefreshToken = refreshToken.Token;
            user.TokenCreated = refreshToken.Created;
            user.TokenExpires = refreshToken.Expires;
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim> {
                new Claim(ClaimTypes.Name, user.Username),
            };

            if (user.TypeOfUser == 1)
            {
                claims.Add(new Claim(ClaimTypes.Role, "Admin"));
            }

            claims.Add(new Claim(ClaimTypes.Role, "Noob"));

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value));

            var credential = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: credential
            );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }


        //Se utiliza el valor out para hacer referencia a multiples parametros
        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using(var hmac = new HMACSHA256())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            }
             // En este punto, Dispose() se llama automáticamente y se liberan los recursos debido al USING
        }

        private bool VerifyPasswordHash(string password, byte[]passwordHash, byte[]passwordSalt)
        {
            using (var hmac =  new HMACSHA256(passwordSalt))
            {
                var passwordConfirmed = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
                return passwordConfirmed.SequenceEqual(passwordHash);
            }
        }

}
}
