﻿using JWTCourse.DTO;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;
namespace JWTCourse.Controllers
{
    public class AuthController : Controller
    {
        public static User user = new User();

        [HttpPost("register")]
        public async Task<ActionResult<User>> UserRegister(UserRegisterDTO res)
        {
            CreatePasswordHash(res.Password, out byte[] passwordHash, out byte[] passwordSalt);
            user.PasswordSalt = passwordSalt;
            user.PasswordHash = passwordHash;
            user.Username = res.Username;
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

            return Ok("User founded");
        }


        //Se utiliza el valor out para hacer referencia a multiples parametros
        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using(var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            }
             // En este punto, Dispose() se llama automáticamente y se liberan los recursos debido al USING
        }

        private bool VerifyPasswordHash(string password, byte[]passwordHash, byte[]passwordSalt)
        {
            using (var hmac =  new HMACSHA512(passwordSalt))
            {
                var passwordConfirmed = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
                return passwordConfirmed.SequenceEqual(passwordHash);
            }
        }

}
}
