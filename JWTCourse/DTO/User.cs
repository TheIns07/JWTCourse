namespace JWTCourse.DTO
{
    public class User
    {
        public string Username { get; set; } = string.Empty;
        public byte[] PasswordHash { get; set; }
        public byte[] PasswordSalt { get; set; }
        public int TypeOfUser { get; set; }
        public string RefreshToken { get; set; } = String.Empty;
        public DateTime TokenCreated { get; set; }
        public DateTime TokenExpires { get; set; }

    }
}
