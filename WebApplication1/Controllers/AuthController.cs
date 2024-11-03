using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using WebApplication1.Models;
using WebApplication1.ModelsDto; 
using System.Data.SqlClient;
using Microsoft.AspNetCore.Authorization;

namespace WebApplication1.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserDataController : ControllerBase
    {
        private readonly string _connectionString;
        private readonly string _tokenString;

        public UserDataController(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("DefaultConnection")!;
            _tokenString = configuration.GetSection("AppSettings:Token").Value!;
        }

        [HttpPost("Registration")]
        public async Task<IActionResult> Registration([FromBody] UserRegistration user)
        {
            string query = "INSERT INTO UserData (FirstName, LastName, Email, HashPassword, CreatedDate) " +
                           "VALUES (@FirstName, @LastName, @Email, @HashPassword, @CreatedDate)";

            string passwordHash = BCrypt.Net.BCrypt.HashPassword(user.HashPassword);
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@FirstName", user.FirstName);
                    command.Parameters.AddWithValue("@LastName", user.LastName);
                    command.Parameters.AddWithValue("@Email", user.Email);
                    command.Parameters.AddWithValue("@HashPassword", passwordHash);
                    command.Parameters.AddWithValue("@CreatedDate", DateTime.Now);

                    await connection.OpenAsync();
                    await command.ExecuteNonQueryAsync();
                }
            }

            string token = CreateToken(user.FirstName, user.Email);
            return Ok(new { Token = token, Message = "User registered and token generated successfully." });
        }


        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UserLogin user)
        {
            string query = "SELECT * FROM UserData WHERE Email = @Email";
            using (SqlConnection connection = new SqlConnection(_connectionString))
            {
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Email", user.Email);
                    await connection.OpenAsync();
                    using (SqlDataReader reader = await command.ExecuteReaderAsync())
                    {
                        if (await reader.ReadAsync())
                        {
                            var userData = new UserData
                            {
                                UserId = reader.GetInt32(reader.GetOrdinal("UserId")),
                                FirstName = reader.GetString(reader.GetOrdinal("FirstName")),
                                LastName = reader.GetString(reader.GetOrdinal("LastName")),
                                Email = reader.GetString(reader.GetOrdinal("Email")),
                                HashPassword = reader.GetString(reader.GetOrdinal("HashPassword")),
                                CreatedDate = reader.GetDateTime(reader.GetOrdinal("CreatedDate"))
                            };

                            if (BCrypt.Net.BCrypt.Verify(user.Password, userData.HashPassword))
                            {
                                var token = CreateToken(userData.FirstName, userData.Email);
                                return Ok(new { Token = token, Message = "User Login successfully." });
                            }
                            else
                                return Unauthorized("Invalid password.");
                        }
                        else
                            return NotFound("User not found.");
                    }
                }
            }
        }
        
        [Authorize]
        [HttpGet("GetUserData")]
        public IActionResult GetUserData()
        {
            if (User.Identity.IsAuthenticated)
                return Ok(new { Message = "This is secure data, accessible only for authenticated users." });
            else
                return Unauthorized();
        }


        private string CreateToken(string firstName, string email)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, firstName),
                new Claim(JwtRegisteredClaimNames.Email, email)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_tokenString));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds
            );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }
    }
}