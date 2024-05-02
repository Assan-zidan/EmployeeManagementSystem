using BaseLibrary.DTOs;
using BaseLibrary.Responses;
using Microsoft.Extensions.Options;
using ServerLibrary.Helpers;
using ServerLibrary.Data;
using ServerLibrary.Repositories.Contrats;
using BaseLibrary.Entities;
using Microsoft.EntityFrameworkCore;
using Constants = ServerLibrary.Helpers.Constants;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ServerLibrary.Repositories.Implementations
{
    public class UserAccountRepository(IOptions<JwtSection> config, AppDbContext appDbContext) : IUserAccount
    {
        public async Task<GeneralResponse> CreateAsync(Register user)
        {
            if (user == null) return new GeneralResponse(false, "Mode is empty");

            var checkuser  = await FindUserByEmail(user.Email!);
            if (checkuser != null) return new GeneralResponse(false, "user registred already");

            var applicationUser = await AddToDatabase(new ApplicationUser()
            {
                Fullname = user.FullName,
                Email = user.Email,
                Password = BCrypt.Net.BCrypt.HashPassword(user.Password)
            });

            //Check, create and asign role
            var checkAdminRole = await appDbContext.SystemRoles.FirstOrDefaultAsync(x => x.Name!.Equals(Constants.Admin));
            if (checkAdminRole is null)
            {
                var createAdminRole = await AddToDatabase(new SystemRole() { Name = Constants.Admin });
                await AddToDatabase(new UserRole() { RoleId = createAdminRole.Id, UserId = applicationUser.Id });
                return new GeneralResponse(true, "Account Created");
            }

            var checkUserRole = await appDbContext.SystemRoles.FirstOrDefaultAsync(x => x.Name!.Equals(Constants.User));
            SystemRole response = new();
            if (checkUserRole is null)
            {
                response = await AddToDatabase(new SystemRole() { Name = Constants.User });
                await AddToDatabase(new UserRole() { RoleId = response.Id, UserId = applicationUser.Id });
            }
            else
            {
                await AddToDatabase(new UserRole() { RoleId = checkUserRole.Id, UserId = applicationUser.Id });
            }
            return new GeneralResponse(true, "Account Created");
        }

        public async Task<LoginResponse> SingInAsync(Login user)
        {
            if (user is null) return new LoginResponse(false, "Model is empty");
            var applicationUser = await FindUserByEmail(user.Email!);

            if (applicationUser is null) return new LoginResponse(false, "User not found");

            //Verify the password
            if (!BCrypt.Net.BCrypt.Verify(user.Password, applicationUser.Password))
                return new LoginResponse(false, "Email/Password not valid");

            //Get the user'a role
            var getUserRole = await FindUserRole(applicationUser.Id);
            if (getUserRole is null) return new LoginResponse(false, "User role not found1");

            var getRoleName = await FindRoleName(getUserRole.RoleId);
            if (getRoleName is null) return new LoginResponse(false, "User role name not found");

            string jwtToken = GenerateToken(applicationUser, getRoleName!.Name!);
            Console.WriteLine(jwtToken);
            string refreshToken = GenerateRefreshToken();

            //Save the refresh token to the database
            var findUser = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(x => x.UserId == applicationUser.Id);
            if (findUser is not null)
            {
                findUser!.Token = refreshToken;
                await appDbContext.SaveChangesAsync();
            }
            else
            {
                await AddToDatabase(new RefreshTokenInfo() { Token = refreshToken, UserId = applicationUser.Id });
            }
            return new LoginResponse(true, "Login successfullt", jwtToken, refreshToken);
        }

        public async Task<LoginResponse> RefreshTokenAsync(RefreshToken token)
        {
            if (token == null) return new LoginResponse(false, "Model is Empty");

            var findToken = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(x => x.Token!.Equals(token.Token));
            if (findToken == null) return new LoginResponse(false, "Refresh token is required");

            //get the user's details
            var user = await appDbContext.ApplicationUsers.FirstOrDefaultAsync(x => x.Id == findToken.UserId);
            if (user is null) return new LoginResponse(false, "Refresh token could not be generated because user not found");

            //get the role name
            var userRole = await FindUserRole(user.Id);
            var roleName = await FindRoleName(userRole!.RoleId);
            string jwtToken = GenerateToken(user, roleName!.Name!);
            string refreshToken = GenerateRefreshToken();

            //Check if the refresh token table contains that user info
            var updateRefreshToken = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(x => x.UserId == user.Id);
            if (updateRefreshToken == null) return new LoginResponse(false, "Refresh token could not be generated because user has not signed in");

            //If it exists, we have to refresh or update the existing token to a new one
            updateRefreshToken.Token = refreshToken;
            await appDbContext.SaveChangesAsync();
            return new LoginResponse(true, "Token refreshed successfully", jwtToken, refreshToken);
        }

        private string GenerateToken(ApplicationUser user, string role)
        {
            if (config.Value.Key == null)
            {
                throw new Exception("JWT secret key is not configured.");
            }
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config.Value.Key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var userClaims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Fullname!),
                new Claim(ClaimTypes.Email, user.Email!),
                new Claim(ClaimTypes.Role, role!)
            };
            var token = new JwtSecurityToken(
                issuer: config.Value.Issuer,
                audience: config.Value.Audience,
                claims: userClaims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: credentials
                );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private static string GenerateRefreshToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

        private async Task<UserRole?> FindUserRole(int userId) =>
           await appDbContext.UserRoles.FirstOrDefaultAsync(x => x.UserId == userId);

        private async Task<SystemRole?> FindRoleName(int roleId) =>
            await appDbContext.SystemRoles.FirstOrDefaultAsync(x => x.Id == roleId);
 


        private Task<ApplicationUser?> FindUserByEmail(string email)
        {
            return appDbContext.ApplicationUsers.FirstOrDefaultAsync(_ => _.Email!.ToLower()!.Equals(email!.ToLower()));
        }

        private async Task<T> AddToDatabase<T>(T model)
        {
            var result = appDbContext.Add(model!);
            await appDbContext.SaveChangesAsync();
            return (T)result.Entity;
        }

       
    }
}
