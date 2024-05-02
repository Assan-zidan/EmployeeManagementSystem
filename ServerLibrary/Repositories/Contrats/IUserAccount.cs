using BaseLibrary.DTOs;
using BaseLibrary.Responses;

namespace ServerLibrary.Repositories.Contrats
{
    public  interface IUserAccount
    {
        Task<GeneralResponse> CreateAsync(Register user);
        Task<LoginResponse> SingInAsync(Login user);

        Task<LoginResponse> RefreshTokenAsync(RefreshToken token);
    }
}
