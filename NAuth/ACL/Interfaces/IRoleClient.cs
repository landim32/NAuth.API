using NAuth.DTO.User;

namespace NAuth.ACL.Interfaces
{
    public interface IRoleClient
    {
        Task<IList<RoleInfo>> ListAsync();
        Task<RoleInfo?> GetByIdAsync(long roleId);
        Task<RoleInfo?> GetBySlugAsync(string slug);
    }
}
