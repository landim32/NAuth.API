namespace NAuth.ACL.Interfaces
{
    public interface ITenantSecretProvider
    {
        string? GetJwtSecret(string tenantId);
    }
}
