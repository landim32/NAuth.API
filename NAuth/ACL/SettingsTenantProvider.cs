using Microsoft.Extensions.Options;
using NAuth.ACL.Interfaces;
using NAuth.DTO.Settings;

namespace NAuth.ACL
{
    public class SettingsTenantProvider : ITenantProvider
    {
        private readonly NAuthSetting _nauthSetting;

        public SettingsTenantProvider(IOptions<NAuthSetting> nauthSetting)
        {
            _nauthSetting = nauthSetting.Value;
        }

        public string? GetTenantId()
        {
            return _nauthSetting.TenantId;
        }
    }
}
