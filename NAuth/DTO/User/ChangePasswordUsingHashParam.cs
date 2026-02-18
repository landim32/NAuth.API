using System.Text.Json.Serialization;

namespace NAuth.DTO.User
{
    public class ChangePasswordUsingHashParam
    {
        [JsonPropertyName("recoveryHash")]
        public string RecoveryHash { get; set; }
        [JsonPropertyName("newPassword")]
        public string NewPassword { get; set; }
    }
}
