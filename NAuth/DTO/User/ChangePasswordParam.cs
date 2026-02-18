using System.Text.Json.Serialization;

namespace NAuth.DTO.User
{
    public class ChangePasswordParam
    {
        [JsonPropertyName("oldPassword")]
        public string OldPassword { get; set; }
        [JsonPropertyName("newPassword")]
        public string NewPassword { get; set; }
    }
}
