using System.Text.Json.Serialization;

namespace NAuth.DTO.User
{
    public class UserTokenResult
    {
        [JsonPropertyName("token")]
        public string Token { get; set; }
        [JsonPropertyName("user")]
        public UserInfo User { get; set; }
    }
}
