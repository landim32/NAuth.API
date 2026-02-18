using System.Text.Json.Serialization;

namespace NAuth.DTO.User
{
    public class UserPhoneInfo
    {
        [JsonPropertyName("phone")]
        public string Phone { get; set; }
    }
}
